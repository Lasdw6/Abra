use crate::Result;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

const MAX_LINE: usize = 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterManifest {
    pub spec: String,
    pub name: String,
    pub version: String,
    pub kinds: Vec<String>,
    pub verbs: Vec<String>,
    #[serde(default)]
    pub executable: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdapterRegistration {
    pub manifest: AdapterManifest,
    pub directory: PathBuf,
    pub executable: PathBuf,
}

#[derive(Debug)]
pub struct AdapterRegistry {
    by_kind: BTreeMap<String, AdapterRegistration>,
    by_name: BTreeMap<String, AdapterRegistration>,
}

impl AdapterRegistry {
    pub fn discover(root: &Path) -> Result<Self> {
        let adapters = root.join("adapters");
        let mut dirs = Vec::new();
        if let Ok(entries) = fs::read_dir(&adapters) {
            for entry in entries {
                let path = entry?.path();
                if path.is_dir() {
                    dirs.push(path);
                }
            }
        }
        let registry = adapters.join("registry.json");
        if let Ok(bytes) = fs::read(registry) {
            dirs.extend(serde_json::from_slice::<Vec<PathBuf>>(&bytes)?);
        }
        dirs.sort();
        dirs.dedup();
        let mut by_kind = BTreeMap::new();
        let mut by_name = BTreeMap::new();
        for directory in dirs {
            let path = directory.join("abra-adapter.json");
            if !path.is_file() {
                continue;
            }
            let manifest: AdapterManifest = serde_json::from_slice(&fs::read(&path)?)?;
            if manifest.spec != "abra-adapter/1" || manifest.kinds.is_empty() {
                return Err(format!("invalid adapter manifest {}", path.display()).into());
            }
            let executable = resolve_executable(&directory, &manifest)?;
            let registration = AdapterRegistration {
                manifest: manifest.clone(),
                directory,
                executable,
            };
            if by_name
                .insert(manifest.name.clone(), registration.clone())
                .is_some()
            {
                return Err(format!("duplicate adapter name {}", manifest.name).into());
            }
            for kind in &manifest.kinds {
                if let Some(other) = by_kind.insert(kind.clone(), registration.clone()) {
                    return Err(format!(
                        "duplicate adapter kind claim {kind}: {} and {}",
                        other.manifest.name, manifest.name
                    )
                    .into());
                }
            }
        }
        Ok(Self { by_kind, by_name })
    }
    pub fn list(&self) -> Vec<&AdapterRegistration> {
        self.by_name.values().collect()
    }
    pub fn for_kind(&self, kind: &str) -> Option<&AdapterRegistration> {
        self.by_kind.get(kind)
    }
    pub fn remove(root: &Path, name: &str) -> Result<()> {
        let registry = Self::discover(root)?;
        let target = registry
            .by_name
            .get(name)
            .ok_or("adapter is not registered")?
            .directory
            .clone();
        update_registry(root, |dirs| dirs.retain(|d| d != &target))
    }
    pub fn add(root: &Path, directory: &Path) -> Result<()> {
        let directory = fs::canonicalize(directory)?;
        if !directory.join("abra-adapter.json").is_file() {
            return Err("directory lacks abra-adapter.json".into());
        }
        update_registry(root, |dirs| {
            if !dirs.contains(&directory) {
                dirs.push(directory.clone());
            }
        })?;
        if let Err(error) = Self::discover(root) {
            let _ = update_registry(root, |dirs| dirs.retain(|d| d != &directory));
            return Err(error);
        }
        Ok(())
    }
    pub async fn export(
        &self,
        kind: &str,
        source: &str,
        daemon_root: &Path,
        timeout: Option<Duration>,
    ) -> Result<ExportResult> {
        let adapter = self
            .for_kind(kind)
            .ok_or_else(|| format!("no adapter registered for kind {kind}"))?;
        require_verb(adapter, "export")?;
        let staging_parent = daemon_root.join("adapter-staging");
        fs::create_dir_all(&staging_parent)?;
        let staging = tempfile::Builder::new()
            .prefix("export-")
            .tempdir_in(&staging_parent)?;
        let result = invoke(adapter, json!({"verb":"export","kind":kind,"source":source,"staging_dir":staging.path(),"options":{}}), timeout).await?;
        validate_staging(staging.path())?;
        let mut export: ExportResult = serde_json::from_value(result)?;
        if let Some(path) = &export.files_path {
            confined(staging.path(), path)?;
        }
        if let Some(floor) = &export.floor {
            if let Some(path) = &floor.thumbnail_path {
                confined(staging.path(), path)?;
            }
        }
        // Keep daemon-owned staging alive for the caller's immediate CAS import.
        if let Some(path) = export.files_path.as_mut() {
            if !path.is_absolute() {
                *path = staging.path().join(&*path);
            }
        }
        let _persisted = staging.keep();
        Ok(export)
    }
    pub async fn import(
        &self,
        kind: &str,
        payload: Value,
        materialized_files: Option<&Path>,
        destination: &Path,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let adapter = self.for_kind(kind).ok_or("adapter disappeared")?;
        require_verb(adapter, "import")?;
        invoke(adapter, json!({"verb":"import","kind":kind,"payload":payload,"materialized_files":materialized_files,"destination":destination,"options":{}}), timeout).await
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExportResult {
    pub payload: Value,
    pub files_path: Option<PathBuf>,
    #[serde(default)]
    pub floor: Option<Floor>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct Floor {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub link: Option<String>,
    pub thumbnail_path: Option<PathBuf>,
}

fn resolve_executable(dir: &Path, manifest: &AdapterManifest) -> Result<PathBuf> {
    let candidate = manifest
        .executable
        .as_deref()
        .map(|x| dir.join(x))
        .unwrap_or_else(|| dir.join(&manifest.name));
    let executable = fs::canonicalize(&candidate)
        .map_err(|_| format!("adapter executable not found: {}", candidate.display()))?;
    if !executable.starts_with(fs::canonicalize(dir)?) {
        return Err("adapter executable escapes its directory".into());
    }
    Ok(executable)
}
fn require_verb(adapter: &AdapterRegistration, verb: &str) -> Result<()> {
    if adapter.manifest.verbs.iter().any(|x| x == verb) {
        Ok(())
    } else {
        Err(format!("adapter {} does not support {verb}", adapter.manifest.name).into())
    }
}
fn update_registry(root: &Path, mutate: impl FnOnce(&mut Vec<PathBuf>)) -> Result<()> {
    let dir = root.join("adapters");
    fs::create_dir_all(&dir)?;
    let path = dir.join("registry.json");
    let mut dirs = fs::read(&path)
        .ok()
        .map(|b| serde_json::from_slice(&b))
        .transpose()?
        .unwrap_or_default();
    mutate(&mut dirs);
    fs::write(path, serde_json::to_vec(&dirs)?)?;
    Ok(())
}
fn confined(root: &Path, path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    };
    let canonical = fs::canonicalize(&absolute)?;
    if !canonical.starts_with(fs::canonicalize(root)?) {
        return Err("adapter staging path escapes daemon-owned directory".into());
    }
    Ok(())
}
fn validate_staging(root: &Path) -> Result<()> {
    fn walk(root: &Path, dir: &Path) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_symlink() {
                return Err("adapter staging directory contains a symlink".into());
            }
            if ty.is_dir() {
                walk(root, &entry.path())?;
            } else {
                confined(root, &entry.path())?;
            }
        }
        Ok(())
    }
    walk(root, root)
}

async fn invoke(
    adapter: &AdapterRegistration,
    mut request: Value,
    timeout: Option<Duration>,
) -> Result<Value> {
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    let request_id = hex::encode(id);
    request["protocol"] = json!("abra-adapter/1");
    request["request_id"] = json!(request_id);
    let mut child = Command::new(&adapter.executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("adapter stdin unavailable")?;
    let stdout = child.stdout.take().ok_or("adapter stdout unavailable")?;
    let line = serde_json::to_vec(&request)?;
    if line.len() > MAX_LINE {
        return Err("adapter request exceeds 1 MiB".into());
    }
    stdin.write_all(&line).await?;
    stdin.write_all(b"\n").await?;
    let operation = async {
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).await?;
        if line.len() > MAX_LINE {
            return Err("adapter response exceeds 1 MiB".into());
        }
        let response: Value =
            serde_json::from_str(&line).map_err(|e| format!("malformed adapter output: {e}"))?;
        if response.get("request_id").and_then(Value::as_str) != Some(&request_id) {
            return Err("adapter response request_id mismatch".into());
        }
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(format!(
                "adapter error: {}",
                response.get("error").unwrap_or(&Value::Null)
            )
            .into());
        }
        Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(
            response.get("result").cloned().unwrap_or_else(|| {
                let mut x = response;
                if let Some(o) = x.as_object_mut() {
                    o.remove("request_id");
                    o.remove("ok");
                }
                x
            }),
        )
    };
    match tokio::time::timeout(timeout.unwrap_or(DEFAULT_TIMEOUT), operation).await {
        Ok(result) => {
            let value = result?;
            drop(stdin);
            reap(&mut child).await?;
            Ok(value)
        }
        Err(_) => {
            cancel(&mut child, &request_id).await;
            Err("adapter operation timed out".into())
        }
    }
}
async fn reap(child: &mut Child) -> Result<()> {
    let status = child.wait().await?;
    if !status.success() {
        return Err(format!("adapter exited with {status}").into());
    }
    Ok(())
}
async fn cancel(child: &mut Child, request_id: &str) {
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(format!("{{\"protocol\":\"abra-adapter/1\",\"request_id\":\"{request_id}\",\"verb\":\"cancel\"}}\n").as_bytes()).await;
    }
    if tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn adapter(root: &Path, dir: &str, name: &str, kind: &str, body: &str) {
        let path = root.join("adapters").join(dir);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("abra-adapter.json"),serde_json::to_vec(&json!({"spec":"abra-adapter/1","name":name,"version":"1","kinds":[kind],"verbs":["export","import"],"executable":"run"})).unwrap()).unwrap();
        let executable = path.join("run");
        fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[test]
    fn discovery_rejects_duplicate_kind_claims() {
        let root = tempfile::tempdir().unwrap();
        adapter(root.path(), "a", "a", "com.test.kind", "exit 0");
        adapter(root.path(), "b", "b", "com.test.kind", "exit 0");
        assert!(AdapterRegistry::discover(root.path())
            .unwrap_err()
            .to_string()
            .contains("duplicate adapter kind"));
    }
    #[tokio::test]
    async fn malformed_timeout_and_escape_are_rejected() {
        let malformed = tempfile::tempdir().unwrap();
        adapter(
            malformed.path(),
            "a",
            "a",
            "com.test.bad",
            "read line; echo nope",
        );
        let registry = AdapterRegistry::discover(malformed.path()).unwrap();
        assert!(registry
            .export(
                "com.test.bad",
                "x",
                malformed.path(),
                Some(Duration::from_secs(1))
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("malformed"));
        let slow = tempfile::tempdir().unwrap();
        adapter(slow.path(), "a", "a", "com.test.slow", "read line; sleep 2");
        let registry = AdapterRegistry::discover(slow.path()).unwrap();
        assert!(registry
            .export(
                "com.test.slow",
                "x",
                slow.path(),
                Some(Duration::from_millis(20))
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        let escape = tempfile::tempdir().unwrap();
        adapter(
            escape.path(),
            "a",
            "a",
            "com.test.escape",
            r#"read line; id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p'); printf '{"request_id":"%s","ok":true,"result":{"payload":{},"files_path":"/tmp"}}\n' "$id""#,
        );
        let registry = AdapterRegistry::discover(escape.path()).unwrap();
        assert!(registry
            .export(
                "com.test.escape",
                "x",
                escape.path(),
                Some(Duration::from_secs(1))
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("escapes"));
    }
    #[tokio::test]
    async fn reference_folder_export_and_import() {
        let root = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("hello"), b"world").unwrap();
        AdapterRegistry::add(
            root.path(),
            Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../adapters/reference-folder"
            )),
        )
        .unwrap();
        let registry = AdapterRegistry::discover(root.path()).unwrap();
        let exported = registry
            .export(
                "dev.abra.folder",
                source.path().to_str().unwrap(),
                root.path(),
                Some(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(
            fs::read(exported.files_path.as_ref().unwrap().join("hello")).unwrap(),
            b"world"
        );
        let destination = tempfile::tempdir().unwrap();
        registry
            .import(
                "dev.abra.folder",
                exported.payload,
                exported.files_path.as_deref(),
                destination.path(),
                Some(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(
            fs::read(destination.path().join("hello")).unwrap(),
            b"world"
        );
    }
}
