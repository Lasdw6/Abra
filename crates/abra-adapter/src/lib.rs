//! Discovery and the `abra-adapter/1` NDJSON runner.
//!
//! Cadabra uses this crate. Other programs can too: it does not depend on
//! `abra-net`, `abra-relay`, or HTTP.

#![forbid(unsafe_code)]

pub mod protocol;

use abra_core::cas::Hash;
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

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterManifest {
    pub spec: String,
    pub name: String,
    pub version: String,
    pub kinds: Vec<String>,
    pub verbs: Vec<String>,
    /// Capsule kinds this adapter answers `control` for. A capsule kind is the
    /// `kind` of its genesis, so it is usually not one of `kinds`.
    #[serde(default)]
    pub controls: Vec<String>,
    #[serde(default)]
    pub executable: Option<String>,
    /// Optional choices a user interface can offer for `source` and
    /// `destination`. Values are passed to the adapter unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presets: Option<Presets>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presets {
    #[serde(default)]
    pub source: Vec<Preset>,
    #[serde(default)]
    pub destination: Vec<Preset>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub label: String,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Presets {
    pub fn validate(&self) -> Result<()> {
        for list in [&self.source, &self.destination] {
            if list.len() > 16 {
                return Err("adapter manifest lists more than 16 presets".into());
            }
            for preset in list {
                if preset.label.is_empty() || preset.label.len() > 80 {
                    return Err("adapter preset label must have 1 to 80 characters".into());
                }
                if preset.description.as_ref().is_some_and(|d| d.len() > 240) {
                    return Err("adapter preset description exceeds 240 characters".into());
                }
                if !(preset.value.is_string() || preset.value.is_object()) {
                    return Err("adapter preset value must be a string or an object".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AdapterRegistration {
    pub manifest: AdapterManifest,
    pub directory: PathBuf,
    pub executable: PathBuf,
    /// Where this registration came from: `root`, `registry`, `flag`, or `env`.
    pub source: &'static str,
}

impl AdapterRegistration {
    pub fn supports(&self, verb: &str) -> bool {
        self.manifest.verbs.iter().any(|x| x == verb)
    }
}

/// A discovery directory supplied for one daemon process only. It is either an
/// adapter directory or a parent whose immediate children are adapter
/// directories. Nothing here is persisted.
#[derive(Clone, Debug)]
pub struct ExtraAdapterDir {
    pub path: PathBuf,
    pub source: &'static str,
}

impl ExtraAdapterDir {
    pub fn flag(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            source: "flag",
        }
    }
    pub fn env(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            source: "env",
        }
    }
    /// Colon-separated `ABRA_ADAPTERS`, in the order it is written.
    pub fn from_env() -> Vec<Self> {
        let Some(value) = std::env::var_os("ABRA_ADAPTERS") else {
            return Vec::new();
        };
        std::env::split_paths(&value)
            .filter(|path| !path.as_os_str().is_empty())
            .map(Self::env)
            .collect()
    }
}

#[derive(Debug)]
pub struct AdapterRegistry {
    by_name: BTreeMap<String, AdapterRegistration>,
    /// Kind claim to adapter name; registrations are stored once, by name.
    kinds: BTreeMap<String, String>,
    /// Capsule kind to the adapter that handles `control` for it.
    controls: BTreeMap<String, String>,
    errors: Vec<String>,
}

impl AdapterRegistry {
    pub fn discover(root: &Path) -> Result<Self> {
        Self::discover_with(root, &[])
    }
    /// `extra` joins `<root>/adapters/*` and the persisted registry for this
    /// process only; the first source that names a directory owns it.
    pub fn discover_with(root: &Path, extra: &[ExtraAdapterDir]) -> Result<Self> {
        let adapters = root.join("adapters");
        let mut errors = Vec::new();
        let mut dirs: BTreeMap<PathBuf, &'static str> = BTreeMap::new();
        if let Ok(entries) = fs::read_dir(&adapters) {
            for entry in entries {
                let path = entry?.path();
                if path.is_dir() {
                    dirs.entry(path).or_insert("root");
                }
            }
        }
        let registry = adapters.join("registry.json");
        if let Ok(bytes) = fs::read(registry) {
            for path in serde_json::from_slice::<Vec<PathBuf>>(&bytes)? {
                dirs.entry(path).or_insert("registry");
            }
        }
        for entry in extra {
            match expand_adapter_dir(&entry.path) {
                Ok(paths) => {
                    for path in paths {
                        dirs.entry(path).or_insert(entry.source);
                    }
                }
                Err(error) => errors.push(format!("{}: {error}", entry.path.display())),
            }
        }
        let mut by_name = BTreeMap::new();
        let mut kinds = BTreeMap::new();
        let mut controls: BTreeMap<String, String> = BTreeMap::new();
        let mut ambiguous_kinds = std::collections::BTreeSet::new();
        let mut ambiguous_controls = std::collections::BTreeSet::new();
        for (directory, source) in dirs {
            let (manifest, executable) = match load_registration(&directory) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(format!("{}: {error}", directory.display()));
                    continue;
                }
            };
            if by_name.contains_key(&manifest.name) {
                errors.push(format!("duplicate adapter name {}", manifest.name));
                continue;
            }
            if let Some((kind, other)) = manifest
                .kinds
                .iter()
                .find_map(|kind| kinds.get(kind).map(|other: &String| (kind, other)))
            {
                errors.push(format!(
                    "duplicate adapter kind claim {kind}: {other} and {}",
                    manifest.name
                ));
                ambiguous_kinds.insert(kind.clone());
                kinds.remove(kind);
                continue;
            }
            if let Some((kind, other)) = manifest
                .controls
                .iter()
                .find_map(|kind| controls.get(kind).map(|other: &String| (kind, other)))
            {
                errors.push(format!(
                    "duplicate adapter control claim {kind}: {other} and {}",
                    manifest.name
                ));
                ambiguous_controls.insert(kind.clone());
                controls.remove(kind);
                continue;
            }
            for kind in &manifest.kinds {
                if !ambiguous_kinds.contains(kind) {
                    kinds.insert(kind.clone(), manifest.name.clone());
                }
            }
            for kind in &manifest.controls {
                if !ambiguous_controls.contains(kind) {
                    controls.insert(kind.clone(), manifest.name.clone());
                }
            }
            by_name.insert(
                manifest.name.clone(),
                AdapterRegistration {
                    manifest,
                    directory,
                    executable,
                    source,
                },
            );
        }
        Ok(Self {
            by_name,
            kinds,
            controls,
            errors,
        })
    }
    pub fn list(&self) -> Value {
        json!({"adapters":self.by_name.values().collect::<Vec<_>>(),"errors":self.errors})
    }
    pub fn for_kind(&self, kind: &str) -> Option<&AdapterRegistration> {
        self.by_name.get(self.kinds.get(kind)?)
    }
    /// The adapter that declared `controls` for this capsule kind.
    pub fn for_control(&self, kind: &str) -> Option<&AdapterRegistration> {
        self.by_name.get(self.controls.get(kind)?)
    }
    pub fn remove(root: &Path, name: &str) -> Result<()> {
        let registry = Self::discover(root)?;
        let registration = registry
            .by_name
            .get(name)
            .ok_or("adapter is not registered")?;
        if registration.source == "flag" || registration.source == "env" {
            return Err(format!(
                "adapter {name} comes from --adapters/ABRA_ADAPTERS and is not persisted"
            )
            .into());
        }
        let target = registration.directory.clone();
        update_registry(root, |dirs| dirs.retain(|d| d != &target))
    }
    pub fn add(root: &Path, directory: &Path, extra: &[ExtraAdapterDir]) -> Result<()> {
        let directory = fs::canonicalize(directory)?;
        let (manifest, _) = load_registration(&directory)?;
        let existing = Self::discover_with(root, extra)?;
        if existing.by_name.contains_key(&manifest.name) {
            return Err(format!("duplicate adapter name {}", manifest.name).into());
        }
        for kind in &manifest.kinds {
            if let Some(other) = existing.for_kind(kind) {
                return Err(format!(
                    "duplicate adapter kind claim {kind}: {} and {}",
                    other.manifest.name, manifest.name
                )
                .into());
            }
        }
        for kind in &manifest.controls {
            if let Some(other) = existing.for_control(kind) {
                return Err(format!(
                    "duplicate adapter control claim {kind}: {} and {}",
                    other.manifest.name, manifest.name
                )
                .into());
            }
        }
        update_registry(root, |dirs| {
            if !dirs.contains(&directory) {
                dirs.push(directory.clone());
            }
        })?;
        Ok(())
    }
    pub async fn export(
        &self,
        kind: &str,
        source: Value,
        options: &BTreeMap<String, String>,
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
        let result = invoke(adapter, json!({"verb":"export","kind":kind,"source":source,"staging_dir":staging.path(),"options":options}), timeout).await?;
        validate_staging(staging.path())?;
        let mut export: ExportResult = serde_json::from_value(result)?;
        if let Some(path) = &export.files_path {
            confined(staging.path(), path)?;
        }
        if let Some(floor) = &export.floor {
            if let Some(path) = &floor.thumbnail_path {
                validate_thumbnail(path)?;
            }
        }
        // Keep daemon-owned staging alive for the caller's immediate CAS import.
        if let Some(path) = export.files_path.as_mut() {
            if !path.is_absolute() {
                *path = staging.path().join(&*path);
            }
        }
        export.staging = Some(staging);
        Ok(export)
    }
    /// Enumerate current transferable items without changing or launching the source.
    pub async fn inventory(&self, adapter_name: &str) -> Result<InventoryReport> {
        let adapter = self
            .by_name
            .get(adapter_name)
            .ok_or_else(|| format!("no adapter registered with name {adapter_name}"))?;
        require_verb(adapter, "inventory")?;
        let kind = adapter
            .manifest
            .kinds
            .first()
            .ok_or("adapter manifest has no kinds")?;
        let value = invoke(
            adapter,
            json!({"verb":"inventory","kind":kind,"options":{}}),
            Some(Duration::from_secs(10)),
        )
        .await?;
        Ok(serde_json::from_value(value)?)
    }
    pub async fn import(
        &self,
        kind: &str,
        payload: Value,
        materialized_files: Option<&Path>,
        destination: Value,
        options: &BTreeMap<String, String>,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        self.import_with_workspace(
            kind,
            payload,
            materialized_files,
            destination,
            None,
            options,
            timeout,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn import_with_workspace(
        &self,
        kind: &str,
        payload: Value,
        materialized_files: Option<&Path>,
        destination: Value,
        workspace: Option<&Path>,
        options: &BTreeMap<String, String>,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let adapter = self.for_kind(kind).ok_or("adapter disappeared")?;
        require_verb(adapter, "import")?;
        invoke(adapter, json!({"verb":"import","kind":kind,"payload":payload,"materialized_files":materialized_files,"destination":destination,"workspace":workspace,"options":options}), timeout).await
    }
    /// Read-only pre-flight for a `send`. The response carries `warnings` and
    /// `blocked` lists the daemon acts on; the adapter moves nothing.
    pub async fn inspect(
        &self,
        kind: &str,
        source: Value,
        options: &BTreeMap<String, String>,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let adapter = self
            .for_kind(kind)
            .ok_or_else(|| format!("no adapter registered for kind {kind}"))?;
        require_verb(adapter, "inspect")?;
        invoke(
            adapter,
            json!({"verb":"inspect","kind":kind,"source":source,"options":options}),
            timeout,
        )
        .await
    }
    /// Read-only picture of a live source: `{media_type, data, width, height,
    /// title?, items?}`. The adapter must not change the source.
    pub async fn preview(
        &self,
        kind: &str,
        source: Value,
        options: &BTreeMap<String, String>,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let adapter = self
            .for_kind(kind)
            .ok_or_else(|| format!("no adapter registered for kind {kind}"))?;
        require_verb(adapter, "preview")?;
        invoke(
            adapter,
            json!({"verb":"preview","kind":kind,"source":source,"options":options}),
            timeout.or(Some(Duration::from_secs(10))),
        )
        .await
    }
    /// Hand a verified control message to the adapter that claims the capsule
    /// kind. The value it returns is what the sender sees in the control ack.
    pub async fn control(
        &self,
        request: &ControlRequest,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let adapter = self
            .for_control(&request.kind)
            .ok_or_else(|| format!("no adapter handles control for {}", request.kind))?;
        require_verb(adapter, "control")?;
        let mut value = serde_json::to_value(request)?;
        value["verb"] = json!("control");
        invoke(adapter, value, timeout).await
    }
}

/// The `control` request body, exactly as the adapter receives it.
#[derive(Clone, Debug, Serialize)]
pub struct ControlRequest {
    /// The capsule's kind, not an adapter payload kind.
    pub kind: String,
    pub capsule_id: Hash,
    /// `pause`, `stop`, or `instruct`.
    pub op: String,
    pub text: Option<String>,
    /// Where this device last materialized the capsule, when it knows.
    pub workspace: Option<PathBuf>,
    pub options: BTreeMap<String, String>,
}

/// What an `inspect` response says about a source the daemon is about to send.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct InspectResult {
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub warnings: Vec<Value>,
    #[serde(default)]
    pub blocked: Vec<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InventoryReport {
    pub label: String,
    pub items: Vec<InventoryItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryItem {
    pub id: String,
    pub kind: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub source: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
    pub transferable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl<'de> Deserialize<'de> for InventoryReport {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            label: String,
            items: Vec<InventoryItem>,
            #[serde(default)]
            error: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        if raw.items.len() > 256 {
            return Err(serde::de::Error::custom(
                "inventory report exceeds 256 items",
            ));
        }
        Ok(Self {
            label: raw.label,
            items: raw.items,
            error: raw.error,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ExportResult {
    pub payload: Value,
    pub files_path: Option<PathBuf>,
    #[serde(default)]
    pub floor: Option<Floor>,
    /// Optional back-reference the adapter derived itself; the daemon copies it
    /// into the partial manifest's `provenance`.
    #[serde(default)]
    pub provenance: Option<ExportProvenance>,
    #[serde(skip)]
    pub staging: Option<tempfile::TempDir>,
}
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ExportProvenance {
    pub capsule_id: Hash,
    #[serde(alias = "snapshot_hash")]
    pub snapshot_id: Hash,
}
#[derive(Clone, Debug, Deserialize)]
pub struct Floor {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub link: Option<String>,
    pub thumbnail_path: Option<PathBuf>,
}

#[derive(Debug)]
pub struct AdapterError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AdapterError {}

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
fn load_registration(directory: &Path) -> Result<(AdapterManifest, PathBuf)> {
    let path = directory.join("abra-adapter.json");
    if !path.is_file() {
        return Err("directory lacks abra-adapter.json".into());
    }
    let manifest: AdapterManifest = serde_json::from_slice(&fs::read(&path)?)?;
    if manifest.spec != "abra-adapter/1" || manifest.kinds.is_empty() {
        return Err(format!("invalid adapter manifest {}", path.display()).into());
    }
    if let Some(presets) = &manifest.presets {
        presets
            .validate()
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    let executable = resolve_executable(directory, &manifest)?;
    Ok((manifest, executable))
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
/// An entry is an adapter directory, or a parent of adapter directories.
fn expand_adapter_dir(path: &Path) -> Result<Vec<PathBuf>> {
    if path.join("abra-adapter.json").is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        return Err("adapter path is not a directory".into());
    }
    let mut children = Vec::new();
    for entry in fs::read_dir(path)? {
        let child = entry?.path();
        if child.join("abra-adapter.json").is_file() {
            children.push(child);
        }
    }
    if children.is_empty() {
        return Err("directory holds no abra-adapter.json and no adapter children".into());
    }
    children.sort();
    Ok(children)
}

fn validate_thumbnail(path: &Path) -> Result<()> {
    let meta = fs::metadata(path).map_err(|_| "adapter thumbnail_path is not a readable file")?;
    if !meta.is_file() {
        return Err("adapter thumbnail_path is not a file".into());
    }
    if meta.len() == 0 || meta.len() > 512 * 1024 {
        return Err("adapter thumbnail must be 1 to 512 KiB".into());
    }
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

/// Spawn `adapter`, write one NDJSON request, and parse the response line.
pub async fn invoke(
    adapter: &AdapterRegistration,
    request: Value,
    timeout: Option<Duration>,
) -> Result<Value> {
    let verb = request
        .get("verb")
        .and_then(Value::as_str)
        .ok_or("adapter request lacks verb")?
        .to_owned();
    let (request_id, request) = protocol::build_request(&verb, request)?;
    let mut child = Command::new(&adapter.executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("adapter stdin unavailable")?;
    let stdout = child.stdout.take().ok_or("adapter stdout unavailable")?;
    let line = serde_json::to_vec(&request)?;
    stdin.write_all(&line).await?;
    stdin.write_all(b"\n").await?;
    let operation = async {
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).await?;
        protocol::parse_response(&verb, &request_id, &line)
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
    fn discovery_reports_duplicate_kind_claims_and_refuses_dispatch() {
        let root = tempfile::tempdir().unwrap();
        adapter(root.path(), "a", "a", "com.test.kind", "exit 0");
        adapter(root.path(), "b", "b", "com.test.kind", "exit 0");
        let registry = AdapterRegistry::discover(root.path()).unwrap();
        assert!(registry.for_kind("com.test.kind").is_none());
        assert!(registry
            .errors
            .iter()
            .any(|error| error.contains("duplicate adapter kind")));
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
                json!("x"),
                &BTreeMap::new(),
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
                json!("x"),
                &BTreeMap::new(),
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
            r#"read line; id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p'); printf '{"request_id":"%s","ok":true,"payload":{},"files_path":"/tmp"}\n' "$id""#,
        );
        let registry = AdapterRegistry::discover(escape.path()).unwrap();
        assert!(registry
            .export(
                "com.test.escape",
                json!("x"),
                &BTreeMap::new(),
                escape.path(),
                Some(Duration::from_secs(1))
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("escapes"));

        let wrapped = tempfile::tempdir().unwrap();
        adapter(
            wrapped.path(),
            "a",
            "a",
            "com.test.wrapped",
            r#"read line; id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p'); printf '{"request_id":"%s","ok":true,"result":{"payload":{},"files_path":null}}\n' "$id""#,
        );
        let registry = AdapterRegistry::discover(wrapped.path()).unwrap();
        assert!(registry
            .export(
                "com.test.wrapped",
                json!("x"),
                &BTreeMap::new(),
                wrapped.path(),
                Some(Duration::from_secs(1)),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("object payload"));

        let failed = tempfile::tempdir().unwrap();
        adapter(
            failed.path(),
            "a",
            "a",
            "com.test.failed",
            r#"read line; id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p'); printf '{"request_id":"%s","ok":false,"error":{"code":"busy","message":"try later","retryable":true}}\n' "$id""#,
        );
        let registry = AdapterRegistry::discover(failed.path()).unwrap();
        let error = registry
            .export(
                "com.test.failed",
                json!("x"),
                &BTreeMap::new(),
                failed.path(),
                Some(Duration::from_secs(1)),
            )
            .await
            .unwrap_err();
        let adapter_error = error.downcast_ref::<AdapterError>().unwrap();
        assert_eq!(adapter_error.code, "busy");
        assert_eq!(adapter_error.message, "try later");
        assert!(adapter_error.retryable);
        assert_eq!(adapter_error.to_string(), "busy: try later");
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
            &[],
        )
        .unwrap();
        let registry = AdapterRegistry::discover(root.path()).unwrap();
        let exported = registry
            .export(
                "dev.abra.folder",
                json!(source.path()),
                &BTreeMap::new(),
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
                json!(destination.path()),
                &BTreeMap::new(),
                Some(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(
            fs::read(destination.path().join("hello")).unwrap(),
            b"world"
        );
        let inspected = registry
            .inspect(
                "dev.abra.folder",
                json!(source.path()),
                &BTreeMap::new(),
                Some(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(inspected["summary"], json!("1 files"));
        assert_eq!(inspected["warnings"], json!([]));
        assert_eq!(inspected["blocked"], json!([]));
        let controlled = registry
            .control(
                &ControlRequest {
                    kind: "dev.abra.workspace".into(),
                    capsule_id: Hash::from_bytes([7; 32]),
                    op: "instruct".into(),
                    text: Some("continue".into()),
                    workspace: Some(destination.path().to_owned()),
                    options: BTreeMap::new(),
                },
                Some(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(controlled["op"], json!("instruct"));
        assert_eq!(controlled["workspace"], json!(destination.path()));
    }

    #[tokio::test]
    async fn export_preserves_json_or_string_source_and_options() {
        let root = tempfile::tempdir().unwrap();
        let captured = root.path().join("captured.json");
        adapter(
            root.path(),
            "capture",
            "capture",
            "com.test.capture",
            &format!(
                r#"read line; printf '%s' "$line" > '{}'; id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p'); printf '{{"request_id":"%s","ok":true,"payload":{{}},"files_path":null}}\n' "$id""#,
                captured.display()
            ),
        );
        let registry = AdapterRegistry::discover(root.path()).unwrap();
        let options = BTreeMap::from([("mode".into(), "fast".into())]);
        registry
            .export(
                "com.test.capture",
                json!({"tab":3}),
                &options,
                root.path(),
                Some(Duration::from_secs(10)),
            )
            .await
            .unwrap();
        let request: Value = serde_json::from_slice(&fs::read(&captured).unwrap()).unwrap();
        assert_eq!(request["source"], json!({"tab":3}));
        assert_eq!(request["options"], json!({"mode":"fast"}));
        registry
            .export(
                "com.test.capture",
                json!("not json"),
                &BTreeMap::new(),
                root.path(),
                Some(Duration::from_secs(10)),
            )
            .await
            .unwrap();
        let request: Value = serde_json::from_slice(&fs::read(captured).unwrap()).unwrap();
        assert_eq!(request["source"], json!("not json"));
    }

    #[tokio::test]
    async fn import_passes_destination_and_options() {
        let root = tempfile::tempdir().unwrap();
        let captured = root.path().join("import.json");
        adapter(
            root.path(),
            "capture",
            "capture",
            "com.test.import",
            &format!(
                r#"read line; printf '%s' "$line" > '{}'; id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p'); printf '{{"request_id":"%s","ok":true,"result":{{}}}}\n' "$id""#,
                captured.display()
            ),
        );
        let registry = AdapterRegistry::discover(root.path()).unwrap();
        registry
            .import_with_workspace(
                "com.test.import",
                json!({}),
                None,
                json!({"profile":"work"}),
                Some(Path::new("/work/demo")),
                &BTreeMap::from([("merge".into(), "true".into())]),
                Some(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        let request: Value = serde_json::from_slice(&fs::read(captured).unwrap()).unwrap();
        assert_eq!(request["destination"], json!({"profile":"work"}));
        assert_eq!(request["workspace"], json!("/work/demo"));
        assert_eq!(request["options"], json!({"merge":"true"}));
    }

    #[test]
    fn two_adapters_claiming_one_control_kind_conflict() {
        let root = tempfile::tempdir().unwrap();
        for name in ["a", "b"] {
            let path = root.path().join("adapters").join(name);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("abra-adapter.json"),serde_json::to_vec(&json!({"spec":"abra-adapter/1","name":name,"version":"1","kinds":[format!("com.test.{name}")],"controls":["dev.abra.workspace"],"verbs":["control"],"executable":"run"})).unwrap()).unwrap();
            let executable = path.join("run");
            fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let registry = AdapterRegistry::discover(root.path()).unwrap();
        assert!(registry.for_control("dev.abra.workspace").is_none());
        assert!(registry
            .errors
            .iter()
            .any(|error| error.contains("duplicate adapter control claim")));
    }

    #[test]
    fn broken_sibling_does_not_block_discovery() {
        let root = tempfile::tempdir().unwrap();
        adapter(root.path(), "good", "good", "com.test.good", "exit 0");
        let broken = root.path().join("adapters/broken");
        fs::create_dir_all(&broken).unwrap();
        fs::write(broken.join("abra-adapter.json"), b"not json").unwrap();
        let registry = AdapterRegistry::discover(root.path()).unwrap();
        assert!(registry.for_kind("com.test.good").is_some());
        assert_eq!(registry.errors.len(), 1);
    }

    fn write_manifest(root: &Path, name: &str, extra: Value) {
        let path = root.join("adapters").join(name);
        fs::create_dir_all(&path).unwrap();
        let mut manifest = json!({"spec":"abra-adapter/1","name":name,"version":"1","kinds":[format!("com.test.{name}")],"verbs":["export"],"executable":"run"});
        if let Some(object) = extra.as_object() {
            for (key, value) in object {
                manifest[key] = value.clone();
            }
        }
        fs::write(
            path.join("abra-adapter.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let executable = path.join("run");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn presets_parse_and_reject_invalid_values() {
        let ok = tempfile::tempdir().unwrap();
        write_manifest(
            ok.path(),
            "ok",
            json!({"presets":{"source":[{"label":"Local","value":"local","description":"from here"},{"label":"Object","value":{"type":"cdp"}}],"destination":[{"label":"Here","value":"local"}]}}),
        );
        let registry = AdapterRegistry::discover(ok.path()).unwrap();
        let presets = registry
            .for_kind("com.test.ok")
            .unwrap()
            .manifest
            .presets
            .as_ref()
            .unwrap();
        assert_eq!(presets.source.len(), 2);
        assert_eq!(presets.destination.len(), 1);
        presets.validate().unwrap();

        let too_many = tempfile::tempdir().unwrap();
        let entries: Vec<Value> = (0..17)
            .map(|i| json!({"label": format!("P{i}"), "value": "x"}))
            .collect();
        write_manifest(
            too_many.path(),
            "many",
            json!({"presets":{"source":entries}}),
        );
        let registry = AdapterRegistry::discover(too_many.path()).unwrap();
        assert!(registry
            .errors
            .iter()
            .any(|error| error.contains("more than 16 presets")));

        let long_label = "a".repeat(81);
        let long_desc = "a".repeat(241);
        for (name, presets, fragment) in [
            (
                "empty",
                json!({"source":[{"label":"","value":"x"}]}),
                "label must have 1 to 80",
            ),
            (
                "long-label",
                json!({"source":[{"label":long_label,"value":"x"}]}),
                "label must have 1 to 80",
            ),
            (
                "long-desc",
                json!({"source":[{"label":"ok","value":"x","description":long_desc}]}),
                "description exceeds 240",
            ),
            (
                "array-value",
                json!({"source":[{"label":"ok","value":[]}]}),
                "string or an object",
            ),
            (
                "number-value",
                json!({"source":[{"label":"ok","value":1}]}),
                "string or an object",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            write_manifest(root.path(), name, json!({"presets": presets}));
            let registry = AdapterRegistry::discover(root.path()).unwrap();
            assert!(
                registry.errors.iter().any(|error| error.contains(fragment)),
                "{name}: {:?}",
                registry.errors
            );
        }
    }

    #[test]
    fn browser_session_manifest_loads_presets() {
        let dir = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../adapters/browser-session"
        ));
        let (manifest, _) = load_registration(dir).unwrap();
        let presets = manifest.presets.expect("browser-session presets");
        assert_eq!(presets.source.len(), 1);
        assert_eq!(presets.destination.len(), 1);
        assert_eq!(presets.source[0].label, "Browser");
        assert_eq!(presets.source[0].value, json!("local"));
        assert_eq!(presets.destination[0].label, "Browser");
        assert_eq!(presets.destination[0].value, json!("local"));
        presets.validate().unwrap();
    }
}
