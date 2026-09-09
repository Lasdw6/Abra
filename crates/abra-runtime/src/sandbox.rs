//! Small filesystem and process helpers used inside temporary sandboxes.

use clap::{Args, Subcommand};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::{fs::PermissionsExt, process::CommandExt};

#[derive(Debug, Args)]
pub struct SandboxArgs {
    #[command(subcommand)]
    command: SandboxCommand,
}

#[derive(Debug, Subcommand)]
enum SandboxCommand {
    /// Pack a directory into an uncompressed tar archive.
    Pack {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        archive: PathBuf,
    },
    /// Extract a validated archive into an empty directory.
    Extract {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    /// Replace a workspace with a validated archive.
    Restore {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        replace: bool,
    },
    /// Start a process in a new session from a JSON specification.
    StartDetached {
        #[arg(long)]
        spec: PathBuf,
    },
}

pub fn run(args: SandboxArgs) -> Result<Value, Box<dyn Error>> {
    match args.command {
        SandboxCommand::Pack { source, archive } => {
            pack_tree(&source, &archive)?;
            Ok(json!({"archive": archive}))
        }
        SandboxCommand::Extract {
            archive,
            destination,
        } => {
            extract_tree(&archive, &destination)?;
            Ok(json!({"destination": destination}))
        }
        SandboxCommand::Restore {
            archive,
            workspace,
            replace,
        } => {
            restore_tree(&archive, &workspace, replace)?;
            Ok(json!({"workspace": workspace, "replaced": replace}))
        }
        SandboxCommand::StartDetached { spec } => start_detached(&spec),
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn normalize_archive_path(path: &Path) -> io::Result<PathBuf> {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => clean.push(part),
            Component::ParentDir => {
                if !clean.pop() {
                    return Err(invalid(format!(
                        "archive path escapes the tree: {}",
                        path.display()
                    )));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(invalid(format!(
                    "archive path escapes the tree: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(clean)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Directory,
    Regular,
    Symlink,
    Hardlink,
}

#[derive(Clone, Debug)]
struct EntryInfo {
    kind: Kind,
    link: Option<PathBuf>,
}

fn validated_entries(archive: &Path) -> io::Result<HashMap<PathBuf, EntryInfo>> {
    let file = File::open(archive)?;
    let mut tar = tar::Archive::new(file);
    let mut entries = HashMap::new();
    for item in tar.entries()? {
        let entry = item?;
        let raw = entry.path()?.into_owned();
        let path = normalize_archive_path(&raw)?;
        let entry_type = entry.header().entry_type();
        if path.as_os_str().is_empty() && entry_type.is_dir() {
            continue;
        }
        if path.as_os_str().is_empty() || entries.contains_key(&path) {
            return Err(invalid(format!(
                "invalid or duplicate archive entry: {}",
                raw.display()
            )));
        }
        let kind = if entry_type.is_dir() {
            Kind::Directory
        } else if entry_type.is_file() {
            Kind::Regular
        } else if entry_type.is_symlink() {
            Kind::Symlink
        } else if entry_type.is_hard_link() {
            Kind::Hardlink
        } else {
            return Err(invalid(format!(
                "unsupported archive entry: {}",
                raw.display()
            )));
        };
        let link = if matches!(kind, Kind::Symlink | Kind::Hardlink) {
            Some(
                entry
                    .link_name()?
                    .ok_or_else(|| {
                        invalid(format!("archive link has no target: {}", raw.display()))
                    })?
                    .into_owned(),
            )
        } else {
            None
        };
        entries.insert(path, EntryInfo { kind, link });
    }

    for (path, info) in &entries {
        let mut parent = path.parent();
        while let Some(candidate) = parent {
            if candidate.as_os_str().is_empty() {
                break;
            }
            if entries
                .get(candidate)
                .is_some_and(|entry| entry.kind != Kind::Directory)
            {
                return Err(invalid(format!(
                    "archive entry has a non-directory parent: {}",
                    path.display()
                )));
            }
            parent = candidate.parent();
        }

        if info.kind == Kind::Hardlink {
            let target = normalize_archive_path(info.link.as_deref().unwrap())?;
            if entries.get(&target).map(|entry| entry.kind) != Some(Kind::Regular) {
                return Err(invalid(format!(
                    "archive hardlink must target a regular member: {}",
                    path.display()
                )));
            }
        }

        if info.kind == Kind::Symlink {
            let raw_target = info.link.as_deref().unwrap();
            if raw_target.is_absolute() {
                return Err(invalid(format!(
                    "archive symlink has an absolute target: {}",
                    path.display()
                )));
            }
            let mut target = path.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
            for component in raw_target.components() {
                match component {
                    Component::CurDir => {}
                    Component::Normal(part) => target.push(part),
                    Component::ParentDir => {
                        if !target.pop() {
                            return Err(invalid(format!(
                                "archive symlink escapes the tree: {}",
                                path.display()
                            )));
                        }
                    }
                    Component::RootDir | Component::Prefix(_) => {
                        return Err(invalid(format!(
                            "archive symlink has an absolute target: {}",
                            path.display()
                        )));
                    }
                }
                if entries
                    .get(&target)
                    .is_some_and(|entry| entry.kind == Kind::Symlink)
                {
                    return Err(invalid(format!(
                        "archive symlink traverses another link: {}",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(entries)
}

fn directory_is_empty(path: &Path) -> io::Result<bool> {
    Ok(fs::read_dir(path)?.next().is_none())
}

fn ensure_empty_destination(destination: &Path) -> io::Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(invalid("extraction destination is a symlink"));
            }
            if !metadata.is_dir() {
                return Err(invalid("extraction destination is not a directory"));
            }
            if !directory_is_empty(destination)? {
                return Err(invalid("extraction destination must be empty"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(destination)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(unix)]
fn create_new_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_new_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn extract_tree(archive: &Path, destination: &Path) -> io::Result<()> {
    let entries = validated_entries(archive)?;
    ensure_empty_destination(destination)?;

    let file = File::open(archive)?;
    let mut tar = tar::Archive::new(file);
    let mut directory_modes = Vec::new();
    for item in tar.entries()? {
        let mut entry = item?;
        let path = normalize_archive_path(&entry.path()?)?;
        if path.as_os_str().is_empty() {
            continue;
        }
        let info = entries
            .get(&path)
            .ok_or_else(|| invalid("archive changed while reading"))?;
        let output = destination.join(&path);
        match info.kind {
            Kind::Directory => {
                fs::create_dir_all(&output)?;
                directory_modes.push((output, entry.header().mode()? & 0o777));
            }
            Kind::Regular => {
                if let Some(parent) = output.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut target = create_new_file(&output)?;
                io::copy(&mut entry, &mut target)?;
                #[cfg(unix)]
                fs::set_permissions(
                    &output,
                    fs::Permissions::from_mode(entry.header().mode()? & 0o777),
                )?;
            }
            Kind::Symlink | Kind::Hardlink => {}
        }
    }

    for (path, info) in &entries {
        if info.kind != Kind::Hardlink {
            continue;
        }
        let output = destination.join(path);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let source = destination.join(normalize_archive_path(info.link.as_deref().unwrap())?);
        let mut input = OpenOptions::new().read(true).open(source)?;
        let mut target = create_new_file(&output)?;
        io::copy(&mut input, &mut target)?;
    }

    #[cfg(unix)]
    for (path, info) in &entries {
        if info.kind == Kind::Symlink {
            use std::os::unix::fs::symlink;
            let output = destination.join(path);
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            symlink(info.link.as_deref().unwrap(), output)?;
        }
    }
    #[cfg(not(unix))]
    if entries.values().any(|entry| entry.kind == Kind::Symlink) {
        return Err(invalid("archive symlinks are unsupported on this platform"));
    }

    #[cfg(unix)]
    for (path, mode) in directory_modes.into_iter().rev() {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn append_tree(builder: &mut tar::Builder<File>, source: &Path, relative: &Path) -> io::Result<()> {
    let mut children = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let name = relative.join(child.file_name());
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            builder.append_dir(&name, &path)?;
            append_tree(builder, &path, &name)?;
        } else if file_type.is_file() || file_type.is_symlink() {
            builder.append_path_with_name(&path, &name)?;
        } else {
            return Err(invalid(format!(
                "unsupported source tree entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn pack_tree(source: &Path, archive: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("pack source must be a directory, not a symlink"));
    }
    let source = fs::canonicalize(source)?;
    let archive_parent = archive
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let archive_name = archive
        .file_name()
        .ok_or_else(|| invalid("archive output must name a file"))?;
    let archive_resolved = fs::canonicalize(archive_parent)?.join(archive_name);
    if archive_resolved.starts_with(&source) {
        return Err(invalid("archive output must not be inside the source tree"));
    }
    let output = create_new_file(archive)?;
    let mut builder = tar::Builder::new(output);
    builder.follow_symlinks(false);
    append_tree(&mut builder, &source, Path::new(""))?;
    builder.finish()
}

fn remove_entry(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn restore_tree(archive: &Path, workspace: &Path, replace: bool) -> io::Result<()> {
    let absolute = if workspace.is_absolute() {
        workspace.to_path_buf()
    } else {
        std::env::current_dir()?.join(workspace)
    };
    if absolute == Path::new("/") {
        return Err(invalid("restore destination must be a non-root directory"));
    }
    if fs::symlink_metadata(&absolute).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(invalid(
            "restore destination must be a non-root directory, not a symlink",
        ));
    }
    fs::create_dir_all(&absolute)?;
    let canonical = fs::canonicalize(&absolute)?;
    if canonical == Path::new("/") {
        return Err(invalid("cannot restore over the filesystem root"));
    }

    let existing = fs::read_dir(&canonical)?.collect::<Result<Vec<_>, _>>()?;
    if !existing.is_empty() && !replace {
        return Err(invalid(
            "workspace is not empty; use --replace-workspace to replace its contents",
        ));
    }

    // Validation happens inside extract_tree before it writes anything. Keep the
    // staging directory under the workspace so final renames stay on one mount.
    let staging = tempfile::Builder::new()
        .prefix(".abra-restore-")
        .tempdir_in(&canonical)?;
    let tree = staging.path().join("tree");
    extract_tree(archive, &tree)?;

    let staging_name = staging
        .path()
        .file_name()
        .ok_or_else(|| invalid("invalid restore staging directory"))?
        .to_os_string();
    let current = fs::read_dir(&canonical)?.collect::<Result<Vec<_>, _>>()?;
    for entry in &current {
        if entry.file_name() == staging_name {
            continue;
        }
        if !replace {
            return Err(invalid(
                "workspace changed during restore; refusing to overwrite it",
            ));
        }
    }
    for entry in current {
        if entry.file_name() != staging_name {
            remove_entry(&entry.path())?;
        }
    }
    for entry in fs::read_dir(&tree)? {
        let entry = entry?;
        fs::rename(entry.path(), canonical.join(entry.file_name()))?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct LaunchSpec {
    argv: Vec<String>,
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    log: PathBuf,
}

fn start_detached(spec_path: &Path) -> Result<Value, Box<dyn Error>> {
    const MAX_SPEC_BYTES: u64 = 1024 * 1024;

    #[cfg(unix)]
    let mut spec_file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(spec_path)?
    };
    #[cfg(not(unix))]
    let mut spec_file = OpenOptions::new().read(true).open(spec_path)?;
    let metadata = spec_file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("detached process spec must be a regular file").into());
    }
    if metadata.len() > MAX_SPEC_BYTES {
        return Err(invalid("detached process spec exceeds 1 MiB").into());
    }
    let mut contents = Vec::new();
    spec_file
        .by_ref()
        .take(MAX_SPEC_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_SPEC_BYTES {
        return Err(invalid("detached process spec exceeds 1 MiB").into());
    }
    let spec: LaunchSpec = serde_json::from_slice(&contents)?;
    if spec.argv.is_empty() {
        return Err(invalid("detached process argv must not be empty").into());
    }
    fs::remove_file(spec_path)?;

    #[cfg(unix)]
    let log = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .append(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&spec.log)?
    };
    #[cfg(not(unix))]
    let log = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&spec.log)?;

    let mut command = Command::new(&spec.argv[0]);
    command.args(&spec.argv[1..]);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    if let Some(mut env) = spec.env {
        for key in ["HOME", "USER", "LANG"] {
            if !env.contains_key(key) {
                if let Some(value) = std::env::var_os(key) {
                    env.insert(key.to_owned(), value.to_string_lossy().into_owned());
                }
            }
        }
        command.env_clear().envs(env);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    Ok(json!({"pid": child.id(), "log": spec.log}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_rejects_archive_inside_source_before_creating_it() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"data").unwrap();
        let archive = source.join("tree.tar");

        let error = pack_tree(&source, &archive).unwrap_err();

        assert!(error.to_string().contains("inside the source tree"));
        assert!(!archive.exists());
    }

    #[test]
    fn detached_spec_is_bounded() {
        let root = tempfile::tempdir().unwrap();
        let spec = root.path().join("spec.json");
        fs::write(&spec, vec![b' '; 1024 * 1024 + 1]).unwrap();

        let error = start_detached(&spec).unwrap_err();

        assert!(error.to_string().contains("exceeds 1 MiB"));
        assert!(spec.exists());
    }

    #[cfg(unix)]
    #[test]
    fn detached_spec_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target.json");
        let spec = root.path().join("spec.json");
        fs::write(&target, br#"{"argv":["true"],"log":"unused"}"#).unwrap();
        symlink(&target, &spec).unwrap();

        assert!(start_detached(&spec).is_err());
        assert!(target.exists());
        assert!(spec.is_symlink());
    }
}
