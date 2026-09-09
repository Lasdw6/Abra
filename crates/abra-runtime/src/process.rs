//! Optional Linux process checkpoint support backed by CRIU.
//!
//! A process bundle is an ordinary directory, so callers can move it through
//! Abra's signed file snapshot path. Process memory is sensitive: all bundle
//! directories and files are made private to the current user.

use blake3::Hasher;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const FORMAT: &str = "abra-process/1";
const MANIFEST_NAME: &str = "manifest.json";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;
const MAX_SAVED_LOG: u64 = 1024 * 1024;
const MAX_MANIFEST_SIZE: usize = 16 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_DEPTH: usize = 512;

type BoxError = Box<dyn Error>;

#[derive(Debug, Args)]
pub struct ProcessArgs {
    #[command(subcommand)]
    pub command: ProcessCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProcessCommand {
    /// Run CRIU's basic host preflight for process checkpoints.
    Check(ToolArgs),
    /// Checkpoint a process tree and copy its workspace while it is frozen.
    Capture(CaptureArgs),
    /// Verify a bundle and report whether this host can restore it.
    Plan(BundleArgs),
    /// Restore a verified bundle at its original absolute workspace path.
    Restore(BundleArgs),
    /// Resume the original process tree after a successful local capture.
    ResumeSource(ResumeSourceArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ToolArgs {
    /// CRIU executable. Abra never invokes sudo or otherwise elevates itself.
    #[arg(long, default_value = "criu")]
    pub criu: PathBuf,
    /// Maximum time to wait for each CRIU command.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout_secs: u64,
}

#[derive(Debug, Args)]
pub struct CaptureArgs {
    /// Root PID of the process tree to checkpoint.
    pub pid: u32,
    /// Absolute workspace directory used by the process.
    #[arg(long)]
    pub workspace: PathBuf,
    /// New bundle directory. It must not exist or overlap the workspace.
    #[arg(long)]
    pub bundle: PathBuf,
    #[command(flatten)]
    pub tool: ToolArgs,
}

#[derive(Debug, Args)]
pub struct BundleArgs {
    /// Process bundle directory.
    pub bundle: PathBuf,
    #[command(flatten)]
    pub tool: ToolArgs,
}

#[derive(Debug, Args)]
pub struct ResumeSourceArgs {
    /// Bundle created from the still-frozen local process tree.
    pub bundle: PathBuf,
}

pub fn run(args: ProcessArgs) -> Result<Value, BoxError> {
    match args.command {
        ProcessCommand::Check(args) => check(args),
        ProcessCommand::Capture(args) => capture(args),
        ProcessCommand::Plan(args) => plan(args),
        ProcessCommand::Restore(args) => restore(args),
        ProcessCommand::ResumeSource(args) => resume_source(args),
    }
}

#[derive(Debug)]
struct ProcessError(String);

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ProcessError {}

fn err(message: impl Into<String>) -> BoxError {
    Box::new(ProcessError(message.into()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct HostFacts {
    os: String,
    distribution: String,
    architecture: String,
    kernel_release: String,
    criu_version: String,
    cpu_features: Vec<String>,
    uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    start_ticks: u64,
    uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    format: String,
    captured_host: HostFacts,
    source_workspace: String,
    source_root: ProcessIdentity,
    source_tree: Vec<ProcessIdentity>,
    source_boot_id: String,
    source_machine_id_hash: String,
    source_left_stopped: bool,
    files: Vec<FileEntry>,
    limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct FileEntry {
    path: String,
    kind: EntryKind,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    blake3: Option<String>,
    mode: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum EntryKind {
    Directory,
    File,
    Symlink,
}

fn check(args: ToolArgs) -> Result<Value, BoxError> {
    if std::env::consts::OS != "linux" {
        return Ok(json!({
            "ok": false,
            "supported": false,
            "reason": format!("process checkpointing requires Linux; this host is {}", std::env::consts::OS),
            "elevation_attempted": false,
        }));
    }

    let timeout = checked_timeout(args.timeout_secs)?;
    match inspect_criu(&args.criu, timeout) {
        Ok((version, _)) => Ok(json!({
            "ok": true,
            "supported": true,
            "check_scope": "criu-default",
            "capture_tested": false,
            "backend": "criu",
            "criu_version": version,
            "os": "linux",
            "architecture": std::env::consts::ARCH,
            "kernel_release": kernel_release()?,
            "elevation_attempted": false,
            "note": "Basic CRIU preflight passed; actual capture may still fail because of process or sandbox restrictions.",
        })),
        Err(error) => Ok(json!({
            "ok": false,
            "supported": false,
            "check_scope": "criu-default",
            "capture_tested": false,
            "reason": error.to_string(),
            "elevation_attempted": false,
        })),
    }
}

fn capture(args: CaptureArgs) -> Result<Value, BoxError> {
    require_linux("capture")?;
    if args.pid <= 1 {
        return Err(err("refusing to checkpoint PID 0 or PID 1"));
    }
    if args.pid == std::process::id() {
        return Err(err("refusing to checkpoint the running Abra process"));
    }
    let timeout = checked_timeout(args.tool.timeout_secs)?;
    let workspace = canonical_source_workspace(&args.workspace)?;
    let bundle = canonical_new_path(&args.bundle, "bundle")?;
    reject_overlap(&workspace, &bundle)?;
    if path_exists_nofollow(&bundle)? {
        return Err(err(format!(
            "bundle destination already exists: {}",
            bundle.display()
        )));
    }

    let caller_uid = current_uid()?;
    let source_before = process_identity(args.pid)?;
    if source_before.uid != caller_uid {
        return Err(err(format!(
            "PID {} belongs to uid {}, but Abra is running as uid {}; run as the process owner without sudo",
            args.pid, source_before.uid, caller_uid
        )));
    }
    reject_controller_ancestor(args.pid)?;
    validate_workspace_tree(&workspace, caller_uid)?;

    let (criu_version, _) = inspect_criu(&args.tool.criu, timeout)?;
    let captured_host = linux_host_facts(criu_version)?;
    let source_boot_id = boot_id()?;
    let source_machine_id_hash = machine_id_hash()?;
    let bundle_parent = bundle
        .parent()
        .ok_or_else(|| err("bundle destination has no parent directory"))?;
    let stage = tempfile::Builder::new()
        .prefix(".abra-process-capture-")
        .tempdir_in(bundle_parent)
        .map_err(|e| {
            err(format!(
                "cannot create private bundle staging directory: {e}"
            ))
        })?;
    set_private_dir(stage.path())?;
    let images = stage.path().join("images");
    let work = stage.path().join(".criu-work");
    let bundled_workspace = stage.path().join("workspace");
    private_create_dir(&images)?;
    private_create_dir(&work)?;
    private_create_dir(&bundled_workspace)?;

    let dump_args = criu_dump_args(args.pid, &images, &work);
    let dump = match run_command(&args.tool.criu, &dump_args, timeout, true) {
        Ok(output) => output,
        Err(error) => {
            let diagnostic =
                preserve_criu_log(&work.join("dump.log"), bundle_parent, ".abra-criu-dump-")
                    .ok()
                    .flatten();
            return Err(err(format!(
                "CRIU dump failed: {error}{}; {}",
                diagnostic_detail(diagnostic.as_deref()),
                recover_stopped_source(args.pid, &source_before)
            )));
        }
    };
    let diagnostic = preserve_criu_log(&work.join("dump.log"), bundle_parent, ".abra-criu-dump-")
        .unwrap_or(None);
    if !dump.status.success() {
        let detail = failure_detail(diagnostic.as_deref(), &dump);
        return Err(err(format!(
            "CRIU dump failed with {}{}; check CRIU permissions, kernel support, and external resources. Abra did not run sudo; {}",
            status_text(dump.status), detail, recover_stopped_source(args.pid, &source_before)
        )));
    }

    let root_after = process_identity(args.pid).map_err(|e| {
        post_dump_error(
            format!("CRIU reported success, but the source PID cannot be identified: {e}"),
            diagnostic.as_deref(),
            args.pid,
            &source_before,
        )
    })?;
    if root_after != source_before {
        return Err(post_dump_error(
            "CRIU reported success, but the root PID identity changed; refusing to copy an inconsistent workspace",
            diagnostic.as_deref(),
            args.pid,
            &source_before,
        ));
    }
    let root_stopped = process_is_stopped(args.pid).map_err(|e| {
        post_dump_error(
            format!("cannot verify CRIU's stopped source: {e}"),
            diagnostic.as_deref(),
            args.pid,
            &source_before,
        )
    })?;
    if !root_stopped {
        return Err(err(format!(
            "CRIU reported success, but PID {} is not stopped; refusing to copy a live workspace{}",
            args.pid,
            diagnostic_detail(diagnostic.as_deref())
        )));
    }
    let source_tree = collect_process_tree(args.pid).map_err(|e| {
        post_dump_error(
            format!("cannot record the stopped source process tree: {e}"),
            diagnostic.as_deref(),
            args.pid,
            &source_before,
        )
    })?;
    if source_tree.is_empty() || source_tree[0] != source_before {
        return Err(post_dump_error(
            "cannot record the stopped source process tree",
            diagnostic.as_deref(),
            args.pid,
            &source_before,
        ));
    }
    for identity in &source_tree {
        let stopped = process_is_stopped(identity.pid).map_err(|e| {
            post_dump_error(
                format!("cannot verify stopped PID {}: {e}", identity.pid),
                diagnostic.as_deref(),
                args.pid,
                &source_before,
            )
        })?;
        if !stopped {
            return Err(post_dump_error(
                format!(
                    "PID {} in the captured tree is not stopped; refusing to copy a live workspace",
                    identity.pid
                ),
                diagnostic.as_deref(),
                args.pid,
                &source_before,
            ));
        }
    }

    let finish = (|| -> Result<Value, BoxError> {
        // The source stays stopped for the entire workspace copy and bundle
        // publication. On failure, the identity-checked cleanup below resumes it.
        validate_workspace_tree(&workspace, caller_uid)?;
        copy_tree(&workspace, &bundled_workspace)?;
        let files = inventory_bundle(stage.path())?;
        let manifest = Manifest {
            format: FORMAT.to_owned(),
            captured_host,
            source_workspace: path_to_string(&workspace)?,
            source_root: source_before.clone(),
            source_tree: source_tree.clone(),
            source_boot_id,
            source_machine_id_hash,
            source_left_stopped: true,
            files,
            limitations: limitations(),
        };
        write_manifest(stage.path(), &manifest)?;
        make_tree_private(stage.path())?;
        fs::remove_dir_all(&work)?;
        rename_noreplace(stage.path(), &bundle)?;
        if let Some(path) = diagnostic.as_deref() {
            let _ = fs::remove_file(path);
        }

        Ok(json!({
            "ok": true,
            "backend": "criu",
            "bundle": bundle,
            "workspace": workspace,
            "source_frozen": true,
            "source": source_before,
            "source_tree": source_tree,
            "resume_command": format!("abra process resume-source {}", shell_display(&bundle)),
            "warning": "The source process tree is still stopped. Keep it stopped while copying this bundle.",
            "limitations": manifest.limitations,
        }))
    })();

    match finish {
        Ok(value) => Ok(value),
        Err(error) => {
            let detail = diagnostic_detail(diagnostic.as_deref());
            match resume_verified_tree(&source_tree) {
                Ok(resumed) => Err(err(format!(
                    "process capture failed after CRIU stopped the source: {error}{detail}; safely resumed verified source PIDs {resumed:?}"
                ))),
                Err(resume_error) => Err(err(format!(
                    "process capture failed after CRIU stopped the source: {error}{detail}; automatic source resume failed: {resume_error}. The source may still be frozen"
                ))),
            }
        }
    }
}

fn plan(args: BundleArgs) -> Result<Value, BoxError> {
    let timeout = checked_timeout(args.tool.timeout_secs)?;
    let bundle = canonical_existing_dir(&args.bundle, "bundle")?;
    let manifest = verify_bundle(&bundle)?;
    let (blockers, destination) =
        compatibility_blockers(&manifest, &bundle, &args.tool.criu, timeout);
    Ok(json!({
        "ok": blockers.is_empty(),
        "compatible": blockers.is_empty(),
        "bundle": bundle,
        "backend": "criu",
        "destination_workspace": manifest.source_workspace,
        "captured_host": manifest.captured_host,
        "destination_host": destination,
        "blockers": blockers,
        "limitations": manifest.limitations,
    }))
}

fn restore(args: BundleArgs) -> Result<Value, BoxError> {
    require_linux("restore")?;
    let timeout = checked_timeout(args.tool.timeout_secs)?;
    let bundle = canonical_existing_dir(&args.bundle, "bundle")?;
    let manifest = verify_bundle(&bundle)?;
    let (blockers, _) = compatibility_blockers(&manifest, &bundle, &args.tool.criu, timeout);
    if !blockers.is_empty() {
        return Err(err(format!(
            "process restore preflight failed: {}",
            blockers.join("; ")
        )));
    }
    make_bundle_payload_private(&bundle)?;

    let destination = PathBuf::from(&manifest.source_workspace);
    if path_exists_nofollow(&destination)? {
        return Err(err(format!(
            "refusing to overwrite the required workspace path: {}",
            destination.display()
        )));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| err("recorded workspace has no parent directory"))?;
    let parent = fs::canonicalize(parent).map_err(|e| {
        err(format!(
            "the parent of the required workspace path is unavailable ({}): {e}",
            parent.display()
        ))
    })?;
    let expected = parent.join(
        destination
            .file_name()
            .ok_or_else(|| err("recorded workspace path has no final component"))?,
    );
    reject_overlap(&expected, &bundle)?;

    let stage = tempfile::Builder::new()
        .prefix(".abra-process-restore-")
        .tempdir_in(&parent)
        .map_err(|e| err(format!("cannot stage restored workspace: {e}")))?;
    set_private_dir(stage.path())?;
    copy_tree(&bundle.join("workspace"), stage.path())?;
    rename_noreplace(stage.path(), &expected)
        .map_err(|e| err(format!("cannot install the restored workspace: {e}")))?;
    if let Err(error) = apply_workspace_modes(&expected, &manifest.files) {
        let _ = fs::remove_dir_all(&expected);
        return Err(err(format!(
            "cannot restore recorded workspace permissions: {error}"
        )));
    }

    let criu_work = tempfile::Builder::new()
        .prefix(".abra-criu-restore-")
        .tempdir_in(&parent)
        .map_err(|e| {
            let _ = fs::remove_dir_all(&expected);
            err(format!("cannot create CRIU restore work directory: {e}"))
        })?;
    set_private_dir(criu_work.path())?;
    let pidfile = criu_work.path().join("restored.pid");
    let restore_args = criu_restore_args(&bundle.join("images"), criu_work.path(), &pidfile);
    let output = run_command(&args.tool.criu, &restore_args, timeout, true);
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            let diagnostic = preserve_criu_log(
                &criu_work.path().join("restore.log"),
                &parent,
                ".abra-criu-restore-",
            )
            .ok()
            .flatten();
            return Err(err(format!(
                "CRIU restore failed with {}{}; the newly created workspace was left at {} so no possibly restored process loses its files",
                status_text(output.status),
                failure_detail(diagnostic.as_deref(), &output),
                expected.display(),
            )));
        }
        Err(error) => {
            let diagnostic = preserve_criu_log(
                &criu_work.path().join("restore.log"),
                &parent,
                ".abra-criu-restore-",
            )
            .ok()
            .flatten();
            return Err(err(format!(
                "CRIU restore failed: {error}{}; the newly created workspace was left at {} so no possibly restored process loses its files",
                diagnostic_detail(diagnostic.as_deref()),
                expected.display(),
            )));
        }
    };
    debug_assert!(output.status.success());
    let restored_pid = fs::read_to_string(&pidfile)
        .map_err(|e| {
            err(format!(
                "CRIU restored the process but did not write its PID: {e}"
            ))
        })?
        .trim()
        .parse::<u32>()
        .map_err(|e| err(format!("CRIU wrote an invalid restored PID: {e}")))?;

    Ok(json!({
        "ok": true,
        "backend": "criu",
        "restored_pid": restored_pid,
        "workspace": expected,
        "detached": true,
        "limitations": manifest.limitations,
    }))
}

fn resume_source(args: ResumeSourceArgs) -> Result<Value, BoxError> {
    require_linux("resume-source")?;
    let bundle = canonical_existing_dir(&args.bundle, "bundle")?;
    let manifest = verify_bundle(&bundle)?;
    if !manifest.source_left_stopped || manifest.source_tree.is_empty() {
        return Err(err(
            "bundle does not identify a source process tree left stopped by Abra",
        ));
    }
    if manifest.source_boot_id != boot_id()? {
        return Err(err(
            "refusing to resume source PIDs after a reboot or on another Linux boot",
        ));
    }
    if manifest.source_machine_id_hash != machine_id_hash()? {
        return Err(err("refusing to resume source PIDs on a different machine"));
    }
    let current_uid = current_uid()?;
    if manifest.source_root.uid != current_uid {
        return Err(err(format!(
            "source belongs to uid {}, but Abra is running as uid {}",
            manifest.source_root.uid, current_uid
        )));
    }

    let resumed = resume_verified_tree(&manifest.source_tree)?;
    Ok(json!({
        "ok": true,
        "resumed": resumed,
        "source": manifest.source_root,
    }))
}

fn resume_verified_tree(tree: &[ProcessIdentity]) -> Result<Vec<u32>, BoxError> {
    for expected in tree {
        let actual = process_identity(expected.pid).map_err(|e| {
            err(format!(
                "refusing to resume any process: PID {} is unavailable: {e}",
                expected.pid
            ))
        })?;
        if actual != *expected {
            return Err(err(format!(
                "refusing to resume any process: PID {} no longer has the captured identity",
                expected.pid
            )));
        }
        if !process_is_stopped(expected.pid)? {
            return Err(err(format!(
                "refusing to resume any process: PID {} is no longer stopped",
                expected.pid
            )));
        }
    }

    let mut resumed = Vec::new();
    for expected in tree.iter().rev() {
        let actual = process_identity(expected.pid)?;
        if actual != *expected {
            return Err(err(format!(
                "PID {} changed identity during resume; already resumed PIDs: {:?}",
                expected.pid, resumed
            )));
        }
        send_sigcont(expected.pid).map_err(|e| {
            err(format!(
                "failed to resume PID {}: {e}; already resumed PIDs: {:?}",
                expected.pid, resumed
            ))
        })?;
        resumed.push(expected.pid);
    }
    resumed.sort_unstable();
    Ok(resumed)
}

fn recover_stopped_source(root: u32, expected: &ProcessIdentity) -> String {
    let actual = match process_identity(root) {
        Ok(actual) if actual == *expected => actual,
        Ok(_) => return "source PID identity changed; Abra did not signal it".to_owned(),
        Err(error) => return format!("source PID state is unavailable: {error}"),
    };
    let _ = actual;
    match process_is_stopped(root) {
        Ok(false) => "source root is not stopped".to_owned(),
        Err(error) => format!("source stop state is unavailable: {error}"),
        Ok(true) => match collect_process_tree(root).and_then(|tree| resume_verified_tree(&tree)) {
            Ok(pids) => format!("safely resumed verified source PIDs {pids:?}"),
            Err(error) => {
                format!("automatic source resume failed: {error}; the source may still be frozen")
            }
        },
    }
}

fn post_dump_error(
    message: impl fmt::Display,
    diagnostic: Option<&Path>,
    root: u32,
    expected: &ProcessIdentity,
) -> BoxError {
    err(format!(
        "{message}{}; {}",
        diagnostic_detail(diagnostic),
        recover_stopped_source(root, expected)
    ))
}

fn checked_timeout(seconds: u64) -> Result<Duration, BoxError> {
    if seconds == 0 {
        return Err(err("timeout must be at least one second"));
    }
    Ok(Duration::from_secs(seconds))
}

fn require_linux(action: &str) -> Result<(), BoxError> {
    if std::env::consts::OS == "linux" {
        Ok(())
    } else {
        Err(err(format!(
            "cannot {action} a process on {}: CRIU process checkpoints require Linux",
            std::env::consts::OS
        )))
    }
}

fn inspect_criu(criu: &Path, timeout: Duration) -> Result<(String, CommandOutput), BoxError> {
    let version_args = vec![OsString::from("--version")];
    let version = run_command(criu, &version_args, timeout, true).map_err(|e| {
        err(format!(
            "cannot run CRIU at {}: {e}. Install CRIU or pass --criu PATH; Abra will not run sudo",
            criu.display()
        ))
    })?;
    if !version.status.success() {
        return Err(err(format!(
            "CRIU version check failed with {}",
            status_text(version.status)
        )));
    }
    let version_text = first_nonempty_line(&version.stdout)
        .or_else(|| first_nonempty_line(&version.stderr))
        .ok_or_else(|| err("CRIU --version returned no version text"))?;
    let check_args = vec![
        OsString::from("check"),
        OsString::from("--no-default-config"),
    ];
    let check = run_command(criu, &check_args, timeout, true)?;
    if !check.status.success() {
        let detail = first_nonempty_line(&check.stderr)
            .or_else(|| first_nonempty_line(&check.stdout))
            .unwrap_or_else(|| "no diagnostic was returned".to_owned());
        return Err(err(format!(
            "CRIU check failed with {}: {}. Grant CRIU the documented checkpoint capabilities or run Abra in a compatible sandbox; Abra will not elevate itself",
            status_text(check.status), detail
        )));
    }
    Ok((version_text, check))
}

#[derive(Debug)]
struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_command(
    program: &Path,
    args: &[OsString],
    timeout: Duration,
    capture_output: bool,
) -> io::Result<CommandOutput> {
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    #[cfg(unix)]
    command.process_group(0);
    if capture_output {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let deadline = Instant::now() + timeout;
    let mut child = command.spawn()?;
    let stdout_reader = child.stdout.take().map(read_pipe);
    let stderr_reader = child.stderr.take().map(read_pipe);
    let status = wait_child(&mut child, deadline)?;
    let stdout = join_pipe(stdout_reader, deadline)?;
    let stderr = join_pipe(stderr_reader, deadline)?;
    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_pipe<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        let result = loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break Ok(bytes),
                Ok(read) => {
                    let remaining = MAX_COMMAND_OUTPUT.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&chunk[..read.min(remaining)]);
                }
                Err(error) => break Err(error),
            }
        };
        let _ = sender.send(result);
    });
    receiver
}

fn join_pipe(
    receiver: Option<mpsc::Receiver<io::Result<Vec<u8>>>>,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    match receiver {
        Some(receiver) => receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => {
                    io::Error::new(io::ErrorKind::TimedOut, "timed out draining command output")
                }
                mpsc::RecvTimeoutError::Disconnected => {
                    io::Error::other("command output reader stopped unexpectedly")
                }
            })?,
        None => Ok(Vec::new()),
    }
}

fn wait_child(child: &mut Child, deadline: Instant) -> io::Result<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                kill_owned_process_group(child);
                let _ = child.wait();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            kill_owned_process_group(child);
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "command timed out and its owned process group was killed",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn kill_owned_process_group(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: the child was placed in a new process group whose id equals
        // its positive PID. Negating it targets only that owned group.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_owned_process_group(child: &mut Child) {
    let _ = child.kill();
}

fn criu_dump_args(pid: u32, images: &Path, work: &Path) -> Vec<OsString> {
    vec![
        "dump".into(),
        "--no-default-config".into(),
        "--tree".into(),
        pid.to_string().into(),
        "--images-dir".into(),
        images.as_os_str().to_owned(),
        "--work-dir".into(),
        work.as_os_str().to_owned(),
        "--log-file".into(),
        "dump.log".into(),
        "--verbosity=4".into(),
        "--leave-stopped".into(),
        "--shell-job".into(),
        "--cpu-cap=all".into(),
    ]
}

fn criu_restore_args(images: &Path, work: &Path, pidfile: &Path) -> Vec<OsString> {
    vec![
        "restore".into(),
        "--no-default-config".into(),
        "--images-dir".into(),
        images.as_os_str().to_owned(),
        "--work-dir".into(),
        work.as_os_str().to_owned(),
        "--log-file".into(),
        "restore.log".into(),
        "--verbosity=4".into(),
        "--restore-detached".into(),
        "--pidfile".into(),
        pidfile.as_os_str().to_owned(),
        "--shell-job".into(),
        "--cpu-cap=all".into(),
    ]
}

fn first_nonempty_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(|line| {
            line.chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .collect::<String>()
        })
        .find(|line| !line.trim().is_empty())
        .map(|line| line.chars().take(512).collect())
}

fn status_text(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => "termination by signal".to_owned(),
    }
}

fn preserve_criu_log(
    source: &Path,
    parent: &Path,
    prefix: &str,
) -> Result<Option<PathBuf>, BoxError> {
    let Ok(mut input) = File::open(source) else {
        return Ok(None);
    };
    let mut saved = tempfile::Builder::new()
        .prefix(prefix)
        .suffix(".log")
        .tempfile_in(parent)?;
    set_private_file(saved.path())?;
    let length = input.metadata()?.len();
    if length > MAX_SAVED_LOG {
        input.seek(SeekFrom::Start(length - MAX_SAVED_LOG))?;
    }
    io::copy(&mut input.take(MAX_SAVED_LOG), saved.as_file_mut())?;
    saved.as_file_mut().sync_all()?;
    let (_, path) = saved.keep().map_err(|error| error.error)?;
    Ok(Some(path))
}

fn diagnostic_detail(path: Option<&Path>) -> String {
    let Some(path) = path else {
        return String::new();
    };
    let detail = fs::read(path)
        .ok()
        .and_then(|bytes| meaningful_diagnostic_line(&bytes))
        .map(|line| format!(": {line}"))
        .unwrap_or_default();
    format!("{detail}; private CRIU log: {}", path.display())
}

fn failure_detail(log: Option<&Path>, output: &CommandOutput) -> String {
    if log.is_some() {
        return diagnostic_detail(log);
    }
    meaningful_diagnostic_line(&output.stderr)
        .or_else(|| meaningful_diagnostic_line(&output.stdout))
        .map(|line| format!(": {line}"))
        .unwrap_or_default()
}

fn meaningful_diagnostic_line(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let lines = text
        .lines()
        .map(sanitize_diagnostic_line)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    lines
        .iter()
        .find(|line| is_permission_error(line))
        .cloned()
        .or_else(|| lines.iter().find(|line| is_specific_error(line)).cloned())
        .or_else(|| {
            lines
                .iter()
                .rev()
                .find(|line| !is_generic_failure(line))
                .cloned()
        })
        .or_else(|| lines.last().cloned())
}

fn is_permission_error(line: &str) -> bool {
    line.contains("Operation not permitted") || line.contains("Permission denied")
}

fn is_specific_error(line: &str) -> bool {
    !is_generic_failure(line)
        && (line.contains("Error (")
            || line.starts_with("Error:")
            || line.contains(": Error:")
            || is_permission_error(line))
}

fn is_generic_failure(line: &str) -> bool {
    line.contains("Dumping FAILED") || line.contains("Restore FAILED")
}
fn sanitize_diagnostic_line(line: &str) -> String {
    line.chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .take(512)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn boot_id() -> Result<String, BoxError> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_owned())
        .map_err(|error| err(format!("cannot read Linux boot identity: {error}")))
}

fn machine_id_hash() -> Result<String, BoxError> {
    let id = fs::read("/etc/machine-id")
        .or_else(|_| fs::read("/var/lib/dbus/machine-id"))
        .map_err(|error| err(format!("cannot read Linux machine identity: {error}")))?;
    let mut hasher = Hasher::new();
    hasher.update(b"abra-process-machine-id\0");
    hasher.update(&id);
    Ok(hasher.finalize().to_hex().to_string())
}

fn reject_controller_ancestor(pid: u32) -> Result<(), BoxError> {
    let mut current = std::process::id();
    let mut seen = BTreeSet::new();
    while current > 1 && seen.insert(current) {
        let parent = process_parent_pid(current)?;
        if parent == pid {
            return Err(err(format!(
                "refusing to checkpoint PID {pid} because it is an ancestor of the running Abra controller"
            )));
        }
        current = parent;
    }
    Ok(())
}

fn process_parent_pid(pid: u32) -> Result<u32, BoxError> {
    let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = fs::read_to_string(&stat_path)
        .map_err(|error| err(format!("cannot read {}: {error}", stat_path.display())))?;
    parse_stat_tail(pid, &stat)?
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| err(format!("Linux process stat has no parent for PID {pid}")))?
        .parse::<u32>()
        .map_err(|error| err(format!("invalid parent PID for process {pid}: {error}")))
}

fn canonical_source_workspace(path: &Path) -> Result<PathBuf, BoxError> {
    if !path.is_absolute() {
        return Err(err("workspace must be an absolute path"));
    }
    let canonical = canonical_existing_dir(path, "workspace")?;
    if canonical == Path::new("/") {
        return Err(err(
            "refusing to capture the filesystem root as a workspace",
        ));
    }
    Ok(canonical)
}

fn canonical_existing_dir(path: &Path, label: &str) -> Result<PathBuf, BoxError> {
    let canonical = fs::canonicalize(path)
        .map_err(|e| err(format!("cannot open {label} {}: {e}", path.display())))?;
    if !canonical.is_dir() {
        return Err(err(format!(
            "{label} is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn canonical_new_path(path: &Path, label: &str) -> Result<PathBuf, BoxError> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| err(format!("{label} destination needs a final path component")))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|e| {
        err(format!(
            "cannot open parent of {label} destination {}: {e}",
            parent.display()
        ))
    })?;
    Ok(parent.join(name))
}

fn path_exists_nofollow(path: &Path) -> Result<bool, BoxError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(err(format!(
            "cannot inspect destination {}: {error}",
            path.display()
        ))),
    }
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, destination: &Path) -> Result<(), BoxError> {
    use std::os::unix::ffi::OsStrExt;

    let source = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| err("source path contains a NUL byte"))?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| err("destination path contains a NUL byte"))?;
    // Call the kernel directly so musl builds do not need a libc renameat2 wrapper.
    // SAFETY: both C strings live through the call, AT_FDCWD makes the paths
    // absolute/current-directory based, and RENAME_NOREPLACE prevents clobbering.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Box::new(io::Error::last_os_error()))
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_noreplace(source: &Path, destination: &Path) -> Result<(), BoxError> {
    if path_exists_nofollow(destination)? {
        return Err(err(format!(
            "destination already exists: {}",
            destination.display()
        )));
    }
    fs::rename(source, destination)?;
    Ok(())
}

fn reject_overlap(first: &Path, second: &Path) -> Result<(), BoxError> {
    if first.starts_with(second) || second.starts_with(first) {
        return Err(err(format!(
            "paths must not overlap: {} and {}",
            first.display(),
            second.display()
        )));
    }
    Ok(())
}

fn path_to_string(path: &Path) -> Result<String, BoxError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| err(format!("path is not valid UTF-8: {}", path.display())))
}

fn shell_display(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(unix)]
fn current_uid() -> Result<u32, BoxError> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .map_err(|e| err(format!("cannot determine current Linux uid: {e}")))
}

#[cfg(not(unix))]
fn current_uid() -> Result<u32, BoxError> {
    Err(err("process checkpoints require a Unix uid"))
}

fn process_identity(pid: u32) -> Result<ProcessIdentity, BoxError> {
    let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = fs::read_to_string(&stat_path)
        .map_err(|e| err(format!("cannot read {}: {e}", stat_path.display())))?;
    let after = parse_stat_tail(pid, &stat)?;
    // The text after `comm` starts at field 3. starttime is field 22.
    let start_ticks = after
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| {
            err(format!(
                "Linux process stat has no start time for PID {pid}"
            ))
        })?
        .parse::<u64>()
        .map_err(|e| err(format!("invalid process start time for PID {pid}: {e}")))?;
    let uid = process_uid(pid)?;
    Ok(ProcessIdentity {
        pid,
        start_ticks,
        uid,
    })
}

fn parse_stat_tail(pid: u32, stat: &str) -> Result<&str, BoxError> {
    let close = stat
        .rfind(')')
        .ok_or_else(|| err(format!("invalid Linux process stat for PID {pid}")))?;
    stat.get(close + 2..)
        .ok_or_else(|| err(format!("invalid Linux process stat for PID {pid}")))
}

fn process_uid(pid: u32) -> Result<u32, BoxError> {
    let status_path = PathBuf::from(format!("/proc/{pid}/status"));
    let status = fs::read_to_string(&status_path)
        .map_err(|e| err(format!("cannot read {}: {e}", status_path.display())))?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| err(format!("Linux process status has no uid for PID {pid}")))?;
    line.split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            err(format!(
                "Linux process status has an invalid uid for PID {pid}"
            ))
        })?
        .parse::<u32>()
        .map_err(|e| err(format!("invalid process uid for PID {pid}: {e}")))
}

fn process_is_stopped(pid: u32) -> Result<bool, BoxError> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let state = status
        .lines()
        .find(|line| line.starts_with("State:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| err(format!("Linux process status has no state for PID {pid}")))?;
    Ok(matches!(state, "T" | "t"))
}

fn collect_process_tree(root: u32) -> Result<Vec<ProcessIdentity>, BoxError> {
    let mut pending = vec![root];
    let mut seen = BTreeSet::new();
    let mut identities = BTreeMap::new();
    while let Some(pid) = pending.pop() {
        if !seen.insert(pid) {
            continue;
        }
        identities.insert(pid, process_identity(pid)?);
        let task_dir = PathBuf::from(format!("/proc/{pid}/task"));
        for task in fs::read_dir(&task_dir)? {
            let task = task?;
            let children = fs::read_to_string(task.path().join("children"))?;
            for child in children.split_whitespace() {
                let child = child
                    .parse::<u32>()
                    .map_err(|e| err(format!("invalid child PID listed for process {pid}: {e}")))?;
                pending.push(child);
            }
        }
    }
    let root_identity = identities
        .remove(&root)
        .ok_or_else(|| err("captured process tree does not contain its root"))?;
    let mut result = vec![root_identity];
    result.extend(identities.into_values());
    Ok(result)
}

#[cfg(target_os = "linux")]
fn send_sigcont(pid: u32) -> Result<(), BoxError> {
    let pid = i32::try_from(pid).map_err(|_| err("PID does not fit Linux pid_t"))?;
    // SAFETY: `kill` does not dereference pointers. The positive PID and fixed
    // signal target only the identity checked immediately before this call.
    let result = unsafe { libc::kill(pid, libc::SIGCONT) };
    if result == 0 {
        Ok(())
    } else {
        Err(Box::new(io::Error::last_os_error()))
    }
}

#[cfg(not(target_os = "linux"))]
fn send_sigcont(_pid: u32) -> Result<(), BoxError> {
    Err(err("SIGCONT process resume requires Linux"))
}

fn linux_host_facts(criu_version: String) -> Result<HostFacts, BoxError> {
    Ok(HostFacts {
        os: "linux".to_owned(),
        distribution: linux_distribution(),
        architecture: std::env::consts::ARCH.to_owned(),
        kernel_release: kernel_release()?,
        criu_version,
        cpu_features: cpu_features()?,
        uid: current_uid()?,
    })
}

fn linux_distribution() -> String {
    let Ok(contents) = fs::read_to_string("/etc/os-release") else {
        return "unknown".to_owned();
    };
    for key in ["PRETTY_NAME=", "NAME="] {
        if let Some(value) = contents.lines().find_map(|line| line.strip_prefix(key)) {
            return value.trim_matches('"').to_owned();
        }
    }
    "unknown".to_owned()
}

fn kernel_release() -> Result<String, BoxError> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .map_err(|e| err(format!("cannot read Linux kernel release: {e}")))
}

fn cpu_features() -> Result<Vec<String>, BoxError> {
    let contents = fs::read_to_string("/proc/cpuinfo")
        .map_err(|e| err(format!("cannot read Linux CPU features: {e}")))?;
    let mut feature_sets = Vec::new();
    for line in contents.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("flags") || key.trim().eq_ignore_ascii_case("features") {
            feature_sets.push(
                value
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>(),
            );
        }
    }
    let mut sets = feature_sets.into_iter();
    let mut common = sets
        .next()
        .ok_or_else(|| err("Linux did not report CPU feature flags"))?;
    for set in sets {
        common = common.intersection(&set).cloned().collect();
    }
    Ok(common.into_iter().collect())
}

fn compatibility_blockers(
    manifest: &Manifest,
    bundle: &Path,
    criu: &Path,
    timeout: Duration,
) -> (Vec<String>, Option<HostFacts>) {
    let mut blockers = Vec::new();
    if std::env::consts::OS != "linux" {
        blockers.push(format!(
            "destination OS is {}; CRIU restore requires Linux",
            std::env::consts::OS
        ));
        return (blockers, None);
    }
    let (version, _) = match inspect_criu(criu, timeout) {
        Ok(result) => result,
        Err(error) => {
            blockers.push(error.to_string());
            return (blockers, None);
        }
    };
    let host = match linux_host_facts(version) {
        Ok(host) => host,
        Err(error) => {
            blockers.push(error.to_string());
            return (blockers, None);
        }
    };
    blockers.extend(compare_hosts(&manifest.captured_host, &host));
    let workspace = PathBuf::from(&manifest.source_workspace);
    if path_exists_nofollow(&workspace).unwrap_or(true) {
        blockers.push(format!(
            "required workspace path already exists and will not be overwritten: {}",
            workspace.display()
        ));
    } else if let Some(parent) = workspace.parent() {
        match fs::canonicalize(parent) {
            Ok(parent) => {
                let expected = parent.join(workspace.file_name().unwrap_or_default());
                if expected.starts_with(bundle) || bundle.starts_with(&expected) {
                    blockers.push("bundle and required workspace path overlap".to_owned());
                }
            }
            Err(error) => blockers.push(format!(
                "required workspace parent is unavailable ({}): {error}",
                parent.display()
            )),
        }
    }
    (blockers, Some(host))
}

fn compare_hosts(captured: &HostFacts, current: &HostFacts) -> Vec<String> {
    let mut blockers = Vec::new();
    if captured.os != current.os {
        blockers.push(format!(
            "OS mismatch: captured on {}, destination is {}",
            captured.os, current.os
        ));
    }
    if captured.architecture != current.architecture {
        blockers.push(format!(
            "architecture mismatch: captured on {}, destination is {}",
            captured.architecture, current.architecture
        ));
    }
    if captured.kernel_release != current.kernel_release {
        blockers.push(format!(
            "kernel mismatch: captured on {}, destination is {}",
            captured.kernel_release, current.kernel_release
        ));
    }
    if captured.criu_version != current.criu_version {
        blockers.push(format!(
            "CRIU version mismatch: captured with {}, destination has {}",
            captured.criu_version, current.criu_version
        ));
    }
    if captured.uid != current.uid {
        blockers.push(format!(
            "uid mismatch: captured as {}, destination is {}",
            captured.uid, current.uid
        ));
    }
    let current_features = current.cpu_features.iter().collect::<BTreeSet<_>>();
    let missing = captured
        .cpu_features
        .iter()
        .filter(|feature| !current_features.contains(feature))
        .take(16)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        blockers.push(format!(
            "destination CPU is missing captured features: {}",
            missing.join(", ")
        ));
    }
    blockers
}

fn limitations() -> Vec<String> {
    vec![
        "Restore requires Linux, the recorded architecture, kernel, CRIU version, CPU features, and uid. No cross-CPU compatibility is claimed.".to_owned(),
        "The workspace is restored only at its recorded absolute path, and an existing destination is never overwritten.".to_owned(),
        "External files, mounts, devices, sockets, terminals, namespaces, cgroups, and network connections may prevent CRIU capture or restore.".to_owned(),
        "Abra does not enable CRIU options that reconnect established TCP connections or inherit arbitrary external resources.".to_owned(),
    ]
}

#[cfg(unix)]
fn validate_workspace_tree(root: &Path, owner_uid: u32) -> Result<(), BoxError> {
    use std::os::unix::fs::MetadataExt;

    fn visit(root: &Path, path: &Path, owner_uid: u32) -> Result<(), BoxError> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.uid() != owner_uid {
            return Err(err(format!(
                "workspace entry is owned by uid {}, expected {}: {}",
                metadata.uid(),
                owner_uid,
                path.display()
            )));
        }
        if path != root {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| err("workspace validation escaped its root"))?;
            safe_relative_string(relative)?;
        }
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            for entry in fs::read_dir(path)? {
                visit(root, &entry?.path(), owner_uid)?;
            }
        } else if !file_type.is_file() && !file_type.is_symlink() {
            return Err(err(format!(
                "workspace contains an unsupported socket, device, or FIFO: {}",
                path.display()
            )));
        }
        Ok(())
    }

    visit(root, root, owner_uid)
}

#[cfg(not(unix))]
fn validate_workspace_tree(_root: &Path, _owner_uid: u32) -> Result<(), BoxError> {
    Err(err("process workspace ownership checks require Unix"))
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), BoxError> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_dir() {
        return Err(err(format!(
            "copy source is not a directory: {}",
            source.display()
        )));
    }
    copy_dir_contents(source, source, destination, 0)?;
    copy_permissions(&metadata, destination)
}

#[cfg(unix)]
fn apply_workspace_modes(root: &Path, entries: &[FileEntry]) -> Result<(), BoxError> {
    use std::os::unix::fs::PermissionsExt;

    let mut workspace_entries = entries
        .iter()
        .filter_map(|entry| {
            entry
                .path
                .strip_prefix("workspace")
                .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
                .map(|suffix| (entry, suffix.trim_start_matches('/')))
        })
        .collect::<Vec<_>>();
    workspace_entries.sort_by_key(|(entry, suffix)| {
        let depth = suffix.split('/').filter(|part| !part.is_empty()).count();
        (entry.kind == EntryKind::Directory, std::cmp::Reverse(depth))
    });
    for (entry, suffix) in workspace_entries {
        if entry.kind == EntryKind::Symlink {
            continue;
        }
        let path = if suffix.is_empty() {
            root.to_owned()
        } else {
            root.join(validate_manifest_path(suffix)?)
        };
        fs::set_permissions(path, fs::Permissions::from_mode(entry.mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_workspace_modes(_root: &Path, _entries: &[FileEntry]) -> Result<(), BoxError> {
    Err(err("restoring process workspace permissions requires Unix"))
}

fn copy_dir_contents(
    root: &Path,
    source: &Path,
    destination: &Path,
    depth: usize,
) -> Result<(), BoxError> {
    if depth >= MAX_PATH_DEPTH {
        return Err(err(format!(
            "workspace exceeds the maximum directory depth of {MAX_PATH_DEPTH}: {}",
            source.display()
        )));
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let relative = source_path
            .strip_prefix(root)
            .map_err(|_| err("workspace copy escaped its root"))?;
        safe_relative_string(relative)?;
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            fs::create_dir(&destination_path)?;
            copy_dir_contents(root, &source_path, &destination_path, depth + 1)?;
            copy_permissions(&metadata, &destination_path)?;
        } else if file_type.is_file() {
            copy_regular_file(&source_path, &destination_path, &metadata)?;
        } else if file_type.is_symlink() {
            copy_symlink(&source_path, &destination_path)?;
        } else {
            return Err(err(format!(
                "workspace contains an unsupported socket, device, or FIFO: {}",
                source_path.display()
            )));
        }
    }
    Ok(())
}

fn copy_regular_file(
    source: &Path,
    destination: &Path,
    metadata: &Metadata,
) -> Result<(), BoxError> {
    let mut input = File::open(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    copy_permissions(metadata, destination)
}

#[cfg(unix)]
fn copy_symlink(source: &Path, destination: &Path) -> Result<(), BoxError> {
    use std::os::unix::fs::symlink;
    let target = fs::read_link(source)?;
    symlink(target, destination)?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_symlink(_source: &Path, _destination: &Path) -> Result<(), BoxError> {
    Err(err("copying process workspace symlinks requires Unix"))
}

#[cfg(unix)]
fn copy_permissions(metadata: &Metadata, destination: &Path) -> Result<(), BoxError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(metadata.permissions().mode()),
    )?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_permissions(_metadata: &Metadata, _destination: &Path) -> Result<(), BoxError> {
    Ok(())
}

fn inventory_bundle(root: &Path) -> Result<Vec<FileEntry>, BoxError> {
    let mut entries = Vec::new();
    inventory_dir(root, root, 0, &mut entries)?;
    entries.sort();
    Ok(entries)
}

fn inventory_dir(
    root: &Path,
    current: &Path,
    depth: usize,
    entries: &mut Vec<FileEntry>,
) -> Result<(), BoxError> {
    if depth >= MAX_PATH_DEPTH {
        return Err(err(format!(
            "bundle exceeds the maximum directory depth of {MAX_PATH_DEPTH}: {}",
            current.display()
        )));
    }
    let mut children = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        if current == root
            && matches!(
                child.file_name().to_str(),
                Some(MANIFEST_NAME | ".abra" | ".criu-work")
            )
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path
            .strip_prefix(root)
            .expect("inventory path is below root");
        let relative = safe_relative_string(relative)?;
        let mode = file_mode(&metadata);
        if metadata.file_type().is_dir() {
            entries.push(FileEntry {
                path: relative,
                kind: EntryKind::Directory,
                size: 0,
                blake3: None,
                mode,
            });
            inventory_dir(root, &path, depth + 1, entries)?;
        } else if metadata.file_type().is_file() {
            let (size, hash) = hash_file(&path)?;
            entries.push(FileEntry {
                path: relative,
                kind: EntryKind::File,
                size,
                blake3: Some(hash),
                mode,
            });
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            let target = target.as_os_str().as_encoded_bytes();
            entries.push(FileEntry {
                path: relative,
                kind: EntryKind::Symlink,
                size: target.len() as u64,
                blake3: Some(blake3::hash(target).to_hex().to_string()),
                mode,
            });
        } else {
            return Err(err(format!(
                "bundle contains an unsupported special file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(u64, String), BoxError> {
    let mut file = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| err("file size overflow while hashing bundle"))?;
    }
    Ok((size, hasher.finalize().to_hex().to_string()))
}

fn safe_relative_string(path: &Path) -> Result<String, BoxError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(err("bundle entry path must be a non-empty relative path"));
    }
    let mut depth = 0;
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(err(format!("unsafe bundle entry path: {}", path.display())));
        }
        depth += 1;
        if depth > MAX_PATH_DEPTH {
            return Err(err(format!(
                "bundle entry path exceeds {MAX_PATH_DEPTH} components: {}",
                path.display()
            )));
        }
    }
    let value = path
        .to_str()
        .map(|value| value.replace(std::path::MAIN_SEPARATOR, "/"))
        .ok_or_else(|| {
            err(format!(
                "bundle entry path is not UTF-8: {}",
                path.display()
            ))
        })?;
    if value.len() > MAX_PATH_BYTES {
        return Err(err(format!(
            "bundle entry path exceeds {MAX_PATH_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn validate_manifest_path(value: &str) -> Result<PathBuf, BoxError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.split('/').count() > MAX_PATH_DEPTH
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(err(format!("unsafe path in process manifest: {value:?}")));
    }
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(err(format!("unsafe path in process manifest: {value:?}")));
    }
    Ok(path)
}

fn write_manifest(root: &Path, manifest: &Manifest) -> Result<(), BoxError> {
    let path = root.join(MANIFEST_NAME);
    let bytes = serde_json::to_vec_pretty(manifest)?;
    if bytes.len() > MAX_MANIFEST_SIZE {
        return Err(err(format!(
            "process bundle manifest exceeds the {MAX_MANIFEST_SIZE}-byte limit"
        )));
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    set_private_file(&path)
}

fn verify_bundle(root: &Path) -> Result<Manifest, BoxError> {
    let manifest_path = root.join(MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|e| err(format!("bundle has no readable {MANIFEST_NAME}: {e}")))?;
    if !metadata.file_type().is_file() {
        return Err(err("bundle manifest must be a regular file"));
    }
    if metadata.len() > MAX_MANIFEST_SIZE as u64 {
        return Err(err(format!(
            "process bundle manifest exceeds the {MAX_MANIFEST_SIZE}-byte limit"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(&manifest_path)?
        .take(MAX_MANIFEST_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MANIFEST_SIZE {
        return Err(err(format!(
            "process bundle manifest exceeds the {MAX_MANIFEST_SIZE}-byte limit"
        )));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|e| err(format!("invalid process bundle manifest: {e}")))?;
    if manifest.format != FORMAT {
        return Err(err(format!(
            "unsupported process bundle format: {}",
            manifest.format
        )));
    }
    if !manifest.source_left_stopped {
        return Err(err(
            "process bundle does not record a frozen source capture",
        ));
    }
    if manifest.source_boot_id.is_empty()
        || manifest.source_machine_id_hash.len() != blake3::OUT_LEN * 2
    {
        return Err(err("manifest has invalid source machine or boot identity"));
    }
    validate_absolute_linux_path(&manifest.source_workspace)?;
    if manifest.source_tree.first() != Some(&manifest.source_root) {
        return Err(err(
            "manifest process tree does not begin with its root identity",
        ));
    }
    let mut pids = BTreeSet::new();
    if manifest.source_tree.iter().any(|identity| {
        identity.pid <= 1 || identity.start_ticks == 0 || !pids.insert(identity.pid)
    }) {
        return Err(err(
            "manifest contains an invalid or duplicate process identity",
        ));
    }

    let expected = manifest
        .files
        .iter()
        .map(|entry| {
            let path = validate_manifest_path(&entry.path)?;
            if !matches!(
                path.components().next(),
                Some(Component::Normal(name)) if name == OsStr::new("images") || name == OsStr::new("workspace")
            ) {
                return Err(err(format!(
                    "unexpected top-level payload path in process manifest: {}",
                    entry.path
                )));
            }
            if entry.mode > 0o7777 {
                return Err(err(format!(
                    "invalid Unix mode in process manifest for {}",
                    entry.path
                )));
            }
            Ok((entry.path.clone(), entry.clone()))
        })
        .collect::<Result<BTreeMap<_, _>, BoxError>>()?;
    if expected.len() != manifest.files.len() {
        return Err(err("manifest contains duplicate file paths"));
    }
    let actual = inventory_bundle(root)?
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    if !inventories_match(&expected, &actual) {
        let missing = expected.keys().find(|path| !actual.contains_key(*path));
        let extra = actual.keys().find(|path| !expected.contains_key(*path));
        let changed = expected
            .iter()
            .find(|(path, entry)| {
                actual
                    .get(*path)
                    .is_some_and(|actual| !entries_match(entry, actual))
            })
            .map(|(path, _)| path);
        return Err(err(format!(
            "process bundle integrity check failed{}{}{}",
            missing
                .map(|p| format!("; missing {p}"))
                .unwrap_or_default(),
            extra
                .map(|p| format!("; unexpected {p}"))
                .unwrap_or_default(),
            changed
                .map(|p| format!("; changed {p}"))
                .unwrap_or_default(),
        )));
    }
    for required in ["images", "workspace"] {
        match actual.get(required) {
            Some(entry) if entry.kind == EntryKind::Directory => {}
            _ => {
                return Err(err(format!(
                    "bundle is missing required {required} directory"
                )))
            }
        }
    }
    match actual.get("images/inventory.img") {
        Some(entry) if entry.kind == EntryKind::File && entry.size > 0 => {}
        _ => {
            return Err(err(
                "bundle has no non-empty CRIU images/inventory.img file",
            ))
        }
    }
    Ok(manifest)
}

fn inventories_match(
    expected: &BTreeMap<String, FileEntry>,
    actual: &BTreeMap<String, FileEntry>,
) -> bool {
    expected.len() == actual.len()
        && expected.iter().all(|(path, entry)| {
            actual
                .get(path)
                .is_some_and(|actual| entries_match(entry, actual))
        })
}

fn entries_match(expected: &FileEntry, actual: &FileEntry) -> bool {
    expected.path == actual.path
        && expected.kind == actual.kind
        && expected.size == actual.size
        && expected.blake3 == actual.blake3
}

fn validate_absolute_linux_path(value: &str) -> Result<PathBuf, BoxError> {
    if value == "/"
        || value.len() > MAX_PATH_BYTES
        || value.split('/').skip(1).count() > MAX_PATH_DEPTH
        || !value.starts_with('/')
        || value.ends_with('/')
        || value
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || value.contains('\\')
    {
        return Err(err(format!(
            "manifest source workspace is not a safe normalized absolute Linux path: {value:?}"
        )));
    }
    Ok(PathBuf::from(value))
}

#[cfg(unix)]
fn file_mode(metadata: &Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn private_create_dir(path: &Path) -> Result<(), BoxError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn private_create_dir(path: &Path) -> Result<(), BoxError> {
    fs::create_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<(), BoxError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<(), BoxError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<(), BoxError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<(), BoxError> {
    Ok(())
}

fn make_tree_private(root: &Path) -> Result<(), BoxError> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        set_private_dir(root)?;
        for entry in fs::read_dir(root)? {
            make_tree_private(&entry?.path())?;
        }
    } else if metadata.is_file() {
        set_private_file(root)?;
    }
    Ok(())
}

fn make_bundle_payload_private(root: &Path) -> Result<(), BoxError> {
    set_private_dir(root)?;
    for name in [MANIFEST_NAME, "images", "workspace"] {
        make_tree_private(&root.join(name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_rename_does_not_replace_existing_destination() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::write(&source, b"source contents").unwrap();
        fs::write(&destination, b"existing contents").unwrap();
        assert!(rename_noreplace(&source, &destination).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"source contents");
        assert_eq!(fs::read(&destination).unwrap(), b"existing contents");
        let available = temp.path().join("available");
        rename_noreplace(&source, &available).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&available).unwrap(), b"source contents");
    }

    fn host(features: &[&str]) -> HostFacts {
        HostFacts {
            os: "linux".to_owned(),
            distribution: "test".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel_release: "6.12.1".to_owned(),
            criu_version: "Version: 4.1".to_owned(),
            cpu_features: features.iter().map(|value| (*value).to_owned()).collect(),
            uid: 1000,
        }
    }

    #[test]
    fn dump_and_restore_use_documented_criu_arguments() {
        let dump = criu_dump_args(42, Path::new("/images"), Path::new("/work"));
        let dump = dump
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(
            dump,
            [
                "dump",
                "--no-default-config",
                "--tree",
                "42",
                "--images-dir",
                "/images",
                "--work-dir",
                "/work",
                "--log-file",
                "dump.log",
                "--verbosity=4",
                "--leave-stopped",
                "--shell-job",
                "--cpu-cap=all"
            ]
        );
        let restore = criu_restore_args(
            Path::new("/images"),
            Path::new("/work"),
            Path::new("/work/pid"),
        );
        let restore = restore
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(
            restore,
            [
                "restore",
                "--no-default-config",
                "--images-dir",
                "/images",
                "--work-dir",
                "/work",
                "--log-file",
                "restore.log",
                "--verbosity=4",
                "--restore-detached",
                "--pidfile",
                "/work/pid",
                "--shell-job",
                "--cpu-cap=all"
            ]
        );
    }

    #[test]
    fn command_runner_drains_output_and_uses_fake_executable() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("fake-criu");
        fs::write(
            &script,
            "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo 'Version: 4.1'; exit 0;; esac\ncase \" $* \" in *\" check \"*) echo checked; exit 0;; esac\nexit 9\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let (version, check) = inspect_criu(&script, Duration::from_secs(2)).unwrap();
        assert_eq!(version, "Version: 4.1");
        assert_eq!(String::from_utf8(check.stdout).unwrap().trim(), "checked");
    }

    #[test]
    fn compatibility_is_fail_closed() {
        let captured = host(&["avx", "sse2"]);
        let mut current = host(&["sse2"]);
        current.kernel_release = "6.13.0".to_owned();
        current.uid = 1001;
        let blockers = compare_hosts(&captured, &current);
        assert!(blockers
            .iter()
            .any(|value| value.contains("kernel mismatch")));
        assert!(blockers.iter().any(|value| value.contains("uid mismatch")));
        assert!(blockers
            .iter()
            .any(|value| value.contains("missing captured features: avx")));
    }

    #[test]
    fn complete_inventory_detects_corruption_and_extra_files() {
        let temp = tempfile::tempdir().unwrap();
        private_create_dir(&temp.path().join("images")).unwrap();
        private_create_dir(&temp.path().join("workspace")).unwrap();
        fs::write(temp.path().join("images/inventory.img"), b"inventory").unwrap();
        fs::write(temp.path().join("workspace/file"), b"data").unwrap();
        fs::set_permissions(
            temp.path().join("workspace/file"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let manifest = Manifest {
            format: FORMAT.to_owned(),
            captured_host: host(&["sse2"]),
            source_workspace: "/tmp/original-workspace".to_owned(),
            source_root: ProcessIdentity {
                pid: 10,
                start_ticks: 99,
                uid: 1000,
            },
            source_tree: vec![ProcessIdentity {
                pid: 10,
                start_ticks: 99,
                uid: 1000,
            }],
            source_boot_id: "test-boot".to_owned(),
            source_machine_id_hash: "a".repeat(blake3::OUT_LEN * 2),
            source_left_stopped: true,
            files: inventory_bundle(temp.path()).unwrap(),
            limitations: limitations(),
        };
        write_manifest(temp.path(), &manifest).unwrap();
        make_tree_private(temp.path()).unwrap();
        fs::create_dir(temp.path().join(".abra")).unwrap();
        fs::write(temp.path().join(".abra/local-metadata"), b"ignored").unwrap();
        fs::set_permissions(
            temp.path().join("workspace/file"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let verified = verify_bundle(temp.path()).unwrap();
        let restored = tempfile::tempdir().unwrap();
        copy_tree(&temp.path().join("workspace"), restored.path()).unwrap();
        apply_workspace_modes(restored.path(), &verified.files).unwrap();
        assert_eq!(
            fs::metadata(restored.path().join("file"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        fs::write(temp.path().join("workspace/file"), b"changed").unwrap();
        let error = verify_bundle(temp.path()).unwrap_err().to_string();
        assert!(error.contains("changed workspace/file"), "{error}");
        fs::write(temp.path().join("workspace/file"), b"data").unwrap();
        fs::write(temp.path().join("workspace/extra"), b"extra").unwrap();
        let error = verify_bundle(temp.path()).unwrap_err().to_string();
        assert!(error.contains("unexpected workspace/extra"), "{error}");
    }

    #[test]
    fn manifest_paths_reject_traversal_and_platform_separators() {
        for path in [
            "../escape",
            "/absolute",
            "images/../../escape",
            "images\\escape",
            "",
        ] {
            assert!(validate_manifest_path(path).is_err(), "accepted {path:?}");
        }
        assert_eq!(
            validate_manifest_path("images/pages-1.img").unwrap(),
            PathBuf::from("images/pages-1.img")
        );
        for path in [
            "tmp/relative",
            "/",
            "/tmp/a/../escape",
            "/tmp/./a",
            "/tmp//a",
            "/tmp/a/",
            "C:\\tmp\\a",
        ] {
            assert!(
                validate_absolute_linux_path(path).is_err(),
                "accepted {path:?}"
            );
        }
        assert_eq!(
            validate_absolute_linux_path("/tmp/a").unwrap(),
            PathBuf::from("/tmp/a")
        );
    }

    #[test]
    fn command_output_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("noisy");
        fs::write(
            &script,
            "#!/bin/sh\ndd if=/dev/zero bs=1024 count=100 2>/dev/null\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let output = run_command(&script, &[], Duration::from_secs(2), true).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), MAX_COMMAND_OUTPUT);
    }

    #[test]
    fn timeout_returns_promptly_after_owned_group_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("slow");
        fs::write(&script, "#!/bin/sh\nsleep 30 &\nwait\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let started = Instant::now();
        let error = run_command(&script, &[], Duration::from_millis(500), false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn saved_criu_log_is_private_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.log");
        fs::write(&source, vec![b'x'; MAX_SAVED_LOG as usize + 4096]).unwrap();
        let saved = preserve_criu_log(&source, temp.path(), ".saved-")
            .unwrap()
            .unwrap();
        assert_eq!(fs::metadata(&saved).unwrap().len(), MAX_SAVED_LOG);
        assert_eq!(
            fs::metadata(&saved).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn diagnostic_prefers_specific_criu_error_over_generic_failure() {
        let log = b"(00.010000) Preparing image\n\
(00.033490) Error (compel/src/lib/ptrace.c:27): suspending seccomp failed: Operation not permitted\n\
(00.033551) Error (compel/src/lib/infect.c:416): Unable to detach from 11770: No such process\n\
(00.033999) Error (criu/cr-dump.c:2090): Dumping FAILED.\n";
        assert_eq!(
            meaningful_diagnostic_line(log).as_deref(),
            Some(
                "(00.033490) Error (compel/src/lib/ptrace.c:27): suspending seccomp failed: Operation not permitted"
            )
        );
    }

    #[test]
    fn manifest_read_and_write_are_bounded() {
        let oversized = tempfile::tempdir().unwrap();
        File::create(oversized.path().join(MANIFEST_NAME))
            .unwrap()
            .set_len(MAX_MANIFEST_SIZE as u64 + 1)
            .unwrap();
        let error = verify_bundle(oversized.path()).unwrap_err().to_string();
        assert!(error.contains("manifest exceeds"), "{error}");

        let output = tempfile::tempdir().unwrap();
        let manifest = Manifest {
            format: FORMAT.to_owned(),
            captured_host: host(&["sse2"]),
            source_workspace: "/tmp/workspace".to_owned(),
            source_root: ProcessIdentity {
                pid: 10,
                start_ticks: 99,
                uid: 1000,
            },
            source_tree: vec![ProcessIdentity {
                pid: 10,
                start_ticks: 99,
                uid: 1000,
            }],
            source_boot_id: "test-boot".to_owned(),
            source_machine_id_hash: "a".repeat(blake3::OUT_LEN * 2),
            source_left_stopped: true,
            files: Vec::new(),
            limitations: vec!["x".repeat(MAX_MANIFEST_SIZE)],
        };
        let error = write_manifest(output.path(), &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("manifest exceeds"), "{error}");
    }

    #[test]
    fn manifest_paths_have_byte_and_depth_limits() {
        let deep = std::iter::repeat_n("a", MAX_PATH_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert!(validate_manifest_path(&deep).is_err());
        assert!(safe_relative_string(Path::new(&deep)).is_err());
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert!(validate_manifest_path(&long).is_err());
        assert!(safe_relative_string(Path::new(&long)).is_err());
        assert!(validate_absolute_linux_path(&format!("/{long}")).is_err());
    }

    #[test]
    fn stat_parser_handles_spaces_and_parentheses_in_process_name() {
        let stat = "99 (worker ) name) S 42 1 2 3";
        assert_eq!(parse_stat_tail(99, stat).unwrap(), "S 42 1 2 3");
    }
}
