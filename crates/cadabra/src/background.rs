//! Background daemon supervision: the pid file, liveness, and `abra stop`.
//!
//! Only `abra daemon --background` writes a pid file. Everything here is
//! advisory bookkeeping around an ordinary process; the daemon itself needs
//! none of it to run.
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const STOP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PidFile {
    pub pid: i32,
    /// The `ps lstart` string of the process at spawn time. It is `None` when
    /// `ps` was unavailable; `stop` then falls back to the command-line check.
    #[serde(default)]
    pub started_at: Option<String>,
    pub binary: String,
    pub root: PathBuf,
}

pub fn pid_path(root: &Path) -> PathBuf {
    root.join("daemon.pid")
}

pub fn log_path(root: &Path) -> PathBuf {
    root.join("daemon.log")
}

impl PidFile {
    pub fn load(root: &Path) -> Result<Option<Self>> {
        match fs::read(pid_path(root)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    pub fn save(&self, root: &Path) -> Result<()> {
        let path = pid_path(root);
        fs::write(&path, serde_json::to_vec(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
    pub fn remove(root: &Path) -> Result<()> {
        match fs::remove_file(pid_path(root)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// A pid we cannot signal but that exists is still alive.
pub fn is_alive(pid: i32) -> bool {
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return false;
    };
    match rustix::process::test_kill_process(pid) {
        Ok(()) => true,
        Err(error) => error == rustix::io::Errno::PERM,
    }
}

/// `(start time, command line)` as `ps` reports them. Pid reuse is the reason
/// both are checked before a signal is sent.
pub fn process_identity(pid: i32) -> Option<(String, String)> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "lstart=", "-o", "command="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields = text.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 6 {
        return None;
    }
    Some((fields[..5].join(" "), fields[5..].join(" ")))
}

/// Drop a pid file left behind by a daemon that is no longer running.
pub fn clear_stale_pid_file(root: &Path) {
    if let Ok(Some(record)) = PidFile::load(root) {
        if !is_alive(record.pid) {
            let _ = PidFile::remove(root);
        }
    }
}

/// Remove the pid file when it names this process, so a clean shutdown leaves
/// no record behind.
pub fn release_pid_file(root: &Path) {
    if let Ok(Some(record)) = PidFile::load(root) {
        if record.pid == std::process::id() as i32 {
            let _ = PidFile::remove(root);
        }
    }
}

/// Terminate the recorded background daemon and remove its pid file.
pub async fn stop(root: &Path) -> Result<Value> {
    let record = PidFile::load(root)?.ok_or_else(|| {
        format!(
            "no daemon pid file at {}; only `daemon --background` records one",
            pid_path(root).display()
        )
    })?;
    if !is_alive(record.pid) {
        PidFile::remove(root)?;
        return Ok(json!({"stopped":false,"pid":record.pid,"reason":"process is not running"}));
    }
    let (started_at, command) = process_identity(record.pid)
        .ok_or_else(|| format!("could not read process identity for pid {}", record.pid))?;
    let root_text = record.root.display().to_string();
    if record
        .started_at
        .as_deref()
        .is_some_and(|recorded| recorded != started_at)
        || !command.contains(&record.binary)
        || !command.contains("daemon")
        || !command.contains(&root_text)
    {
        return Err(format!(
            "refusing to stop pid {}; it is not the recorded Abra daemon",
            record.pid
        )
        .into());
    }
    let pid = rustix::process::Pid::from_raw(record.pid).ok_or("invalid recorded pid")?;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
    let deadline = tokio::time::Instant::now() + STOP_TIMEOUT;
    while is_alive(record.pid) {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "daemon pid {} did not exit within {} seconds",
                record.pid,
                STOP_TIMEOUT.as_secs()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    PidFile::remove(root)?;
    Ok(json!({"stopped":true,"pid":record.pid,"root":record.root}))
}

/// A backgrounded daemon leaves the launching terminal's session so a Ctrl-C
/// there does not reach it. The re-executed child calls this itself, which
/// keeps the parent free of `pre_exec` and unsafe code.
pub fn detach_from_terminal() {
    if std::env::var_os("ABRA_DAEMON_DETACH").is_some() {
        let _ = rustix::process::setsid();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_round_trips_and_removes() {
        let root = tempfile::tempdir().unwrap();
        assert!(PidFile::load(root.path()).unwrap().is_none());
        PidFile {
            pid: 4242,
            started_at: Some("Wed Sep 3 12:00:00 2026".into()),
            binary: "/tmp/abra".into(),
            root: root.path().to_path_buf(),
        }
        .save(root.path())
        .unwrap();
        let loaded = PidFile::load(root.path()).unwrap().unwrap();
        assert_eq!(loaded.pid, 4242);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(pid_path(root.path()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        PidFile::remove(root.path()).unwrap();
        assert!(PidFile::load(root.path()).unwrap().is_none());
    }

    #[test]
    fn this_process_is_alive_and_identifiable() {
        let pid = std::process::id() as i32;
        assert!(is_alive(pid));
        assert!(!is_alive(0));
        let (started_at, command) = process_identity(pid).expect("ps reports this process");
        assert!(!started_at.is_empty());
        assert!(!command.is_empty());
    }

    #[test]
    fn a_stale_pid_file_is_cleared_on_startup() {
        let root = tempfile::tempdir().unwrap();
        PidFile {
            // Pid 0 is never a live process id here, so this record is stale.
            pid: 0,
            started_at: None,
            binary: "/tmp/abra".into(),
            root: root.path().to_path_buf(),
        }
        .save(root.path())
        .unwrap();
        clear_stale_pid_file(root.path());
        assert!(PidFile::load(root.path()).unwrap().is_none());
    }
}
