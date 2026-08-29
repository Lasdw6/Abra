#![cfg(unix)]

use std::{
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn real_cli_round_trips_status_over_uds() {
    let root = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_abra");
    let child = Command::new(binary)
        .args(["--root", root.path().to_str().unwrap(), "daemon", "--yes"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);
    for _ in 0..100 {
        let output = Command::new(binary)
            .args(["--root", root.path().to_str().unwrap(), "--json", "status"])
            .output()
            .unwrap();
        if output.status.success() {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["running"], true);
            assert_eq!(value["root"], root.path().to_str().unwrap());
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("daemon socket did not become ready")
}
