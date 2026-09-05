#![cfg(unix)]

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
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
fn uds_rejects_oversize_line() {
    let root = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_abra");
    let child = Command::new(binary)
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "daemon",
            "--yes",
            "--transport",
            "tcp",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);
    let socket = root.path().join("cadabra.sock");
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(&vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"], "request too large");
}

#[test]
fn real_cli_round_trips_status_over_uds() {
    let root = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_abra");
    let child = Command::new(binary)
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "daemon",
            "--yes",
            "--transport",
            "tcp",
        ])
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

#[test]
fn python_checkpoint_round_trips_through_cli_and_signed_manifest() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let fake_proc = tempfile::tempdir().unwrap();
    let runtime_dir = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_abra");
    let child = Command::new(binary)
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "daemon",
            "--yes",
            "--transport",
            "tcp",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);
    for _ in 0..200 {
        if root.path().join("cadabra.sock").exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let call = |args: &[&str]| {
        Command::new(binary)
            .args(["--root", root.path().to_str().unwrap(), "--json"])
            .args(args)
            .output()
            .unwrap()
    };
    let path = workspace.path().to_str().unwrap();
    let initialized = call(&["init", path]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let observer = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../adapters/sandbox/collector/observer.py");
    let capture = Command::new("python3")
        .arg(observer)
        .args([
            "--workspace",
            path,
            "--proc",
            fake_proc.path().to_str().unwrap(),
            "--runtime-dirs",
            runtime_dir.path().to_str().unwrap(),
            "--once",
            "--barrier",
            "proof",
        ])
        .output()
        .unwrap();
    assert!(
        capture.status.success(),
        "{}",
        String::from_utf8_lossy(&capture.stderr)
    );
    // A periodic writer must not change which ledger the snapshot embeds.
    std::fs::write(
        workspace.path().join(".abra/observed.json"),
        b"bad periodic data",
    )
    .unwrap();
    let snapshot = call(&[
        "snapshot",
        path,
        "--observation-barrier",
        "proof",
        "--observation-host",
        "{\"configured_resources\":{\"cpus\":2}}",
    ]);
    assert!(
        snapshot.status.success(),
        "{}",
        String::from_utf8_lossy(&snapshot.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&snapshot.stdout).unwrap();
    assert_eq!(result["observation_barrier"], "proof");
    let capsule = result["capsule_id"].as_str().unwrap();
    let id = result["snapshot_id"].as_str().unwrap();
    let bytes = std::fs::read(
        root.path()
            .join(format!("capsules/{capsule}/snapshots/{id}.cjson")),
    )
    .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let observed = &manifest["extensions"]["dev.abra.observed"];
    assert_eq!(observed["schema"], "dev.abra.observed/3");
    assert_eq!(observed["observer"]["barrier"], "proof");
    assert_eq!(observed["host"]["facts"]["configured_resources"]["cpus"], 2);
    let missing = call(&["snapshot", path, "--observation-barrier", "missing"]);
    assert!(!missing.status.success());
}
