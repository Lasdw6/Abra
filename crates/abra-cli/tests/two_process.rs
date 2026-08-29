use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Daemons(Vec<Child>);
impl Drop for Daemons {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn abra(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_abra"))
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .expect("run abra")
}

fn json(root: &Path, args: &[&str]) -> Value {
    let output = abra(root, args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("single JSON result")
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn two_real_processes_pair_send_and_accept_byte_identically() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    let mut daemons = Daemons(Vec::new());
    for root in [&a, &b] {
        daemons.0.push(
            Command::new(env!("CARGO_BIN_EXE_abra"))
                .arg("--root")
                .arg(root)
                .args(["daemon", "--yes"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for(&root.join("cadabra.sock"));
    }

    let ticket_output = abra(&b, &["pair", "ticket"]);
    assert!(ticket_output.status.success());
    let ticket = String::from_utf8(ticket_output.stdout).unwrap();
    assert!(ticket.trim().starts_with("abra-pair/1/"));
    let pair = json(&a, &["--json", "pair", "add", ticket.trim()]);
    assert!(pair.get("peer_id").is_some());

    let peer = json(&b, &["--json", "status"])["peer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    let expected = b"two process byte authority\n";
    fs::write(source.join("payload.bin"), expected).unwrap();
    let sent = json(
        &a,
        &["--json", "send", &peer, "--path", source.to_str().unwrap()],
    );
    let snapshot = sent["snapshot_id"].as_str().unwrap().to_owned();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let inbox = json(&b, &["--json", "inbox"]);
        if inbox
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == snapshot)
        {
            break;
        }
        assert!(Instant::now() < deadline, "delivery timed out");
        thread::sleep(Duration::from_millis(25));
    }
    let destination = temp.path().join("accepted");
    json(
        &b,
        &[
            "--json",
            "accept",
            &snapshot,
            "--to",
            destination.to_str().unwrap(),
        ],
    );
    assert_eq!(fs::read(destination.join("payload.bin")).unwrap(), expected);
}
