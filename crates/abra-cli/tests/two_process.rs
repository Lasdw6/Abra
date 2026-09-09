use serde_json::Value;
use std::{
    fs,
    net::{TcpListener, TcpStream},
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

fn start_daemon(root: &Path, transport: &str) -> Result<Child, String> {
    start_daemon_with_relay(root, transport, "n0")
}

fn start_daemon_with_relay(root: &Path, transport: &str, relay: &str) -> Result<Child, String> {
    let config = Command::new(env!("CARGO_BIN_EXE_abra"))
        .arg("--root")
        .arg(root)
        .args(["config", "set", "iroh_relay", relay])
        .output()
        .unwrap();
    if !config.status.success() {
        return Err(String::from_utf8_lossy(&config.stderr).into_owned());
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_abra"))
        .arg("--root")
        .arg(root)
        .args(["daemon", "--yes", "--transport", transport])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !abra(root, &["--json", "status"]).status.success() {
        if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok(child)
}

fn pair(a: &Path, b: &Path) {
    let ticket_output = abra(b, &["pair", "ticket"]);
    assert!(
        ticket_output.status.success(),
        "{}",
        String::from_utf8_lossy(&ticket_output.stderr)
    );
    let ticket = String::from_utf8(ticket_output.stdout).unwrap();
    assert!(ticket.trim().starts_with("abra-pair/1/"));
    let paired = json(a, &["--json", "pair", "add", ticket.trim()]);
    assert!(paired.get("peer_id").is_some());
}

fn wait_for_inbox(root: &Path, snapshot: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let inbox = json(root, &["--json", "inbox"]);
        if inbox
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == snapshot)
        {
            return;
        }
        assert!(Instant::now() < deadline, "delivery timed out");
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_outbox_state(root: &Path, snapshot: &str, state: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let outbox = json(root, &["--json", "outbox"]);
        if outbox
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["snapshot_id"] == snapshot && entry["state"] == state)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "outbox entry did not reach {state}: {outbox}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn peer_id(root: &Path) -> String {
    json(root, &["--json", "status"])["peer_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn send_link(from: &Path, to: &Path, link: &str) -> String {
    let peer = peer_id(to);
    json(from, &["--json", "send", &peer, "--link", link])["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn restart_both(daemons: &mut Daemons, a: &Path, b: &Path, transport: &str) {
    for child in &mut daemons.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    daemons.0.clear();
    for root in [a, b] {
        daemons.0.push(start_daemon(root, transport).unwrap());
    }
}

#[test]
fn paired_daemons_restart_then_send_and_ack_both_directions() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    let mut daemons = Daemons(Vec::new());
    for root in [&a, &b] {
        daemons.0.push(start_daemon(root, "tcp").unwrap());
    }
    let ports = [&a, &b].map(|root| fs::read_to_string(root.join("net/tcp-port")).unwrap());
    assert!(ports
        .iter()
        .all(|port| port.trim().parse::<u16>().unwrap() != 0));

    pair(&a, &b);
    restart_both(&mut daemons, &a, &b, "tcp");
    for (root, port) in [&a, &b].into_iter().zip(ports) {
        assert_eq!(fs::read_to_string(root.join("net/tcp-port")).unwrap(), port);
    }

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
        &["--json", "accept", &snapshot, destination.to_str().unwrap()],
    );
    assert_eq!(fs::read(destination.join("payload.bin")).unwrap(), expected);

    let a_peer = json(&a, &["--json", "status"])["peer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let reverse = temp.path().join("reverse");
    fs::create_dir(&reverse).unwrap();
    fs::write(reverse.join("reply"), b"back after restart").unwrap();
    let sent = json(
        &b,
        &[
            "--json",
            "send",
            &a_peer,
            "--path",
            reverse.to_str().unwrap(),
        ],
    );
    let reverse_snapshot = sent["snapshot_id"].as_str().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let inbox = json(&a, &["--json", "inbox"]);
        if inbox
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == reverse_snapshot)
        {
            break;
        }
        assert!(Instant::now() < deadline, "reverse delivery timed out");
        thread::sleep(Duration::from_millis(25));
    }
    for root in [&a, &b] {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let outbox = json(root, &["--json", "outbox"]);
            if outbox
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["state"] == "acked")
            {
                break;
            }
            assert!(Instant::now() < deadline, "outbox did not ack");
            thread::sleep(Duration::from_millis(25));
        }
    }
}

#[test]
fn stale_tcp_port_falls_back_and_is_rewritten() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("daemon");
    let mut daemon = start_daemon(&root, "tcp").unwrap();
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    let old_port = fs::read_to_string(root.join("net/tcp-port"))
        .unwrap()
        .trim()
        .parse::<u16>()
        .unwrap();
    let occupied = TcpListener::bind(("127.0.0.1", old_port)).unwrap();
    let mut restarted = start_daemon(&root, "tcp").unwrap();
    let new_port = fs::read_to_string(root.join("net/tcp-port"))
        .unwrap()
        .trim()
        .parse::<u16>()
        .unwrap();
    assert_ne!(new_port, old_port);
    drop(occupied);
    restarted.kill().unwrap();
    restarted.wait().unwrap();
}

#[test]
fn paired_iroh_daemons_restart_then_send_and_ack_both_directions() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    let mut daemons = Daemons(Vec::new());
    for root in [&a, &b] {
        match start_daemon_with_relay(root, "iroh", "none") {
            Ok(child) => daemons.0.push(child),
            Err(error) if error.contains("Failed to create netmon monitor") => {
                eprintln!("skipping iroh test: {error}");
                return;
            }
            Err(error) => panic!("iroh daemon failed to become ready: {error}"),
        }
    }
    let ports = [&a, &b].map(|root| fs::read_to_string(root.join("net/iroh-port")).unwrap());
    assert!(ports
        .iter()
        .all(|port| port.trim().parse::<u16>().unwrap() != 0));

    pair(&a, &b);
    for child in &mut daemons.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    daemons.0.clear();
    for root in [&a, &b] {
        match start_daemon_with_relay(root, "iroh", "none") {
            Ok(child) => daemons.0.push(child),
            Err(error) if error.contains("Failed to create netmon monitor") => {
                eprintln!("skipping iroh test after restart: {error}");
                return;
            }
            Err(error) => panic!("iroh daemon failed after restart: {error}"),
        }
    }
    for (root, port) in [&a, &b].into_iter().zip(ports) {
        assert_eq!(
            fs::read_to_string(root.join("net/iroh-port")).unwrap(),
            port
        );
    }

    let a_to_b = send_link(&a, &b, "https://example.test/a-to-b");
    let b_to_a = send_link(&b, &a, "https://example.test/b-to-a");
    wait_for_inbox(&b, &a_to_b, Duration::from_secs(15));
    wait_for_inbox(&a, &b_to_a, Duration::from_secs(15));
    wait_for_outbox_state(&a, &a_to_b, "acked", Duration::from_secs(15));
    wait_for_outbox_state(&b, &b_to_a, "acked", Duration::from_secs(15));
}

#[test]
fn n0_relay_daemons_pair_and_deliver() {
    if std::env::var_os("ABRA_TEST_IROH_INTERNET").is_none() {
        eprintln!("skipping Internet iroh test; set ABRA_TEST_IROH_INTERNET=1 to run it");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    let mut daemons = Daemons(Vec::new());
    for root in [&a, &b] {
        match start_daemon_with_relay(root, "iroh", "n0") {
            Ok(child) => daemons.0.push(child),
            Err(error) if error.contains("Failed to create netmon monitor") => {
                eprintln!("skipping iroh test: {error}");
                return;
            }
            Err(error) => panic!("iroh daemon failed to become ready: {error}"),
        }
    }

    pair(&a, &b);
    let snapshot = send_link(&a, &b, "https://example.test/cross-nat");
    wait_for_inbox(&b, &snapshot, Duration::from_secs(30));
    wait_for_outbox_state(&a, &snapshot, "acked", Duration::from_secs(30));
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn build_and_start_relay(port: u16, secret: &str, data_dir: &Path) -> Child {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let build = Command::new(env!("CARGO"))
        .args(["build", "-p", "abra-relay"])
        .current_dir(&workspace)
        .output()
        .expect("build abra-relay");
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(Into::into)
        .unwrap_or_else(|| workspace.join("target"));
    let child = Command::new(target.join("debug/abra-relay"))
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .arg("--data-dir")
        .arg(data_dir)
        .env("ABRA_RELAY_SECRET", secret)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start abra-relay");
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "relay failed to bind");
        thread::sleep(Duration::from_millis(25));
    }
    child
}

#[test]
fn relay_delivers_to_restarted_offline_daemon_and_returns_ack() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    let secret = "two-process-relay-secret";
    let port = free_port();
    let mut processes = Daemons(vec![build_and_start_relay(
        port,
        secret,
        &temp.path().join("relay"),
    )]);
    for root in [&a, &b] {
        processes.0.push(start_daemon(root, "tcp").unwrap());
    }
    pair(&a, &b);

    let relay_url = format!("http://127.0.0.1:{port}");
    for root in [&a, &b] {
        json(
            root,
            &["--json", "config", "set", "relay_after_attempts", "0"],
        );
        json(
            root,
            &["--json", "config", "set", "relay_poll_seconds", "5"],
        );
        json(
            root,
            &["--json", "relay", "add", &relay_url, "--secret", secret],
        );
    }

    let b_peer = peer_id(&b);
    let a_peer = peer_id(&a);
    let accepted = temp.path().join("relay-auto-accepted");
    json(
        &b,
        &[
            "--json",
            "policy",
            "grant",
            "--peer",
            &a_peer,
            "--kind",
            "dev.abra.bundle",
            "--auto-accept",
            "--to",
            accepted.to_str().unwrap(),
        ],
    );
    processes.0[2].kill().unwrap();
    processes.0[2].wait().unwrap();
    let source = temp.path().join("relay-source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("payload"), "from relay").unwrap();
    let snapshot = json(
        &a,
        &[
            "--json",
            "send",
            &b_peer,
            "--path",
            source.to_str().unwrap(),
        ],
    )["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    wait_for_outbox_state(&a, &snapshot, "awaiting_ack", Duration::from_secs(10));

    processes.0.push(start_daemon(&b, "tcp").unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !fs::read_to_string(accepted.join(&snapshot).join("payload"))
        .is_ok_and(|value| value == "from relay")
    {
        assert!(Instant::now() < deadline, "relay grant did not auto-accept");
        thread::sleep(Duration::from_millis(25));
    }
    wait_for_outbox_state(&a, &snapshot, "acked", Duration::from_secs(30));
}

/// Always stop a backgrounded daemon, including when an assertion panics.
struct Background(std::path::PathBuf);
impl Drop for Background {
    fn drop(&mut self) {
        let _ = abra(&self.0, &["--json", "stop"]);
    }
}

#[test]
fn background_daemon_records_a_pid_file_and_stop_terminates_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("background");
    let started = json(
        &root,
        &[
            "--json",
            "daemon",
            "--background",
            "--yes",
            "--transport",
            "tcp",
        ],
    );
    let guard = Background(root.clone());
    let pid = started["pid"].as_i64().unwrap();
    assert!(started["peer_id"].as_str().unwrap().len() == 64);

    // The daemon answers on its own, and the CLI recorded who it is.
    assert_eq!(
        json(&root, &["--json", "status"])["peer_id"],
        started["peer_id"]
    );
    let record: Value =
        serde_json::from_slice(&fs::read(root.join("daemon.pid")).unwrap()).unwrap();
    assert_eq!(record["pid"], pid);
    assert_eq!(record["root"], root.to_str().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(root.join("daemon.pid"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join("daemon.log"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    // A second --background refuses rather than racing the first.
    let again = abra(
        &root,
        &["daemon", "--background", "--yes", "--transport", "tcp"],
    );
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already running"));

    let stopped = json(&root, &["--json", "stop"]);
    assert_eq!(stopped["stopped"], true);
    assert_eq!(stopped["pid"], pid);
    assert!(!root.join("daemon.pid").exists());
    let deadline = Instant::now() + Duration::from_secs(5);
    while abra(&root, &["--json", "status"]).status.success() {
        assert!(
            Instant::now() < deadline,
            "daemon still answering after stop"
        );
        thread::sleep(Duration::from_millis(25));
    }
    // Stopping again reports there is nothing recorded.
    let missing = abra(&root, &["--json", "stop"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("no daemon pid file"));
    std::mem::forget(guard);
}

#[test]
fn one_command_sends_a_workspace_and_the_other_side_accepts_the_latest() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    let mut daemons = Daemons(Vec::new());
    for root in [&a, &b] {
        daemons.0.push(start_daemon(root, "tcp").unwrap());
    }
    pair(&a, &b);

    let workspace = temp.path().join("my-workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("turn"), "one").unwrap();
    json(&a, &["--json", "init", workspace.to_str().unwrap()]);
    let peer = peer_id(&b);
    let sent = json(
        &a,
        &[
            "--json",
            "send",
            &peer,
            "--path",
            workspace.to_str().unwrap(),
            "--wait",
        ],
    );
    assert_eq!(sent["workspace_detected"], true);
    assert_eq!(sent["entry"]["state"], "acked");

    let here = temp.path().join("here");
    let accepted = json(
        &b,
        &[
            "--json",
            "accept",
            "--latest",
            "--kind",
            "dev.abra.workspace",
            here.to_str().unwrap(),
        ],
    );
    assert_eq!(accepted["accepted"], sent["snapshot_id"]);
    assert_eq!(fs::read_to_string(here.join("turn")).unwrap(), "one");
}
