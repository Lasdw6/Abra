#!/usr/bin/env python3
"""Remote half of the provider transfer test. Uses only disposable /tmp paths."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request


BASE = Path("/tmp/abra-provider-test")
WORKSPACE = BASE / "workspace"
ROOT = BASE / "state"
ARGV = [sys.executable, "-m", "http.server", "8123", "--bind", "127.0.0.1"]
MARKER = "abra-daytona-portable-service\n"


def cli(*args, check=True):
    result = subprocess.run(
        [str(BASE / "abra"), "--root", str(ROOT), "--json", *map(str, args)],
        text=True, capture_output=True, timeout=150,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    return json.loads(result.stdout) if check else result


def wait_http():
    for _ in range(100):
        try:
            with urllib.request.urlopen("http://127.0.0.1:8123/marker.txt", timeout=1) as response:
                assert response.read().decode() == MARKER
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("HTTP service did not return the transferred marker")


def start_service():
    return subprocess.Popen(
        ARGV, cwd=WORKSPACE, env={"PATH": "/usr/bin:/bin", "NODE_ENV": "test"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, start_new_session=True,
    )


def capture():
    WORKSPACE.mkdir()
    (WORKSPACE / "marker.txt").write_text(MARKER)
    cli("init", WORKSPACE)
    child = start_service()
    try:
        wait_http()
        command = [
            sys.executable, str(BASE / "observer.py"), "--workspace", str(WORKSPACE),
            "--process-group", str(child.pid), "--once", "--barrier", "daytona",
        ]
        subprocess.run(command, check=True, capture_output=True, timeout=60)
        pinned = WORKSPACE / ".abra/observed-daytona.json"
        ledger = json.loads(pinned.read_bytes())
        candidate = next(c for c in ledger["service_candidates"] if 8123 in c["recipe"].get("ports", []))
        assert candidate["restartability"] == "unverified", candidate
        assert candidate["requires_adapter_confirmation"] is True
        # A newer/broken live ledger must not replace the selected capture.
        (WORKSPACE / ".abra/observed.json").write_text("invalid periodic data")
        snapshot = cli("snapshot", WORKSPACE, "--observation-barrier", "daytona")
        assert snapshot["observation_barrier"] == "daytona"
        manifest = json.loads((ROOT / "capsules" / snapshot["capsule_id"] / "snapshots" / (snapshot["snapshot_id"] + ".cjson")).read_bytes())
        observed = manifest["extensions"]["dev.abra.observed"]
        assert observed["schema"] == "dev.abra.observed/3"
        assert observed["observer"]["barrier"] == "daytona"
        assert manifest["recipes"] == ledger["recipes"]
        assert cli("snapshot", WORKSPACE, "--observation-barrier", "missing", check=False).returncode != 0
        pinned.unlink()
        return {
            "ok": True, "snapshot": snapshot, "resources": observed["resources"],
            "barrier_matches": True, "missing_capture_rejected": True,
            "service_candidate_unverified": True,
            "observed_sha256": hashlib.sha256(json.dumps(observed, sort_keys=True).encode()).hexdigest(),
        }
    finally:
        os.killpg(child.pid, signal.SIGTERM)
        child.wait()


def receive(snapshot_id, observed_sha256):
    cli("accept", snapshot_id, WORKSPACE)
    assert (WORKSPACE / "marker.txt").read_text() == MARKER
    metadata = WORKSPACE / ".abra"
    observed = json.loads((metadata / "received-observed.json").read_bytes())
    assert hashlib.sha256(json.dumps(observed, sort_keys=True).encode()).hexdigest() == observed_sha256
    recipes = json.loads((metadata / "recipes.json").read_bytes())
    recipe = next(r for r in recipes if 8123 in r.get("ports", []))
    # Only this known test fixture is approved for execution.
    assert recipe["argv"] == ARGV and recipe["cwd"] == ".", recipe
    import socket
    with socket.socket() as sock:
        assert sock.connect_ex(("127.0.0.1", 8123)) != 0, "Accept started a service"
    previous = (metadata / "recipes.json").read_bytes()
    subprocess.run([
        sys.executable, str(BASE / "observer.py"), "--workspace", str(WORKSPACE), "--once",
    ], check=True, capture_output=True, timeout=60)
    assert (metadata / "recipes.json").read_bytes() == previous
    child = start_service()
    try:
        wait_http()
    finally:
        os.killpg(child.pid, signal.SIGTERM)
        child.wait()
    return {
        "ok": True, "files_transferred": True, "identical_received_ledger": True,
        "received_recipes_preserved": True, "no_automatic_execution": True,
        "explicit_service_restart": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["capture", "receive"])
    parser.add_argument("--snapshot")
    parser.add_argument("--observed-sha256")
    args = parser.parse_args()
    result = capture() if args.mode == "capture" else receive(args.snapshot, args.observed_sha256)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
