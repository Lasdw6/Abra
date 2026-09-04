#!/usr/bin/env python3
"""Exercise the observer against real Linux processes in a disposable sandbox."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observer", type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("observer", args.observer)
    observer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)

    with tempfile.TemporaryDirectory(prefix="abra-observer-probe-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir()
        runtimes = root / "runtimes"
        runtimes.mkdir()
        fixture = root / "fixture.py"
        fixture.write_text('''import json, os, socket, subprocess, sys, time
tcp = socket.socket()
tcp.bind(("127.0.0.1", 0))
tcp.listen()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", 0))
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], cwd="/")
print(json.dumps({"worker": child.pid, "tcp": tcp.getsockname()[1], "udp": udp.getsockname()[1]}), flush=True)
time.sleep(120)
''')
        sentinel = "abra-synthetic-secret-never-export"
        child = subprocess.Popen(
            [sys.executable, str(fixture), "--token", sentinel],
            cwd=workspace,
            env={"PATH": "/usr/bin:/bin", "NODE_ENV": "test", "ABRA_RECIPE_TOKEN": sentinel},
            stdout=subprocess.PIPE, text=True, start_new_session=True,
        )
        try:
            facts = json.loads(child.stdout.readline())
            options = observer.create_parser().parse_args([
                "--workspace", str(workspace), "--process-group", str(child.pid),
                "--runtime-dirs", str(runtimes), "--once", "--barrier", "providerproof",
            ])
            ledger = observer.cycle(options, {})
            assert sentinel not in json.dumps(ledger), "Secret leaked into observation"
            rows = {row["pid"]: row for row in ledger["processes"]}
            assert child.pid in rows and facts["worker"] in rows, "Workload membership lost"
            assert rows[facts["worker"]]["cwd"] is None, "External cwd marked portable"
            ports = {(p["proto"], p["port"]) for p in rows[child.pid]["ports"]}
            assert ("tcp", facts["tcp"]) in ports and ("udp", facts["udp"]) in ports, "Socket ownership lost"
            assert len(ledger["service_candidates"]) == 1, "Workers were not grouped"
            assert ledger["service_candidates"][0]["restartability"] == "blocked"
            assert ledger["recipes"] == [], "Incomplete service became a restart recipe"
            capture = workspace / ".abra/observed-providerproof.json"
            original = capture.read_bytes()
            options.once = False
            observer.cycle(options, {})
            assert capture.read_bytes() == original, "Periodic observer replaced pinned capture"
            try:
                observer.write_ledger(str(workspace), ledger, True, "providerproof")
            except FileExistsError:
                pass
            else:
                raise AssertionError("Capture overwrite permitted")
            check_integers(ledger)
            assert capture.stat().st_mode & 0o777 == 0o600
            print(json.dumps({
                "ok": True, "real_processes_and_sockets": True,
                "outside_workspace_worker": True, "secret_redaction": True,
                "blocked_recipe": True, "immutable_capture": True,
                "integer_profile": True, "resources": ledger["resources"],
                "collection_errors": ledger["collection_errors"],
            }, indent=2))
        finally:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait()
            child.stdout.close()


def check_integers(value):
    if isinstance(value, dict):
        for item in value.values():
            check_integers(item)
    elif isinstance(value, list):
        for item in value:
            check_integers(item)
    elif isinstance(value, (int, float)):
        assert isinstance(value, int) and abs(value) <= 9007199254740991


if __name__ == "__main__":
    main()
