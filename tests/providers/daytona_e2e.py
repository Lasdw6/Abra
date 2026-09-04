#!/usr/bin/env python3
"""Test a Linux Abra binary on two disposable Daytona sandboxes."""

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shlex
import sys
import time
import uuid

from daytona import CreateSandboxFromSnapshotParams, Daytona, DaytonaConfig


REPO = Path(__file__).resolve().parents[2]
BASE = "/tmp/abra-provider-test"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abra", type=Path, required=True, help="Linux x86_64 Abra binary")
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--observer-only", action="store_true", help="Check observation and capture in one sandbox, without network transfer")
    args = parser.parse_args()
    if not os.environ.get("DAYTONA_API_KEY"):
        parser.error("Set DAYTONA_API_KEY")
    binary = args.abra.read_bytes()
    if binary[:4] != b"\x7fELF":
        parser.error("--abra must be a Linux ELF binary")
    args.report_dir.mkdir(parents=True, exist_ok=True)
    client = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))
    run_id = uuid.uuid4().hex[:12]
    sandboxes = []
    report = {
        "ok": False, "provider": "daytona", "run_id": run_id,
        "mode": "observer-only" if args.observer_only else "transfer",
        "sdk_version": importlib.metadata.version("daytona"),
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "sandboxes": [], "deleted": [],
    }
    started = time.monotonic()

    def save():
        (args.report_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def execute(sandbox, command, timeout=60):
        response = sandbox.process.exec(command, timeout=timeout)
        if response.exit_code != 0:
            # Commands can carry pairing tickets, so report only process output.
            raise RuntimeError(f"Sandbox command exited {response.exit_code}: {response.result}")
        return response.result

    def cli(sandbox, *parts, timeout=150):
        return execute(sandbox, shlex.join([BASE + "/abra", "--root", BASE + "/state", *parts]), timeout)

    try:
        for role in (("source",) if args.observer_only else ("source", "destination")):
            print(f"Creating {role} sandbox", flush=True)
            sandbox = client.create(CreateSandboxFromSnapshotParams(
                name=f"abra-observer-{run_id}-{role}",
                labels={"project": "abra", "purpose": "observer-e2e", "run": run_id},
                auto_stop_interval=15, auto_delete_interval=0, ttl_minutes=30,
            ), timeout=120)
            sandboxes.append(sandbox)
            report["sandboxes"].append({
                "role": role, "id": sandbox.id,
                "configured_cpu": sandbox.cpu, "configured_memory_gib": sandbox.memory,
            })
            save()
            execute(sandbox, f"mkdir -m 700 {BASE}")
            sandbox.fs.upload_file(binary, BASE + "/abra")
            for file in ("observer.py", "test_observer.py"):
                sandbox.fs.upload_file(str(REPO / "adapters/firecracker/guest" / file), BASE + "/" + file)
            for file in ("observer_probe.py", "workspace_probe.py"):
                sandbox.fs.upload_file(str(Path(__file__).parent / file), BASE + "/" + file)
            execute(sandbox, f"chmod 700 {BASE}/abra")
            cli(sandbox, "config", "set", "iroh_relay", "n0")
            cli(sandbox, "daemon", "--yes", "--background")

        source = sandboxes[0]
        print("Checking observer with real processes and sockets", flush=True)
        unit_output = execute(source, f"python3 -m unittest discover -s {BASE} -p test_observer.py")
        (args.report_dir / "observer-tests.log").write_text(unit_output)
        report["observer_unit_tests"] = True
        report["process_probe"] = json.loads(execute(source, f"python3 {BASE}/observer_probe.py {BASE}/observer.py"))
        resources = report["process_probe"]["resources"]
        assert resources["effective_cpu_millicores"] == int(source.cpu * 1000)
        assert resources["effective_memory_bytes"] == int(source.memory * 1024 ** 3)
        report["effective_resources_match_provider"] = True
        save()

        print("Capturing the running service", flush=True)
        report["capture"] = json.loads(execute(source, f"python3 {BASE}/workspace_probe.py capture", 120))
        save()
        if not args.observer_only:
            destination = sandboxes[1]
            print("Pairing sandboxes and transferring the signed snapshot", flush=True)
            ticket = cli(destination, "pair", "ticket").strip()
            cli(source, "pair", "add", ticket)
            peer = json.loads(cli(destination, "--json", "status"))["peer_id"]
            snapshot = report["capture"]["snapshot"]["snapshot_id"]
            cli(source, "send", peer, "--snapshot", snapshot, "--wait", "--timeout", "120s")
            report["network_transfer_acknowledged"] = True
            print("Checking receipt and explicit service restart", flush=True)
            report["receipt"] = json.loads(execute(destination, shlex.join([
                "python3", BASE + "/workspace_probe.py", "receive", "--snapshot", snapshot,
                "--observed-sha256", report["capture"]["observed_sha256"],
            ]), 120))
        report["ok"] = True
    except Exception as error:
        report["error"] = str(error).replace(os.environ["DAYTONA_API_KEY"], "<redacted>")
        print(report["error"], file=sys.stderr, flush=True)
    finally:
        for sandbox in sandboxes:
            try:
                logs = sandbox.process.exec(f"cat {BASE}/state/daemon.log", timeout=15)
                (args.report_dir / f"daemon-{sandbox.id}.log").write_text(logs.result)
            except Exception:
                pass
            try:
                print(f"Deleting test sandbox {sandbox.id}", flush=True)
                client.delete(sandbox, timeout=60, wait=True)
                report["deleted"].append(sandbox.id)
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(str(error).replace(os.environ["DAYTONA_API_KEY"], "<redacted>"))
                report["ok"] = False
            save()
        report["elapsed_seconds"] = round(time.monotonic() - started, 1)
        save()
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
