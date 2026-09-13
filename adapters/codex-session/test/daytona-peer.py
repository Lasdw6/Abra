#!/usr/bin/env python3
"""Test direct Abra peer transport from macOS into a Daytona sandbox."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
import uuid

import daytona


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
KIND = "dev.abra.codex.session.v1"


def run(argv, *, timeout=180):
    result = subprocess.run(
        [str(item) for item in argv],
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{Path(str(argv[0])).name} exited {result.returncode}: {detail[-3000:]}")
    return result.stdout


def ticket_relay_urls(encoded):
    payload = encoded.strip().split("/", 2)[2]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    ticket = json.loads(base64.urlsafe_b64decode(payload))
    relay_urls = []
    for address in ticket["addresses"]:
        for transport_address in json.loads(address)["addrs"]:
            relay = transport_address.get("Relay")
            if relay:
                relay_urls.append(relay)
    return relay_urls


def ticket_after_relay_ready(make_ticket, relay_mode, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        ticket = make_ticket().strip()
        relays = ticket_relay_urls(ticket)
        if relay_mode == "none" or relays:
            return ticket, relays
        if time.monotonic() >= deadline:
            return ticket, relays
        time.sleep(0.25)


class Remote:
    def __init__(self, sandbox):
        self.sandbox = sandbox

    def exec(self, argv, *, timeout=180):
        response = self.sandbox.process.exec(
            shlex.join([str(item) for item in argv]) + " 2>&1",
            timeout=timeout,
        )
        return response.exit_code, response.result or ""

    def run(self, argv, *, timeout=180):
        code, output = self.exec(argv, timeout=timeout)
        if code != 0:
            raise RuntimeError(f"remote {Path(str(argv[0])).name} exited {code}: {output[-3000:]}")
        return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-archive", type=Path, required=True)
    parser.add_argument("--abra", type=Path, default=REPO / "target" / "debug" / "abra")
    parser.add_argument(
        "--iroh-relay",
        default="n0",
        help="n0, none, or one HTTPS Iroh relay URL; applied to both peers",
    )
    parser.add_argument(
        "--daytona-domain-allow-list",
        help="optional Daytona domain allow list, for example *.relay.n0.iroh.link",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path(tempfile.gettempdir()) / "abra-codex-daytona-peer-report.json",
    )
    args = parser.parse_args()
    if not os.environ.get("DAYTONA_API_KEY"):
        parser.error("set DAYTONA_API_KEY")
    if not args.linux_archive.is_file():
        parser.error(f"Linux archive is missing: {args.linux_archive}")
    if not args.abra.is_file():
        parser.error(f"Mac Abra binary is missing: {args.abra}")

    owned = Path(tempfile.mkdtemp(prefix="acdp-", dir="/tmp"))
    mac_root = owned / "r"
    mac_home = owned / "c"
    mac_workspace = owned / "w"
    remote_bundle = "/tmp/abra-codex-peer/received"
    remote_workspace = "/tmp/abra-codex-peer/workspace"
    remote_home = "/tmp/abra-codex-peer/codex-home"
    remote_root = "/tmp/abra-codex-peer/root"
    remote_abra = "/tmp/abra-codex-peer/dist/abra"
    remote_adapters = "/tmp/abra-codex-peer/dist/adapters/codex-session"
    client = None
    sandbox = None
    remote = None
    report = {
        "ok": False,
        "route": "direct Abra peer from macOS ARM64 to Daytona Linux x86_64",
        "paired": False,
        "pair_confirmed": False,
        "session_acked": False,
        "session_imported": False,
        "sandbox_deleted": False,
        "stage": "setup",
        "iroh_relay": args.iroh_relay,
        "daytona_domain_allow_list": args.daytona_domain_allow_list,
    }
    started = time.monotonic()

    try:
        mac_home.mkdir(parents=True, mode=0o700)
        mac_workspace.mkdir()
        (mac_workspace / "transport-proof.txt").write_text("DIRECT_DAYTONA\n")

        client = daytona.Daytona(daytona.DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))
        params_options = dict(
            name="abra-peer-" + secrets.token_hex(5),
            language="typescript",
            labels={"project": "abra", "purpose": "direct-peer-e2e"},
            auto_stop_interval=30,
            auto_delete_interval=60,
        )
        if args.daytona_domain_allow_list:
            params_options["domain_allow_list"] = args.daytona_domain_allow_list
        params = daytona.CreateSandboxFromSnapshotParams(**params_options)
        print("Creating disposable Daytona peer", flush=True)
        sandbox = client.create(params, timeout=300)
        report["sandbox_id"] = sandbox.id
        remote = Remote(sandbox)
        remote.run(["mkdir", "-p", "/tmp/abra-codex-peer/dist", remote_home, remote_workspace])
        sandbox.fs.upload_file(str(args.linux_archive), "/tmp/abra-codex-peer/dist.tgz")
        remote.run(["tar", "-xzf", "/tmp/abra-codex-peer/dist.tgz", "-C", "/tmp/abra-codex-peer/dist"])
        remote.run(["chmod", "755", remote_abra])
        remote.run([remote_abra, "--version"])

        remote_codex_version = remote.run(["codex", "--version"]).strip().removeprefix("codex-cli ")
        session_id = str(uuid.uuid4())
        session_dir = mac_home / "sessions" / "2026" / "09" / "12"
        session_dir.mkdir(parents=True)
        rollout = session_dir / f"rollout-2026-09-12T20-00-00-{session_id}.jsonl"
        records = [
            {
                "timestamp": "2026-09-12T20:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": session_id,
                    "session_id": session_id,
                    "timestamp": "2026-09-12T20:00:00Z",
                    "cwd": str(mac_workspace),
                    "cli_version": remote_codex_version,
                    "model_provider": "openai",
                    "history_mode": "full",
                },
            },
            {
                "timestamp": "2026-09-12T20:00:01Z",
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "direct Daytona transport"},
            },
        ]
        rollout.write_text("".join(json.dumps(item) + "\n" for item in records))
        os.chmod(rollout, 0o600)

        report["stage"] = "mac_daemon"
        run([
            args.abra,
            "--root",
            mac_root,
            "config",
            "set",
            "iroh_relay",
            args.iroh_relay,
        ])
        run([
            args.abra, "--root", mac_root, "daemon", "--background", "--yes",
            "--adapters", REPO / "adapters" / "codex-session",
        ])
        report["stage"] = "daytona_daemon"
        remote.run([
            remote_abra,
            "--root",
            remote_root,
            "config",
            "set",
            "iroh_relay",
            args.iroh_relay,
        ])
        remote.run([
            remote_abra, "--root", remote_root, "daemon", "--background", "--yes",
            "--adapters", remote_adapters,
        ])
        mac_peer = json.loads(run([args.abra, "--root", mac_root, "--json", "status"]))["peer_id"]
        remote_peer = json.loads(remote.run([remote_abra, "--root", remote_root, "--json", "status"]))["peer_id"]
        report.update({"mac_peer": mac_peer, "daytona_peer": remote_peer})

        report["stage"] = "pair"
        remote_ticket, report["daytona_ticket_relay_urls"] = ticket_after_relay_ready(
            lambda: remote.run([
                remote_abra,
                "--root",
                remote_root,
                "pair",
                "ticket",
            ]),
            args.iroh_relay,
        )
        if args.iroh_relay != "none" and not report["daytona_ticket_relay_urls"]:
            raise RuntimeError("Daytona pairing ticket has no Iroh relay URL")
        ticket, report["ticket_relay_urls"] = ticket_after_relay_ready(
            lambda: run([args.abra, "--root", mac_root, "pair", "ticket"]),
            args.iroh_relay,
        )
        if args.iroh_relay != "none" and not report["ticket_relay_urls"]:
            raise RuntimeError("Mac pairing ticket has no Iroh relay URL")
        pair_argv = [remote_abra, "--root", remote_root, "pair", "add", ticket]
        confirm_error = "pair confirmation was not attempted"
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(remote.exec, pair_argv, timeout=120)
            deadline = time.monotonic() + 90
            while not future.done() and time.monotonic() < deadline:
                confirmation = subprocess.run(
                    [str(args.abra), "--root", str(mac_root), "pair", "confirm", remote_peer],
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                if confirmation.returncode == 0:
                    confirm_error = ""
                    report["pair_confirmed"] = True
                    break
                confirm_error = (confirmation.stderr or confirmation.stdout).strip()[-1000:]
                time.sleep(1)
            pair_code, pair_output = future.result(timeout=130)
        if confirm_error:
            report["confirm_error"] = confirm_error
        if pair_code != 0:
            report["pair_error"] = pair_output[-1000:]
            raise RuntimeError(f"Daytona could not pair with the Mac: {pair_output[-1000:]}")
        report["paired"] = True

        report["stage"] = "send"
        sent = json.loads(run([
            args.abra, "--root", mac_root, "--json", "send", remote_peer,
            "--kind", KIND,
            "--source", json.dumps({"session_id": session_id, "codex_home": str(mac_home)}),
            "--workspace", mac_workspace,
            "--wait", "--timeout", "120s",
        ], timeout=180))
        report["session_acked"] = sent["entry"]["state"] == "acked"
        if not report["session_acked"]:
            raise RuntimeError("direct session delivery was not acknowledged")

        report["stage"] = "accept"
        accepted = json.loads(remote.run([
            remote_abra, "--root", remote_root, "--json", "accept", "--latest",
            "--kind", KIND, remote_bundle,
            "--workspace", remote_workspace,
            "--destination", json.dumps({"codex_home": remote_home}),
        ], timeout=180))
        report["session_imported"] = accepted["import"]["result"]["session_id"] == session_id
        if not report["session_imported"]:
            raise RuntimeError("Daytona imported the wrong session")
        marker = remote.run(["cat", remote_workspace + "/transport-proof.txt"]).strip()
        if marker != "DIRECT_DAYTONA":
            raise RuntimeError("Daytona workspace marker was not restored")
        report.update({"ok": True, "stage": "complete"})
    except Exception as error:
        report["error"] = str(error).replace(os.environ["DAYTONA_API_KEY"], "<redacted>")
        daemon_log = mac_root / "daemon.log"
        if daemon_log.is_file():
            report["mac_daemon_log_tail"] = daemon_log.read_text(errors="replace")[-3000:]
        if remote is not None:
            try:
                _, remote_log = remote.exec(["cat", remote_root + "/daemon.log"])
                report["daytona_daemon_log_tail"] = remote_log[-3000:]
            except Exception:
                pass
    finally:
        try:
            run([args.abra, "--root", mac_root, "stop"], timeout=30)
        except Exception:
            pass
        if remote is not None:
            try:
                remote.run([remote_abra, "--root", remote_root, "stop"], timeout=30)
            except Exception:
                pass
        if sandbox is not None and client is not None:
            try:
                print("Deleting disposable Daytona peer", flush=True)
                client.delete(sandbox, timeout=180, wait=True)
                report["sandbox_deleted"] = True
            except Exception as error:
                report["sandbox_cleanup_error"] = str(error).replace(
                    os.environ["DAYTONA_API_KEY"], "<redacted>"
                )
                report["ok"] = False
        report["elapsed_seconds"] = round(time.monotonic() - started, 1)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        shutil.rmtree(owned, ignore_errors=True)

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
