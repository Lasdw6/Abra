#!/usr/bin/env python3
"""Run a real Mac -> Daytona -> Mac Codex session handoff."""

import argparse
import base64
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time

import daytona


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ADAPTER = REPO / "adapters" / "codex-session" / "bin" / "adapter.js"
KIND = "dev.abra.codex.session.v1"

OFFLINE_READER = r'''import json, os, subprocess, sys
codex, thread_id, memory_token = sys.argv[1:]
child = subprocess.Popen(
    [codex, "app-server", "--stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    env=os.environ,
)
next_id = 1

def send(message):
    child.stdin.write(json.dumps(message) + "\n")
    child.stdin.flush()

def rpc(method, params):
    global next_id
    request_id = next_id
    next_id += 1
    send({"id": request_id, "method": method, "params": params})
    while True:
        line = child.stdout.readline()
        if not line:
            raise RuntimeError("app-server closed before replying to " + method)
        message = json.loads(line)
        if message.get("id") != request_id:
            continue
        if message.get("error"):
            raise RuntimeError(json.dumps(message["error"]))
        return message["result"]

try:
    rpc("initialize", {
        "clientInfo": {"name": "abra_daytona_test", "title": "Abra Daytona test", "version": "0.1.0"},
        "capabilities": {"experimentalApi": True},
    })
    send({"method": "initialized"})
    resumed = rpc("thread/resume", {"threadId": thread_id})
    history = rpc("thread/read", {"threadId": thread_id, "includeTurns": True})
    rendered = json.dumps(history["thread"]["turns"])
    if resumed["thread"]["id"] != thread_id:
        raise RuntimeError("resumed the wrong thread")
    if memory_token not in rendered or "SOURCE_DONE" not in rendered:
        raise RuntimeError("restored history is incomplete")
    print(json.dumps({"ok": True, "thread_id": thread_id, "history_restored": True}))
finally:
    if child.stdin:
        child.stdin.close()
    child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
'''


def run(argv, *, cwd=None, env=None, input_text=None, timeout=480):
    merged = os.environ.copy()
    if env:
        merged.update(env)
    result = subprocess.run(
        [str(item) for item in argv],
        cwd=cwd,
        env=merged,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{Path(str(argv[0])).name} exited {result.returncode}: {detail[-4000:]}")
    return result.stdout


def adapter_request(request, *, env=None):
    value = {
        "protocol": "abra-adapter/1",
        "request_id": "c0de",
        "kind": KIND,
        **request,
    }
    output = run(["node", ADAPTER], env=env, input_text=json.dumps(value) + "\n")
    try:
        response = json.loads(output.strip())
    except json.JSONDecodeError as error:
        raise RuntimeError(f"local adapter returned invalid JSON: {output[-2000:]!r}") from error
    if not response.get("ok"):
        raise RuntimeError("adapter failed: " + json.dumps(response.get("error")))
    return response


def codex_turn(codex, codex_home, workspace, args, prompt):
    output = run([
        codex,
        "exec",
        "--json",
        "--sandbox",
        "workspace-write",
        "-C",
        workspace,
        *args,
        prompt,
    ], env={"CODEX_HOME": str(codex_home)}, timeout=8 * 60)
    events = [json.loads(line) for line in output.splitlines() if line.strip()]
    started = next((event for event in events if event.get("type") == "thread.started"), {})
    messages = [
        event.get("item", {}).get("text", "")
        for event in events
        if event.get("type") == "item.completed"
        and event.get("item", {}).get("type") == "agent_message"
    ]
    return started.get("thread_id"), (messages[-1] if messages else "")


def archive(path, entries):
    with tarfile.open(path, "w:gz") as bundle:
        for source, name in entries:
            bundle.add(source, arcname=name)


class Remote:
    def __init__(self, sandbox):
        self.sandbox = sandbox

    def run(self, argv, *, cwd=None, env=None, timeout=480):
        command = shlex.join([str(item) for item in argv]) + " 2>&1"
        response = self.sandbox.process.exec(
            command,
            cwd=cwd,
            env=env or None,
            timeout=timeout,
        )
        output = response.result or ""
        if response.exit_code != 0:
            raise RuntimeError(f"remote {Path(str(argv[0])).name} exited {response.exit_code}: {output[-4000:]}")
        return output

    def adapter_request(self, adapter, request, *, env=None):
        value = {
            "protocol": "abra-adapter/1",
            "request_id": "c0de",
            "kind": KIND,
            **request,
        }
        encoded = base64.b64encode((json.dumps(value) + "\n").encode()).decode()
        command = (
            f"printf %s {shlex.quote(encoded)} | base64 -d | "
            f"{shlex.join(['env', *[f'{key}={item}' for key, item in (env or {}).items()], 'node', adapter])}"
        )
        response = self.sandbox.process.exec(command + " 2>&1", timeout=480)
        output = response.result or ""
        if response.exit_code != 0:
            raise RuntimeError(f"remote adapter process exited {response.exit_code}: {output[-4000:]}")
        result = None
        for line in reversed(output.splitlines()):
            try:
                result = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
        if result is None:
            raise RuntimeError(f"remote adapter returned invalid JSON: {output[-2000:]!r}")
        if not result.get("ok"):
            raise RuntimeError("remote adapter failed: " + json.dumps(result.get("error")))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--auth-file",
        type=Path,
        default=Path.home() / ".codex" / "auth.json",
        help="Codex login copied separately into temporary local and Daytona homes",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path(tempfile.gettempdir()) / "abra-codex-daytona-report.json",
    )
    args = parser.parse_args()

    if not os.environ.get("DAYTONA_API_KEY"):
        parser.error("set DAYTONA_API_KEY")
    codex = shutil.which("codex")
    if not codex:
        parser.error("codex is not installed on the Mac")
    if not args.auth_file.is_file():
        parser.error(f"Codex auth file is missing: {args.auth_file}")

    root = Path(tempfile.mkdtemp(prefix="abra-codex-daytona-local-"))
    source_home = root / "codex-source"
    source_workspace = root / "workspace-source"
    source_bundle = root / "bundle-source"
    adapter_tar = root / "adapter.tgz"
    transfer_tar = root / "transfer.tgz"
    returned_tar = root / "returned.tgz"
    returned = root / "returned"
    sandbox = None
    client = None
    cleanup_error = None
    report = {
        "ok": False,
        "route": "mac-arm64 -> daytona-linux-x86_64 -> mac-arm64",
        "carrier": "Daytona file API with the Codex adapter at both endpoints",
        "sdk_version": importlib.metadata.version("daytona"),
        "auth_transported_by_adapter": False,
        "sandbox_deleted": False,
    }
    started_at = time.monotonic()

    try:
        source_home.mkdir(mode=0o700)
        source_workspace.mkdir()
        shutil.copy2(args.auth_file, source_home / "auth.json")
        os.chmod(source_home / "auth.json", 0o600)

        nonce = secrets.token_hex(6).upper()
        file_token = "FILE_" + nonce
        memory_token = "MEMORY_" + nonce
        thread_id, first_message = codex_turn(
            codex,
            source_home,
            source_workspace,
            ["--skip-git-repo-check"],
            " ".join([
                "This is an Abra Mac to Daytona integration test.",
                f"Use the shell to create transport-proof.txt containing exactly {file_token} followed by a newline.",
                f"Remember {memory_token} in this conversation, but do not write it to a file.",
                "Reply exactly SOURCE_DONE after the file exists.",
            ]),
        )
        if first_message.strip() != "SOURCE_DONE" or not thread_id:
            raise RuntimeError(f"unexpected source turn: {first_message!r}")
        if (source_workspace / "transport-proof.txt").read_text().strip() != file_token:
            raise RuntimeError("source tool did not create the expected file")

        report["stage"] = "mac_export"
        local_version = run([codex, "--version"]).strip()
        exported = adapter_request({
            "verb": "export",
            "source": {"session_id": thread_id, "codex_home": str(source_home)},
            "staging_dir": str(source_bundle),
            "options": {},
        }, env={"CODEX_BIN": codex})

        archive(adapter_tar, [
            (REPO / "adapters" / "codex-session", "adapters/codex-session"),
            (REPO / "adapters" / "lib", "adapters/lib"),
        ])
        archive(transfer_tar, [
            (source_bundle, "bundle-source"),
            (source_workspace, "workspace"),
        ])

        client = daytona.Daytona(daytona.DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))
        name = "abra-codex-" + secrets.token_hex(5)
        params = daytona.CreateSandboxFromSnapshotParams(
            name=name,
            language="typescript",
            labels={"project": "abra", "purpose": "codex-session-e2e"},
            auto_stop_interval=30,
            auto_delete_interval=60,
        )
        print("Creating disposable Daytona sandbox", flush=True)
        report["stage"] = "daytona_create"
        sandbox = client.create(params, timeout=300)
        report["sandbox_id"] = sandbox.id
        remote = Remote(sandbox)
        remote_root = "/tmp/abra-codex-daytona"
        remote_tool = remote_root + "/tool"
        remote_codex = remote_tool + "/node_modules/.bin/codex"
        remote_home = remote_root + "/codex-home"
        remote_workspace = remote_root + "/workspace"
        remote_adapter = remote_root + "/repo/adapters/codex-session/bin/adapter.js"
        remote_bundle = remote_root + "/bundle-source"
        remote_back = remote_root + "/bundle-back"

        report["stage"] = "daytona_prepare"
        remote.run(["mkdir", "-p", remote_root, remote_home, remote_root + "/repo"])
        remote.run(["chmod", "700", remote_root, remote_home])
        sandbox.fs.upload_file(str(adapter_tar), remote_root + "/adapter.tgz")
        sandbox.fs.upload_file(str(transfer_tar), remote_root + "/transfer.tgz")
        remote.run(["tar", "-xzf", remote_root + "/adapter.tgz", "-C", remote_root + "/repo"])
        remote.run(["tar", "-xzf", remote_root + "/transfer.tgz", "-C", remote_root])

        report["stage"] = "daytona_install_codex"
        version_number = local_version.removeprefix("codex-cli ")
        remote.run([
            "npm", "install", "--silent", "--prefix", remote_tool,
            "@openai/codex@" + version_number,
        ], timeout=8 * 60)
        remote_version = remote.run([remote_codex, "--version"]).strip()
        if remote_version != local_version:
            raise RuntimeError(f"Codex version mismatch: Mac {local_version}, Daytona {remote_version}")

        report["stage"] = "daytona_verify_no_auth"
        unauthenticated = remote.sandbox.process.exec(
            shlex.join(["env", "CODEX_HOME=" + remote_home, remote_codex, "login", "status"]) + " 2>&1",
            timeout=30,
        )
        if unauthenticated.exit_code == 0 or "Not logged in" not in (unauthenticated.result or ""):
            raise RuntimeError("Daytona Codex home was unexpectedly authenticated")

        report["stage"] = "daytona_import"
        imported = remote.adapter_request(remote_adapter, {
            "verb": "import",
            "payload": exported["payload"],
            "materialized_files": remote_bundle,
            "destination": {"codex_home": remote_home, "workspace": remote_workspace},
            "options": {},
        }, env={"CODEX_BIN": remote_codex})
        if imported["result"]["session_id"] != thread_id:
            raise RuntimeError("Daytona imported the wrong thread")

        report["stage"] = "daytona_offline_resume"
        offline_reader = root / "offline-reader.py"
        offline_reader.write_text(OFFLINE_READER)
        sandbox.fs.upload_file(str(offline_reader), remote_root + "/offline-reader.py")
        offline_result = remote.run([
            "env", "CODEX_HOME=" + remote_home,
            "python3", remote_root + "/offline-reader.py",
            remote_codex, thread_id, memory_token,
        ], timeout=60)
        try:
            offline_summary = json.loads(offline_result.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as error:
            raise RuntimeError(f"offline reader returned invalid JSON: {offline_result[-2000:]!r}") from error
        if not offline_summary["history_restored"]:
            raise RuntimeError("Daytona did not restore offline history")

        report["stage"] = "daytona_auth"
        sandbox.fs.upload_file(str(args.auth_file), remote_home + "/auth.json")
        remote.run(["chmod", "600", remote_home + "/auth.json"])
        remote.run(["env", "CODEX_HOME=" + remote_home, remote_codex, "login", "status"])

        report["stage"] = "daytona_model_turn"
        remote_output = remote.run([
            "env", "CODEX_HOME=" + remote_home,
            remote_codex,
            "exec", "--json", "--dangerously-bypass-approvals-and-sandbox", "-C", remote_workspace,
            "resume", "--skip-git-repo-check", thread_id,
            " ".join([
                "Read transport-proof.txt without changing it.",
                f"Reply exactly DAYTONA_CONTINUED FILE={file_token} MEMORY={memory_token}",
                "Use the memory token from the transferred conversation.",
            ]),
        ], timeout=8 * 60)
        remote_events = []
        for line in remote_output.splitlines():
            if not line.strip():
                continue
            try:
                remote_events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if not remote_events:
            raise RuntimeError(f"Daytona Codex returned no JSON events: {remote_output[-2000:]!r}")
        remote_messages = [
            event.get("item", {}).get("text", "")
            for event in remote_events
            if event.get("type") == "item.completed"
            and event.get("item", {}).get("type") == "agent_message"
        ]
        expected_remote = f"DAYTONA_CONTINUED FILE={file_token} MEMORY={memory_token}"
        received_remote = remote_messages[-1].strip() if remote_messages else ""
        if received_remote.rstrip(".") != expected_remote:
            raise RuntimeError(f"Daytona turn returned an unexpected reply: {received_remote!r}")

        report["stage"] = "daytona_export"
        returned_export = remote.adapter_request(remote_adapter, {
            "verb": "export",
            "source": {"session_id": thread_id, "codex_home": remote_home},
            "staging_dir": remote_back,
            "options": {},
        }, env={"CODEX_BIN": remote_codex})
        remote.run([
            "tar", "-czf", remote_root + "/returned.tgz",
            "-C", remote_root, "bundle-back", "workspace",
        ])
        sandbox.fs.download_file(remote_root + "/returned.tgz", str(returned_tar))
        returned.mkdir()
        with tarfile.open(returned_tar, "r:gz") as bundle:
            bundle.extractall(returned, filter="data")

        report["stage"] = "mac_import"
        if (returned / "workspace" / "transport-proof.txt").read_text().strip() != file_token:
            raise RuntimeError("returned Daytona workspace is incomplete")
        shutil.copytree(returned / "workspace", source_workspace, dirs_exist_ok=True)
        adapter_request({
            "verb": "import",
            "payload": returned_export["payload"],
            "materialized_files": str(returned / "bundle-back"),
            "destination": {"codex_home": str(source_home), "workspace": str(source_workspace)},
            "options": {},
        }, env={"CODEX_BIN": codex})

        report["stage"] = "mac_model_turn"
        returned_thread, third_message = codex_turn(
            codex,
            source_home,
            source_workspace,
            ["resume", "--skip-git-repo-check", thread_id],
            " ".join([
                "Confirm that the preceding assistant reply began with DAYTONA_CONTINUED",
                f"and that the original memory token was {memory_token}.",
                "Reply exactly MAC_RESUMED.",
            ]),
        )
        if returned_thread != thread_id or third_message.strip() != "MAC_RESUMED":
            raise RuntimeError("Mac did not resume the returned Daytona thread")

        report.update({
            "ok": True,
            "stage": "complete",
            "thread_id": thread_id,
            "mac_codex_version": local_version,
            "daytona_codex_version": remote_version,
            "offline_history_without_auth": True,
            "daytona_model_continuation": True,
            "mac_return_continuation": True,
            "workspace_round_trip": True,
        })
    except Exception as error:
        report["error"] = str(error).replace(os.environ["DAYTONA_API_KEY"], "<redacted>")
    finally:
        if sandbox is not None and client is not None:
            try:
                print("Deleting disposable Daytona sandbox", flush=True)
                client.delete(sandbox, timeout=180, wait=True)
                report["sandbox_deleted"] = True
            except Exception as error:
                cleanup_error = str(error).replace(os.environ["DAYTONA_API_KEY"], "<redacted>")
                report["sandbox_cleanup_error"] = cleanup_error
                report["ok"] = False
        report["elapsed_seconds"] = round(time.monotonic() - started_at, 1)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        shutil.rmtree(root, ignore_errors=True)

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] and not cleanup_error else 1


if __name__ == "__main__":
    raise SystemExit(main())
