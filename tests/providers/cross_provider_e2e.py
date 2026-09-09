#!/usr/bin/env python3
"""Exercise portable Abra continuation in both directions between two providers."""

import argparse
import datetime
import json
import os
import platform
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SANDBOX = REPO / "adapters" / "sandbox"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "checkpoint_workload.py"
sys.path.insert(0, str(SANDBOX))

from abra_sandbox import coordinator  # noqa: E402
from abra_sandbox.drivers import load  # noqa: E402


REMOTE_FACTS = r'''import json, platform, sqlite3, sys
print(json.dumps({"system": platform.system(), "machine": platform.machine(),
                  "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                  "executable": sys.executable}, sort_keys=True))'''

MAKE_TEMP = r'''import json, os, sys, tempfile
parent = os.path.realpath(sys.argv[1])
if not os.path.isdir(parent):
    raise SystemExit("temp parent is not a directory: " + parent)
path = tempfile.mkdtemp(prefix=sys.argv[2], dir=parent)
print(json.dumps(path))'''

SAFE_RENAME = r'''import os, sys
source, destination, owner = map(os.path.realpath, sys.argv[1:])
if os.path.commonpath((source, owner)) != owner or os.path.commonpath((destination, owner)) != owner:
    raise SystemExit("rename escaped the owned run directory")
if not os.path.isdir(source) or os.path.exists(destination):
    raise SystemExit("rename source is missing or destination already exists")
os.rename(source, destination)'''

SAFE_STOP = r'''import os, signal, subprocess, sys, time
pid = int(sys.argv[1])
workspace, fixture = sys.argv[2], sys.argv[3]
if pid <= 1:
    raise SystemExit("refusing unsafe pid")
try:
    with open("/proc/%d/cmdline" % pid, "rb") as handle:
        command = handle.read().replace(b"\0", b" ").decode("utf-8", "replace")
except OSError:
    result = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True)
    command = result.stdout.strip() if result.returncode == 0 else ""
if workspace not in command or fixture not in command:
    raise SystemExit("pid does not match this run's held workload: " + command[:500])
os.kill(pid, signal.SIGTERM)
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        raise SystemExit(0)
    time.sleep(0.1)
os.kill(pid, signal.SIGKILL)'''

SAFE_REMOVE = r'''import os, shutil, sys
path, parent = map(os.path.realpath, sys.argv[1:])
if os.path.dirname(path) != parent or not os.path.basename(path).startswith("abra-cross-provider-"):
    raise SystemExit("refusing to remove a directory not owned by this run")
if os.path.isdir(path):
    shutil.rmtree(path)'''


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def redact(value):
    text = str(value)
    secret = os.environ.get("DAYTONA_API_KEY")
    return text.replace(secret, "<redacted>") if secret else text


def canonical_machine(value):
    value = value.lower().replace("-", "_")
    return {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}.get(value, value)


def binary_machine(path):
    with open(path, "rb") as handle:
        head = handle.read(32)
    if head[:4] == b"\x7fELF":
        endian = "<" if head[5] == 1 else ">"
        machine = struct.unpack(endian + "H", head[18:20])[0]
        return {62: "x86_64", 183: "aarch64", 40: "arm"}.get(machine, "elf-%d" % machine), "ELF"
    magic = head[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        endian = "<" if magic == b"\xcf\xfa\xed\xfe" else ">"
        cpu = struct.unpack(endian + "I", head[4:8])[0]
        return {0x01000007: "x86_64", 0x0100000C: "aarch64"}.get(cpu, "macho-%d" % cpu), "Mach-O"
    raise ValueError("inside Abra binary is neither ELF nor a native 64-bit Mach-O file: %s" % path)


def json_output(data):
    lines = [line for line in data.decode("utf-8", "replace").splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("command returned no JSON")
    return json.loads(lines[-1])


def load_endpoint(path):
    with open(path) as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("driver") not in ("local", "ssh", "daytona"):
        raise ValueError("endpoint %s needs driver local, ssh, or daytona" % path)
    if not isinstance(value.get("options", {}), dict):
        raise ValueError("endpoint %s options must be an object" % path)
    value.setdefault("options", {})
    value.setdefault("label", Path(path).stem)
    value.setdefault("parent", "/tmp")
    return value


class Endpoint:
    def __init__(self, spec, role):
        self.spec = spec
        self.role = role
        self.auto_local_root = None
        options = dict(spec["options"])
        if spec["driver"] == "local" and not options.get("root"):
            self.auto_local_root = tempfile.mkdtemp(prefix="abra-cross-provider-local-%s-" % role)
            options["root"] = self.auto_local_root
        self.driver = load(spec["driver"], options)
        self.owners = []
        self.runtime = json_output(self.driver.check(["python3", "-c", REMOTE_FACTS], timeout=30))

    def configure_runtime(self, fallback, override=None):
        binary = override or self.spec.get("inside_abra") or fallback
        binary = os.path.realpath(os.path.expanduser(str(binary)))
        if not os.path.isfile(binary):
            raise RuntimeError("remote Abra binary does not exist for %s: %s" % (self.label, binary))
        coordinator.configure_runtime(self.driver, binary)

    @property
    def label(self):
        return str(self.spec["label"])

    @property
    def parent(self):
        return str(self.spec["parent"])

    def make_owner(self):
        output = self.driver.check(
            ["python3", "-c", MAKE_TEMP, self.parent, "abra-cross-provider-%s-" % self.role], timeout=30
        )
        path = json_output(output)
        self.owners.append(path)
        return path

    def make_workspace(self, owner, prefix):
        return json_output(self.driver.check(["python3", "-c", MAKE_TEMP, owner, prefix], timeout=30))

    def cleanup(self, errors):
        for owner in reversed(self.owners):
            code, out, err = self.driver.exec(["python3", "-c", SAFE_REMOVE, owner, self.parent], timeout=120)
            if code != 0:
                errors.append("%s cleanup failed for %s: %s" % (self.label, owner, redact((err or out).decode("utf-8", "replace"))))
        try:
            self.driver.close()
        except Exception as error:
            errors.append("%s driver close failed: %s" % (self.label, redact(error)))
        if self.auto_local_root:
            shutil.rmtree(self.auto_local_root, ignore_errors=True)

    def public_facts(self):
        facts = dict(self.driver.facts())
        facts.pop("root", None)
        facts.update({"label": self.label, "runtime": self.runtime})
        return facts


class Runner:
    def __init__(self, args):
        self.args = args
        self.report_dir = Path(args.report_dir).resolve()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.report = {
            "schema": "dev.abra.cross-provider-portability-report.v1",
            "started_at": now(),
            "ok": False,
            "capture_mode": args.capture_mode,
            "checkpoint": 40,
            "completion": 100,
            "claims": {
                "continuation": "portable application state from committed files",
                "native_memory": False,
                "firecracker_native_comparison": False,
                "tool_calls": "synthetic deterministic tool calls; no external tool side effects are replayed",
            },
            "directions": [],
            "cleanup_errors": [],
        }
        self.endpoints = []

    def save(self):
        rendered = redact(json.dumps(self.report, indent=2, sort_keys=True)) + "\n"
        (self.report_dir / "report.json").write_text(rendered)

    def local_abra(self, root, *args, timeout=None):
        command = [str(self.args.abra), "--root", str(root), "--json"] + [str(arg) for arg in args]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout or self.args.phase_timeout)
        if completed.returncode != 0:
            raise RuntimeError("abra %s failed: %s" % (args[0], redact(completed.stderr.strip() or completed.stdout.strip())))
        return json.loads(completed.stdout)

    def start_local_root(self, root):
        completed = subprocess.run(
            [str(self.args.abra), "--root", str(root), "daemon", "--background", "--yes"],
            capture_output=True, text=True, timeout=self.args.phase_timeout,
        )
        if completed.returncode != 0:
            raise RuntimeError("abra daemon failed: %s" % redact(completed.stderr.strip() or completed.stdout.strip()))

    def stop_local_roots(self, roots, direction):
        for role, root in roots.items():
            log = Path(root) / "daemon.log"
            if log.is_file():
                target = self.report_dir / ("daemon-%s-%s.log" % (direction, role))
                target.write_text(redact(log.read_text(errors="replace")))
            subprocess.run(
                [str(self.args.abra), "--root", str(root), "stop"], capture_output=True,
                timeout=self.args.phase_timeout,
            )

    def command_json(self, endpoint, argv, timeout=None, cwd=None):
        return json_output(endpoint.driver.check(argv, timeout=timeout or self.args.phase_timeout, cwd=cwd))

    def fixture_command(self, remote_fixture, verb, workspace, number=None, hold=False):
        command = ["python3", remote_fixture, verb, "--workspace", workspace]
        if verb == "run":
            command += ["--until", str(number)]
            if hold:
                command.append("--hold")
        elif verb == "verify":
            command += ["--expected", str(number)]
        return command

    def wait_checkpoint(self, endpoint, remote_fixture, workspace, pid):
        deadline = time.monotonic() + self.args.phase_timeout
        last = None
        while time.monotonic() < deadline:
            code, out, _ = endpoint.driver.exec(
                self.fixture_command(remote_fixture, "status", workspace), timeout=30
            )
            if code == 0:
                last = json_output(out)
                if last["integrity_ok"] and last["completed"] == 40:
                    endpoint.driver.check(["kill", "-0", str(pid)], timeout=10)
                    return last
            time.sleep(1)
        raise RuntimeError("timed out waiting for held checkpoint 40; last status: %r" % last)

    def prepare_held(self, endpoint, owner, remote_fixture):
        workspace = endpoint.make_workspace(owner, "source-workspace-")
        command = self.fixture_command(remote_fixture, "run", workspace, 40, hold=True)
        code, out, err = endpoint.driver.exec(command, cwd=workspace, detach=True)
        if code != 0:
            raise RuntimeError("could not start held workload: %s" % redact((err or out).decode("utf-8", "replace")))
        pid = int(coordinator.last_line(out))
        status = self.wait_checkpoint(endpoint, remote_fixture, workspace, pid)
        verified = self.command_json(endpoint, self.fixture_command(remote_fixture, "verify", workspace, 40))
        return workspace, pid, command, status, verified

    def stop_held(self, endpoint, pid, workspace, remote_fixture):
        endpoint.driver.check(
            ["python3", "-c", SAFE_STOP, str(pid), workspace, remote_fixture], timeout=30
        )

    def disable_source(self, endpoint, owner, workspace):
        disabled = workspace + ".disabled"
        endpoint.driver.check(["python3", "-c", SAFE_RENAME, workspace, disabled, owner], timeout=30)
        code, _, _ = endpoint.driver.exec(["test", "!", "-e", workspace], timeout=10)
        if code != 0:
            raise RuntimeError("source workspace still exists after disabling it")
        return disabled

    def reference(self, endpoint, owner, remote_fixture):
        workspace = endpoint.make_workspace(owner, "reference-workspace-")
        started = time.monotonic()
        command = self.fixture_command(remote_fixture, "run", workspace, 100)
        status = self.command_json(endpoint, command, cwd=workspace)
        verified = self.command_json(endpoint, self.fixture_command(remote_fixture, "verify", workspace, 100))
        return {
            "command": command,
            "runtime_s": round(time.monotonic() - started, 3),
            "status": status,
            "verified": verified["integrity_ok"],
        }

    def inside_call(self, endpoint, binary, root, *args, timeout=None):
        return self.command_json(
            endpoint, [binary, "--root", root, "--json"] + [str(arg) for arg in args],
            timeout=timeout or self.args.phase_timeout,
        )

    def capture_inside(self, endpoint, owner, workspace, receiver_root, receiver_peer, capture):
        local_binary = self.args.inside_abra_override or endpoint.spec.get("inside_abra")
        if not local_binary:
            raise RuntimeError("inside capture needs inside_abra in the %s endpoint JSON" % endpoint.label)
        local_binary = os.path.realpath(os.path.expanduser(str(local_binary)))
        if not os.path.isfile(local_binary):
            raise RuntimeError("inside Abra binary does not exist: %s" % local_binary)
        selected_machine, binary_format = binary_machine(local_binary)
        endpoint_machine = canonical_machine(endpoint.runtime["machine"])
        if canonical_machine(selected_machine) != endpoint_machine:
            raise RuntimeError(
                "inside Abra binary architecture %s does not match %s endpoint architecture %s"
                % (selected_machine, endpoint.label, endpoint_machine)
            )

        inside_dir = endpoint.make_workspace(owner, "inside-abra-")
        binary = inside_dir + "/abra"
        root = inside_dir + "/root"
        endpoint.driver.put(local_binary, binary, 0o700)
        endpoint.driver.check([binary, "--version"], timeout=30)
        endpoint.driver.check([binary, "--root", root, "daemon", "--background", "--yes"], timeout=self.args.phase_timeout)
        capture["inside_binary"] = {
            "source": local_binary,
            "format": binary_format,
            "machine": selected_machine,
            "uploaded_to_owned_directory": True,
        }
        try:
            ticket_result = subprocess.run(
                [str(self.args.abra), "--root", str(receiver_root), "pair", "ticket"],
                capture_output=True, text=True, timeout=self.args.phase_timeout,
            )
            if ticket_result.returncode != 0:
                raise RuntimeError("could not create receiver pairing ticket: %s" % redact(ticket_result.stderr))
            self.inside_call(endpoint, binary, root, "pair", "add", ticket_result.stdout.strip())

            barrier = secrets.token_hex(6)
            endpoint.driver.check(
                [binary, "observe", "--workspace", workspace, "--once", "--barrier", barrier],
                timeout=self.args.phase_timeout,
            )
            host = endpoint.public_facts()
            host["native"] = None
            self.inside_call(endpoint, binary, root, "init", workspace)
            snapshot = self.inside_call(
                endpoint, binary, root, "snapshot", workspace,
                "--observation-barrier", barrier, "--observation-host", json.dumps(host, sort_keys=True),
            )
            capture.update({
                "snapshot_id": snapshot["snapshot_id"],
                "capsule_id": snapshot["capsule_id"],
                "observation_barrier": barrier,
                "membership": "workspace",
                "capture_location": "inside-source-endpoint",
            })
            endpoint.driver.exec(["rm", "-f", workspace + "/.abra/observed-" + barrier + ".json"], timeout=30)
            return binary, root
        except Exception:
            endpoint.driver.exec([binary, "--root", root, "stop"], timeout=30)
            raise

    def run_capture(self, mode, source, destination, source_owner, destination_owner,
                    source_fixture, destination_fixture, roots, receiver_peer, reference, direction_name):
        result = {
            "mode": mode,
            "phase_timings_s": {},
            "capture": {},
            "source_disabled": False,
            "integrity": {},
            "output_equivalence": {},
        }
        total = time.monotonic()
        held_pid = None
        inside_daemon = None
        workspace = None
        try:
            stage = time.monotonic()
            workspace, held_pid, start_command, checkpoint, verified = self.prepare_held(
                source, source_owner, source_fixture
            )
            result["start_command"] = start_command
            result["checkpoint_status"] = checkpoint
            result["integrity"]["checkpoint_40"] = verified["integrity_ok"]
            result["phase_timings_s"]["prepare_and_hold"] = round(time.monotonic() - stage, 3)

            stage = time.monotonic()
            name = "%s-%s-%s" % (direction_name, mode, secrets.token_hex(4))
            if mode == "outside":
                captured = coordinator.capture(
                    source.driver, name, workspace, coordinator.Abra(str(self.args.abra), str(roots["a"])),
                    membership="workspace",
                    remote_abra=source.spec.get("inside_abra") or self.args.inside_abra_override,
                )
                result["capture"] = {
                    "snapshot_id": captured["snapshot_id"],
                    "capsule_id": captured["capsule_id"],
                    "observation_barrier": captured["observation_barrier"],
                    "membership": "workspace",
                    "capture_location": "outside-coordinator",
                    "collection_errors": captured["collection_errors"],
                }
            else:
                inside_daemon = self.capture_inside(
                    source, source_owner, workspace, roots["b"], receiver_peer, result["capture"]
                )
            result["phase_timings_s"]["capture"] = round(time.monotonic() - stage, 3)

            post_capture = self.command_json(source, self.fixture_command(source_fixture, "verify", workspace, 40))
            result["integrity"]["after_capture_40"] = post_capture["integrity_ok"]

            stage = time.monotonic()
            self.stop_held(source, held_pid, workspace, source_fixture)
            held_pid = None
            disabled = self.disable_source(source, source_owner, workspace)
            result["source_disabled"] = True
            result["source_disabled_path"] = disabled
            result["phase_timings_s"]["stop_and_disable_source"] = round(time.monotonic() - stage, 3)

            stage = time.monotonic()
            if mode == "outside":
                sent = self.local_abra(
                    roots["a"], "send", receiver_peer, "--snapshot", result["capture"]["snapshot_id"],
                    "--wait", "--timeout", "%ds" % self.args.transfer_timeout,
                    timeout=self.args.transfer_timeout + 30,
                )
            else:
                binary, inside_root = inside_daemon
                sent = self.inside_call(
                    source, binary, inside_root, "send", receiver_peer,
                    "--snapshot", result["capture"]["snapshot_id"], "--wait",
                    "--timeout", "%ds" % self.args.transfer_timeout,
                    timeout=self.args.transfer_timeout + 30,
                )
                source.driver.check([binary, "--root", inside_root, "stop"], timeout=30)
                inside_daemon = None
            state = sent.get("entry", {}).get("state")
            if state != "acked":
                raise RuntimeError("snapshot send was not acknowledged: %r" % state)
            result["transfer"] = {"acked": True, "state": state}
            result["phase_timings_s"]["transfer"] = round(time.monotonic() - stage, 3)

            stage = time.monotonic()
            destination_workspace = destination.make_workspace(destination_owner, "restored-workspace-")
            restored = coordinator.restore(
                destination.driver, name, result["capture"]["snapshot_id"], destination_workspace,
                coordinator.Abra(str(self.args.abra), str(roots["b"])),
                remote_abra=destination.spec.get("inside_abra") or self.args.inside_abra_override,
            )
            result["restore"] = {
                "mode": restored["mode"],
                "remote_workspace": destination_workspace,
                "started": restored["started"],
                "portable_available": restored["restore_plan"]["portable"]["available"],
            }
            restored_40 = self.command_json(
                destination, self.fixture_command(destination_fixture, "verify", destination_workspace, 40)
            )
            result["integrity"]["restored_40"] = restored_40["integrity_ok"]
            result["phase_timings_s"]["restore_and_verify"] = round(time.monotonic() - stage, 3)

            stage = time.monotonic()
            resume_command = self.fixture_command(destination_fixture, "run", destination_workspace, 100)
            final_status = self.command_json(destination, resume_command, cwd=destination_workspace)
            final_verified = self.command_json(
                destination, self.fixture_command(destination_fixture, "verify", destination_workspace, 100)
            )
            result["resume_command"] = resume_command
            result["final_status"] = final_status
            result["integrity"]["final_100"] = final_verified["integrity_ok"]
            fields = ("digest", "task_ids", "tool_call_count")
            result["output_equivalence"] = {
                field: final_status[field] == reference["status"][field] for field in fields
            }
            result["output_equivalence"]["all"] = all(result["output_equivalence"].values())
            if not result["output_equivalence"]["all"]:
                raise AssertionError("resumed output differs from uninterrupted reference")
            result["phase_timings_s"]["resume_and_verify"] = round(time.monotonic() - stage, 3)
            result["phase_timings_s"]["total"] = round(time.monotonic() - total, 3)
            return result
        finally:
            if held_pid is not None and workspace is not None:
                try:
                    self.stop_held(source, held_pid, workspace, source_fixture)
                except Exception as error:
                    self.report["cleanup_errors"].append("held workload cleanup failed: %s" % redact(error))
            if inside_daemon is not None:
                binary, inside_root = inside_daemon
                code, out, err = source.driver.exec([binary, "--root", inside_root, "stop"], timeout=30)
                if code != 0:
                    self.report["cleanup_errors"].append(
                        "inside daemon cleanup failed: %s" % redact((err or out).decode("utf-8", "replace"))
                    )

    def run_direction(self, source, destination):
        direction_name = "%s-to-%s" % (source.role, destination.role)
        direction = {
            "name": direction_name,
            "source": source.public_facts(),
            "destination": destination.public_facts(),
            "cross_cpu": canonical_machine(source.runtime["machine"]) != canonical_machine(destination.runtime["machine"]),
            "captures": {},
        }
        self.report["directions"].append(direction)
        self.save()
        source_owner = source.make_owner()
        destination_owner = destination.make_owner()
        source_fixture = source_owner + "/checkpoint_workload.py"
        destination_fixture = destination_owner + "/checkpoint_workload.py"
        source.driver.put(str(FIXTURE), source_fixture, 0o700)
        destination.driver.put(str(FIXTURE), destination_fixture, 0o700)

        roots_base = Path(tempfile.mkdtemp(prefix="abra-cross-provider-roots-"))
        roots = {"a": roots_base / "a", "b": roots_base / "b"}
        for root in roots.values():
            root.mkdir(mode=0o700)
        try:
            for root in roots.values():
                self.start_local_root(root)
            receiver_peer = self.local_abra(roots["b"], "status")["peer_id"]
            if self.args.capture_mode in ("outside", "both"):
                ticket_result = subprocess.run(
                    [str(self.args.abra), "--root", str(roots["b"]), "pair", "ticket"],
                    check=True, capture_output=True, text=True, timeout=self.args.phase_timeout,
                )
                self.local_abra(roots["a"], "pair", "add", ticket_result.stdout.strip())

            direction["reference"] = self.reference(source, source_owner, source_fixture)
            modes = ("outside", "inside") if self.args.capture_mode == "both" else (self.args.capture_mode,)
            for mode in modes:
                direction["captures"][mode] = self.run_capture(
                    mode, source, destination, source_owner, destination_owner,
                    source_fixture, destination_fixture, roots, receiver_peer,
                    direction["reference"], direction_name,
                )
                self.save()
            if self.args.capture_mode == "both":
                outside = direction["captures"]["outside"]["final_status"]
                inside = direction["captures"]["inside"]["final_status"]
                fields = ("digest", "task_ids", "tool_call_count")
                direction["inside_outside_semantic_equality"] = {
                    field: outside[field] == inside[field] for field in fields
                }
                direction["inside_outside_semantic_equality"]["all"] = all(
                    direction["inside_outside_semantic_equality"].values()
                )
                if not direction["inside_outside_semantic_equality"]["all"]:
                    raise AssertionError("inside and outside continuation results differ")
        finally:
            self.stop_local_roots(roots, direction_name)
            shutil.rmtree(roots_base, ignore_errors=True)

    def run(self):
        left = Endpoint(load_endpoint(self.args.left), "left")
        self.endpoints.append(left)
        right = Endpoint(load_endpoint(self.args.right), "right")
        self.endpoints.append(right)
        try:
            for endpoint in self.endpoints:
                endpoint.configure_runtime(self.args.abra, self.args.inside_abra_override)
            self.report["endpoints"] = {"left": left.public_facts(), "right": right.public_facts()}
            self.run_direction(left, right)
            self.run_direction(right, left)
            if self.report["cleanup_errors"]:
                raise RuntimeError("cleanup failed: " + "; ".join(self.report["cleanup_errors"]))
            self.report["ok"] = True
        finally:
            for endpoint in reversed(self.endpoints):
                endpoint.cleanup(self.report["cleanup_errors"])
            if self.report["cleanup_errors"]:
                self.report["ok"] = False
            self.report["finished_at"] = now()
            self.save()


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", required=True, help="left endpoint JSON file")
    parser.add_argument("--right", required=True, help="right endpoint JSON file")
    parser.add_argument("--abra", default=coordinator.default_abra(), help="local coordinator abra binary")
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--capture-mode", choices=("outside", "inside", "both"), default="outside")
    parser.add_argument("--inside-abra", dest="inside_abra_override", help="local native abra binary for both endpoints")
    parser.add_argument("--phase-timeout", type=int, default=300)
    parser.add_argument("--transfer-timeout", type=int, default=300)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.phase_timeout <= 0 or args.transfer_timeout <= 0:
        raise SystemExit("timeouts must be positive")
    args.abra = os.path.realpath(os.path.expanduser(args.abra))
    if not os.path.isfile(args.abra):
        raise SystemExit("abra binary does not exist: %s" % args.abra)
    runner = Runner(args)
    try:
        runner.run()
    except Exception as error:
        runner.report["error"] = redact(error)
        runner.report["ok"] = False
        runner.report["finished_at"] = now()
        runner.save()
        print("cross-provider e2e failed: %s" % redact(error), file=sys.stderr)
        return 1
    print(json.dumps(runner.report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
