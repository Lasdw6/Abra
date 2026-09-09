"""Capture -> send -> accept -> restore through the local driver, a stub collector,
the real abra binary and two real background daemons in temp roots."""

import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

PACKAGE = pathlib.Path(__file__).resolve().parents[1]
REPO = PACKAGE.parents[1]
sys.path.insert(0, str(PACKAGE))

from abra_sandbox import coordinator  # noqa: E402
from abra_sandbox.drivers.local import LocalDriver  # noqa: E402

ABRA = os.environ.get("ABRA_BIN") or str(REPO / "target/release/abra")
OBSERVER = PACKAGE / "collector/observer.py"

# Same command line as the real collector, but the process facts come from a
# fake /proc holding one http.server process, built with the collector's own
# functions. macOS has no /proc, so this is what the test can run.
STUB = '''#!/usr/bin/env python3
import importlib.util, os, pathlib, sys, tempfile
spec = importlib.util.spec_from_file_location("abra_observer", %(observer)r)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
parser = observer.create_parser()
args = parser.parse_args()
assert args.all and args.once and args.barrier, sys.argv
with tempfile.TemporaryDirectory() as temp:
    proc = pathlib.Path(temp)
    (proc / "net").mkdir(); (proc / "self/ns").mkdir(parents=True)
    (proc / "self/ns/net").symlink_to("net:[1]")
    (proc / "uptime").write_text("100.0 0.0\\n")
    (proc / "meminfo").write_text("MemTotal:        524288 kB\\n")
    (proc / "self/mountinfo").write_text("")
    header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\\n"
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (proc / "net" / name).write_text(header)
    (proc / "net/tcp").open("a").write("0: 00000000:%%04X 00000000:0000 0A 0 0 0 0 0 300\\n" %% %(port)d)
    base = proc / "77"
    (base / "fd").mkdir(parents=True); (base / "ns").mkdir()
    (base / "ns/net").symlink_to("net:[1]")
    (base / "fd/0").symlink_to("socket:[300]")
    (base / "cmdline").write_bytes(b"python3\\x00-m\\x00http.server\\x00%(port)d\\x00")
    (base / "environ").write_bytes(b"NODE_ENV=test\\x00")
    (base / "stat").write_text("77 (python3) S 1 " + " ".join(["0"] * 17) + " 770\\n")
    (base / "status").write_text("Uid:\\t%%d\\t0\\t0\\t0\\n" %% os.getuid())
    os.symlink(args.workspace, base / "cwd"); os.symlink("/usr/bin/python3", base / "exe")
    args.proc = str(proc)
    ledger = observer.cycle(args, {})
print(observer.json.dumps({"filename": observer.capture_filename(args.barrier), "barrier": args.barrier,
                           "processes": len(ledger["processes"]), "recipes": len(ledger["recipes"])}))
'''


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def listening(port):
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


def wait_for(description, check, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise AssertionError("timed out: " + description)


@unittest.skipUnless(os.path.exists(ABRA), "build abra first: cargo build --release -p abra-cli")
class CoordinatorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.mkdtemp(prefix="abra-sandbox-test-")
        cls.roots = {}
        cls.pids = []
        for name in ("a", "b"):
            root = os.path.join(cls.temp, "root-" + name)
            os.makedirs(root, mode=0o700)
            cls.roots[name] = root
            subprocess.run([ABRA, "--root", root, "daemon", "--background", "--yes"], check=True, capture_output=True)
        cls.abra_a = coordinator.Abra(ABRA, cls.roots["a"])
        cls.abra_b = coordinator.Abra(ABRA, cls.roots["b"])
        ticket = subprocess.run([ABRA, "--root", cls.roots["b"], "pair", "ticket"], check=True, capture_output=True, text=True).stdout.strip()
        cls.abra_a.call("pair", "add", ticket)
        cls.peer_b = cls.abra_b.call("status")["peer_id"]
        cls.port = free_port()
        cls.stub = os.path.join(cls.temp, "stub_collector.py")
        with open(cls.stub, "w") as handle:
            handle.write(STUB % {"observer": str(OBSERVER), "port": cls.port})

    @classmethod
    def tearDownClass(cls):
        for pid in cls.pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        for root in cls.roots.values():
            subprocess.run([ABRA, "--root", root, "stop"], capture_output=True)
        shutil.rmtree(cls.temp, ignore_errors=True)

    def sandbox(self, name):
        root = os.path.join(self.temp, "sandbox-" + name)
        os.makedirs(os.path.join(root, "workspace"))
        driver = LocalDriver(root=root)
        self.addCleanup(driver.close)
        return driver, os.path.join(root, "workspace")

    def assert_no_transient_files(self, driver):
        entries = os.listdir(driver.tmp_dir())
        self.assertEqual(1, len(entries))
        self.assertTrue(entries[0].startswith("abra-runner-"))
        self.assertEqual(["abra"], os.listdir(os.path.join(driver.tmp_dir(), entries[0])))

    def test_capture_send_accept_restore(self):
        driver_a, workspace_a = self.sandbox("a")
        with open(os.path.join(workspace_a, "marker.txt"), "w") as handle:
            handle.write("hello from sandbox a\n")
        os.makedirs(os.path.join(workspace_a, "nested"))
        with open(os.path.join(workspace_a, "nested", "file.bin"), "wb") as handle:
            handle.write(bytes(range(256)))

        captured = coordinator.capture(driver_a, "demo", workspace_a, self.abra_a, "all", collector=self.stub)
        self.assertEqual(12, len(captured["observation_barrier"]))
        self.assertEqual(1, captured["service_candidates"])
        self.assertEqual([self.port], captured["recipes"][0]["ports"])
        self.assertEqual(["python3", "-m", "http.server", str(self.port)], captured["recipes"][0]["argv"])
        self.assertIsNone(captured["browser"])
        self.assertIsNone(captured["native"])
        mirror = captured["mirror"]
        self.assertEqual(os.path.join(self.roots["a"], "sandboxes", "demo", "workspace"), mirror)
        with open(os.path.join(mirror, "nested", "file.bin"), "rb") as handle:
            self.assertEqual(bytes(range(256)), handle.read())
        self.assertTrue(os.path.isfile(os.path.join(mirror, ".abra", "capsule_id")))
        self.assertFalse(os.path.exists(os.path.join(mirror, ".abra", "observed-%s.json" % captured["observation_barrier"])))
        self.assertFalse(os.path.exists(os.path.join(workspace_a, ".abra", "observed-%s.json" % captured["observation_barrier"])))
        self.assert_no_transient_files(driver_a)
        manifest_path = os.path.join(self.roots["a"], "capsules", captured["capsule_id"], "snapshots", captured["snapshot_id"] + ".cjson")
        with open(manifest_path) as handle:
            manifest = json.load(handle)
        observed = manifest["extensions"]["dev.abra.observed"]
        self.assertEqual(captured["observation_barrier"], observed["observer"]["barrier"])
        self.assertEqual("all", observed["coverage"]["scope"])
        self.assertEqual({"provider": "local", "root": driver_a.root, "native": None}, observed["host"]["facts"])
        self.assertEqual(captured["recipes"], manifest["recipes"])

        # A second capture replaces mirror files that vanished remotely and keeps .abra.
        os.unlink(os.path.join(workspace_a, "nested", "file.bin"))
        second = coordinator.capture(driver_a, "demo", workspace_a, self.abra_a, "all", collector=self.stub)
        self.assertEqual(captured["capsule_id"], second["capsule_id"])
        self.assertNotEqual(captured["snapshot_id"], second["snapshot_id"])
        self.assertFalse(os.path.exists(os.path.join(mirror, "nested", "file.bin")))

        sent = self.abra_a.call("send", self.peer_b, "--snapshot", second["snapshot_id"], "--wait", "--timeout", "60s")
        self.assertEqual("acked", sent["entry"]["state"])

        driver_b, workspace_b = self.sandbox("b")
        restored = coordinator.restore(driver_b, "demo", second["snapshot_id"], workspace_b, self.abra_b)
        self.assertEqual("portable", restored["mode"])
        self.assertTrue(restored["restore_plan"]["portable"]["available"])
        self.assertEqual([], restored["started"])
        self.assertIsNone(restored["browser"])
        self.assertEqual(1, len(restored["candidates"]))
        self.assertEqual(0, restored["candidates"][0]["index"])
        self.assertEqual("unverified", restored["candidates"][0]["restartability"])
        with open(os.path.join(workspace_b, "marker.txt")) as handle:
            self.assertEqual("hello from sandbox a\n", handle.read())
        self.assertTrue(os.path.isfile(os.path.join(workspace_b, ".abra", "recipes.json")))
        self.assertTrue(os.path.isfile(os.path.join(workspace_b, ".abra", "received-observed.json")))
        self.assertFalse(os.path.exists(os.path.join(workspace_b, ".abra", "capsule_id")))
        self.assertFalse(os.path.exists(os.path.join(workspace_b, ".abra", "snapshot_id")))
        self.assertFalse(listening(self.port), "restore without --start must not run anything")
        self.assert_no_transient_files(driver_b)

        with open(os.path.join(workspace_b, "stale.txt"), "w") as handle:
            handle.write("not in the snapshot")
        with self.assertRaisesRegex(RuntimeError, "--replace-workspace"):
            coordinator.restore(driver_b, "demo", second["snapshot_id"], workspace_b, self.abra_b)
        started = coordinator.restore(driver_b, "demo", second["snapshot_id"], workspace_b, self.abra_b,
                                      start=[0], replace_workspace=True)
        self.assertFalse(os.path.exists(os.path.join(workspace_b, "stale.txt")))
        self.assertEqual(1, len(started["started"]))
        pid = started["started"][0]["pid"]
        self.pids.append(pid)
        self.assertEqual(workspace_b, started["started"][0]["cwd"])
        wait_for("http.server on the restored workspace", lambda: listening(self.port))
        with urllib.request.urlopen("http://127.0.0.1:%d/marker.txt" % self.port, timeout=5) as response:
            self.assertEqual(b"hello from sandbox a\n", response.read())
        os.kill(pid, signal.SIGTERM)

        # The capturing root can restore into a fresh sandbox too (mirror exists, so --replace).
        driver_c, workspace_c = self.sandbox("c")
        again = coordinator.restore(driver_c, "demo", captured["snapshot_id"], workspace_c, self.abra_a)
        self.assertEqual([], again["started"])
        self.assertTrue(os.path.isfile(os.path.join(workspace_c, "nested", "file.bin")))
        self.assertTrue(os.path.isfile(os.path.join(mirror, "nested", "file.bin")))

    def test_blocked_candidate_is_refused(self):
        driver = LocalDriver(root=os.path.join(self.temp, "sandbox-blocked"))
        candidate = {"recipe": {"argv": ["db"], "cwd": None}, "restartability": "blocked",
                     "missing_requirements": ["working_directory_outside_workspace"]}
        with self.assertRaises(RuntimeError):
            coordinator.start_candidate(driver, "/workspace", 0, candidate)

    def test_cli_rejects_bad_driver_option(self):
        completed = subprocess.run([sys.executable, "-m", "abra_sandbox", "capture", "--driver", "local", "--name", "x", "--driver-opt", "novalue"],
                                   cwd=str(PACKAGE), capture_output=True, text=True)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("key=value", completed.stderr)


if __name__ == "__main__":
    unittest.main()
