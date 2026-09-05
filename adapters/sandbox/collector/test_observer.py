import argparse
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).with_name("observer.py")
SPEC = importlib.util.spec_from_file_location("abra_observer", PATH)
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


class ObserverTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.proc = self.root / "proc"
        self.runtime = self.root / "bin"
        self.workspace.mkdir()
        self.proc.mkdir()
        self.runtime.mkdir()
        (self.proc / "net").mkdir()
        (self.proc / "self").mkdir()
        (self.proc / "self/ns").mkdir()
        (self.proc / "self/ns/net").symlink_to("net:[1]")
        (self.proc / "uptime").write_text("100.0 0.0\n")
        (self.proc / "meminfo").write_text("MemTotal:        524288 kB\n")
        (self.proc / "self" / "mountinfo").write_text("")
        header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        for name in ("tcp", "tcp6", "udp", "udp6"):
            (self.proc / "net" / name).write_text(header)

    def tearDown(self):
        self.temp.cleanup()

    def add_process(self, pid, ppid, argv, ports=(), env=None, cwd=None):
        base = self.proc / str(pid)
        (base / "fd").mkdir(parents=True)
        (base / "ns").mkdir()
        (base / "ns/net").symlink_to("net:[1]")
        (base / "cmdline").write_bytes(b"\0".join(x.encode() for x in argv) + b"\0")
        (base / "environ").write_bytes(b"\0".join((k + "=" + v).encode() for k, v in (env or {}).items()) + b"\0")
        fields = ["S", str(ppid)] + ["0"] * 17 + [str(pid * 10)]
        (base / "stat").write_text("%d (process %d) %s\n" % (pid, pid, " ".join(fields)))
        (base / "status").write_text("Uid:\t%d\t%d\t%d\t%d\n" % ((os.getuid(),) * 4))
        os.symlink(str(cwd or self.workspace), base / "cwd")
        os.symlink("/usr/bin/" + pathlib.Path(argv[0]).name, base / "exe")
        for index, (proto, port, inode) in enumerate(ports):
            os.symlink("socket:[%s]" % inode, base / "fd" / str(index))
            table = self.proc / "net" / proto
            with table.open("a") as handle:
                state = "0A" if proto.startswith("tcp") else "07"
                handle.write("0: 00000000:%04X 00000000:0000 %s 0 0 0 0 0 %s\n" % (port, state, inode))

    def args(self, **changes):
        values = dict(workspace=str(self.workspace), proc=str(self.proc), once=True, barrier=None, interval=2.0)
        values.update(changes)
        return argparse.Namespace(**values)

    def capture(self):
        return observer.capture(self.args(), {})

    def test_wrapper_collapse_and_udp(self):
        self.add_process(10, 1, ["npm", "run", "dev"])
        self.add_process(11, 10, ["sh", "-c", "node server.js"])
        self.add_process(12, 11, ["node", "server.js"], [("tcp", 5173, "100"), ("udp", 5353, "101")])
        ledger = self.capture()
        self.assertEqual([{"argv": ["npm", "run", "dev"], "cwd": ".", "ports": [5173], "started_at": ledger["recipes"][0]["started_at"]}], ledger["recipes"])
        self.assertEqual({("tcp", 5173), ("udp", 5353)}, {(x["proto"], x["port"]) for x in ledger["processes"][0]["ports"]})

    def test_codex_and_bash_are_separate_roots(self):
        self.add_process(20, 1, ["codex"])
        self.add_process(21, 20, ["bash", "-c", "npm run dev"])
        self.add_process(22, 21, ["npm", "run", "dev"], [("tcp", 8123, "200")])
        recipes = self.capture()["recipes"]
        self.assertEqual([["bash", "-c", "npm run dev"], ["codex"]], [x["argv"] for x in recipes])
        self.assertEqual([8123], recipes[0]["ports"])
        self.assertNotIn("ports", recipes[1])

    def test_interactive_shell_is_not_recipe(self):
        self.add_process(30, 1, ["bash"])
        ledger = self.capture()
        self.assertEqual(1, len(ledger["processes"]))
        self.assertEqual([], ledger["recipes"])

    def test_redaction_and_environment_rules(self):
        argv = ["server", "--token=abc", "-password", "next", "API_KEY=value", "Authorization: Bearer abc", "Basic xyz", "ghp_123"]
        env = {"NODE_ENV": "Bearer envsecret", "ABRA_RECIPE_SAFE": "sk-live", "ABRA_RECIPE_TOKEN": "drop", "OTHER": "drop"}
        self.add_process(40, 1, argv, env=env)
        row = self.capture()["processes"][0]
        self.assertEqual(["server", "--token=<redacted>", "-password", "<redacted>", "API_KEY=<redacted>", "Authorization: Bearer <redacted>", "Basic <redacted>", "<redacted>"], row["argv"])
        self.assertEqual({"ABRA_RECIPE_SAFE": "<redacted>", "NODE_ENV": "Bearer <redacted>"}, row["env"])
        self.assertTrue(row["redacted"])

    def test_long_argv_is_truncated_and_not_recipe(self):
        self.add_process(50, 1, ["server"] + [str(x) for x in range(256)])
        ledger = self.capture()
        self.assertTrue(ledger["processes"][0]["truncated"])
        self.assertEqual([], ledger["recipes"])

    def test_secure_output_preserves_recipes_file(self):
        metadata = self.workspace / ".abra"
        metadata.mkdir()
        recipes = metadata / "recipes.json"
        recipes.write_bytes(b"keep me")
        observer.write_ledger(str(self.workspace), {"ok": True}, True)
        output = metadata / "observed.json"
        self.assertEqual(0o700, stat.S_IMODE(metadata.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
        self.assertEqual(b"keep me", recipes.read_bytes())
        self.assertEqual([], list(metadata.glob(".observed.json.*.tmp")))

    def test_symlinked_metadata_is_refused(self):
        target = self.root / "target"
        target.mkdir()
        os.symlink(target, self.workspace / ".abra")
        with self.assertRaises(OSError):
            observer.write_ledger(str(self.workspace), {"ok": True})
        self.assertFalse((target / "observed.json").exists())

    def test_once_barrier_and_runtime(self):
        node = self.runtime / "node"
        node.write_text("#!/bin/sh\necho v99.1.0\n")
        node.chmod(0o755)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = observer.main(["--workspace", str(self.workspace), "--proc", str(self.proc), "--runtime-dirs", str(self.runtime), "--once", "--barrier", "X"])
        self.assertEqual(0, code)
        summary = json.loads(stdout.getvalue())
        ledger = json.loads((self.workspace / ".abra" / "observed-X.json").read_text())
        self.assertEqual("X", summary["barrier"])
        self.assertEqual("X", ledger["observer"]["barrier"])
        self.assertEqual("v99.1.0", ledger["runtimes"]["node"])

    def test_size_cap_drops_processes(self):
        rows = [{"pid": x, "ppid": 0, "argv": ["bash", "x" * 3000], "cwd": ".", "state": "S"} for x in range(200)]
        with mock.patch.object(observer, "scan_processes", return_value=rows), mock.patch.object(observer, "platform_info", return_value={}), mock.patch.object(observer, "resource_info", return_value={}):
            ledger = observer.capture(self.args(), {})
        self.assertLessEqual(len(json.dumps(ledger, separators=(",", ":"), sort_keys=True).encode()), 256 * 1024)
        self.assertGreater(ledger["limits"]["processes_dropped"], 0)

    def test_capture_is_immutable_and_periodic_cannot_replace_it(self):
        captured = observer.cycle(self.args(barrier="checkpoint"), {})
        filename = self.workspace / ".abra/observed-checkpoint.json"
        original = filename.read_bytes()
        observer.cycle(self.args(once=False), {})
        self.assertEqual(original, filename.read_bytes())
        self.assertEqual("checkpoint", captured["observer"]["barrier"])
        self.assertNotIn("barrier", json.loads((self.workspace / ".abra/observed.json").read_text())["observer"])
        with self.assertRaises(FileExistsError):
            observer.cycle(self.args(barrier="checkpoint"), {})
        self.assertEqual(original, filename.read_bytes())
        self.assertEqual([], list(filename.parent.glob("*.tmp")))

    def test_barrier_rejects_paths_and_existing_symlinks(self):
        for value in ("../outside", "", "é", "a" * 65, "bad/name"):
            with self.assertRaises(ValueError):
                observer.write_ledger(str(self.workspace), {}, True, value)
        metadata = self.workspace / ".abra"
        metadata.mkdir()
        target = self.root / "outside"
        target.write_text("unchanged")
        (metadata / "observed-X.json").symlink_to(target)
        with self.assertRaises(FileExistsError):
            observer.write_ledger(str(self.workspace), {}, True, "X")
        self.assertEqual("unchanged", target.read_text())

    def test_shell_and_url_secrets_never_reach_ledger(self):
        commands = [
            ["sh", "-c", "server --token actualsecret"],
            ["bash", "-lc", "export TOKEN=actualsecret; server"],
            ["curl", "https://user:actualsecret@example.test/path"],
            ["curl", "https://example.test/?api_key=actualsecret"],
            ["node", "--eval", "const x = 'actualsecret'"],
        ]
        for index, argv in enumerate(commands):
            self.add_process(100 + index, 1, argv)
        ledger = self.capture()
        self.assertNotIn("actualsecret", json.dumps(ledger))
        self.assertEqual([], ledger["recipes"])
        self.assertTrue(all(c["restartability"] == "blocked" for c in ledger["service_candidates"]))

    def test_redacted_environment_names_are_requirements(self):
        self.add_process(90, 1, ["server"], env={"DATABASE_PASSWORD": "actualsecret", "NODE_ENV": "development"})
        ledger = self.capture()
        self.assertNotIn("actualsecret", json.dumps(ledger))
        self.assertIn("DATABASE_PASSWORD", ledger["processes"][0]["missing_environment"])
        self.assertIn("environment:DATABASE_PASSWORD", ledger["service_candidates"][0]["missing_requirements"])
        self.assertEqual([], ledger["recipes"])

    def test_workers_are_grouped_and_service_is_unverified(self):
        self.add_process(90, 1, ["node", "server.js"])
        self.add_process(91, 90, ["node", "worker.js"], [("tcp", 8123, "90")])
        ledger = self.capture()
        self.assertEqual(2, len(ledger["processes"]))
        self.assertEqual(1, len(ledger["recipes"]))
        candidate = ledger["service_candidates"][0]
        self.assertEqual([90, 91], candidate["source_pids"])
        self.assertEqual("unverified", candidate["restartability"])
        self.assertTrue(candidate["requires_adapter_confirmation"])
        self.assertEqual([8123], candidate["recipe"]["ports"])

    def test_descendant_outside_workspace_is_preserved_and_blocked(self):
        self.add_process(90, 1, ["node", "server.js"])
        self.add_process(91, 90, ["node", "worker.js"], cwd=self.root)
        ledger = self.capture()
        worker = next(row for row in ledger["processes"] if row["pid"] == 91)
        self.assertEqual("descendant", worker["membership"])
        self.assertIsNone(worker["cwd"])
        self.assertEqual([], ledger["recipes"])

    def test_cgroup_membership_includes_service_outside_workspace(self):
        self.add_process(90, 1, ["database"], cwd=self.root)
        self.add_process(91, 1, ["unrelated"])
        (self.proc / "90/cgroup").write_text("0::/sandbox/db\n")
        (self.proc / "91/cgroup").write_text("0::/sandbox-other\n")
        ledger = observer.capture(self.args(cgroup="/sandbox"), {})
        self.assertEqual([90], [row["pid"] for row in ledger["processes"]])
        self.assertEqual("cgroup", ledger["coverage"]["scope"])

    def test_all_membership_selects_every_process_except_the_collector(self):
        self.add_process(90, 1, ["database"], cwd=self.root)
        self.add_process(91, 1, ["python3", "-m", "http.server", "8123"], [("tcp", 8123, "300")])
        self.add_process(os.getpid(), 1, ["observer"])
        ledger = observer.capture(self.args(all=True), {})
        self.assertEqual([91, 90], [row["pid"] for row in ledger["processes"]])
        self.assertEqual({"all"}, {row["membership"] for row in ledger["processes"]})
        self.assertEqual("all", ledger["coverage"]["scope"])
        self.assertEqual([[8123]], [recipe["ports"] for recipe in ledger["recipes"]])
        parser = observer.create_parser()
        self.assertTrue(parser.parse_args(["--all"]).all)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["--all", "--cgroup", "/sandbox"])

    def test_init_outside_workspace_is_a_boundary_not_a_service_root(self):
        self.add_process(1, 0, ["sleep", "infinity"], [("tcp", 2280, "400")], cwd=self.root)
        self.add_process(91, 1, ["python3", "-m", "http.server", "8123"], [("tcp", 8123, "300")])
        self.add_process(92, 91, ["python3", "-m", "http.server", "8123"])
        ledger = observer.capture(self.args(all=True), {})
        by_root = {c["root_pid"]: c for c in ledger["service_candidates"]}
        self.assertEqual({1, 91}, set(by_root))
        self.assertEqual([91, 92], by_root[91]["source_pids"])
        self.assertEqual("unverified", by_root[91]["restartability"])
        self.assertEqual("blocked", by_root[1]["restartability"])
        self.assertEqual([[8123]], [recipe["ports"] for recipe in ledger["recipes"]])

    def test_process_group_membership(self):
        self.add_process(90, 1, ["database"], cwd=self.root)
        self.add_process(91, 1, ["unrelated"])
        path = self.proc / "90/stat"
        fields = path.read_text().rsplit(")", 1)
        tail = fields[1].split()
        tail[2] = "42"
        path.write_text(fields[0] + ") " + " ".join(tail))
        ledger = observer.capture(self.args(process_group=42), {})
        self.assertEqual([90], [row["pid"] for row in ledger["processes"]])

    def test_collection_failure_differs_from_empty_workspace(self):
        with mock.patch.object(observer.os, "listdir", side_effect=PermissionError()):
            ledger = self.capture()
        self.assertEqual([], ledger["processes"])
        self.assertIn({"collector": "processes", "code": "permission_denied", "count": 1}, ledger["collection_errors"])
        self.assertFalse(ledger["coverage"]["complete"])
        self.assertEqual("dev.abra.observed/3", ledger["schema"])
        self.assertLessEqual(ledger["observer"]["capture_started_at"], ledger["observer"]["capture_finished_at"])

    def test_effective_limits_include_parent_cgroup(self):
        root = self.root / "cgroup"
        child = root / "sandbox/child"
        child.mkdir(parents=True)
        for directory, memory, cpu in [(root, "max", "max 100000"), (root / "sandbox", "104857600", "50000 100000"), (child, "209715200", "200000 100000")]:
            (directory / "memory.max").write_text(memory)
            (directory / "cpu.max").write_text(cpu)
            (directory / "cpuset.cpus.effective").write_text("0-3")
        result = observer.resource_info(str(self.proc), "/sandbox/child", str(root), [])
        self.assertEqual(104857600, result["effective_memory_bytes"])
        self.assertEqual(500, result["effective_cpu_millicores"])

    def test_external_files_and_mounts_are_explicitly_not_captured(self):
        self.add_process(90, 1, ["server"])
        (self.proc / "90/fd/5").symlink_to("/var/lib/database/data.db")
        (self.proc / "self/mountinfo").write_text("1 0 8:1 / /var/lib/database rw - ext4 /dev/vdb rw\n")
        ledger = self.capture()
        self.assertEqual(["/var/lib/database/data.db"], ledger["processes"][0]["external_open_files"])
        self.assertEqual("not-captured", ledger["mounts"][0]["capture"])
        self.assertTrue(ledger["mounts"][0]["mutable"])

    def test_namespace_mismatch_does_not_assign_foreign_ports(self):
        self.add_process(90, 1, ["server"], [("tcp", 8123, "90")])
        (self.proc / "90/ns/net").unlink()
        (self.proc / "90/ns/net").symlink_to("net:[2]")
        ledger = self.capture()
        self.assertNotIn("ports", ledger["processes"][0])
        self.assertTrue(any(e["code"] == "unsupported_namespace" for e in ledger["collection_errors"]))

    def test_cached_environment_preserves_its_own_freshness(self):
        environment = {"platform": {"arch": "test"}, "runtimes": {"node": "v22"},
                       "observed_at": "2020-01-01T00:00:00.000Z", "collection_errors": []}
        with mock.patch.object(observer, "probe_runtimes", side_effect=AssertionError("must use cache")):
            ledger = observer.capture(self.args(), {}, environment)
        self.assertEqual(environment["observed_at"], ledger["observer"]["environment_observed_at"])
        self.assertEqual({"node": "v22"}, ledger["runtimes"])

    def test_ledger_numbers_fit_abra_integer_profile(self):
        ledger = observer.capture(self.args(once=False, interval=0.25, environment_interval=3.5), {})
        def check(value):
            if isinstance(value, dict):
                for item in value.values():
                    check(item)
            elif isinstance(value, list):
                for item in value:
                    check(item)
            elif isinstance(value, (int, float)):
                self.assertIsInstance(value, int)
                self.assertLessEqual(abs(value), 9007199254740991)
        check(ledger)
        self.assertEqual(250, ledger["observer"]["interval_ms"])
        self.assertEqual(3500, ledger["observer"]["environment_refresh_interval_ms"])


if __name__ == "__main__":
    unittest.main()
