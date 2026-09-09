#!/usr/bin/env python3
"""Capture a Daytona sandbox with abra-sandbox, move the snapshot to a second
Abra root on this machine, and restore it into a second Daytona sandbox.

Two sandboxes come from one image with python3, node and chromium. Sandbox A
runs an HTTP fixture and a headless chromium holding a test cookie. Root A
captures A. Root B receives the snapshot and the browser bundle, then restores
both into sandbox B and starts the HTTP candidate explicitly.
"""

import argparse
import importlib.metadata
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SANDBOX = REPO / "adapters/sandbox"
ADAPTER = REPO / "adapters/browser-session"
sys.path.insert(0, str(SANDBOX))

from abra_sandbox import coordinator  # noqa: E402
from abra_sandbox.coordinator import ADAPTER_SKIP, CDP_PROBE, last_line  # noqa: E402
from abra_sandbox.drivers.daytona import DaytonaDriver  # noqa: E402

DEFAULT_IMAGE = "mcr.microsoft.com/playwright:v1.49.1-noble"
PORT = 8123
CDP_PORT = 9222
MARKER = "abra-daytona-sandbox-marker\n"
FIXTURE = "/tmp/abra-fixture"
CHROME_FLAGS = ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run",
                "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=%d" % CDP_PORT]
FIND_CHROME = ("for c in chromium chromium-browser google-chrome google-chrome-stable; do command -v $c && exit 0; done; "
               "ls -d /ms-playwright/chromium-*/chrome-linux/chrome 2>/dev/null | head -n1")
FETCH = "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=5).read().decode())"
LISTENING = "import socket, sys; sys.exit(0 if socket.socket().connect_ex(('127.0.0.1', int(sys.argv[1]))) == 0 else 1)"


def redact(text):
    return str(text).replace(os.environ.get("DAYTONA_API_KEY", "\0"), "<redacted>")


class Run:
    def __init__(self, args):
        self.args = args
        self.report_dir = args.report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = uuid.uuid4().hex[:12]
        self.report = {"ok": False, "provider": "daytona", "run_id": self.run_id,
                       "sdk_version": importlib.metadata.version("daytona"), "browser": not args.no_browser,
                       "image": {"requested": args.image, "used": None, "fallback": False},
                       "sandboxes": [], "checks": {}, "timings_s": {}, "deleted": []}
        self.client = None
        self.sandboxes = {}
        self.drivers = {}
        self.roots = {}
        self.started = time.monotonic()

    def save(self):
        (self.report_dir / "report.json").write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")

    def check(self, name, ok, detail=None):
        self.report["checks"][name] = ok if detail is None else {"ok": ok, "detail": detail}
        self.save()
        if not ok:
            raise AssertionError("check failed: %s %s" % (name, detail or ""))

    def log(self, name, text):
        (self.report_dir / name).write_text(redact(text))

    # -- local Abra roots ---------------------------------------------------

    def abra(self, root, *args, timeout=300):
        argv = [str(self.args.abra), "--root", root, "--json"] + [str(a) for a in args]
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if completed.returncode != 0:
            raise RuntimeError("abra %s failed: %s" % (args[0], completed.stderr.strip() or completed.stdout.strip()))
        return json.loads(completed.stdout)

    def coordinator(self, root, name, *args):
        argv = [sys.executable, str(SANDBOX / "bin/abra-sandbox")] + list(args) + ["--abra", str(self.args.abra), "--abra-root", root, "--json"]
        if self.args.remote_abra:
            argv += ["--remote-abra", str(self.args.remote_abra)]
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=1200)
        self.log("coordinator-%s.log" % name, "$ %s\n%s\n%s" % (shlex.join(argv[2:]), completed.stdout, completed.stderr))
        if completed.returncode != 0:
            raise RuntimeError("abra-sandbox %s failed: %s" % (args[0], completed.stderr.strip()))
        return json.loads(completed.stdout)

    def start_roots(self):
        base = Path(tempfile.mkdtemp(prefix="abra-daytona-roots-"))
        for role in ("a", "b"):
            root = base / role
            root.mkdir(mode=0o700)
            self.roots[role] = str(root)
            self.abra(str(root), "daemon", "--background", "--yes", "--adapters", str(REPO / "adapters"))
        ticket = subprocess.run([str(self.args.abra), "--root", self.roots["b"], "pair", "ticket"], check=True,
                                capture_output=True, text=True).stdout.strip()
        self.abra(self.roots["a"], "pair", "add", ticket)
        self.peer_b = self.abra(self.roots["b"], "status")["peer_id"]

    def stop_roots(self):
        for role, root in self.roots.items():
            log = Path(root) / "daemon.log"
            if log.exists():
                self.log("daemon-%s.log" % role, log.read_text())
            subprocess.run([str(self.args.abra), "--root", root, "stop"], capture_output=True)
        if self.roots and not self.args.keep:
            shutil.rmtree(Path(self.roots["a"]).parent, ignore_errors=True)

    # -- sandboxes ------------------------------------------------------------

    def create_sandboxes(self):
        import daytona

        self.client = daytona.Daytona(daytona.DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))
        for role in ("a", "b"):
            common = {"name": "abra-sandbox-%s-%s" % (self.run_id, role),
                      "labels": {"project": "abra", "purpose": "sandbox-e2e", "run": self.run_id},
                      "auto_stop_interval": 15, "auto_delete_interval": 0, "ttl_minutes": 60}
            print("Creating sandbox %s" % role, flush=True)
            box = None
            if self.args.image and not self.report["image"]["fallback"]:
                params = daytona.CreateSandboxFromImageParams(
                    image=self.args.image, resources=daytona.Resources(cpu=1, memory=2, disk=8), **common)
                try:
                    with open(self.report_dir / "image-build.log", "a") as log:
                        box = self.client.create(params, timeout=900, on_snapshot_create_logs=lambda chunk: log.write(chunk))
                    self.report["image"]["used"] = self.args.image
                except Exception as error:
                    self.report["image"].update({"fallback": True, "error": redact(error)})
                    print("Image params failed, falling back to the default snapshot: %s" % redact(error), flush=True)
            if box is None:
                box = self.client.create(daytona.CreateSandboxFromSnapshotParams(**common), timeout=180)
                self.report["image"]["used"] = box.snapshot or "default"
            self.sandboxes[role] = box
            driver = DaytonaDriver(sandbox=box.id)
            self.drivers[role] = driver
            coordinator.configure_runtime(driver, self.args.remote_abra or self.args.abra)
            home = last_line(driver.check(["sh", "-c", "echo $HOME"]))
            code, _, _ = driver.exec(["sh", "-c", "mkdir -p /workspace && test -w /workspace"])
            workspace = "/workspace" if code == 0 else home + "/workspace"
            driver.check(["mkdir", "-p", workspace])
            entry = {"role": role, "id": box.id, "cpu": box.cpu, "memory_gib": box.memory, "user": box.user,
                     "workspace": workspace, "tools": self.tools(driver)}
            self.report["sandboxes"].append(entry)
            self.save()
        if self.report["browser"]:
            missing = [role for role, entry in zip(("a", "b"), self.report["sandboxes"])
                       if not (entry["tools"]["node"] and entry["tools"]["chromium"])]
            if missing and self.report["image"]["fallback"]:
                self.install_browser_tools(missing)
            missing = [role for role, entry in zip(("a", "b"), self.report["sandboxes"])
                       if not (entry["tools"]["node"] and entry["tools"]["chromium"])]
            if missing:
                self.report["browser"] = False
                self.report["browser_skipped_reason"] = "node or chromium missing in sandbox(es) %s" % ",".join(missing)
                print(self.report["browser_skipped_reason"], flush=True)
        self.save()

    def tools(self, driver):
        def version(argv):
            code, out, _ = driver.exec(argv, timeout=30)
            return last_line(out) if code == 0 else None
        chrome = last_line(driver.exec(["sh", "-c", FIND_CHROME])[1]) or None
        return {"python3": version(["python3", "--version"]), "node": version(["node", "--version"]), "chromium": chrome}

    def install_browser_tools(self, roles):
        script = ("export DEBIAN_FRONTEND=noninteractive; (sudo -n true 2>/dev/null && S='sudo -n') || S=''; "
                  "$S apt-get update -qq && $S apt-get install -y -qq chromium nodejs")
        for role in roles:
            driver = self.drivers[role]
            code, out, _ = driver.exec(["sh", "-c", script], timeout=900)
            self.log("apt-%s.log" % role, out.decode("utf-8", "replace"))
            entry = next(e for e in self.report["sandboxes"] if e["role"] == role)
            entry["tools"] = self.tools(driver)
            entry["apt_install_exit"] = code

    def delete_sandboxes(self):
        for role, box in self.sandboxes.items():
            driver = self.drivers.get(role)
            if driver is not None:
                try:
                    logs = driver.exec(["sh", "-c", "for f in /tmp/abra-runner-*/start-*.log; do test -e \"$f\" || continue; echo \"== $f\"; tail -n 100 \"$f\"; done"], timeout=30)[1]
                    self.log("sandbox-%s-processes.log" % role, logs.decode("utf-8", "replace"))
                except Exception:
                    pass
                try:
                    driver.close()
                except Exception as error:
                    self.report.setdefault("cleanup_errors", []).append(redact(error))
                    self.report["ok"] = False
            if self.args.keep:
                continue
            try:
                print("Deleting sandbox %s" % box.id, flush=True)
                self.client.delete(box, timeout=120, wait=True)
                self.report["deleted"].append(box.id)
            except Exception as error:
                self.report.setdefault("cleanup_errors", []).append(redact(error))
                self.report["ok"] = False
            self.save()

    # -- helpers inside a sandbox ---------------------------------------------

    def workspace(self, role):
        return next(e["workspace"] for e in self.report["sandboxes"] if e["role"] == role)

    def start(self, role, argv, cwd, env=None):
        full_env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
        full_env.update(env or {})
        code, out, err = self.drivers[role].exec(argv, env=full_env, cwd=cwd, detach=True)
        if code != 0:
            raise RuntimeError("could not start %s in %s: %s" % (argv[0], role, (err or out).decode("utf-8", "replace")))
        return int(last_line(out))

    def wait(self, description, check, seconds=90):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(1)
        raise AssertionError("timed out: " + description)

    def fetch(self, role, url):
        code, out, _ = self.drivers[role].exec(["python3", "-c", FETCH, url], timeout=15)
        return out.decode("utf-8", "replace") if code == 0 else None

    def listening(self, role, port):
        return self.drivers[role].exec(["python3", "-c", LISTENING, str(port)], timeout=15)[0] == 0

    def start_chromium(self, role):
        entry = next(e for e in self.report["sandboxes"] if e["role"] == role)
        pid = self.start(role, [entry["tools"]["chromium"]] + CHROME_FLAGS + ["--user-data-dir=/tmp/abra-chrome-%s" % role, "about:blank"],
                         cwd="/tmp", env={"HOME": "/tmp"})
        self.wait("chromium CDP in %s" % role, lambda: self.fetch(role, "http://127.0.0.1:%d/json/version" % CDP_PORT) is not None)
        return pid

    def cdp_url(self, role):
        return last_line(self.drivers[role].check(["python3", "-c", CDP_PROBE % CDP_PORT], timeout=30))

    def fixture(self, role, verb, *args):
        driver = self.drivers[role]
        driver.put_tree(str(ADAPTER), FIXTURE, exclude=ADAPTER_SKIP)
        out = driver.check(["node", FIXTURE + "/bin/cdp-fixture.mjs", verb, "--cdp", self.cdp_url(role)] + list(args), timeout=120)
        return json.loads(last_line(out))

    # -- the flow ---------------------------------------------------------------

    def run(self):
        cookie = "abra-cookie-" + uuid.uuid4().hex
        local_value = "abra-local-" + uuid.uuid4().hex
        self.report["secrets_under_test"] = {"cookie_prefix": cookie[:12], "local_prefix": local_value[:11]}
        stage = time.monotonic()
        self.start_roots()
        self.create_sandboxes()
        self.report["timings_s"]["setup"] = round(time.monotonic() - stage, 1)
        a, b = self.drivers["a"], self.drivers["b"]
        ws_a, ws_b = self.workspace("a"), self.workspace("b")
        browser = self.report["browser"]

        print("Preparing sandbox A", flush=True)
        a.check(["sh", "-c", "printf %s " + shlex.quote(MARKER) + " > " + shlex.quote(ws_a + "/marker.txt")])
        a.check(["sh", "-c", "mkdir -p %s/src && printf 'print(1)\\n' > %s/src/app.py" % (shlex.quote(ws_a), shlex.quote(ws_a))])
        self.start("a", ["python3", "-m", "http.server", str(PORT), "--bind", "127.0.0.1"], cwd=ws_a)
        self.wait("http fixture in A", lambda: self.fetch("a", "http://127.0.0.1:%d/marker.txt" % PORT) == MARKER)
        if browser:
            self.start_chromium("a")
            seeded = self.fixture("a", "set", "--url", "http://127.0.0.1:%d/marker.txt" % PORT, "--cookie", "sid=" + cookie,
                                  "--local", "abra=" + local_value)
            self.check("fixture_seeded", seeded["cookies"] == ["sid"], seeded)

        print("Capturing sandbox A from root A", flush=True)
        stage = time.monotonic()
        name = "daytona-" + self.run_id
        capture_args = ["capture", "--driver", "daytona", "--driver-opt", "sandbox=" + self.sandboxes["a"].id, "--name", name,
                        "--remote-workspace", ws_a, "--membership", "all"]
        if browser:
            capture_args += ["--browser-port", str(CDP_PORT)]
        captured = self.coordinator(self.roots["a"], "capture", *capture_args)
        self.report["timings_s"]["capture"] = round(time.monotonic() - stage, 1)
        self.report["capture"] = captured
        manifest_path = Path(self.roots["a"]) / "capsules" / captured["capsule_id"] / "snapshots" / (captured["snapshot_id"] + ".cjson")
        manifest = json.loads(manifest_path.read_bytes())
        observed = manifest["extensions"]["dev.abra.observed"]
        self.check("barrier_matches", observed["observer"]["barrier"] == captured["observation_barrier"])
        self.check("scope_all", observed["coverage"]["scope"] == "all")
        self.check("host_facts_daytona", observed["host"]["facts"].get("provider") == "daytona"
                   and observed["host"]["facts"].get("sandbox_id") == self.sandboxes["a"].id, observed["host"]["facts"])
        box = self.sandboxes["a"]
        resources = observed["resources"]
        self.report["resources"] = {"observed": resources, "sandbox_cpu": box.cpu, "sandbox_memory_gib": box.memory}
        self.check("resources_match_provider", resources.get("effective_cpu_millicores") == int(box.cpu * 1000)
                   and resources.get("effective_memory_bytes") == int(box.memory * 1024 ** 3), self.report["resources"])
        candidates = observed["service_candidates"]
        index = next((i for i, c in enumerate(candidates) if PORT in c["recipe"].get("ports", [])), None)
        self.check("service_candidate_8123", index is not None, [c["recipe"].get("argv") for c in candidates])
        self.check("candidate_unverified", candidates[index]["restartability"] == "unverified", candidates[index])
        self.check("recipe_in_manifest", any(PORT in r.get("ports", []) for r in manifest.get("recipes", [])))
        mirror = Path(captured["mirror"])
        self.check("mirror_has_files", (mirror / "marker.txt").read_text() == MARKER and (mirror / "src/app.py").is_file())
        leaked = []
        for path in Path(self.roots["a"]).rglob("*"):
            relative = path.relative_to(self.roots["a"])
            if path.is_file() and not any(part.startswith("browser-") for part in relative.parts):
                data = path.read_bytes()
                if cookie.encode() in data or local_value.encode() in data:
                    leaked.append(str(relative))
        self.check("cookie_outside_bundle", leaked == [], leaked)
        found_abra = a.exec(["sh", "-c", "command -v abra; find /tmp %s -maxdepth 3 -type f -name abra" % shlex.quote(ws_a)])[1]
        managed_abra = a.runtime().encode()
        self.check("only_managed_abra_in_sandbox", found_abra.splitlines() == [managed_abra],
                   found_abra.decode("utf-8", "replace"))
        leftovers = a.exec(["sh", "-c", "ls -d /tmp/abra-collector-* /tmp/abra-browser-* 2>/dev/null"])[1]
        self.check("sandbox_temp_dirs_removed", leftovers.strip() == b"", leftovers.decode("utf-8", "replace"))
        self.check("pinned_ledger_removed_remotely", a.exec(["test", "-e", "%s/.abra/observed-%s.json" % (ws_a, captured["observation_barrier"])])[0] != 0)
        bundle_a = None
        if browser:
            self.check("browser_bundle_captured", captured["browser"] is not None and "127.0.0.1" in captured["browser"]["domains"], captured["browser"])
            bundle_a = captured["browser"]["bundle"]

        print("Sending snapshot and bundle to root B", flush=True)
        stage = time.monotonic()
        sent = self.abra(self.roots["a"], "send", self.peer_b, "--snapshot", captured["snapshot_id"], "--wait", "--timeout", "300s")
        self.check("snapshot_acked", sent["entry"]["state"] == "acked")
        bundle_snapshot = None
        if browser:
            sent_bundle = self.abra(self.roots["a"], "send", self.peer_b, "--kind", "dev.abra.browser.session.v1",
                                    "--source", "bundle:" + bundle_a, "--wait", "--timeout", "300s")
            self.check("bundle_acked", sent_bundle["entry"]["state"] == "acked")
            bundle_snapshot = sent_bundle["snapshot_id"]
        self.report["timings_s"]["transfer"] = round(time.monotonic() - stage, 1)

        print("Restoring into sandbox B from root B", flush=True)
        stage = time.monotonic()
        bundle_b = None
        if browser:
            bundle_b = str(Path(self.roots["b"]) / "browser-bundle")
            self.abra(self.roots["b"], "accept", bundle_snapshot, bundle_b, "--no-import")
            self.check("bundle_materialized", (Path(bundle_b) / "manifest.json").is_file())
        restore_args = ["restore", "--driver", "daytona", "--driver-opt", "sandbox=" + self.sandboxes["b"].id, "--name", name,
                        "--snapshot", captured["snapshot_id"], "--remote-workspace", ws_b]
        pushed = self.coordinator(self.roots["b"], "restore-no-start", *restore_args)
        self.report["restore_no_start"] = pushed
        self.check("nothing_started_without_start", pushed["started"] == [] and not self.listening("b", PORT))
        self.check("files_pushed", self.fetch("b", "file://%s/marker.txt" % ws_b) == MARKER
                   and b.exec(["test", "-f", ws_b + "/src/app.py"])[0] == 0)
        self.check("no_capsule_id_pushed", b.exec(["test", "-e", ws_b + "/.abra/capsule_id"])[0] != 0)
        self.check("recipes_pushed", b.exec(["test", "-s", ws_b + "/.abra/recipes.json"])[0] == 0)
        candidate_index = next((c["index"] for c in pushed["candidates"] if PORT in c["ports"]), None)
        self.check("candidate_listed", candidate_index is not None, pushed["candidates"])
        if browser:
            self.start_chromium("b")
            restore_args += ["--browser", bundle_b, "--browser-port", str(CDP_PORT)]
        restored = self.coordinator(self.roots["b"], "restore-start", *restore_args, "--replace-workspace", "--start", str(candidate_index))
        self.report["restore"] = restored
        self.report["timings_s"]["restore"] = round(time.monotonic() - stage, 1)
        self.check("candidate_started", len(restored["started"]) == 1 and restored["started"][0]["pid"] > 0, restored["started"])
        self.wait("http fixture in B", lambda: self.fetch("b", "http://127.0.0.1:%d/marker.txt" % PORT) == MARKER)
        self.check("marker_served_on_b", True)
        if browser:
            self.check("bundle_imported", bool(restored["browser"] and restored["browser"]["install_id"]), restored["browser"])
            got = self.fixture("b", "get", "--url", "http://127.0.0.1:%d/" % PORT)
            self.check("cookie_present_in_b", any(c["name"] == "sid" and c["value"] == cookie for c in got["cookies"]),
                       {"cookies": [c["name"] for c in got["cookies"]], "tabs": got["tabs"]})
            self.check("local_storage_present_in_b", any(i["name"] == "abra" and i["value"] == local_value for i in got["local_storage"]),
                       [i["name"] for i in got["local_storage"]])
        self.report["ok"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--abra", type=Path, default=Path(os.environ.get("ABRA_BIN") or REPO / "target/release/abra"),
                        help="local abra binary for the two roots on this machine")
    parser.add_argument("--remote-abra", type=Path,
                        help="Linux Abra binary to upload to Daytona (defaults to --abra)")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="sandbox image; empty string means the default snapshot")
    parser.add_argument("--no-browser", action="store_true", help="skip the chromium half")
    parser.add_argument("--keep", action="store_true", help="keep sandboxes and roots for debugging")
    args = parser.parse_args()
    if not os.environ.get("DAYTONA_API_KEY"):
        parser.error("set DAYTONA_API_KEY in the environment")
    if not args.abra.is_file():
        parser.error("abra binary not found at %s" % args.abra)
    if args.remote_abra and not args.remote_abra.is_file():
        parser.error("remote Abra binary not found at %s" % args.remote_abra)
    run = Run(args)
    try:
        run.run()
    except Exception as error:
        run.report["error"] = redact(error)
        run.report["ok"] = False
        print("FAILED: " + run.report["error"], file=sys.stderr, flush=True)
    finally:
        run.report["elapsed_s"] = round(time.monotonic() - run.started, 1)
        run.save()
        try:
            run.delete_sandboxes()
        finally:
            run.stop_roots()
            run.save()
    print(json.dumps(run.report, indent=2, sort_keys=True))
    return 0 if run.report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
