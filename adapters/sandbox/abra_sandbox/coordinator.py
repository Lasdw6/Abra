"""Capture a sandbox into a local Abra snapshot, or push a snapshot back into one.

An architecture-compatible Abra binary and, when asked, the browser-session
adapter run from owned temporary directories that the driver removes on close.
"""

import json
import os
import posixpath
import secrets
import shutil
import struct
import subprocess
import tempfile

from .drivers.base import CommandError

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.realpath(os.path.join(HERE, "..", "..", ".."))
COLLECTOR = os.path.join(HERE, "..", "collector", "observer.py")
ADAPTER_DIR = os.path.join(REPO, "adapters", "browser-session")
ADAPTER_SKIP = ("test", "facade", "README.md", "node_modules")
LOCAL_ONLY = (".abra/capsule_id", ".abra/snapshot_id")
MINIMAL_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
CDP_PROBE = ("fetch('http://127.0.0.1:%s/json/version').then(r=>r.json())"
             ".then(v=>console.log(v.webSocketDebuggerUrl))"
             ".catch(e=>{console.error(e);process.exit(1)})")


class Abra:
    """The local abra CLI against one root."""

    def __init__(self, binary, root):
        self.binary = binary
        self.root = root

    def call(self, *args):
        argv = [self.binary, "--root", self.root, "--json"] + list(args)
        completed = subprocess.run(argv, capture_output=True, text=True)
        if completed.returncode != 0:
            raise RuntimeError("abra %s failed: %s" % (args[0], (completed.stderr or completed.stdout).strip()))
        return json.loads(completed.stdout)


def default_abra():
    if os.environ.get("ABRA_BIN"):
        return os.environ["ABRA_BIN"]
    found = shutil.which("abra")
    if found:
        return found
    return os.path.join(REPO, "target", "release", "abra")


def default_root():
    return os.environ.get("ABRA_ROOT") or os.path.join(os.path.expanduser("~"), ".abra")


def mirror_path(abra_root, name):
    if not name or "/" in name or name in (".", ".."):
        raise ValueError("sandbox name must be one path component")
    return os.path.join(abra_root, "sandboxes", name, "workspace")


def last_line(output):
    lines = [line for line in output.decode("utf-8", "replace").splitlines() if line.strip()]
    return lines[-1] if lines else ""


def membership_flags(membership):
    if membership == "all":
        return ["--all"]
    if membership == "workspace":
        return []
    if membership.startswith("cgroup:"):
        return ["--cgroup", membership[len("cgroup:"):]]
    if membership.startswith("pgrp:"):
        return ["--process-group", membership[len("pgrp:"):]]
    raise ValueError("membership must be all, workspace, cgroup:<path> or pgrp:<pid>")


def _machine(value):
    value = value.strip().lower()
    if value in ("x86_64", "amd64"):
        return "x86_64"
    if value in ("aarch64", "arm64"):
        return "aarch64"
    return value


def binary_platforms(binary):
    """Return the OS and machine pairs encoded in an ELF or Mach-O binary."""
    with open(binary, "rb") as handle:
        header = handle.read(4096)
    if header.startswith(b"\x7fELF") and len(header) >= 20:
        byte_order = "<" if header[5] == 1 else ">" if header[5] == 2 else None
        if byte_order is None:
            raise RuntimeError("remote Abra ELF binary has an invalid byte order")
        machine = struct.unpack(byte_order + "H", header[18:20])[0]
        names = {62: "x86_64", 183: "aarch64"}
        if machine not in names:
            raise RuntimeError("remote Abra ELF architecture %d is unsupported" % machine)
        return {("linux", names[machine])}

    magics = {
        b"\xce\xfa\xed\xfe": ("<", 4), b"\xcf\xfa\xed\xfe": ("<", 8),
        b"\xfe\xed\xfa\xce": (">", 4), b"\xfe\xed\xfa\xcf": (">", 8),
    }
    if header[:4] in magics and len(header) >= 8:
        byte_order, _ = magics[header[:4]]
        cpu = struct.unpack(byte_order + "I", header[4:8])[0]
        names = {0x01000007: "x86_64", 0x0100000c: "aarch64"}
        if cpu not in names:
            raise RuntimeError("remote Abra Mach-O architecture %#x is unsupported" % cpu)
        return {("darwin", names[cpu])}

    if header[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and len(header) >= 8:
        is_64 = header[:4] == b"\xca\xfe\xba\xbf"
        count = struct.unpack(">I", header[4:8])[0]
        stride = 32 if is_64 else 20
        names = {0x01000007: "x86_64", 0x0100000c: "aarch64"}
        result = set()
        for index in range(count):
            offset = 8 + index * stride
            if offset + 4 > len(header):
                raise RuntimeError("remote Abra universal Mach-O header is truncated")
            cpu = struct.unpack(">I", header[offset:offset + 4])[0]
            if cpu in names:
                result.add(("darwin", names[cpu]))
        if result:
            return result
    raise RuntimeError("remote Abra must be an ELF or Mach-O executable: %s" % binary)


def configure_runtime(driver, local_binary):
    """Reject a wrong-platform binary before putting any executable in the sandbox."""
    system = last_line(driver.check(["uname", "-s"])).lower()
    machine = _machine(last_line(driver.check(["uname", "-m"])))
    remote = ({"linux": "linux", "darwin": "darwin"}.get(system), machine)
    if remote[0] is None:
        raise RuntimeError("sandbox OS %r is unsupported by the uploaded Abra runner" % system)
    platforms = binary_platforms(local_binary)
    if remote not in platforms:
        available = ", ".join("%s/%s" % item for item in sorted(platforms))
        raise RuntimeError("remote Abra architecture mismatch: sandbox is %s/%s, binary is %s" %
                           (remote[0], remote[1], available))
    driver.configure_runtime(local_binary)


def sync_tree(driver, remote_dir, mirror):
    """Make mirror match the remote tree, keeping local-only files in .abra."""
    parent = os.path.dirname(mirror)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent, prefix=".pull-") as staging:
        pulled = os.path.join(staging, "tree")
        driver.get_tree(remote_dir, pulled)
        os.makedirs(mirror, exist_ok=True)
        for entry in os.listdir(mirror):
            if entry != ".abra":
                remove(os.path.join(mirror, entry))
        for entry in os.listdir(pulled):
            source = os.path.join(pulled, entry)
            if entry != ".abra":
                os.rename(source, os.path.join(mirror, entry))
                continue
            metadata = os.path.join(mirror, ".abra")
            os.makedirs(metadata, mode=0o700, exist_ok=True)
            for name in os.listdir(source):
                if ".abra/" + name in LOCAL_ONLY or not os.path.isfile(os.path.join(source, name)):
                    continue
                os.replace(os.path.join(source, name), os.path.join(metadata, name))


def remove(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def resolve_cdp(driver, cdp, port):
    if cdp:
        return cdp
    if not port:
        raise ValueError("browser needs --browser-cdp or --browser-port")
    return last_line(driver.check(["node", "-e", CDP_PROBE % int(port)], timeout=30))


def push_adapter(driver, adapter_dir, remote):
    for name in ("bin", "lib", "package.json", "abra-adapter.json"):
        if not os.path.exists(os.path.join(adapter_dir, name)):
            raise FileNotFoundError("browser-session adapter is missing %s in %s" % (name, adapter_dir))
    driver.put_tree(adapter_dir, remote, exclude=ADAPTER_SKIP)


def capture_browser(driver, barrier, adapter_dir, cdp, port, out_dir):
    remote = "%s/abra-browser-%s" % (driver.tmp_dir(), barrier)
    try:
        push_adapter(driver, adapter_dir, remote)
        ws = resolve_cdp(driver, cdp, port)
        driver.check(["node", remote + "/bin/abra-browser.js", "export", "--from", "cdp", ws, "--out", remote + "/bundle"],
                     timeout=180, env={"ABRA_BROWSER_DATA_DIR": remote + "/data"})
        driver.get_tree(remote + "/bundle", out_dir)
    finally:
        driver.exec(["rm", "-rf", remote])
    with open(os.path.join(out_dir, "manifest.json")) as handle:
        manifest = json.load(handle)
    return {"bundle": out_dir, "fingerprint": manifest["signature"]["fingerprint"],
            "domains": [entry["domain"] for entry in manifest.get("domains", [])],
            "tabs": [tab["url"] for tab in manifest.get("tabs", [])]}


def capture(driver, name, remote_workspace, abra, membership="all", browser_cdp=None, browser_port=None,
            collector=None, adapter_dir=None, remote_abra=None):
    configure_runtime(driver, remote_abra or abra.binary)
    barrier = secrets.token_hex(6)
    mirror = mirror_path(abra.root, name)
    remote = "%s/abra-collector-%s" % (driver.tmp_dir(), barrier)
    try:
        if collector:
            driver.put(collector, remote + "/observer.py", 0o700)
            argv = ["python3", remote + "/observer.py", "--workspace", remote_workspace]
        else:
            argv = [driver.runtime(), "observe", "--workspace", remote_workspace]
        argv += membership_flags(membership)
        summary = json.loads(last_line(driver.check(argv + ["--once", "--barrier", barrier], timeout=180)))
    finally:
        driver.exec(["rm", "-rf", remote])
    if summary.get("barrier") != barrier:
        raise RuntimeError("collector reported barrier %r, expected %r" % (summary.get("barrier"), barrier))
    sync_tree(driver, remote_workspace, mirror)
    pinned = os.path.join(mirror, ".abra", "observed-%s.json" % barrier)
    if not os.path.isfile(pinned):
        raise RuntimeError("collector output %s did not come out with the tree" % pinned)
    with open(pinned) as handle:
        ledger = json.load(handle)

    browser = None
    if browser_cdp or browser_port:
        out_dir = os.path.join(os.path.dirname(mirror), "browser-%s" % barrier)
        browser = capture_browser(driver, barrier, adapter_dir or ADAPTER_DIR, browser_cdp, browser_port, out_dir)

    host = dict(driver.facts())
    host["native"] = driver.native_capture()
    if not os.path.isfile(os.path.join(mirror, ".abra", "capsule_id")):
        abra.call("init", mirror)
    snapshot = abra.call("snapshot", mirror, "--observation-barrier", barrier, "--observation-host", json.dumps(host))
    os.unlink(pinned)
    driver.exec(["rm", "-f", posixpath.join(remote_workspace, ".abra", "observed-%s.json" % barrier)])
    return {"snapshot_id": snapshot["snapshot_id"], "capsule_id": snapshot["capsule_id"],
            "observation_barrier": barrier, "mirror": mirror, "recipes": ledger.get("recipes", []),
            "service_candidates": len(ledger.get("service_candidates", [])), "browser": browser,
            "native": host["native"], "collection_errors": ledger.get("collection_errors", [])}


def load_candidates(mirror):
    """Service candidates with their index, from the received ledger or recipes.json."""
    metadata = os.path.join(mirror, ".abra")
    observed = os.path.join(metadata, "received-observed.json")
    if os.path.isfile(observed):
        with open(observed) as handle:
            return json.load(handle).get("service_candidates", [])
    recipes = os.path.join(metadata, "recipes.json")
    if os.path.isfile(recipes):
        with open(recipes) as handle:
            return [{"recipe": recipe, "restartability": "unverified", "missing_requirements": []}
                    for recipe in json.load(handle)]
    return []


def describe(index, candidate):
    recipe = candidate["recipe"]
    return {"index": index, "restartability": candidate.get("restartability"), "argv": recipe.get("argv"),
            "cwd": recipe.get("cwd"), "ports": recipe.get("ports", []),
            "missing_requirements": candidate.get("missing_requirements", [])}


def start_candidate(driver, remote_workspace, index, candidate):
    recipe = candidate["recipe"]
    if candidate.get("restartability") == "blocked" or recipe.get("cwd") is None:
        raise RuntimeError("candidate %d is blocked: %s" % (index, ", ".join(candidate.get("missing_requirements", []))))
    cwd = posixpath.normpath(posixpath.join(remote_workspace, recipe["cwd"]))
    env = dict(MINIMAL_ENV)
    env.update(recipe.get("env") or {})
    code, out, err = driver.exec(recipe["argv"], env=env, cwd=cwd, detach=True)
    if code != 0:
        raise CommandError("start of candidate %d failed: %s" % (index, (err or out).decode("utf-8", "replace").strip()))
    return {"index": index, "pid": int(last_line(out)), "argv": recipe["argv"], "cwd": cwd, "ports": recipe.get("ports", [])}


def restore_browser(driver, bundle, adapter_dir, cdp, port, receipts_dir):
    with open(os.path.join(bundle, "manifest.json")) as handle:
        fingerprint = json.load(handle)["signature"]["fingerprint"]
    token = secrets.token_hex(6)
    remote = "%s/abra-browser-%s" % (driver.tmp_dir(), token)
    try:
        push_adapter(driver, adapter_dir, remote)
        driver.put_tree(bundle, remote + "/bundle")
        ws = resolve_cdp(driver, cdp, port)
        # The caller chose to restore this bundle; its own fingerprint is the trusted sender.
        output = driver.check(["node", remote + "/bin/abra-browser.js", "import", remote + "/bundle", "--to", "cdp", ws,
                               "--trust-sender", fingerprint], timeout=180, env={"ABRA_BROWSER_DATA_DIR": remote + "/data"})
        receipt_remote = last_line(output)
        os.makedirs(receipts_dir, mode=0o700, exist_ok=True)
        receipt_local = os.path.join(receipts_dir, "receipt-%s.json" % token)
        driver.get(receipt_remote, receipt_local)
    finally:
        driver.exec(["rm", "-rf", remote + "/bundle", remote + "/bin", remote + "/lib", remote + "/package.json",
                     remote + "/abra-adapter.json"])
    with open(receipt_local) as handle:
        receipt = json.load(handle)
    return {"bundle": bundle, "fingerprint": fingerprint, "receipt": receipt_local,
            "install_id": receipt.get("install_id"), "domains": receipt.get("domains"),
            "remote_data_dir": remote + "/data"}


def restore(driver, name, snapshot_id, remote_workspace, abra, browser=None, browser_cdp=None,
            browser_port=None, start=(), adapter_dir=None, replace_workspace=False, remote_abra=None):
    configure_runtime(driver, remote_abra or abra.binary)
    plan = abra.call("restore-plan", snapshot_id)
    if not plan["portable"]["available"]:
        raise RuntimeError("portable restore is unavailable: %s" % plan["portable"]["error"])
    mirror = mirror_path(abra.root, name)
    os.makedirs(os.path.dirname(mirror), mode=0o700, exist_ok=True)
    if os.path.isfile(os.path.join(mirror, ".abra", "capsule_id")):
        # The mirror is the coordinator's copy, never a place for local edits.
        abra.call("accept", snapshot_id, mirror, "--replace", "--discard-local", "--allow-divergence")
    else:
        abra.call("accept", snapshot_id, mirror)
    driver.restore_tree(mirror, remote_workspace, exclude=LOCAL_ONLY, replace=replace_workspace)
    pushed = sum(1 for base, _, files in os.walk(mirror) for name in files
                 if os.path.relpath(os.path.join(base, name), mirror) not in LOCAL_ONLY)
    candidates = load_candidates(mirror)
    started = []
    for index in start:
        if index < 0 or index >= len(candidates):
            raise IndexError("no candidate with index %d (have %d)" % (index, len(candidates)))
        started.append(start_candidate(driver, remote_workspace, index, candidates[index]))
    browser_result = None
    if browser:
        browser_result = restore_browser(driver, browser, adapter_dir or ADAPTER_DIR, browser_cdp, browser_port,
                                         os.path.join(os.path.dirname(mirror), "receipts"))
    return {"snapshot_id": snapshot_id, "mirror": mirror, "remote_workspace": remote_workspace,
            "mode": "portable", "restore_plan": plan,
            "pushed_files": pushed, "candidates": [describe(i, c) for i, c in enumerate(candidates)],
            "started": started, "browser": browser_result}
