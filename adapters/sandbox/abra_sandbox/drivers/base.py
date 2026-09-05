"""Driver interface plus tar-based tree transfer shared by every driver."""

import json
import os
import secrets
import shlex
import tarfile
import tempfile

from .. import tree
from ..tree import unpack_tree

# Runs inside the sandbox. Reads a JSON spec, starts the command in its own
# session with output in a log file, prints the pid and exits.
LAUNCHER = r'''
import json, os, subprocess, sys
with open(sys.argv[1]) as handle:
    spec = json.load(handle)
os.unlink(sys.argv[1])
env = spec.get("env")
if env is not None:
    for key in ("HOME", "USER", "LANG"):
        if key in os.environ:
            env.setdefault(key, os.environ[key])
log = open(spec["log"], "ab")
child = subprocess.Popen(spec["argv"], cwd=spec.get("cwd"), env=env, stdin=subprocess.DEVNULL,
                         stdout=log, stderr=log, start_new_session=True)
print(child.pid)
'''.strip()


class CommandError(RuntimeError):
    pass


class Driver:
    """One sandbox. Paths are sandbox paths; bytes move through put/get only."""

    name = "base"

    def exec(self, argv, timeout=60, env=None, cwd=None, detach=False):
        """Run argv in the sandbox. Returns (exit_code, stdout_bytes, stderr_bytes).

        env adds variables for this command. detach=True starts argv in its own
        session with exactly env (plus HOME/USER/LANG) and returns at once with
        the pid in stdout; used only by `restore --start`.
        """
        if detach:
            return self.start_detached(argv, env, cwd)
        return self.run(argv, timeout, env, cwd)

    def run(self, argv, timeout, env, cwd):
        raise NotImplementedError

    def put(self, local_file, remote_file, mode=0o600):
        raise NotImplementedError

    def get(self, remote_file, local_file):
        raise NotImplementedError

    def tmp_dir(self):
        return "/tmp"

    def facts(self):
        """Provider facts for the snapshot's observation_host. No secrets."""
        return {"provider": self.name}

    def native_capture(self):
        """Provider snapshot handle, or None when the provider has none we use."""
        return None

    def close(self):
        pass

    def check(self, argv, timeout=60, env=None, cwd=None):
        code, out, err = self.exec(argv, timeout=timeout, env=env, cwd=cwd)
        if code != 0:
            detail = (err or out).decode("utf-8", "replace").strip()
            raise CommandError("%s exited %s in %s sandbox: %s" % (argv[0], code, self.name, detail[-2000:]))
        return out

    def start_detached(self, argv, env, cwd):
        token = secrets.token_hex(6)
        spec = "%s/abra-start-%s.json" % (self.tmp_dir(), token)
        log = "%s/abra-start-%s.log" % (self.tmp_dir(), token)
        with tempfile.NamedTemporaryFile("w", suffix=".json") as local:
            json.dump({"argv": list(argv), "cwd": cwd, "env": env, "log": log}, local)
            local.flush()
            self.put(local.name, spec)
        code, out, err = self.run(["python3", "-c", LAUNCHER, spec], 30, None, None)
        return code, out, err

    def put_tree(self, local_dir, remote_dir, exclude=()):
        """Copy a local directory into the sandbox. exclude lists relative paths to skip."""
        archive = "%s/abra-tree-%s.tar" % (self.tmp_dir(), secrets.token_hex(6))
        with tempfile.NamedTemporaryFile(suffix=".tar") as local:
            pack_tree(local_dir, local.name, exclude)
            self.put(local.name, archive)
        self.check(["sh", "-c", 'mkdir -p "$1" && tar -C "$1" -xf "$2" && rm -f "$2"', "sh", remote_dir, archive], timeout=600)

    def get_tree(self, remote_dir, local_dir):
        """Copy a sandbox directory to local_dir, which is created if missing."""
        archive = "%s/abra-tree-%s.tar" % (self.tmp_dir(), secrets.token_hex(6))
        # COPYFILE_DISABLE keeps macOS tar (local driver) from adding ._ entries.
        self.check(["tar", "-C", remote_dir, "-cf", archive, "."], timeout=600, env={"COPYFILE_DISABLE": "1"})
        try:
            with tempfile.NamedTemporaryFile(suffix=".tar") as local:
                self.get(archive, local.name)
                unpack_tree(local.name, local_dir)
        finally:
            self.exec(["rm", "-f", archive])

    def restore_tree(self, local_dir, remote_dir, exclude=(), replace=False):
        """Restore exactly this tree; nonempty destinations require explicit replacement."""
        remote = "%s/abra-restore-%s" % (self.tmp_dir(), secrets.token_hex(6))
        try:
            with tempfile.NamedTemporaryFile(suffix=".tar") as local:
                pack_tree(local_dir, local.name, exclude)
                self.put(local.name, remote + ".tar")
            self.put(tree.__file__, remote + ".py")
            self.check(["python3", remote + ".py", remote + ".tar", remote_dir,
                        "replace" if replace else "empty"], timeout=600)
        finally:
            self.exec(["rm", "-f", remote + ".tar", remote + ".py"])


def shell_command(argv, env=None, cwd=None):
    """One sh command line for drivers that only take a string."""
    parts = []
    if cwd:
        parts.append("cd %s &&" % shlex.quote(cwd))
    if env:
        parts.append("env " + " ".join("%s=%s" % (key, shlex.quote(value)) for key, value in sorted(env.items())))
    parts.append(shlex.join(argv))
    return " ".join(parts)


def _anonymous(info):
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def pack_tree(local_dir, archive, exclude=()):
    local_dir = os.path.realpath(local_dir)
    skipped = {os.path.normpath(path) for path in exclude}
    with tarfile.open(archive, "w") as tar:
        for base, dirs, files in os.walk(local_dir):
            relative_base = os.path.relpath(base, local_dir)
            keep = []
            for name in dirs:
                relative = os.path.normpath(os.path.join(relative_base, name))
                if relative in skipped:
                    continue
                keep.append(name)
                tar.add(os.path.join(base, name), arcname=relative, recursive=False, filter=_anonymous)
            dirs[:] = keep
            for name in files:
                relative = os.path.normpath(os.path.join(relative_base, name))
                if relative in skipped:
                    continue
                tar.add(os.path.join(base, name), arcname=relative, recursive=False, filter=_anonymous)
