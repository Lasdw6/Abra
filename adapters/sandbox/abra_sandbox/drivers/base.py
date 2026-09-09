"""Driver interface plus tree transfer through a temporary remote Abra."""

import json
import os
import posixpath
import secrets
import shlex
import tarfile
import tempfile

from ..tree import unpack_tree


class CommandError(RuntimeError):
    pass


class Driver:
    """One sandbox. Paths are sandbox paths; bytes move through put/get only."""

    name = "base"

    def configure_runtime(self, local_binary):
        """Choose the architecture-compatible Abra binary uploaded on first use."""
        binary = os.path.realpath(local_binary)
        if not os.path.isfile(binary):
            raise FileNotFoundError("remote Abra binary does not exist: %s" % binary)
        configured = getattr(self, "_runtime_local", None)
        if configured and configured != binary:
            raise RuntimeError("sandbox driver is already configured with another Abra binary")
        self._runtime_local = binary

    def runtime(self):
        """Return the remote Abra path, uploading it into an owned directory once."""
        existing = getattr(self, "_runtime_remote", None)
        if existing:
            return existing
        local = getattr(self, "_runtime_local", None)
        if not local:
            raise RuntimeError("sandbox driver needs configure_runtime() before tree or detached operations")
        parent = self.tmp_dir().rstrip("/") or "/"
        marker = posixpath.join(parent, "abra-runner-")
        prefix = marker + "XXXXXXXXXXXX"
        owned = _last_line(self.check(["mktemp", "-d", prefix]))
        suffix = owned[len(marker):] if owned.startswith(marker) else ""
        if (len(suffix) != 12 or not suffix.isascii() or not suffix.isalnum()
                or posixpath.normpath(owned) != owned):
            raise RuntimeError("mktemp returned an invalid remote Abra directory: %r" % owned)
        remote = owned + "/abra"
        self._runtime_dir = owned
        try:
            self.put(local, remote, 0o700)
        except Exception:
            self.run(["rm", "-rf", owned], 30, None, None)
            self._runtime_dir = None
            raise
        self._runtime_remote = remote
        return remote

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
        owned = getattr(self, "_runtime_dir", None)
        self._runtime_remote = None
        self._runtime_dir = None
        if owned:
            self.run(["rm", "-rf", owned], 30, None, None)

    def check(self, argv, timeout=60, env=None, cwd=None):
        code, out, err = self.exec(argv, timeout=timeout, env=env, cwd=cwd)
        if code != 0:
            detail = (err or out).decode("utf-8", "replace").strip()
            raise CommandError("%s exited %s in %s sandbox: %s" % (argv[0], code, self.name, detail[-2000:]))
        return out

    def start_detached(self, argv, env, cwd):
        token = secrets.token_hex(6)
        runtime = self.runtime()
        owned = os.path.dirname(runtime)
        spec = "%s/start-%s.json" % (owned, token)
        log = "%s/start-%s.log" % (owned, token)
        with tempfile.NamedTemporaryFile("w", suffix=".json") as local:
            json.dump({"argv": list(argv), "cwd": cwd, "env": env, "log": log}, local)
            local.flush()
            self.put(local.name, spec)
        code, out, err = self.run([runtime, "sandbox-helper", "start-detached", "--spec", spec], 30, None, None)
        if code == 0:
            try:
                out = (str(json.loads(_last_line(out))["pid"]) + "\n").encode()
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                return 1, b"", ("invalid sandbox-helper output: %s" % error).encode()
        return code, out, err

    def put_tree(self, local_dir, remote_dir, exclude=()):
        """Copy a local directory into the sandbox. exclude lists relative paths to skip."""
        runtime = self.runtime()
        archive = "%s/tree-%s.tar" % (os.path.dirname(runtime), secrets.token_hex(6))
        with tempfile.NamedTemporaryFile(suffix=".tar") as local:
            pack_tree(local_dir, local.name, exclude)
            self.put(local.name, archive)
        try:
            self.check([runtime, "sandbox-helper", "extract", "--archive", archive,
                        "--destination", remote_dir], timeout=600)
        finally:
            self.exec(["rm", "-f", archive])

    def get_tree(self, remote_dir, local_dir):
        """Copy a sandbox directory to local_dir, which is created if missing."""
        runtime = self.runtime()
        archive = "%s/tree-%s.tar" % (os.path.dirname(runtime), secrets.token_hex(6))
        self.check([runtime, "sandbox-helper", "pack", "--source", remote_dir,
                    "--archive", archive], timeout=600)
        try:
            with tempfile.NamedTemporaryFile(suffix=".tar") as local:
                self.get(archive, local.name)
                unpack_tree(local.name, local_dir)
        finally:
            self.exec(["rm", "-f", archive])

    def restore_tree(self, local_dir, remote_dir, exclude=(), replace=False):
        """Restore exactly this tree; nonempty destinations require explicit replacement."""
        runtime = self.runtime()
        remote = "%s/restore-%s.tar" % (os.path.dirname(runtime), secrets.token_hex(6))
        try:
            with tempfile.NamedTemporaryFile(suffix=".tar") as local:
                pack_tree(local_dir, local.name, exclude)
                self.put(local.name, remote)
            command = [runtime, "sandbox-helper", "restore", "--archive", remote,
                       "--workspace", remote_dir]
            if replace:
                command.append("--replace")
            self.check(command, timeout=600)
        finally:
            self.exec(["rm", "-f", remote])


def _last_line(output):
    lines = [line for line in output.decode("utf-8", "replace").splitlines() if line.strip()]
    return lines[-1] if lines else ""


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
