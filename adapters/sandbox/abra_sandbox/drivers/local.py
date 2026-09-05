"""Runs commands on this machine with temp files under one root. Tests only."""

import os
import shutil
import subprocess
import tempfile

from .base import Driver


class LocalDriver(Driver):
    name = "local"

    def __init__(self, root=None, **_):
        self.root = os.path.realpath(root or tempfile.mkdtemp(prefix="abra-sandbox-"))
        os.makedirs(self.tmp_dir(), exist_ok=True)

    def tmp_dir(self):
        return os.path.join(self.root, "tmp")

    def run(self, argv, timeout, env, cwd):
        full_env = dict(os.environ)
        full_env.update(env or {})
        try:
            completed = subprocess.run(argv, cwd=cwd, env=full_env, timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return 124, b"", b"timed out"
        return completed.returncode, completed.stdout, completed.stderr

    def put(self, local_file, remote_file, mode=0o600):
        os.makedirs(os.path.dirname(remote_file), exist_ok=True)
        shutil.copyfile(local_file, remote_file)
        os.chmod(remote_file, mode)

    def get(self, remote_file, local_file):
        shutil.copyfile(remote_file, local_file)

    def facts(self):
        return {"provider": "local", "root": self.root}
