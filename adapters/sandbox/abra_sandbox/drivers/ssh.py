"""ssh/scp driver for any Linux box we hold a key for, including Firecracker guests."""

import os
import subprocess

from .base import CommandError, Driver, shell_command


class SshDriver(Driver):
    name = "ssh"

    def __init__(self, host, user="root", key=None, port="22", known_hosts=None, **_):
        self.host = host
        self.user = user
        self.key = key
        self.known_hosts = os.path.abspath(os.path.expanduser(known_hosts)) if known_hosts else None
        self.port = str(port)
        self.target = "%s@%s" % (user, host)

    def _base(self, program, port_flag):
        argv = [program, "-o", "StrictHostKeyChecking=yes",
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", port_flag, self.port]
        if self.known_hosts:
            escaped = self.known_hosts.replace("\\", "\\\\").replace('"', '\\"')
            argv += ["-o", 'UserKnownHostsFile="%s"' % escaped]
        if self.key:
            argv += ["-i", self.key]
        return argv

    def run(self, argv, timeout, env, cwd):
        command = self._base("ssh", "-p") + [self.target, shell_command(argv, env, cwd)]
        try:
            completed = subprocess.run(command, timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return 124, b"", b"timed out"
        return completed.returncode, completed.stdout, completed.stderr

    def put(self, local_file, remote_file, mode=0o600):
        self.check(["mkdir", "-p", os.path.dirname(remote_file)])
        self._copy(local_file, "%s:%s" % (self.target, remote_file))
        self.check(["chmod", "%o" % mode, remote_file])

    def get(self, remote_file, local_file):
        self._copy("%s:%s" % (self.target, remote_file), local_file)

    def _copy(self, source, destination):
        completed = subprocess.run(self._base("scp", "-P") + [source, destination], capture_output=True)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).decode("utf-8", "replace").strip()
            raise CommandError("scp exited %s: %s" % (completed.returncode, detail))

    def facts(self):
        return {"provider": "ssh", "host": self.host, "port": int(self.port), "user": self.user}
