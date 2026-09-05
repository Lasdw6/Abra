from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from abra_sandbox.drivers.ssh import SshDriver
from abra_sandbox.drivers.base import CommandError


class SshTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ssh"), "OpenSSH is required")
    def test_openssh_enforces_host_verification_even_with_permissive_user_config(self):
        with tempfile.TemporaryDirectory(prefix="abra ssh ") as directory:
            config = Path(directory) / "config"
            config.write_text("Host *\n  StrictHostKeyChecking no\n")
            known_hosts = str(Path(directory) / "known hosts")
            driver = SshDriver(host="example.invalid", known_hosts=known_hosts)
            # Parse the same -o options for ssh and scp using OpenSSH itself.
            for program, port_flag in (("ssh", "-p"), ("scp", "-P")):
                argv = driver._base(program, port_flag)
                argv[0] = "ssh"
                argv[argv.index(port_flag)] = "-p"
                result = subprocess.run(argv + ["-G", "-F", str(config), driver.target],
                                        capture_output=True, text=True, check=True)
                options = dict(line.split(" ", 1) for line in result.stdout.splitlines())
                self.assertEqual("true", options["stricthostkeychecking"])
                self.assertIn(known_hosts, options["userknownhostsfile"])

    def test_default_preserves_normal_known_hosts_configuration(self):
        driver = SshDriver(host="example.invalid")
        for program, port_flag in (("ssh", "-p"), ("scp", "-P")):
            argv = driver._base(program, port_flag)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertFalse(any(arg.startswith("UserKnownHostsFile=") for arg in argv))

    def test_host_key_failure_is_returned_without_retrying_insecurely(self):
        driver = SshDriver(host="example.invalid")
        with patch("abra_sandbox.drivers.ssh.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 255, b"", b"Host key verification failed.")
            code, _, err = driver.run(["true"], 10, None, None)
            self.assertEqual(255, code)
            self.assertIn(b"Host key verification failed", err)
            run.assert_called_once()

    def test_copy_exposes_host_key_failure(self):
        driver = SshDriver(host="example.invalid")
        with patch("abra_sandbox.drivers.ssh.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 255, b"", b"Host key verification failed.")
            with self.assertRaisesRegex(CommandError, "Host key verification failed"):
                driver.get("/workspace/file", "/unused")
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
