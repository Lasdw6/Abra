import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from abra_sandbox import coordinator
from abra_sandbox.drivers.base import Driver


class RecordingDriver(Driver):
    name = "recording"

    def __init__(self):
        self.commands = []
        self.uploads = []
        self._runtime_local = "/local/abra"
        self._runtime_remote = "/owned/abra"
        self._runtime_dir = "/owned"

    def run(self, argv, timeout, env, cwd):
        self.commands.append(list(argv))
        if "start-detached" in argv:
            return 0, b'{"pid":321}\n', b""
        return 0, b'{}\n', b""

    def put(self, local_file, remote_file, mode=0o600):
        self.uploads.append((local_file, remote_file, mode))

    def get(self, remote_file, local_file):
        with tarfile.open(local_file, "w"):
            pass


class MktempDriver(Driver):
    name = "mktemp"

    def __init__(self, output):
        self.output = output
        self.commands = []
        self.uploads = []

    def run(self, argv, timeout, env, cwd):
        self.commands.append(list(argv))
        if argv[0] == "mktemp":
            return 0, self.output, b""
        return 0, b"", b""

    def put(self, local_file, remote_file, mode=0o600):
        self.uploads.append((local_file, remote_file, mode))


class ProbeDriver:
    def __init__(self, system=b"Linux\n", machine=b"x86_64\n"):
        self.system = system
        self.machine = machine
        self.configured = None

    def check(self, argv):
        return self.system if argv[-1] == "-s" else self.machine

    def configure_runtime(self, binary):
        self.configured = binary


class RuntimeTest(unittest.TestCase):
    def test_valid_mktemp_directory_is_removed_on_close(self):
        with tempfile.NamedTemporaryFile() as binary:
            driver = MktempDriver(b"/tmp/abra-runner-Ab12Cd34Ef56\n")
            driver.configure_runtime(binary.name)
            self.assertEqual("/tmp/abra-runner-Ab12Cd34Ef56/abra", driver.runtime())
            driver.close()
        self.assertEqual([(os.path.realpath(binary.name), "/tmp/abra-runner-Ab12Cd34Ef56/abra", 0o700)],
                         driver.uploads)
        self.assertIn(["rm", "-rf", "/tmp/abra-runner-Ab12Cd34Ef56"], driver.commands)

    def test_invalid_mktemp_output_is_never_retained_or_removed(self):
        with tempfile.NamedTemporaryFile() as binary:
            for output in (b"/\n", b"/tmp/other\n", b"/tmp/abra-runner-short\n",
                           b"/tmp/abra-runner-abcdefghijkl/../victim\n"):
                with self.subTest(output=output):
                    driver = MktempDriver(output)
                    driver.configure_runtime(binary.name)
                    with self.assertRaisesRegex(RuntimeError, "invalid remote Abra directory"):
                        driver.runtime()
                    driver.close()
                    self.assertEqual([], driver.uploads)
                    self.assertFalse(any(command[:2] == ["rm", "-rf"] for command in driver.commands))

    def test_remote_operations_use_abra_without_python_or_system_tar(self):
        driver = RecordingDriver()
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            (source / "file").write_text("data")
            driver.put_tree(str(source), "/remote/new")
            driver.get_tree("/remote/source", str(Path(temp) / "pulled"))
            driver.restore_tree(str(source), "/remote/workspace", replace=True)
            code, out, _ = driver.start_detached(["service", "--flag"], {"A": "B"}, "/remote/workspace")
        self.assertEqual(0, code)
        self.assertEqual(b"321\n", out)
        helper_commands = [command for command in driver.commands if command and command[0] == "/owned/abra"]
        self.assertEqual({"extract", "pack", "restore", "start-detached"},
                         {command[2] for command in helper_commands})
        self.assertFalse(any(command[0] in ("python", "python3", "tar") for command in driver.commands))

    def test_wrong_architecture_fails_before_driver_configuration(self):
        with tempfile.NamedTemporaryFile() as binary:
            header = bytearray(64)
            header[:4] = b"\x7fELF"
            header[5] = 1
            header[18:20] = (183).to_bytes(2, "little")
            binary.write(header)
            binary.flush()
            driver = ProbeDriver()
            with self.assertRaisesRegex(RuntimeError, "architecture mismatch"):
                coordinator.configure_runtime(driver, binary.name)
        self.assertIsNone(driver.configured)

    def test_matching_binary_is_configured(self):
        with tempfile.NamedTemporaryFile() as binary:
            header = bytearray(64)
            header[:4] = b"\x7fELF"
            header[5] = 1
            header[18:20] = (62).to_bytes(2, "little")
            binary.write(header)
            binary.flush()
            driver = ProbeDriver()
            coordinator.configure_runtime(driver, binary.name)
        self.assertEqual(binary.name, driver.configured)


if __name__ == "__main__":
    unittest.main()
