import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from abra_sandbox.drivers.base import CommandError, pack_tree
from abra_sandbox.drivers.local import LocalDriver
from abra_sandbox.tree import unpack_tree


class TreeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "tree.tar"
        self.destination = self.root / "destination"
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.outside / "marker").write_text("keep")

    def archive_entries(self, entries):
        with tarfile.open(self.archive, "w") as tar:
            for name, kind, value in entries:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                if kind == tarfile.REGTYPE:
                    payload = value.encode()
                    entry.size = len(payload)
                    tar.addfile(entry, io.BytesIO(payload))
                else:
                    entry.linkname = value
                    tar.addfile(entry)

    def test_hostile_archives_are_rejected_before_writing(self):
        for entries in [
            [("../outside/marker", tarfile.REGTYPE, "bad")],
            [(str(self.outside / "marker"), tarfile.REGTYPE, "bad")],
            [("link", tarfile.SYMTYPE, str(self.outside)), ("link/marker", tarfile.REGTYPE, "bad")],
            [("link", tarfile.SYMTYPE, "../outside"), ("link/marker", tarfile.REGTYPE, "bad")],
            [("marker", tarfile.LNKTYPE, str(self.outside / "marker"))],
            [("marker", tarfile.LNKTYPE, "../outside/marker")],
            [("dir", tarfile.SYMTYPE, "."), ("dir/marker", tarfile.REGTYPE, "bad")],
            [("a", tarfile.SYMTYPE, "b"), ("b", tarfile.SYMTYPE, ".")],
            [("a", tarfile.SYMTYPE, "b/../ok"), ("b", tarfile.SYMTYPE, ".")],
            [("same", tarfile.REGTYPE, "first"), ("same", tarfile.REGTYPE, "second")],
            [("pipe", tarfile.FIFOTYPE, "")],
        ]:
            with self.subTest(entries=entries):
                self.archive_entries(entries)
                with self.assertRaises(ValueError):
                    unpack_tree(self.archive, self.destination)
                self.assertEqual("keep", (self.outside / "marker").read_text())
                self.assertEqual([], list(self.destination.iterdir()))

    def test_regular_files_empty_dirs_and_internal_links_round_trip(self):
        source = self.root / "source"
        (source / "empty").mkdir(parents=True)
        (source / "bin").mkdir()
        (source / "script").write_text("hello")
        (source / "script").chmod(0o755)
        (source / "bin/run").symlink_to("../script")
        os.link(source / "script", source / "hardlink")
        (source / "..hidden").write_text("valid filename")
        pack_tree(source, self.archive)
        unpack_tree(self.archive, self.destination)
        self.assertEqual("hello", (self.destination / "bin/run").read_text())
        self.assertEqual("hello", (self.destination / "hardlink").read_text())
        self.assertTrue((self.destination / "empty").is_dir())
        self.assertEqual(0o755, (self.destination / "script").stat().st_mode & 0o777)
        self.assertTrue((self.destination / "..hidden").is_file())

    def test_existing_destinations_cannot_redirect_extraction(self):
        self.archive_entries([("marker", tarfile.REGTYPE, "bad")])
        self.destination.symlink_to(self.outside)
        with self.assertRaisesRegex(ValueError, "symlink"):
            unpack_tree(self.archive, self.destination)
        self.destination.unlink()
        self.destination.mkdir()
        (self.destination / "marker").symlink_to(self.outside / "marker")
        with self.assertRaisesRegex(ValueError, "empty"):
            unpack_tree(self.archive, self.destination)
        self.assertEqual("keep", (self.outside / "marker").read_text())

    def test_restore_refuses_overlay_and_explicit_replace_removes_stale_files(self):
        source = self.root / "source"
        source.mkdir()
        (source / "current").write_text("snapshot")
        self.destination.mkdir()
        (self.destination / "old").write_text("stale")
        (self.destination / "link").symlink_to(self.outside)
        driver = LocalDriver(root=str(self.root / "driver"))
        with self.assertRaisesRegex(CommandError, "--replace-workspace"):
            driver.restore_tree(str(source), str(self.destination))
        self.assertEqual("stale", (self.destination / "old").read_text())
        self.assertFalse((self.destination / "current").exists())
        driver.restore_tree(str(source), str(self.destination), replace=True)
        self.assertEqual(["current"], os.listdir(self.destination))
        self.assertEqual("keep", (self.outside / "marker").read_text())
        self.assertEqual([], os.listdir(driver.tmp_dir()))

    def test_invalid_archive_preserves_workspace_and_cleans_remote_temps(self):
        source = self.root / "source"
        source.mkdir()
        (source / "escape").symlink_to(self.outside)
        self.destination.mkdir()
        (self.destination / "old").write_text("keep")
        driver = LocalDriver(root=str(self.root / "driver"))
        with self.assertRaisesRegex(CommandError, "absolute target"):
            driver.restore_tree(str(source), str(self.destination), replace=True)
        self.assertEqual(["old"], os.listdir(self.destination))
        self.assertEqual("keep", (self.destination / "old").read_text())
        self.assertEqual([], os.listdir(driver.tmp_dir()))

    def test_restore_rejects_symlink_and_root_destinations(self):
        source = self.root / "source"
        source.mkdir()
        self.destination.symlink_to(self.outside)
        driver = LocalDriver(root=str(self.root / "driver"))
        for destination in (str(self.destination), "/"):
            with self.assertRaisesRegex(CommandError, "non-root directory"):
                driver.restore_tree(str(source), destination, replace=True)
        self.assertEqual("keep", (self.outside / "marker").read_text())


if __name__ == "__main__":
    unittest.main()
