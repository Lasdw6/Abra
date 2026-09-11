import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ADAPTER = Path(__file__).resolve().parents[1] / "files.py"


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "existing-projects"
        self.root.mkdir()
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def call(self, verb, **fields):
        request = {"protocol": "abra-adapter/1", "request_id": "test", "verb": verb, **fields}
        result = subprocess.run([str(ADAPTER)], input=json.dumps(request) + "\n", text=True, capture_output=True, env={**os.environ, "ABRA_FILES_ROOT": str(self.root)}, check=True)
        response = json.loads(result.stdout)
        self.assertEqual(response["request_id"], "test")
        return response

    def capture(self, source):
        self.counter += 1
        stage = self.base / f"stage-{self.counter}"
        stage.mkdir()
        return self.call("export", source=source, staging_dir=str(stage))

    def test_roundtrip_to_chosen_existing_folder_and_no_overwrite(self):
        (self.root / "note.txt").write_bytes(b"hello\x00world")
        folder = self.root / "project"
        folder.mkdir()
        (folder / "run.sh").write_text("echo hi\n")
        (folder / "run.sh").chmod(0o755)
        (folder / "empty").mkdir()
        target = self.base / "existing-destination"
        target.mkdir()
        (target / "unrelated").write_text("keep")
        for item in self.call("inventory")["items"]:
            exported = self.capture(item["source"])
            self.assertTrue(exported["ok"], exported)
            imported = self.call("import", materialized_files=exported["files_path"], destination=str(target))
            self.assertTrue(imported["ok"], imported)
            self.assertEqual(imported["result"]["destination"], str(target))
            self.assertEqual(imported["result"]["paths"], [str(target / item["label"])])
            repeated = self.call("import", materialized_files=exported["files_path"], destination=str(target))
            self.assertEqual(repeated["error"]["code"], "conflict")
        self.assertEqual((target / "note.txt").read_bytes(), b"hello\x00world")
        self.assertEqual((target / "project/run.sh").stat().st_mode & 0o777, 0o755)
        self.assertTrue((target / "project/empty").is_dir())
        self.assertEqual((target / "unrelated").read_text(), "keep")
        self.assertEqual((self.root / "note.txt").read_bytes(), b"hello\x00world")
        self.assertFalse(any(p.name.startswith(("Received-", ".abra-incoming-")) for p in target.iterdir()))

    def test_dynamic_roots_browsing_and_all_mode(self):
        other = self.base / "any-other-folder"
        other.mkdir()
        (other / "note").write_text("data")
        options = {"mode": "selected", "paths": json.dumps([str(self.root), str(other)])}
        roots = self.call("inventory", options=options)
        self.assertEqual(roots["context"]["path"], None)
        self.assertEqual({i["source"]["absolute_path"] for i in roots["items"]}, {str(self.root), str(other)})
        opened = self.call("inventory", options={**options, "browse_path": str(other)})
        self.assertEqual(opened["context"]["path"], str(other))
        self.assertIsNone(opened["context"]["parent"])
        self.assertEqual(opened["items"][0]["label"], "note")
        self.assertTrue(self.capture(opened["items"][0]["source"])["ok"])
        outside = self.call("inventory", options={**options, "browse_path": str(self.base)})
        self.assertIn("outside the selected", outside["error"])
        all_folders = self.call("inventory", options={"mode": "all", "browse_path": str(self.base)})
        self.assertTrue(all_folders["ok"])
        self.assertEqual(all_folders["context"]["parent"], str(self.base.parent))
        self.assertFalse((self.base / "Abra").exists())
        alias = self.base / "folder-alias"
        alias.symlink_to(other, target_is_directory=True)
        via_alias = self.call("inventory", options={"mode": "all", "browse_path": str(alias)})
        self.assertTrue(via_alias["ok"], via_alias)
        self.assertTrue(self.capture(via_alias["items"][0]["source"])["ok"])

    def test_missing_path_reports_error_and_pagination_reaches_all_items(self):
        self.root.rmdir()
        missing = self.call("inventory")
        self.assertIn("No such file", missing["error"])
        self.assertEqual(missing["context"]["browser"], "filesystem")
        self.assertFalse(self.root.exists())
        self.root.mkdir()
        for i in range(260):
            (self.root / str(i)).touch()
        first = self.call("inventory")
        self.assertEqual(len(first["items"]), 256)
        second = self.call("inventory", options={"offset": str(first["context"]["next_offset"])})
        self.assertIsNone(second["context"]["next_offset"])
        self.assertEqual(len({i["id"] for i in first["items"] + second["items"]}), 260)

    def test_inventory_sorts_folders_first_and_names_naturally(self):
        for name in ("file10", "file2", "Alpha"):
            (self.root / name).touch()
        for name in ("folder10", "folder2"):
            (self.root / name).mkdir()
        labels = [item["label"] for item in self.call("inventory")["items"]]
        self.assertEqual(labels, ["folder2", "folder10", "Alpha", "file2", "file10"])

    def test_stale_modified_deleted_and_parent_replaced(self):
        file = self.root / "note"
        file.write_text("old")
        first = self.call("inventory")["items"][0]
        file.write_text("new content")
        second = self.call("inventory")["items"][0]
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(self.capture(first["source"])["error"]["code"], "stale_source")
        file.unlink()
        self.assertEqual(self.capture(second["source"])["error"]["code"], "not_found")
        file.touch()
        third = self.call("inventory")["items"][0]
        self.root.rename(self.base / "old")
        self.root.mkdir()
        (self.root / "note").touch()
        self.assertEqual(self.capture(third["source"])["error"]["code"], "stale_source")

    def test_symlinks_special_files_traversal_and_cleanup(self):
        folder = self.root / "folder"
        folder.mkdir()
        (folder / "escape").symlink_to(self.base)
        (self.root / "link").symlink_to(self.base)
        os.mkfifo(self.root / "pipe")
        items = self.call("inventory")["items"]
        self.assertEqual([i["label"] for i in items], ["folder"])
        self.assertFalse(self.capture(items[0]["source"])["ok"])
        source = {**items[0]["source"], "path": "../outside"}
        self.assertEqual(self.capture(source)["error"]["code"], "invalid_request")
        target = self.base / "target"
        target.mkdir()
        result = self.call("import", materialized_files=str(folder), destination=str(target))
        self.assertFalse(result["ok"])
        self.assertEqual(list(target.iterdir()), [])

    def test_size_limit_and_display_name(self):
        file = self.root / "large"
        with file.open("wb") as stream:
            stream.truncate(1024 * 1024 * 1024 + 1)
        item = self.call("inventory")["items"][0]
        self.assertEqual(self.capture(item["source"])["error"]["code"], "limit_exceeded")
        file.unlink()
        (self.root / "line\nbreak").touch()
        item = self.call("inventory")["items"][0]
        self.assertEqual(item["label"], "line break")
        self.assertTrue(self.capture(item["source"])["ok"])

    def test_destination_required_and_collision_symlink_preserved(self):
        materialized = self.base / "materialized"
        materialized.mkdir()
        (materialized / "file").write_text("data")
        for destination in (None, str(materialized), {"type": "shared-folder"}, "relative/path"):
            result = self.call("import", materialized_files=str(materialized), destination=destination)
            self.assertFalse(result["ok"], result)
        target = self.base / "target"
        target.mkdir()
        (target / "file").symlink_to(self.base / "nonexistent")
        result = self.call("import", materialized_files=str(materialized), destination=str(target))
        self.assertEqual(result["error"]["code"], "conflict")
        self.assertTrue((target / "file").is_symlink())


if __name__ == "__main__":
    unittest.main()
