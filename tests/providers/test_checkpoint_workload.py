#!/usr/bin/env python3
"""Subprocess tests for the provider checkpoint workload fixture."""

import json
import select
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


FIXTURE = Path(__file__).parent / "fixtures" / "checkpoint_workload.py"


class CheckpointWorkloadTest(unittest.TestCase):
    def command(self, *arguments, check=True):
        completed = subprocess.run(
            [sys.executable, str(FIXTURE), *map(str, arguments)],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if check and completed.returncode != 0:
            self.fail(
                "fixture failed with exit %d:\nstdout: %s\nstderr: %s"
                % (completed.returncode, completed.stdout, completed.stderr)
            )
        return completed

    def run_until(self, workspace, task_count):
        result = self.command("run", "--workspace", workspace, "--until", task_count)
        return json.loads(result.stdout)

    def assert_verification_fails(self, workspace, expected):
        result = self.command(
            "verify", "--workspace", workspace, "--expected", expected, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verification failed", result.stderr)

    def test_held_checkpoint_resumes_to_uninterrupted_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference = root / "reference"
            resumed = root / "resumed"
            reference_status = self.run_until(reference, 100)

            process = subprocess.Popen(
                [
                    sys.executable,
                    str(FIXTURE),
                    "run",
                    "--workspace",
                    str(resumed),
                    "--until",
                    "40",
                    "--hold",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                readable, _, _ = select.select([process.stdout], [], [], 10)
                self.assertTrue(readable, "held workload did not announce readiness")
                ready = json.loads(process.stdout.readline())
                self.assertEqual(ready["event"], "ready")
                self.assertEqual(ready["completed"], 40)
                self.assertTrue(ready["integrity_ok"])
                self.assertIsNone(process.poll(), "held workload exited after readiness")
            finally:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)

            resumed_status = self.run_until(resumed, 100)
            self.assertEqual(resumed_status, reference_status)
            self.assertEqual(resumed_status["tool_call_count"], 100)
            verified = self.command(
                "verify", "--workspace", resumed, "--expected", 100
            )
            self.assertEqual(json.loads(verified.stdout), reference_status)

    def test_verify_rejects_generated_output_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workload"
            self.run_until(workspace, 5)
            output = workspace / "outputs" / "task-000003.json"
            output.write_bytes(output.read_bytes() + b"corrupt\n")
            self.assert_verification_fails(workspace, 5)

    def test_verify_rejects_duplicate_ledger_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workload"
            self.run_until(workspace, 5)
            ledger = workspace / "simulated_tool_calls.jsonl"
            first_line = ledger.read_bytes().splitlines(keepends=True)[0]
            with ledger.open("ab") as ledger_file:
                ledger_file.write(first_line)
            self.assert_verification_fails(workspace, 5)

    def test_verify_rejects_missing_database_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workload"
            self.run_until(workspace, 5)
            connection = sqlite3.connect(workspace / "state.sqlite3")
            try:
                connection.execute("DELETE FROM tasks WHERE task_id = 3")
                connection.commit()
            finally:
                connection.close()
            self.assert_verification_fails(workspace, 5)

    def test_verify_rejects_corrupt_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workload"
            self.run_until(workspace, 5)
            (workspace / "state.sqlite3").write_bytes(b"not a sqlite database\n")
            result = self.command(
                "verify", "--workspace", workspace, "--expected", 5, check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("verification failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
