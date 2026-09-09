#!/usr/bin/env python3
"""Deterministic stateful workload for provider checkpoint portability tests."""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path


SCHEMA_VERSION = 1
MAX_TASKS = 10_000
DATABASE_NAME = "state.sqlite3"
LEDGER_NAME = "simulated_tool_calls.jsonl"
OUTPUT_DIRECTORY = "outputs"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def task_record(task_id):
    input_text = "task-%06d" % task_id
    arguments = {
        "operation": "sha256",
        "payload": input_text,
        "seed": "abra-checkpoint-workload-v1",
    }
    result_digest = hashlib.sha256(canonical_json(arguments).encode("ascii")).hexdigest()
    call_id = "simulated-call-%06d" % task_id
    output = {
        "result_digest": result_digest,
        "simulated_call_id": call_id,
        "task_id": task_id,
    }
    output_bytes = (canonical_json(output) + "\n").encode("ascii")
    output_name = "task-%06d.json" % task_id
    ledger = {
        "arguments": arguments,
        "call_id": call_id,
        "kind": "simulated_tool_call",
        "result": {"sha256": result_digest},
        "task_id": task_id,
        "tool": "deterministic_hash",
    }
    ledger_json = canonical_json(ledger)
    return {
        "task_id": task_id,
        "input_text": input_text,
        "arguments_json": canonical_json(arguments),
        "result_digest": result_digest,
        "output_name": output_name,
        "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "ledger_json": ledger_json,
        "output_bytes": output_bytes,
    }


def row_dict(row):
    return {
        "task_id": row[0],
        "input_text": row[1],
        "arguments_json": row[2],
        "result_digest": row[3],
        "output_name": row[4],
        "output_sha256": row[5],
        "ledger_json": row[6],
    }


def stored_record(record):
    return {key: value for key, value in record.items() if key != "output_bytes"}


def checked_workspace(raw_path, create=False):
    workspace = Path(raw_path).expanduser().absolute()
    if workspace.exists():
        if workspace.is_symlink() or not workspace.is_dir():
            raise ValueError("workspace must be a real directory: %s" % workspace)
    elif create:
        workspace.mkdir(parents=True)
    return workspace


def reject_symlink(path, description):
    if path.is_symlink():
        raise ValueError("%s must not be a symbolic link: %s" % (description, path))


def write_atomic(path, data):
    reject_symlink(path, "workload file")
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".%s." % path.name, dir=str(path.parent), delete=False
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def create_database(path):
    reject_symlink(path, "database")
    connection = sqlite3.connect(str(path))
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                task_id INTEGER PRIMARY KEY,
                input_text TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                result_digest TEXT NOT NULL,
                output_name TEXT NOT NULL UNIQUE,
                output_sha256 TEXT NOT NULL,
                ledger_json TEXT NOT NULL
            )
            """
        )
        connection.execute("PRAGMA user_version=%d" % SCHEMA_VERSION)
        connection.commit()
    finally:
        connection.close()


def initialize_workspace(workspace):
    database = workspace / DATABASE_NAME
    ledger = workspace / LEDGER_NAME
    outputs = workspace / OUTPUT_DIRECTORY
    reject_symlink(database, "database")
    reject_symlink(ledger, "ledger")
    reject_symlink(outputs, "output directory")
    if outputs.exists() and not outputs.is_dir():
        raise ValueError("output path is not a directory: %s" % outputs)
    outputs.mkdir(exist_ok=True)
    if not database.exists():
        create_database(database)
    if not ledger.exists():
        write_atomic(ledger, b"")


def read_database(database):
    reject_symlink(database, "database")
    if not database.is_file():
        raise ValueError("missing database: %s" % database)
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if integrity != [("ok",)]:
            raise ValueError("database integrity check failed: %s" % integrity)
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
            raise ValueError("unsupported database schema version: %s" % version)
        rows = connection.execute(
            """
            SELECT task_id, input_text, arguments_json, result_digest,
                   output_name, output_sha256, ledger_json
            FROM tasks ORDER BY task_id
            """
        ).fetchall()
    finally:
        connection.close()
    return [row_dict(row) for row in rows]


def framed_hash(hasher, label, data):
    label_bytes = label.encode("utf-8")
    hasher.update(len(label_bytes).to_bytes(4, "big"))
    hasher.update(label_bytes)
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)


def workload_digest(rows, ledger_bytes, output_files):
    hasher = hashlib.sha256()
    hasher.update(b"abra-checkpoint-workload-digest-v1\0")
    framed_hash(hasher, "logical_database_rows", canonical_json(rows).encode("ascii"))
    framed_hash(hasher, "simulated_tool_call_ledger", ledger_bytes)
    for name, contents in output_files:
        framed_hash(hasher, "generated_output_name", name.encode("ascii"))
        framed_hash(hasher, "generated_output_bytes", contents)
    return hasher.hexdigest()


def inspect_workspace(workspace):
    errors = []
    rows = []
    ledger_bytes = None
    output_files = []

    try:
        rows = read_database(workspace / DATABASE_NAME)
    except (OSError, sqlite3.Error, ValueError) as error:
        errors.append(str(error))

    task_ids = [row.get("task_id") for row in rows]
    integer_ids = [task_id for task_id in task_ids if isinstance(task_id, int)]
    completed = max(integer_ids, default=0)
    if task_ids != list(range(1, completed + 1)):
        errors.append("database task IDs are duplicated, missing, or out of order")

    for row in rows:
        task_id = row.get("task_id")
        if not isinstance(task_id, int) or not 1 <= task_id <= MAX_TASKS:
            errors.append("database contains an invalid task ID: %r" % task_id)
            continue
        if row != stored_record(task_record(task_id)):
            errors.append("database row does not match deterministic task %d" % task_id)

    ledger = workspace / LEDGER_NAME
    try:
        reject_symlink(ledger, "ledger")
        ledger_bytes = ledger.read_bytes()
    except (OSError, ValueError) as error:
        errors.append("could not read ledger: %s" % error)

    tool_call_count = 0
    if ledger_bytes is not None:
        try:
            ledger_lines = ledger_bytes.splitlines()
            tool_call_count = len(ledger_lines)
            parsed_ledger = [json.loads(line.decode("ascii")) for line in ledger_lines]
            expected_ledger = [json.loads(row["ledger_json"]) for row in rows]
            expected_bytes = b"".join(
                (row["ledger_json"] + "\n").encode("ascii") for row in rows
            )
            if parsed_ledger != expected_ledger or ledger_bytes != expected_bytes:
                errors.append("simulated tool-call ledger does not match database rows")
            ledger_task_ids = [
                entry.get("task_id") if isinstance(entry, dict) else None
                for entry in parsed_ledger
            ]
            if ledger_task_ids != task_ids:
                errors.append("ledger task IDs are duplicated, missing, or out of order")
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError) as error:
            errors.append("simulated tool-call ledger is corrupt: %s" % error)

    outputs = workspace / OUTPUT_DIRECTORY
    try:
        reject_symlink(outputs, "output directory")
        if not outputs.is_dir():
            raise ValueError("missing output directory: %s" % outputs)
        entries = sorted(outputs.iterdir(), key=lambda entry: entry.name)
        for entry in entries:
            reject_symlink(entry, "generated output")
            if not entry.is_file():
                raise ValueError("unexpected entry in output directory: %s" % entry.name)
            output_files.append((entry.name, entry.read_bytes()))
    except (OSError, ValueError) as error:
        errors.append(str(error))

    expected_names = [row["output_name"] for row in rows]
    actual_names = [name for name, _ in output_files]
    if actual_names != expected_names:
        errors.append("generated output files are missing, duplicated, or unexpected")
    output_by_name = dict(output_files)
    for row in rows:
        expected = task_record(row["task_id"])["output_bytes"]
        actual = output_by_name.get(row["output_name"])
        if actual is not None and actual != expected:
            errors.append("generated output is corrupt: %s" % row["output_name"])

    digest = None
    if ledger_bytes is not None:
        try:
            digest = workload_digest(rows, ledger_bytes, output_files)
        except (UnicodeEncodeError, TypeError, ValueError) as error:
            errors.append("could not calculate workload digest: %s" % error)

    status = {
        "completed": completed,
        "next_task": completed + 1,
        "digest": digest,
        "task_ids": task_ids,
        "tool_call_count": tool_call_count,
        "integrity_ok": not errors,
    }
    return status, errors


def materialize_task(workspace, record):
    write_atomic(workspace / OUTPUT_DIRECTORY / record["output_name"], record["output_bytes"])


def materialize_ledger(workspace, rows):
    contents = b"".join((row["ledger_json"] + "\n").encode("ascii") for row in rows)
    write_atomic(workspace / LEDGER_NAME, contents)


def run_tasks(workspace, until):
    initialize_workspace(workspace)
    status, errors = inspect_workspace(workspace)
    if errors:
        raise ValueError("workspace is not resumable: %s" % "; ".join(errors))
    if status["completed"] > until:
        raise ValueError(
            "workspace already completed task %d, beyond --until %d"
            % (status["completed"], until)
        )

    database = workspace / DATABASE_NAME
    connection = sqlite3.connect(str(database))
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        for task_id in range(status["completed"] + 1, until + 1):
            record = task_record(task_id)
            connection.execute(
                """
                INSERT INTO tasks (
                    task_id, input_text, arguments_json, result_digest,
                    output_name, output_sha256, ledger_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["task_id"],
                    record["input_text"],
                    record["arguments_json"],
                    record["result_digest"],
                    record["output_name"],
                    record["output_sha256"],
                    record["ledger_json"],
                ),
            )
            connection.commit()
            materialize_task(workspace, record)
    finally:
        connection.close()

    rows = read_database(database)
    materialize_ledger(workspace, rows)
    status, errors = inspect_workspace(workspace)
    if errors:
        raise ValueError("workload checkpoint is invalid: %s" % "; ".join(errors))
    return status


def bounded_task_count(value):
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if not 0 <= number <= MAX_TASKS:
        raise argparse.ArgumentTypeError("must be between 0 and %d" % MAX_TASKS)
    return number


def print_json(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="run or resume deterministic tasks")
    run.add_argument("--workspace", required=True)
    run.add_argument("--until", required=True, type=bounded_task_count)
    run.add_argument("--hold", action="store_true")

    status = commands.add_parser("status", help="inspect persisted workload state")
    status.add_argument("--workspace", required=True)

    verify = commands.add_parser("verify", help="verify a completed checkpoint")
    verify.add_argument("--workspace", required=True)
    verify.add_argument("--expected", required=True, type=bounded_task_count)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            workspace = checked_workspace(args.workspace, create=True)
            status = run_tasks(workspace, args.until)
            if args.hold:
                print_json({"event": "ready", **status})
                while True:
                    time.sleep(3600)
            print_json(status)
            return 0

        workspace = checked_workspace(args.workspace)
        status, errors = inspect_workspace(workspace)
        if args.command == "status":
            print_json(status)
            return 0

        expected_ids = list(range(1, args.expected + 1))
        if status["task_ids"] != expected_ids:
            errors.append(
                "expected tasks 1 through %d, found %s"
                % (args.expected, status["task_ids"])
            )
        if errors:
            print("checkpoint workload verification failed: %s" % "; ".join(errors), file=sys.stderr)
            return 1
        print_json(status)
        return 0
    except (OSError, sqlite3.Error, ValueError) as error:
        print("checkpoint workload failed: %s" % error, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
