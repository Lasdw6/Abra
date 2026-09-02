#!/usr/bin/env python3
"""Observe workspace processes and write recipes as data; never execute them."""
import argparse
import datetime
import json
import os
import pathlib
import socket
import struct
import time

ENV_KEYS = {"NODE_ENV", "PORT", "HOST", "RUST_LOG", "PYTHONPATH", "VIRTUAL_ENV"}


def listen_inodes():
    ports = {}
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = pathlib.Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) >= 10 and fields[3] == "0A":
                port = int(fields[1].rsplit(":", 1)[1], 16)
                ports.setdefault(fields[9], set()).add(port)
    return ports


def started_at(stat_fields):
    try:
        ticks = os.sysconf("SC_CLK_TCK")
        boot = time.time() - float(pathlib.Path("/proc/uptime").read_text().split()[0])
        epoch = boot + int(stat_fields[19]) / ticks
        return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OSError, ValueError, IndexError):
        return None


def recipe(pid, workspace, inode_ports):
    base = pathlib.Path("/proc") / str(pid)
    try:
        cwd = pathlib.Path(os.readlink(base / "cwd")).resolve()
        relative = cwd.relative_to(workspace)
        argv = [x.decode("utf-8") for x in (base / "cmdline").read_bytes().split(b"\0") if x]
        environ = {}
        for item in (base / "environ").read_bytes().split(b"\0"):
            if b"=" not in item:
                continue
            key, value = item.split(b"=", 1)
            key, value = key.decode("utf-8"), value.decode("utf-8")
            if key in ENV_KEYS or key.startswith("ABRA_RECIPE_"):
                environ[key] = value
        # Everything after the closing ')' is stable even when comm contains spaces.
        stat_fields = (base / "stat").read_text().rsplit(")", 1)[1].split()
        sockets = []
        for fd in (base / "fd").iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if target.startswith("socket:["):
                sockets.extend(inode_ports.get(target[8:-1], ()))
    except (OSError, UnicodeError, ValueError):
        return None
    if not argv:
        return None
    result = {"argv": argv, "cwd": str(relative) if str(relative) else "."}
    if environ:
        result["env"] = dict(sorted(environ.items()))
    if sockets:
        result["ports"] = sorted(set(sockets))
    start = started_at(stat_fields)
    if start:
        result["started_at"] = start
    return result


def capture(workspace):
    inode_ports = listen_inodes()
    rows = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            row = recipe(int(name), workspace, inode_ports)
            if row:
                rows.append(row)
    rows.sort(key=lambda row: (row["cwd"], row["argv"]))
    return rows[:256]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=pathlib.Path, default=pathlib.Path("/workspace"))
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    metadata = workspace / ".abra"
    metadata.mkdir(parents=True, exist_ok=True)
    while True:
        output = metadata / "recipes.json"
        temporary = metadata / ".recipes.json.tmp"
        temporary.write_text(json.dumps(capture(workspace), separators=(",", ":")))
        os.replace(temporary, output)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

