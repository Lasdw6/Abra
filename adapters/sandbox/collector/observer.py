#!/usr/bin/env python3
"""Collect bounded sandbox facts and service candidates without starting services."""

import argparse
import datetime
import errno
import json
import math
import selectors
import signal
import shlex
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.parse


ENV_KEYS = {"NODE_ENV", "PORT", "HOST", "RUST_LOG", "PYTHONPATH", "VIRTUAL_ENV"}
SECRET = re.compile(r"(pass(word|wd|phrase)?|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|auth|credential|cookie|bearer)", re.I)
TOKEN = re.compile(r"^(sk-|sk_live_|sk_test_|ghp_|gho_|github_pat_|xox[abp]-|AKIA[0-9A-Z]{16}$|eyJ[A-Za-z0-9_-]{10,}\.|-----BEGIN)")
TOKEN_ANYWHERE = re.compile(r"(?<![A-Za-z0-9_])(sk-(?:live_|test_)?[A-Za-z0-9_-]{6,}|gh[po]_[A-Za-z0-9_]{6,}|github_pat_[A-Za-z0-9_]{6,}|xox[abp]-[A-Za-z0-9-]{6,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)")
AUTH = re.compile(r"\b(Bearer|Basic)\s+\S+", re.I)
SHELLS = {"sh", "bash", "dash", "zsh", "fish", "ksh"}
INTERPRETERS = {"node", "nodejs", "python", "python3", "ruby", "perl", "bun", "deno"}
RUNTIMES = ["node", "npm", "python3", "rustc", "cargo", "go", "java", "ruby", "bun", "deno", "codex", "google-chrome"]
MAX_FILE = 240 * 1024
BARRIER = re.compile(r"^[A-Za-z0-9_-]{1,64}$", re.ASCII)


def canonical_time(epoch=None):
    if epoch is None:
        epoch = time.time()
    value = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (value.microsecond // 1000)


def limited(path, limit):
    with open(path, "rb") as handle:
        return handle.read(limit + 1)


def text(path):
    raw = limited(path, 1024 * 1024)
    if len(raw) > 1024 * 1024:
        raise ValueError("collector input exceeds 1 MiB")
    return raw.decode("utf-8", "replace")


def report(errors, collector, code):
    if errors is None:
        return
    for row in errors:
        if row["collector"] == collector and row["code"] == code:
            row["count"] += 1
            return
    if len(errors) < 64:
        errors.append({"collector": collector, "code": code, "count": 1})


def report_error(errors, collector, error):
    code = "permission_denied" if isinstance(error, PermissionError) else "unavailable"
    if isinstance(error, FileNotFoundError):
        code = "missing_or_exited"
    report(errors, collector, code)


def parse_stat(path):
    head, tail = text(path).rsplit(")", 1)
    fields = tail.split()
    return int(head.split(" ", 1)[0]), fields[0], int(fields[1]), int(fields[2]), int(fields[19])


def redact_authorization(match):
    return match.group(1) + " <redacted>"


def redact_value(value):
    if TOKEN.search(value):
        return "<redacted>", True
    changed = TOKEN_ANYWHERE.sub("<redacted>", AUTH.sub(redact_authorization, value))
    # An argument may itself be a shell command or a URL with credentials.
    if re.search(r"(?:--?[\w-]*(?:token|password|secret|api[-_]?key)[\w-]*)[=\s]+\S", changed, re.I):
        return "<redacted>", True
    if re.search(r"[a-z][a-z0-9+.-]*://[^\s/]*@", changed, re.I):
        return "<redacted>", True
    try:
        parsed = urllib.parse.urlsplit(changed)
        if parsed.scheme and parsed.netloc:
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            if parsed.fragment or any(SECRET.search(key) for key, _ in query):
                return "<redacted>", True
    except (ValueError, UnicodeError):
        if "://" in changed:
            return "<redacted>", True
    return changed, changed != value


def redact_argv(argv):
    output = []
    redacted = False
    hide_next = False
    executable = os.path.basename(argv[0]).lstrip("-") if argv else ""
    opaque_next = False
    for value in argv:
        if opaque_next:
            safe_shell = False
            if executable in SHELLS and not re.search(r"[;$`|&<>\n(){}]", value):
                try:
                    words = shlex.split(value)
                    safe_shell = bool(words) and os.path.basename(words[0]) not in SHELLS and not redact_argv(words)[1]
                except ValueError:
                    pass
            output.append(value if safe_shell else "<redacted>")
            redacted |= not safe_shell
            opaque_next = False
            continue
        if ((executable in SHELLS and value.startswith("-") and "c" in value[1:])
                or (executable in INTERPRETERS and value in ("-c", "-e", "--eval"))):
            opaque_next = True
        if hide_next:
            output.append("<redacted>")
            redacted = True
            hide_next = False
            continue
        if "=" in value:
            name, _ = value.split("=", 1)
            if SECRET.search(name.lstrip("-")):
                output.append(name + "=<redacted>")
                redacted = True
                continue
        value, changed = redact_value(value)
        output.append(value)
        redacted |= changed
        if value.startswith("-") and SECRET.search(value.lstrip("-")):
            hide_next = True
    return output, redacted


def parse_env(path, errors=None, missing=None):
    try:
        raw = limited(path, 256 * 1024)
    except OSError as error:
        report_error(errors, "environment", error)
        if missing is not None:
            missing.append("environment_unreadable")
        return {}, False, False
    items = []
    redacted = False
    truncated = len(raw) > 256 * 1024
    for entry in raw[:256 * 1024].split(b"\0"):
        if b"=" not in entry:
            continue
        key, value = entry.split(b"=", 1)
        key = key.decode("utf-8", "replace")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key):
            continue
        if SECRET.search(key):
            redacted = True
            if missing is not None and len(missing) < 64:
                missing.append(key)
            continue
        if key not in ENV_KEYS and not key.startswith("ABRA_RECIPE_"):
            continue
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            truncated = True
            continue
        if len(value) > 4096:
            value = value[:4096]
            truncated = True
        value, changed = redact_value(value)
        redacted |= changed
        if changed and missing is not None and len(missing) < 64:
            missing.append(key)
        items.append((key, value))
    output = {}
    total = 0
    for key, value in sorted(items):
        size = len(key.encode()) + len(value.encode())
        if len(output) >= 64 or total + size > 16 * 1024:
            truncated = True
            continue
        output[key] = value
        total += size
    return output, redacted, truncated


def socket_map(proc, errors=None):
    output = {}
    tables = (("tcp", "tcp", 1), ("tcp6", "tcp", 1), ("udp", "udp", 0), ("udp6", "udp", 0))
    for name, protocol, tcp in tables:
        try:
            lines = text(os.path.join(proc, "net", name)).splitlines()[1:]
        except (OSError, ValueError) as error:
            report_error(errors, "sockets", error)
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or (tcp and fields[3] != "0A"):
                continue
            try:
                port = int(fields[1].rsplit(":", 1)[1], 16)
            except ValueError:
                continue
            if port:
                output.setdefault(fields[9], set()).add((protocol, port))
    return output


def process_ports(base, inodes, errors=None, external=None):
    found = set()
    try:
        with os.scandir(os.path.join(base, "fd")) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096:
                    report(errors, "file_descriptors", "truncated")
                    break
                try:
                    target = os.readlink(entry.path)
                except OSError as error:
                    report_error(errors, "file_descriptors", error)
                    continue
                if external is not None and target.startswith("/") and len(external) >= 64:
                    report(errors, "external_files", "truncated")
                if external is not None and target.startswith("/") and len(external) < 64:
                    safe, changed = redact_value(target)
                    if not changed and len(safe) <= 4096:
                        external.add(safe)
                if target.startswith("socket:[") and target.endswith("]"):
                    found.update(inodes.get(target[8:-1], ()))
    except OSError as error:
        report_error(errors, "file_descriptors", error)
    return [{"proto": protocol, "port": port} for protocol, port in sorted(found)]


def username(path):
    try:
        for line in text(path).splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
                try:
                    return pwd.getpwuid(uid).pw_name
                except KeyError:
                    return str(uid)
    except (OSError, ValueError):
        return None


def process_metadata(proc, errors=None):
    parents = {}
    states = {}
    starts = {}
    groups = {}
    try:
        names = [name for name in os.listdir(proc) if name.isdigit()]
    except OSError as error:
        report_error(errors, "processes", error)
        names = []
    if len(names) > 8192:
        report(errors, "processes", "scan_truncated")
    for name in sorted(names, key=int)[:8192]:
        try:
            pid, state, parent_pid, process_group, start = parse_stat(os.path.join(proc, name, "stat"))
            parents[pid] = parent_pid
            states[pid] = state
            starts[pid] = start
            groups[pid] = process_group
        except (OSError, ValueError, IndexError) as error:
            report_error(errors, "processes", error)
    return parents, states, starts, groups


def process_clock(proc):
    try:
        boot = time.time() - float(text(os.path.join(proc, "uptime")).split()[0])
        ticks = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError):
        return None, None
    return boot, ticks


def read_process(pid, workspace, proc, parent_pid, state, start, inodes, clock, errors=None):
    base = os.path.join(proc, str(pid))
    try:
        link = os.readlink(os.path.join(base, "cwd"))
        if link.endswith(" (deleted)"):
            return None
        cwd = os.path.realpath(link)
        inside = os.path.commonpath((workspace, cwd)) == workspace
        raw = limited(os.path.join(base, "cmdline"), 64 * 1024)
    except (OSError, ValueError) as error:
        report_error(errors, "process_details", error)
        return None
    if not raw:
        return None
    truncated = len(raw) > 64 * 1024
    try:
        argv = [item.decode("utf-8") for item in raw[:64 * 1024].split(b"\0") if item]
    except UnicodeDecodeError:
        argv = ["<omitted: non-UTF8 command>"]
        truncated = True
    if not argv:
        return None
    if len(argv) > 256:
        argv = argv[:256]
        truncated = True
    for index, argument in enumerate(argv):
        if len(argument) > 4096:
            argv[index] = "<omitted: argument exceeds limit>"
            truncated = True
    argv, argv_redacted = redact_argv(argv)
    missing = []
    env, env_redacted, env_truncated = parse_env(os.path.join(base, "environ"), errors, missing)
    row = {"pid": pid, "ppid": parent_pid, "start_ticks": start, "argv": argv,
           "cwd": os.path.relpath(cwd, workspace).replace(os.sep, "/") if inside else None,
           "workspace_relation": "inside" if inside else "outside", "state": state}
    if not inside:
        row["external_cwd"] = redact_value(cwd)[0][:4096]
    if missing:
        row["missing_environment"] = sorted(set(missing))
    try:
        row["exe"] = redact_value(os.readlink(os.path.join(base, "exe")))[0][:4096]
    except OSError:
        pass
    user = username(os.path.join(base, "status"))
    if user is not None:
        row["user"] = user
    if env:
        row["env"] = env
    external = set()
    ports = process_ports(base, inodes, errors, external)
    external = sorted(path for path in external if not (path == workspace or path.startswith(workspace + os.sep)))
    if external:
        row["external_open_files"] = external
    if ports:
        row["ports"] = ports
    boot, ticks = clock
    if boot is not None:
        row["started_at"] = canonical_time(boot + start / ticks)
    if argv_redacted or env_redacted:
        row["redacted"] = True
    if truncated or env_truncated:
        row["truncated"] = True
    try:
        if parse_stat(os.path.join(base, "stat"))[4] != start:
            report(errors, "processes", "pid_reused")
            return None
    except (OSError, ValueError, IndexError) as error:
        report_error(errors, "processes", error)
        return None
    return row


def scan_processes(workspace, proc, errors=None, cgroup=None, process_group=None, all_processes=False):
    parents, states, starts, groups = process_metadata(proc, errors)
    inodes = socket_map(proc, errors)
    workspace = os.path.realpath(workspace)
    clock = process_clock(proc)
    selected = {}
    for pid in sorted(parents):
        if pid == os.getpid():
            continue
        try:
            if all_processes:
                selected[pid] = "all"
            elif cgroup is not None:
                paths = [line.split(":", 2)[2] for line in text(os.path.join(proc, str(pid), "cgroup")).splitlines() if line.startswith("0::")]
                if any(path == cgroup or path.startswith(cgroup.rstrip("/") + "/") for path in paths):
                    selected[pid] = "cgroup"
            elif process_group is not None:
                if groups[pid] == process_group:
                    selected[pid] = "process_group"
            else:
                cwd = os.path.realpath(os.readlink(os.path.join(proc, str(pid), "cwd")))
                if os.path.commonpath((workspace, cwd)) == workspace:
                    selected[pid] = "workspace"
        except (OSError, ValueError) as error:
            report_error(errors, "membership", error)
    # Include children even if they changed directory or process group after launch.
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if pid != os.getpid() and pid not in selected and parent in selected:
                selected[pid] = "descendant"
                changed = True
    output = []
    try:
        network_namespace = os.readlink(os.path.join(proc, "self/ns/net"))
    except OSError:
        network_namespace = None
        report(errors, "network_namespaces", "unavailable")
    if len(selected) > 1024:
        report(errors, "processes", "details_truncated")
    for pid, membership in sorted(selected.items())[:1024]:
        row = read_process(pid, workspace, proc, parents[pid], states[pid], starts[pid], inodes, clock, errors)
        if row is not None:
            row["membership"] = membership
            try:
                if os.readlink(os.path.join(proc, str(pid), "ns/net")) != network_namespace:
                    row.pop("ports", None)
                    report(errors, "network_namespaces", "unsupported_namespace")
            except OSError:
                row.pop("ports", None)
                report(errors, "network_namespaces", "unavailable")
            output.append(row)
    return output


def command_name(argv):
    name = os.path.basename(argv[0]).lstrip("-")
    if name in INTERPRETERS and len(argv) > 1 and not argv[1].startswith("-"):
        name = os.path.basename(argv[1])
    return name


def interactive(row):
    return command_name(row["argv"]) in SHELLS and not any(value.startswith("-") and "c" in value[1:] for value in row["argv"][1:])


def derive_services(processes):
    by_pid = {row["pid"]: row for row in processes}
    groups = {}
    for row in processes:
        if interactive(row):
            continue
        root = row
        seen = {root["pid"]}
        while True:
            parent = by_pid.get(root["ppid"])
            if parent is None or parent["pid"] in seen or interactive(parent):
                break
            # Agent-launched services have their own lifecycle; ordinary workers do not.
            if command_name(parent["argv"]) in {"codex", "claude", "agent"}:
                break
            # With --all, init or a sandbox supervisor outside the workspace adopts
            # every orphan; it is a boundary, not the root of those services.
            if parent["pid"] == 1 and parent.get("cwd") is None:
                break
            seen.add(parent["pid"])
            root = parent
        groups.setdefault(root["pid"], {"root": root, "members": []})["members"].append(row)
    output = []
    for group in groups.values():
        root, members = group["root"], group["members"]
        missing = set()
        for row in members:
            if row.get("redacted"):
                missing.add("redacted_arguments_or_environment")
            if row.get("truncated"):
                missing.add("truncated_process_data")
            if row.get("cwd") is None:
                missing.add("working_directory_outside_workspace")
            missing.update("environment:" + name for name in row.get("missing_environment", []))
        recipe = {"argv": root["argv"], "cwd": root.get("cwd")}
        for key in ("env", "started_at"):
            if key in root:
                recipe[key] = root[key]
        ports = sorted({p["port"] for row in members for p in row.get("ports", []) if p["proto"] == "tcp"})
        if ports:
            recipe["ports"] = ports
        output.append({"source": "process-tree-inference", "source_pids": sorted(row["pid"] for row in members),
                       "root_pid": root["pid"], "recipe": recipe,
                       "restartability": "blocked" if missing else "unverified",
                       "missing_requirements": sorted(missing),
                       "reasons": ["listening_socket" if ports else "observed_process", "children_grouped_with_parent"],
                       "requires_adapter_confirmation": True,
                       "requirements": {"executable": root.get("exe"),
                                        "external_files": sorted({path for row in members for path in row.get("external_open_files", [])})[:64],
                                        "runtime_verification": "required"}})
    output.sort(key=lambda candidate: (not bool(candidate["recipe"].get("ports")), candidate["root_pid"]))
    return output


def derive_recipes(processes):
    return [candidate["recipe"] for candidate in derive_services(processes) if candidate["restartability"] == "unverified"]


def platform_info(proc):
    uname = os.uname()
    output = {"os": uname.sysname.lower(), "arch": uname.machine, "kernel": uname.release}
    if uname.nodename:
        output["hostname"] = redact_value(uname.nodename)[0][:128]
    try:
        output["boot_id"] = text(os.path.join(proc, "sys/kernel/random/boot_id")).strip()
    except OSError:
        pass
    release = {}
    try:
        for line in text("/etc/os-release").splitlines():
            key, separator, value = line.rstrip().partition("=")
            if separator and key.lower() in ("id", "version_id"):
                release[key.lower()] = value.strip("\"'")
    except OSError:
        pass
    if release:
        output["os_release"] = release
    try:
        image = text("/etc/abra/image-id").strip()
        if image and len(image) <= 128:
            output["image_id"] = redact_value(image)[0]
    except OSError:
        pass
    return output


def resource_info(proc, cgroup=None, cgroup_root="/sys/fs/cgroup", errors=None):
    output = {"source": "guest-os"}
    try:
        for line in text(os.path.join(proc, "meminfo")).splitlines():
            if line.startswith("MemTotal:"):
                output["memory_mb"] = int(line.split()[1]) // 1024
                break
    except (OSError, ValueError) as error:
        report_error(errors, "resources", error)
    if os.cpu_count() is not None:
        output["cpus"] = os.cpu_count()
    try:
        output["affinity_cpus"] = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        output["affinity_cpus"] = output.get("cpus")
    try:
        if cgroup is None:
            cgroup = next(line[3:] for line in text(os.path.join(proc, "self/cgroup")).splitlines() if line.startswith("0::"))
        root = os.path.realpath(cgroup_root)
        directory = os.path.realpath(os.path.join(root, cgroup.lstrip("/")))
        if os.path.commonpath((root, directory)) != root:
            raise ValueError("cgroup escapes root")
        memory = output.get("memory_mb", math.inf) * 1024 * 1024
        cpus = output.get("affinity_cpus") or math.inf
        while True:
            for name in ("memory.max", "cpu.max", "cpuset.cpus.effective"):
                try:
                    value = text(os.path.join(directory, name)).strip()
                    if name == "memory.max" and value != "max":
                        memory = min(memory, int(value))
                    elif name == "cpu.max":
                        quota, period = value.split()
                        if quota != "max":
                            cpus = min(cpus, int(quota) / int(period))
                    elif name == "cpuset.cpus.effective" and value:
                        count = 0
                        for part in value.split(","):
                            ends = part.split("-")
                            count += int(ends[-1]) - int(ends[0]) + 1
                        cpus = min(cpus, count)
                except (OSError, ValueError, ZeroDivisionError) as error:
                    report_error(errors, "cgroup_limits", error)
            if directory == root:
                break
            directory = os.path.dirname(directory)
        if math.isfinite(memory):
            output["effective_memory_bytes"] = memory
        if math.isfinite(cpus):
            output["effective_cpu_millicores"] = int(cpus * 1000)
        output["cgroup"] = cgroup
    except (OSError, ValueError, StopIteration) as error:
        report_error(errors, "cgroup_limits", error)
    return output


def probe_runtimes(dirs, errors=None):
    output = {}
    env = {"PATH": os.pathsep.join(dirs)}
    for name in RUNTIMES:
        for directory in dirs:
            path = os.path.join(directory, name)
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                continue
            child = None
            try:
                child = subprocess.Popen([path, "--version"], stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         env=env, start_new_session=True)
                data = bytearray()
                deadline = time.monotonic() + 3
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    while len(data) < 4096 and time.monotonic() < deadline:
                        if not selector.select(max(0, deadline - time.monotonic())):
                            break
                        chunk = os.read(child.stdout.fileno(), 4096 - len(data))
                        if not chunk:
                            break
                        data.extend(chunk)
                        if b"\n" in data:
                            break
                if data:
                    version, redacted = redact_value(bytes(data).decode("utf-8", "replace").splitlines()[0].strip())
                    if version and not redacted:
                        output[name] = version[:64]
                else:
                    report(errors, "runtimes", "probe_failed_or_timed_out")
            except OSError as error:
                report_error(errors, "runtimes", error)
            finally:
                if child is not None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except PermissionError:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    child.wait()
                    child.stdout.close()
            break
    return output


def mount_info(proc, workspace, errors=None):
    output = []
    workspace = os.path.realpath(workspace)
    try:
        lines = text(os.path.join(proc, "self", "mountinfo")).splitlines()
    except (OSError, ValueError) as error:
        report_error(errors, "mounts", error)
        return output
    for line in lines:
        fields = line.split()
        try:
            split = fields.index("-")
            target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
            inside = target == workspace or target.startswith(workspace + os.sep)
            if inside and ".abra" in os.path.relpath(target, workspace).split(os.sep):
                inside = False
            output.append({"target": redact_value(target)[0][:4096], "fstype": fields[split + 1],
                           "source": redact_value(fields[split + 2])[0][:4096],
                           "mutable": "rw" in fields[5].split(","),
                           "capture": "workspace-file-tree" if inside else "not-captured",
                           "contents_verified": False})
        except (ValueError, IndexError):
            report(errors, "mounts", "malformed_record")
        if len(output) >= 64:
            report(errors, "mounts", "truncated")
            break
    return output


def collect_environment(args):
    errors = []
    result = {"platform": platform_info(args.proc),
              "runtimes": probe_runtimes(args.runtime_dirs.split(os.pathsep), errors),
              "source": "guest-os", "observed_at": canonical_time(), "collection_errors": errors}
    return result


def encoded_ledger(ledger):
    return json.dumps(ledger, separators=(",", ":"), sort_keys=True).encode()


def enforce_size_limit(ledger):
    for field, counter in (("processes", "processes_dropped"), ("service_candidates", "services_dropped")):
        while len(encoded_ledger(ledger)) > MAX_FILE and ledger[field]:
            # Drop in batches to avoid repeatedly serializing a huge ledger once per row.
            count = max(1, len(ledger[field]) // 2)
            del ledger[field][-count:]
            ledger["limits"][counter] += count
            if field == "service_candidates":
                ledger["recipes"] = [c["recipe"] for c in ledger[field] if c["restartability"] == "unverified"]
    if len(encoded_ledger(ledger)) > MAX_FILE:
        raise ValueError("observed ledger exceeds 240 KiB after dropping process and service records")
    if any(ledger["limits"].values()):
        ledger["coverage"]["complete"] = False


def capture(args, runtimes, environment=None):
    started = canonical_time()
    errors = []
    processes = scan_processes(args.workspace, args.proc, errors, getattr(args, "cgroup", None), getattr(args, "process_group", None), getattr(args, "all", False))
    processes.sort(key=lambda row: (not bool(row.get("ports")), row.get("started_at", "9999"), row["pid"]))
    services = derive_services(processes)
    processes_dropped = max(0, len(processes) - 512)
    processes = processes[:512]
    services_dropped = max(0, len(services) - 256)
    services = services[:256]
    if environment is None:
        environment = {"platform": platform_info(args.proc), "runtimes": runtimes, "observed_at": started, "collection_errors": []}
    resources = resource_info(args.proc, getattr(args, "cgroup", None), getattr(args, "cgroup_root", "/sys/fs/cgroup"), errors)
    mounts = mount_info(args.proc, args.workspace, errors)
    finished = canonical_time()
    observer = {"version": 3, "observed_at": finished, "capture_started_at": started, "capture_finished_at": finished,
                "mode": "once" if args.once else "periodic", "environment_observed_at": environment["observed_at"],
                "environment_refresh_interval_ms": int(getattr(args, "environment_interval", 300) * 1000)}
    if args.once and args.barrier is not None:
        observer["barrier"] = args.barrier
    if not args.once:
        observer["interval_ms"] = int(args.interval * 1000)
    errors.extend(environment.get("collection_errors", []))
    ledger = {"schema": "dev.abra.observed/3", "observer": observer,
              "platform": environment["platform"], "resources": resources, "runtimes": environment["runtimes"],
              "processes": processes, "service_candidates": services,
              "recipes": [c["recipe"] for c in services if c["restartability"] == "unverified"],
              "mounts": mounts, "collection_errors": errors,
              "coverage": {"complete": False, "scope": "all" if getattr(args, "all", False) else "cgroup" if getattr(args, "cgroup", None) else "process_group" if getattr(args, "process_group", None) else "workspace-and-descendants",
                           "consistency": "best-effort", "applications_quiesced": False,
                           "limitations": ["observation_is_not_a_restart_guarantee", "environment_allowlist", "observer_network_namespace_only", "external_file_contents_not_captured", "app_checkpoints_require_adapters"]},
              "limits": {"processes_dropped": processes_dropped, "services_dropped": services_dropped}}
    enforce_size_limit(ledger)
    return ledger


def capture_filename(barrier=None):
    if barrier is None:
        return "observed.json"
    if not BARRIER.fullmatch(barrier):
        raise ValueError("barrier must be 1 to 64 ASCII letters, digits, underscores or hyphens")
    return "observed-%s.json" % barrier


def write_ledger(workspace, ledger, sync_directory=False, barrier=None):
    filename = capture_filename(barrier)
    workspace_fd = None
    metadata_fd = None
    temp_fd = None
    temp = None
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        workspace_fd = os.open(workspace, directory_flags | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.mkdir(".abra", 0o700, dir_fd=workspace_fd)
        except FileExistsError:
            pass
        # NOFOLLOW and dir_fd keep every write inside the opened workspace directory.
        metadata_fd = os.open(".abra", directory_flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=workspace_fd)
        if not stat.S_ISDIR(os.fstat(metadata_fd).st_mode):
            raise OSError(errno.ENOTDIR, ".abra is not a directory")
        os.fchmod(metadata_fd, 0o700)
        temp = ".observed.json.%d.%s.tmp" % (os.getpid(), secrets.token_hex(4))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        temp_fd = os.open(temp, flags, 0o600, dir_fd=metadata_fd)
        with os.fdopen(temp_fd, "wb", closefd=True) as handle:
            temp_fd = None
            handle.write(encoded_ledger(ledger))
            handle.flush()
            os.fsync(handle.fileno())
        if barrier is None:
            os.rename(temp, filename, src_dir_fd=metadata_fd, dst_dir_fd=metadata_fd)
        else:
            # Linking publishes a fully written capture atomically and refuses collisions.
            os.link(temp, filename, src_dir_fd=metadata_fd, dst_dir_fd=metadata_fd, follow_symlinks=False)
            os.unlink(temp, dir_fd=metadata_fd)
        temp = None
        if sync_directory:
            os.fsync(metadata_fd)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp is not None and metadata_fd is not None:
            try:
                os.unlink(temp, dir_fd=metadata_fd)
            except OSError:
                pass
        if metadata_fd is not None:
            os.close(metadata_fd)
        if workspace_fd is not None:
            os.close(workspace_fd)


def cycle(args, runtimes, environment=None):
    ledger = capture(args, runtimes, environment)
    write_ledger(args.workspace, ledger, args.once, args.barrier if args.once else None)
    return ledger


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default="/workspace")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--barrier")
    parser.add_argument("--proc", default="/proc")
    membership = parser.add_mutually_exclusive_group()
    membership.add_argument("--cgroup", help="cgroup v2 path, relative to the cgroup mount, e.g. /sandbox")
    membership.add_argument("--process-group", type=int)
    membership.add_argument("--all", action="store_true", help="every process in /proc; use when the sandbox is the whole PID namespace")
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup")
    parser.add_argument("--environment-interval", type=float, default=300)
    parser.add_argument("--runtime-dirs", default="/usr/local/bin:/usr/bin:/bin")
    return parser


def main(argv=None):
    os.umask(0o077)
    parser = create_parser()
    args = parser.parse_args(argv)
    if any(not math.isfinite(value) or not 0.001 <= value <= 86400 for value in (args.interval, args.environment_interval)):
        parser.error("intervals must be between 0.001 and 86400 seconds")
    if args.barrier is not None and (not args.once or not BARRIER.fullmatch(args.barrier)):
        parser.error("--barrier requires --once and 1 to 64 ASCII letters, digits, underscores or hyphens")
    if args.process_group is not None and args.process_group <= 0:
        parser.error("--process-group must be positive")
    if args.cgroup is not None and (not args.cgroup.startswith("/") or ".." in args.cgroup.split("/")):
        parser.error("--cgroup must be an absolute cgroup path without '..'")
    environment = collect_environment(args)
    refreshed = time.monotonic()
    runtimes = environment["runtimes"]
    if args.once:
        try:
            ledger = cycle(args, runtimes, environment)
        except Exception as error:
            print("abra-observer: %s" % error, file=sys.stderr)
            return 1
        summary = {"filename": capture_filename(args.barrier), "observed_at": ledger["observer"]["observed_at"], "processes": len(ledger["processes"]), "recipes": len(ledger["recipes"])}
        if args.barrier is not None:
            summary["barrier"] = args.barrier
        print(json.dumps(summary, separators=(",", ":"), sort_keys=True))
        return 0
    while True:
        try:
            if time.monotonic() - refreshed >= args.environment_interval:
                environment = collect_environment(args)
                refreshed = time.monotonic()
            cycle(args, environment["runtimes"], environment)
        except Exception as error:
            print("abra-observer: %s" % error, file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
