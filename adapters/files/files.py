#!/usr/bin/env python3
"""Files inventory and staging adapter; transport belongs to Abra core."""
import contextlib
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import sys
import uuid
import unicodedata

KIND = "dev.abra.files.v1"
MAX_ITEMS = 256
MAX_ENTRIES = 10000
MAX_BYTES = 1024 * 1024 * 1024
MAX_DEPTH = 64
NOFOLLOW = os.O_NOFOLLOW
DIRECTORY = os.O_DIRECTORY


class Failure(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message


def fail(code, message):
    raise Failure(code, message)


def display(value, limit):
    cleaned = "".join(char if not unicodedata.category(char).startswith("C") else " " for char in value)
    return cleaned.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def root_path():
    return os.path.abspath(os.path.expanduser(os.environ.get("ABRA_FILES_ROOT", "~")))


def name_only(value):
    if not isinstance(value, str) or not value or value in (".", "..") or "/" in value or "\\" in value or "\0" in value:
        fail("invalid_request", "Selection must be a single relative file or folder name")
    return value


def identity(info):
    return {"device": str(info.st_dev), "inode": str(info.st_ino), "type": stat.S_IFMT(info.st_mode), "modified_ns": str(info.st_mtime_ns), "size": info.st_size}


@contextlib.contextmanager
def directory(path, create=False):
    # Resolve the explicitly chosen folder, including OS aliases such as macOS /tmp.
    # Entries inside it are still opened without following symlinks.
    if create:
        os.makedirs(path, mode=0o700, exist_ok=True)
    fd = os.open(os.path.realpath(path), os.O_RDONLY | DIRECTORY | NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)


def root_identity(fd):
    info = os.fstat(fd)
    return {"device": str(info.st_dev), "inode": str(info.st_ino)}


def absolute_path(value):
    if not isinstance(value, str) or not value or "\0" in value:
        fail("invalid_request", "Choose an absolute folder path or a path starting with ~")
    expanded = os.path.expanduser(value)
    if not os.path.isabs(expanded):
        fail("invalid_request", "Choose an absolute folder path or a path starting with ~")
    return os.path.abspath(expanded)


def natural_name(value):
    return [int(part) if part.isdigit() else part.casefold() for part in re.split(r"(\d+)", value)]


def _inventory(req):
    options = req.get("options") or {}
    mode = options.get("mode", "all")
    if mode not in ("selected", "all"):
        fail("invalid_request", "Files mode must be selected or all")
    paths = json.loads(options.get("paths", "[]"))
    if not isinstance(paths, list) or len(paths) > 32:
        fail("invalid_request", "Choose up to 32 folders")
    roots = list(dict.fromkeys(os.path.realpath(absolute_path(path)) for path in paths)) if mode == "selected" else []
    browse = options.get("browse_path")
    path = absolute_path(browse) if browse else (root_path() if mode == "all" else None)
    if path and mode == "selected" and not any(
        os.path.commonpath((os.path.realpath(path), os.path.realpath(root))) == os.path.realpath(root)
        for root in roots
    ):
        fail("permission_denied", "This folder is outside the selected folders")
    offset = int(options.get("offset", "0"))
    if offset < 0 or offset > 1000000:
        fail("invalid_request", "Invalid folder page")
    parent = None
    if path:
        candidate = os.path.dirname(path)
        if candidate != path and (mode == "all" or any(
            os.path.commonpath((os.path.realpath(candidate), os.path.realpath(root))) == os.path.realpath(root)
            for root in roots
        )):
            parent = candidate
    context = {"browser": "filesystem", "requested_options": options, "mode": mode, "roots": roots if mode == "selected" else [root_path()], "path": path, "parent": parent,
               "offset": offset, "next_offset": None}
    items = []

    def item(full, info, parent_id):
        name = os.path.basename(full)
        entry_type = "directory" if stat.S_ISDIR(info.st_mode) else "file"
        source = {"path": name, "absolute_path": full, "entry_type": entry_type,
                  "root": parent_id, "expected": identity(info)}
        return {"id": hashlib.sha256(full.encode()).hexdigest(), "kind": KIND,
                "label": display(name or full, 200),
                "detail": "Folder" if entry_type == "directory" else f"File · {info.st_size} bytes",
                "source": source, "transferable": True}

    if path:
        with directory(path) as root:
            with os.scandir(root) as entries:
                ordered = []
                for entry in entries:
                    if entry.name.startswith(".abra-incoming-"):
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
                        ordered.append((entry.name, info))
                        if len(ordered) > MAX_ENTRIES:
                            fail("limit_exceeded", "This folder contains more than 10,000 visible entries")
                ordered.sort(key=lambda value: (not stat.S_ISDIR(value[1].st_mode), natural_name(value[0])))
                page = ordered[offset:offset + MAX_ITEMS]
                if offset + len(page) < len(ordered):
                    context["next_offset"] = offset + len(page)
                parent_id = root_identity(root)
                for name, info in page:
                    items.append(item(os.path.join(path, name), info, parent_id))
    else:
        for selected in roots:
            try:
                with directory(os.path.dirname(selected)) as parent_fd:
                    info = os.stat(os.path.basename(selected) or ".", dir_fd=parent_fd, follow_symlinks=False)
                    if not stat.S_ISDIR(info.st_mode):
                        fail("invalid_request", "Selected paths must be existing folders")
                    selected_item = item(selected, info, root_identity(parent_fd))
                    if selected == os.path.sep:
                        selected_item["transferable"] = False
                        selected_item["reason"] = "Open this folder and select its contents"
                    items.append(selected_item)
            except OSError as error:
                items.append({"id": hashlib.sha256(selected.encode()).hexdigest(), "kind": KIND,
                              "label": display(selected, 200), "source": {"absolute_path": selected},
                              "transferable": False, "reason": display(str(error), 1000)})
    description = f"Browsing {path}. Select items to transfer." if path else "Choose a folder to open or select folders to transfer."
    return {"label": "Files", "description": display(description, 1024), "context": context, "items": items}


def inventory(req):
    try:
        return _inventory(req)
    except (Failure, OSError, ValueError, TypeError) as error:
        options = req.get("options") or {}
        # Keep controls available when a chosen folder disappears or access is denied.
        message = error.message if isinstance(error, Failure) else str(error)
        return {"label": "Files", "items": [], "error": display(message, 4096),
                "context": {"browser": "filesystem", "requested_options": options,
                            "mode": options.get("mode", "all"), "roots": [],
                            "path": options.get("browse_path"), "parent": None,
                            "offset": 0, "next_offset": None}}


def copy_entry(source_fd, target_fd, name, budget, depth=0, expected=None):
    name_only(name)
    before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
    if expected is not None and identity(before) != expected:
        fail("stale_source", "The selected item changed; refresh the device inventory")
    if not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
        fail("permission_denied", "Symlinks and special files cannot be transferred")
    budget["entries"] += 1
    if budget["entries"] > MAX_ENTRIES or depth > MAX_DEPTH:
        fail("limit_exceeded", "Transfer exceeds 10,000 entries or 64 folder levels")
    flags = os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK
    if stat.S_ISDIR(before.st_mode):
        flags |= DIRECTORY
    source = os.open(name, flags, dir_fd=source_fd)
    try:
        opened = os.fstat(source)
        if identity(before) != identity(opened):
            fail("stale_source", "A source item changed during capture")
        if stat.S_ISDIR(opened.st_mode):
            os.mkdir(name, mode=0o700, dir_fd=target_fd)
            target = os.open(name, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=target_fd)
            try:
                with os.scandir(source) as entries:
                    for entry in entries:
                        copy_entry(source, target, entry.name, budget, depth + 1)
                os.fchmod(target, stat.S_IMODE(opened.st_mode) & 0o777)
            finally:
                os.close(target)
        else:
            if budget["bytes"] + opened.st_size > MAX_BYTES:
                fail("limit_exceeded", "Transfer exceeds 1 GiB")
            target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=target_fd)
            try:
                while True:
                    chunk = os.read(source, 1024 * 1024)
                    if not chunk:
                        break
                    budget["bytes"] += len(chunk)
                    if budget["bytes"] > MAX_BYTES:
                        fail("limit_exceeded", "Transfer exceeds 1 GiB")
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(target, view):]
                os.fchmod(target, stat.S_IMODE(opened.st_mode) & 0o777)
                budget["files"] += 1
            finally:
                os.close(target)
        if identity(os.fstat(source)) != identity(opened) or identity(os.stat(name, dir_fd=source_fd, follow_symlinks=False)) != identity(opened):
            fail("stale_source", "A source item changed during capture")
    finally:
        os.close(source)


def remove_created(parent, name):
    """Delete only a failed import subtree through its already-open parent."""
    child = os.open(name, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=parent)
    try:
        os.fchmod(child, 0o700)
        with os.scandir(child) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    remove_created(child, entry.name)
                else:
                    os.unlink(entry.name, dir_fd=child)
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent)


def export(req):
    source = req.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("expected"), dict):
        fail("invalid_request", "Choose a file or folder from fresh inventory")
    name = name_only(source.get("path"))
    staging = req.get("staging_dir")
    if not isinstance(staging, str):
        fail("invalid_request", "staging_dir is required")
    budget = {"entries": 0, "files": 0, "bytes": 0}
    full = absolute_path(source["absolute_path"]) if "absolute_path" in source else os.path.join(root_path(), name)
    if os.path.basename(full) != name:
        fail("invalid_request", "Selection name does not match its path")
    with directory(os.path.dirname(full)) as root, directory(staging) as stage:
        if source.get("root") != root_identity(root):
            fail("stale_source", "The source folder changed; refresh the device inventory")
        os.mkdir("files", mode=0o700, dir_fd=stage)
        target = os.open("files", os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=stage)
        try:
            copy_entry(root, target, name, budget, expected=source["expected"])
        finally:
            os.close(target)
    return {"payload": {"schema": KIND, "name": name, **budget}, "files_path": os.path.join(staging, "files"), "floor": {"title": display(name, 200)}}


def publish_entry(source_fd, target_fd, name):
    """Atomically publish without replacing an existing file, folder, or symlink."""
    libc = ctypes.CDLL(None, use_errno=True)
    encoded = os.fsencode(name)
    if sys.platform == "darwin":
        rename = libc.renameatx_np
        flag = 4  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        rename = libc.renameat2
        flag = 1  # RENAME_NOREPLACE
    else:
        fail("unsupported_platform", "Files currently supports macOS and Linux")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_fd, encoded, target_fd, encoded, flag):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            fail("conflict", f"{name} already exists in the destination; choose another folder")
        raise OSError(code, os.strerror(code), name)


def import_files(req):
    destination = req.get("destination")
    materialized = req.get("materialized_files")
    if not isinstance(materialized, str):
        fail("invalid_request", "materialized_files is required")
    if isinstance(destination, dict):
        destination = destination.get("path")
    if destination in (None, "local", "files", materialized):
        fail("invalid_request", "Choose a destination folder on the receiving device")
    root = absolute_path(destination)
    real_materialized, real_root = os.path.realpath(materialized), os.path.realpath(root)
    if os.path.commonpath((real_materialized, real_root)) == real_materialized:
        fail("invalid_request", "The destination cannot be inside materialized files")
    budget = {"entries": 0, "files": 0, "bytes": 0}
    published = []
    with directory(materialized) as source, directory(root, create=True) as target_root:
        names = os.listdir(source)
        for name in names:
            name_only(name)
            try:
                os.stat(name, dir_fd=target_root, follow_symlinks=False)
            except FileNotFoundError:
                continue
            fail("conflict", f"{name} already exists in the destination; choose another folder")
        received = ".abra-incoming-" + uuid.uuid4().hex
        os.mkdir(received, mode=0o700, dir_fd=target_root)
        target = os.open(received, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=target_root)
        try:
            for name in names:
                copy_entry(source, target, name, budget)
            for name in names:
                publish_entry(target, target_root, name)
                published.append(os.path.join(root, name))
        except Exception as error:
            # Never remove published files: another process could already be using them.
            if published:
                fail("partial_import", f"Import stopped: {error}. Already received: {', '.join(published)}")
            raise
        finally:
            os.close(target)
            remove_created(target_root, received)
    return {"result": {"imported": True, "destination": root, "paths": published, **budget}}


def dispatch(req):
    if not isinstance(req, dict) or req.get("protocol") != "abra-adapter/1":
        fail("invalid_request", "Expected abra-adapter/1 protocol")
    if req.get("kind", KIND) != KIND:
        fail("invalid_request", "Unsupported Files kind")
    verb = req.get("verb")
    if verb == "inventory":
        return inventory(req)
    if verb == "export":
        return export(req)
    if verb == "import":
        return import_files(req)
    fail("unsupported_verb", "Unsupported verb")


def main():
    while True:
        line = sys.stdin.buffer.readline(1024 * 1024 + 1)
        if not line:
            return
        req = {}
        try:
            if len(line) > 1024 * 1024:
                fail("invalid_request", "Request exceeds 1 MiB")
            req = json.loads(line)
            fields = {"ok": True, **dispatch(req)}
        except Failure as error:
            fields = {"ok": False, "error": {"code": error.code, "message": error.message, "retryable": False}}
        except (OSError, ValueError, TypeError) as error:
            code = "not_found" if isinstance(error, FileNotFoundError) else "permission_denied" if isinstance(error, OSError) else "invalid_request"
            fields = {"ok": False, "error": {"code": code, "message": str(error), "retryable": False}}
        print(json.dumps({"request_id": req.get("request_id") if isinstance(req, dict) else None, **fields}, separators=(",", ":")), flush=True)
        if len(line) > 1024 * 1024:
            return


if __name__ == "__main__":
    main()
