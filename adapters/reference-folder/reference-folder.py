#!/usr/bin/env python3
import json, os, shutil, stat, sys

def reply(req, ok=True, **fields):
    print(json.dumps({"request_id": req.get("request_id"), "ok": ok, **fields}, separators=(",", ":")), flush=True)

def inside(root, path):
    return os.path.commonpath((os.path.realpath(root), os.path.realpath(path))) == os.path.realpath(root)

def contains_symlink(root):
    for current, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            if stat.S_ISLNK(os.lstat(os.path.join(current, name)).st_mode):
                return True
    return False

def safe_copytree(source, destination):
    boundary = os.path.realpath(destination)
    os.makedirs(destination, exist_ok=True)
    for current, dirs, names in os.walk(source, followlinks=False):
        relative = os.path.relpath(current, source)
        target_root = destination if relative == "." else os.path.join(destination, relative)
        if not inside(boundary, target_root): raise PermissionError("destination escape")
        os.makedirs(target_root, exist_ok=True)
        for name in dirs + names:
            source_path, target = os.path.join(current, name), os.path.join(target_root, name)
            if not inside(boundary, target): raise PermissionError("destination escape")
            if os.path.islink(source_path):
                if os.path.lexists(target): raise PermissionError("destination path is unsafe")
                os.symlink(os.readlink(source_path), target)
                if not inside(boundary, target):
                    os.unlink(target); raise PermissionError("destination escape")
            elif os.path.isdir(source_path):
                os.makedirs(target, exist_ok=True)
            else:
                shutil.copy2(source_path, target, follow_symlinks=False)

for line in sys.stdin:
    try:
        req = json.loads(line)
        if req.get("protocol") != "abra-adapter/1":
            reply(req, False, error={"code":"invalid_request","message":"bad protocol","retryable":False}); continue
        verb = req.get("verb")
        if verb == "export":
            source, staging = req.get("source"), req.get("staging_dir")
            if not source or not os.path.isdir(source) or not staging:
                reply(req, False, error={"code":"not_found","message":"source folder not found","retryable":False}); continue
            if contains_symlink(source):
                reply(req, False, error={"code":"permission_denied","message":"source folder contains a symlink","retryable":False}); continue
            target = os.path.join(staging, "files")
            if not inside(staging, target): raise ValueError("staging escape")
            shutil.copytree(source, target, symlinks=True)
            reply(req, payload={"schema":"dev.abra.folder/1"}, files_path=target, floor={"title":os.path.basename(os.path.abspath(source))})
        elif verb == "import":
            materialized, destination = req.get("materialized_files"), req.get("destination")
            if materialized and os.path.realpath(materialized) != os.path.realpath(destination):
                os.makedirs(destination, exist_ok=True)
                safe_copytree(materialized, destination)
            reply(req, result={"imported":True})
        elif verb == "inspect":
            source = req.get("source")
            if not source or not os.path.isdir(source):
                reply(req, False, error={"code":"not_found","message":"source folder not found","retryable":False}); continue
            warnings, blocked, count = [], [], 0
            for root, _, names in os.walk(source):
                for name in names:
                    path = os.path.join(root, name)
                    count += 1
                    relative = os.path.relpath(path, source)
                    if name == ".env":
                        blocked.append({"code":"dotenv","message":"environment file would be sent","item":relative})
                    elif os.path.isfile(path) and os.path.getsize(path) > 1024 * 1024:
                        warnings.append({"code":"large-file","message":"file is larger than 1 MiB","item":relative})
            reply(req, summary=f"{count} files", warnings=warnings, blocked=blocked)
        elif verb == "control":
            reply(req, result={"op":req.get("op"),"text":req.get("text"),"workspace":req.get("workspace")})
        elif verb == "cancel":
            # This single-threaded adapter can only be cancelled by killing it.
            reply(req, False, error={"code":"cancelled","message":"cancelled","retryable":False}); break
        else:
            reply(req, False, error={"code":"unsupported_verb","message":"unsupported verb","retryable":False})
    except PermissionError as error:
        reply(locals().get("req", {}), False, error={"code":"permission_denied","message":str(error),"retryable":False})
    except Exception:
        reply(locals().get("req", {}), False, error={"code":"internal","message":"adapter operation failed","retryable":False})
