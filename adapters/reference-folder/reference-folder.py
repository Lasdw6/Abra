#!/usr/bin/env python3
import json, os, shutil, sys, time

def reply(req, ok=True, **fields):
    print(json.dumps({"request_id": req.get("request_id"), "ok": ok, **fields}, separators=(",", ":")), flush=True)

def inside(root, path):
    return os.path.commonpath((os.path.realpath(root), os.path.realpath(path))) == os.path.realpath(root)

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
            target = os.path.join(staging, "files")
            if not inside(staging, target): raise ValueError("staging escape")
            shutil.copytree(source, target, symlinks=True)
            reply(req, result={"payload":{"schema":"dev.abra.folder/1"},"files_path":target,"floor":{"title":os.path.basename(os.path.abspath(source))}})
        elif verb == "import":
            materialized, destination = req.get("materialized_files"), req.get("destination")
            if materialized and os.path.realpath(materialized) != os.path.realpath(destination):
                os.makedirs(destination, exist_ok=True)
                shutil.copytree(materialized, destination, dirs_exist_ok=True, symlinks=True)
            reply(req, result={"result":{"imported":True}})
        elif verb == "watch":
            reply(req, watching=True)
            source, previous = req.get("source"), None
            while True:
                stamp = max((os.stat(os.path.join(r, f)).st_mtime_ns for r, _, fs in os.walk(source) for f in fs), default=0)
                if previous is not None and stamp != previous:
                    print(json.dumps({"request_id":req["request_id"],"event":"changed","cursor":str(stamp),"hint":"folder changed"}), flush=True)
                previous = stamp; time.sleep(.25)
        elif verb == "cancel":
            reply(req, False, error={"code":"cancelled","message":"cancelled","retryable":False}); break
        else:
            reply(req, False, error={"code":"unsupported_verb","message":"unsupported verb","retryable":False})
    except Exception as error:
        reply(locals().get("req", {}), False, error={"code":"internal","message":str(error),"retryable":False})
