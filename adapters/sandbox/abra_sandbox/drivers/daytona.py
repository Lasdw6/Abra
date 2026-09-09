"""Daytona driver. The API key comes only from DAYTONA_API_KEY."""

import os
import shlex

from .base import Driver


class DaytonaDriver(Driver):
    name = "daytona"

    def __init__(self, sandbox=None, create=None, image=None, cpu=None, memory=None, disk=None,
                 name=None, labels=None, auto_stop=None, delete=None, **_):
        import daytona

        key = os.environ.get("DAYTONA_API_KEY")
        if not key:
            raise RuntimeError("set DAYTONA_API_KEY in the environment")
        self.client = daytona.Daytona(daytona.DaytonaConfig(api_key=key))
        self.delete_on_close = str(delete) == "1"
        if sandbox:
            self.sandbox = self.client.get(sandbox)
        elif str(create) == "1":
            options = {
                "name": name,
                "labels": dict(item.split("=", 1) for item in labels.split(",")) if labels else None,
                "auto_stop_interval": int(auto_stop) if auto_stop else None,
            }
            resources = daytona.Resources(cpu=int(cpu) if cpu else None, memory=int(memory) if memory else None,
                                          disk=int(disk) if disk else None)
            if image:
                params = daytona.CreateSandboxFromImageParams(image=image, resources=resources, **options)
            else:
                params = daytona.CreateSandboxFromSnapshotParams(**options)
            self.sandbox = self.client.create(params, timeout=600)
        else:
            raise RuntimeError("daytona driver needs sandbox=<id> or create=1")

    def run(self, argv, timeout, env, cwd):
        # exec returns text output only, so stderr is folded into stdout.
        response = self.sandbox.process.exec(shlex.join(argv) + " 2>&1", cwd=cwd, env=env or None, timeout=timeout)
        return response.exit_code, (response.result or "").encode("utf-8", "replace"), b""

    def put(self, local_file, remote_file, mode=0o600):
        self.check(["mkdir", "-p", os.path.dirname(remote_file)])
        self.sandbox.fs.upload_file(local_file, remote_file)
        self.check(["chmod", "%o" % mode, remote_file])

    def get(self, remote_file, local_file):
        self.sandbox.fs.download_file(remote_file, local_file)

    def facts(self):
        box = self.sandbox
        try:
            box.refresh_data()
        except Exception:
            pass
        return {"provider": "daytona", "sandbox_id": box.id, "name": box.name, "snapshot": box.snapshot,
                "target": box.target, "cpu": box.cpu, "memory_gib": box.memory, "disk_gib": box.disk,
                "os_user": box.user, "state": str(box.state) if box.state else None}

    def native_capture(self):
        # Daytona's snapshot() builds an image and is slow; not used yet.
        return None

    def close(self):
        super().close()
        if self.delete_on_close:
            self.client.delete(self.sandbox, timeout=120, wait=True)
