"""Driver registry. Provider SDKs are imported inside their driver module."""

import importlib

DRIVERS = {"local": "local", "ssh": "ssh", "daytona": "daytona"}
CLASS_NAMES = {"local": "LocalDriver", "ssh": "SshDriver", "daytona": "DaytonaDriver"}


def load(name, options):
    if name not in DRIVERS:
        raise ValueError("unknown driver %r; choose from %s" % (name, ", ".join(sorted(DRIVERS))))
    module = importlib.import_module("abra_sandbox.drivers." + DRIVERS[name])
    return getattr(module, CLASS_NAMES[name])(**options)
