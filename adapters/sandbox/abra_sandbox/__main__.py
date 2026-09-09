"""abra-sandbox capture|restore."""

import argparse
import json
import os
import sys

from . import coordinator
from .drivers import load


def driver_option(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError("--driver-opt takes key=value")
    key, _, rest = value.partition("=")
    return key.strip(), rest


def add_common(parser):
    parser.add_argument("--driver", required=True, choices=["local", "ssh", "daytona"])
    parser.add_argument("--driver-opt", action="append", default=[], type=driver_option, metavar="K=V")
    parser.add_argument("--name", required=True, help="local sandbox name; the mirror lives under <root>/sandboxes/<name>")
    parser.add_argument("--remote-workspace", default="/workspace")
    parser.add_argument("--browser-cdp", metavar="WS_URL")
    parser.add_argument("--browser-port", type=int, metavar="PORT")
    parser.add_argument("--abra", default=coordinator.default_abra(), help="abra binary (default: ABRA_BIN, PATH, target/release)")
    parser.add_argument("--remote-abra", help="architecture-compatible Abra binary to upload to the sandbox (default: --abra)")
    parser.add_argument("--abra-root", default=coordinator.default_root())
    parser.add_argument("--adapter-dir", default=coordinator.ADAPTER_DIR, help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true")


def build_parser():
    parser = argparse.ArgumentParser(prog="abra-sandbox", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture", help="collect once, pull the tree, take a local abra snapshot")
    add_common(capture)
    capture.add_argument("--membership", default="all", help="all | workspace | cgroup:<path> | pgrp:<pid>")
    capture.add_argument("--collector", help=argparse.SUPPRESS)
    restore = commands.add_parser("restore", help="accept a snapshot locally and push its files into a sandbox")
    add_common(restore)
    restore.add_argument("--snapshot", required=True)
    restore.add_argument("--replace-workspace", action="store_true",
                         help="replace all existing remote workspace contents with the snapshot")
    restore.add_argument("--browser", metavar="BUNDLE_DIR", help="browser bundle to import into the sandbox browser")
    restore.add_argument("--start", action="append", type=int, default=[], metavar="INDEX",
                         help="start this service candidate; nothing runs otherwise")
    return parser


def redact(text):
    for name in ("DAYTONA_API_KEY",):
        value = os.environ.get(name)
        if value:
            text = text.replace(value, "<redacted>")
    return text


def print_human(result):
    for key, value in result.items():
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        print("%s: %s" % (key, value))


def main(argv=None):
    args = build_parser().parse_args(argv)
    abra = coordinator.Abra(args.abra, os.path.realpath(args.abra_root))
    try:
        driver = load(args.driver, dict(args.driver_opt))
    except Exception as error:
        print("abra-sandbox: %s" % redact(str(error)), file=sys.stderr)
        return 1
    try:
        if args.command == "capture":
            result = coordinator.capture(driver, args.name, args.remote_workspace, abra, args.membership,
                                         args.browser_cdp, args.browser_port, args.collector, args.adapter_dir,
                                         args.remote_abra)
        else:
            result = coordinator.restore(driver, args.name, args.snapshot, args.remote_workspace, abra, args.browser,
                                        args.browser_cdp, args.browser_port, args.start, args.adapter_dir,
                                        args.replace_workspace, args.remote_abra)
    except Exception as error:
        print("abra-sandbox: %s" % redact(str(error)), file=sys.stderr)
        return 1
    finally:
        driver.close()
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print_human(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
