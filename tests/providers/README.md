# Sandbox provider tests

These tests create disposable workloads. They exercise portable workspace
transfer and the observer on the provider's actual Linux environment.

## Daytona

Use Python 3.11 or newer and an API key allowed to create and delete sandboxes:

```sh
python3.11 -m venv /tmp/abra-daytona-venv
/tmp/abra-daytona-venv/bin/pip install daytona==0.210.0
export DAYTONA_API_KEY  # Set this through your shell or secret manager.
/tmp/abra-daytona-venv/bin/python tests/providers/daytona_e2e.py \
  --abra /path/to/linux-x86_64/abra \
  --report-dir /tmp/abra-daytona-results
```

Build the binary from this checkout on a compatible Linux host with
`cargo build --locked --release -p abra-cli`. A macOS executable cannot run
inside the sandbox. Use the default Daytona image, or a matching Linux build
environment, for a dynamically linked binary.

The runner creates two sandboxes with unique names and labels. It uploads the
binary, observer, and test scripts. It runs the observer unit tests and a real
process/socket test, then checks that effective CPU and memory limits match
Daytona's configuration. A running HTTP service produces a pinned observation
and a workspace snapshot. Abra pairs the two sandboxes through its normal iroh
transport and sends the signed snapshot with delivery acknowledgement.

The receiver checks the files and exact observer data, confirms that accepting
the snapshot did not start a service, and checks that a new observation does
not overwrite received recipes. The test then explicitly starts its known HTTP
fixture and fetches the transferred file. It never executes arbitrary received
recipes.

The runner writes `report.json` and logs to the supplied directory, then deletes
both sandboxes in `finally`, waiting for destruction. Each sandbox also has a
30-minute TTL and deletes when auto-stopped. A cleanup failure makes the run
fail and records the sandbox IDs. The API key stays in the local SDK process;
it is not uploaded into either sandbox.

The transfer test needs outbound access to iroh's relay endpoints at
`*.relay.n0.iroh.link`. Daytona's [network policy](https://www.daytona.io/docs/en/network-limits/)
can restrict these by organization tier. If pairing times out and the daemon
reports that the relay is not ready, check provider egress before assuming an
observer failure. The September 4, 2026 run passed all observation and capture
checks, but Daytona reset connections to all four default relay endpoints, so
transfer and destination restart were not reached.

Add `--observer-only` to check the observer and signed capture in one sandbox
without pairing or transfer. The report records this mode explicitly.

`observer_probe.py` and `workspace_probe.py` use the Python standard library
and can also run inside other sandbox providers. This test does not exercise
provider-native VM snapshots or cross-architecture restore.
