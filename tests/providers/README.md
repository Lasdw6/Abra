# Sandbox provider tests

These tests create disposable sandboxes at a provider and run the
[sandbox coordinator](../../adapters/sandbox/README.md) against them from this
machine. Nothing Abra-specific is installed in the sandbox.

## Daytona

Use Python 3.11 or newer and an API key allowed to create and delete sandboxes:

```sh
python3.11 -m venv /tmp/abra-daytona-venv
/tmp/abra-daytona-venv/bin/pip install daytona==0.210.0
cargo build --release -p abra-cli
export DAYTONA_API_KEY  # Set this through your shell or secret manager.
/tmp/abra-daytona-venv/bin/python tests/providers/daytona_sandbox_e2e.py \
  --remote-abra /path/to/linux-abra \
  --report-dir /tmp/abra-daytona-results
```

`--abra` selects the binary for the local roots. `--remote-abra` selects the
Linux binary temporarily uploaded to Daytona. Its architecture must match the
sandbox. The test fails before upload when the binary format, OS, or CPU does
not match. You can omit `--remote-abra` only when `--abra` already matches the
sandbox.

The runner creates two sandboxes from `mcr.microsoft.com/playwright:v1.49.1-noble`
(python3, node 22, chromium; `--image` changes it). If image creation fails it
falls back to Daytona's default snapshot, tries `apt-get install chromium nodejs`,
and records the fallback in the report. Two Abra roots start on this machine
with `daemon --background --adapters adapters` and pair over iroh.

Sandbox A gets a workspace with a marker file, `python3 -m http.server 8123`,
and headless chromium with CDP on 9222. The CDP fixture
(`adapters/browser-session/bin/cdp-fixture.mjs`) sets a cookie and a
localStorage entry for `http://127.0.0.1:8123` and opens the marker page.
`abra-sandbox capture` runs from root A with the daytona driver. The runner
checks: ledger barrier matches the snapshot, host facts name the sandbox,
`effective_cpu_millicores` and `effective_memory_bytes` match the sandbox's
cpu and memory, a service candidate for 8123 is `unverified`, the mirror holds
the files, the cookie and localStorage values appear in no file under root A
outside the browser bundle, and no completed coordinator temp dirs remain in
the sandbox. One runner-owned Abra directory exists while the test's direct
driver is open, and its path is checked. Cleanup closes that driver and removes
the directory before deleting or preserving the sandbox.

Root A sends the snapshot and the browser bundle (`--source bundle:<dir>`) to
root B with `--wait`. Root B materializes the bundle with `accept --no-import`
and runs `abra-sandbox restore` into sandbox B twice: first without `--start`,
which pushes the files and must start nothing (8123 is checked closed), then
with `--replace-workspace`, `--start <index>` and `--browser`. The runner then fetches the marker
from the started server inside B and reads B's chromium through the fixture:
the cookie and localStorage entry must be present.

`--no-browser` skips the chromium half. `--keep` leaves sandboxes and roots
for inspection. The report (`report.json`), coordinator output, daemon logs and
sandbox process logs go to `--report-dir`. Both sandboxes are deleted in
`finally`, waiting for destruction; a cleanup failure fails the run. Each
sandbox also has a 60-minute TTL. The API key stays in the local SDK process
and is redacted from error strings.

The transfer step needs outbound access from this machine only; the sandboxes
do not talk to iroh relays. Process `started_at` values from inside a Daytona
sandbox can be wrong because the container's `/proc/uptime` is the host's; the
runner does not assert on them.

This test does not exercise provider-native snapshots or cross-architecture
restore. The Firecracker equivalent is `adapters/sandbox/tests/firecracker_e2e.sh`.
