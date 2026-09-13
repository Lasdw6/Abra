# Abra codex-session

An `abra-adapter/1` adapter that moves one Codex CLI session. A session is one
`rollout-*.jsonl` file under `$CODEX_HOME/sessions/`. Kind:
`dev.abra.codex.session.v1`. Zero dependencies, Node 20+.

```sh
abra send <peer> --kind dev.abra.codex.session.v1 --source '{"session_id":"<uuid>"}'
abra accept <id> <dir> --destination '{"codex_home":"/home/me/.codex","workspace":"/work/demo"}'
```

`bin/adapter.js` is the stdio loop built on `adapters/lib/adapter.js`; all the
behavior lives in `lib/session.js`.

The manifest advertises `inventory`. Its inventory response labels the source
`Codex`, describes it, and returns paused threads as opaque session selectors.
Abra Cloud builds its source tab and list directly from that response. The
Cloud app does not register or identify this adapter by name. Active threads
remain visible but unavailable until their current writer releases the session.

Export takes a writer lock and validates the rollout. Its first record must be
`session_meta`. The UUID must match the filename, and the file must end in a
newline. Export scans for credential shapes and copies the file to staging as
`session.jsonl`. It writes `manifest.json` with counts, hashes, sizes, and the
last imported ancestor. A secret finding aborts export with its category and
line number. Inspect it locally before using `--adapter-option allow_secrets=true`.

Import verifies the bundle against the manifest and outer payload. It refuses a
rollout that diverged from the declared ancestor. It does not merge histories.
It also refuses the same UUID at another rollout path. Import checks the local
`codex --version`, then installs the file as `0600` under `0700` directories.
It records a checkpoint for the next handoff. Import runs nothing. Its result
contains the `codex resume` command to run by hand.

Sessions are limited to 512 MiB. Export source objects accept `session_id`,
`codex_home`, `workspace_snapshot_id`, `workspace_capsule_id`,
`workspace_ancestor_snapshot_id`, and `workspace_name`. A string source is the
session id.

Destination objects require `codex_home`. They may include `workspace` and
`expected_workspace_ancestor`. The last field must match the bundle's
`workspace_ancestor_snapshot_id`.

`CODEX_BIN` selects the Codex executable for version checks and control.
For `instruct`, control reads the session id from
`<workspace>/.abra/codex-session.json`. It runs `codex exec ... resume` in that
workspace. Pause and stop are recorded only.

Options: `allow_secrets`, `allow_version_mismatch`, `skip_version_check`,
`stage_only`, `lock_nonce`.

## Tests

```sh
node --test adapters/codex-session/test/*.test.js
```

They use temporary `CODEX_HOME` directories and never touch a real `~/.codex`.
`ABRA_CODEX_TEST_REAL=1` also checks the installed `codex` version and uses a
real, unauthenticated app-server to verify writer locking and characterize
forked-child behavior.

## Platforms

macOS, Linux, and Windows are supported. The Codex home defaults to
`CODEX_HOME`, else `.codex` under the OS home directory, which is what Windows
needs because `HOME` is usually unset there.

The writer lock is held by a child process so a crash releases it. On macOS and
Linux that child is `perl` holding an advisory `flock` (`PERL_BIN` overrides the
path). Windows has no `flock`, so the child is `node`: it claims the lock name
with an exclusive create, records its pid, and reclaims the file only when the
recorded pid is gone. Both report a busy lock the same way.

`codex` is resolved through PATH using PATHEXT on Windows, and a `.cmd` or
`.bat` wrapper is run through `ComSpec`. Cancelling a `control` request tears
the whole process tree down with `taskkill /T` on Windows, where terminating
only the direct child would orphan whatever the wrapper started.

The live test uses two real Abra daemons and real Codex model turns. It copies a
login file into private temporary homes for the duration of the test; the
adapter bundle itself does not transport that file. The test removes both homes
afterward.

```sh
ABRA_CODEX_TEST_REAL=1 \
ABRA_CODEX_TEST_LIVE=1 \
ABRA_CODEX_TEST_AUTH_FILE="$HOME/.codex/auth.json" \
node --test adapters/codex-session/test/live-handoff.test.js
```

The live test sends a tool-using session and workspace to a second peer,
rebuilds readable history without destination auth, continues the model turn
through Abra's remote control after destination auth is supplied, sends the
result back, and continues it again. It consumes Codex usage and requires
`target/debug/abra`; build that with `cargo build --locked -p abra-cli` first.

The Daytona test moves the same durable state between macOS ARM64 and a
disposable Daytona Linux x86_64 sandbox. It uses the Daytona file API as the
carrier and runs this adapter at both endpoints. It is separate from direct Abra
peer connectivity inside Daytona.

```sh
python3.11 -m venv /tmp/abra-daytona-codex-venv
/tmp/abra-daytona-codex-venv/bin/pip install daytona==0.198.0
export DAYTONA_API_KEY
/tmp/abra-daytona-codex-venv/bin/python \
  adapters/codex-session/test/daytona-handoff.py
```

The test verifies offline history before destination auth is present. It then
copies the selected auth file separately, continues a real model turn in
Daytona, returns the updated session, and resumes it on the Mac. Daytona denied
Codex's nested command sandbox in the tested container, so the remote turn uses
Codex's sandbox bypass inside the disposable provider sandbox. The test deletes
its sandbox in `finally` and reports cleanup failure as a test failure.

`daytona-peer.py` tests the direct network route using a Linux Abra release
archive:

```sh
/tmp/abra-daytona-codex-venv/bin/python \
  adapters/codex-session/test/daytona-peer.py \
  --linux-archive /path/to/abra-x86_64-unknown-linux-gnu.tar.gz \
  --iroh-relay https://use1-1.relay.n0.iroh.link \
  --daytona-domain-allow-list use1-1.relay.n0.iroh.link
```

The September 12, 2026 Mac and Daytona run passed pairing, confirmation,
session acknowledgement, and Codex session import through the relay. Daytona's
HTTPS proxy presents a private CA through `SSL_CERT_FILE`; Abra adds that CA to
Iroh's embedded Mozilla roots and uses the standard proxy environment. The test
also waits for Iroh's initial network report before publishing a direct-only
fallback.

Daytona rejected the default n0 relay hostname because Iroh sent its absolute
DNS form with a trailing dot. Daytona's per-sandbox allow-list validator also
rejected a wildcard containing that dot. Use a specific relay URL without the
trailing dot and put that exact hostname in the sandbox allow list, as shown
above. For a dedicated relay, pass the same HTTPS URL to both daemons with
`--iroh-relay https://relay.example`. The test records the relay URLs in both
tickets and fails if the expected relay is absent.
