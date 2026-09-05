# Abra sandbox coordinator

`abra-sandbox` attaches Abra to a sandbox you do not control: a Daytona
sandbox, a machine you can only ssh into, a Firecracker guest. It runs next to
your local Abra daemon and only needs two things from the provider: run a
command, and move files in and out.

```
  coordinator (your machine, next to the local Abra daemon)
    1. pick a provider driver
    2. push the collector in, run it ONCE with a barrier id
    3. pull files + ledger out into a local mirror workspace
    4. ask the driver for native state (optional, may be None)
    5. local `abra snapshot` signs and stores the snapshot

  sandbox (any provider)
    collector (one-shot, no install) -> .abra/observed-<barrier>.json
    browser-session adapter run via exec -> bundle dir, pulled out as files
```

Nothing Abra-specific stays in the sandbox. No Abra daemon or binary goes in.
The only things pushed are `collector/observer.py` and, when you ask for a
browser session, the `adapters/browser-session` `bin/` and `lib/` files. Both
land in a temp dir that is removed after the run.

## Layout

```
bin/abra-sandbox                 shim, runs the package with python3
abra_sandbox/coordinator.py      capture / restore logic
abra_sandbox/drivers/            local, ssh, daytona
collector/observer.py            the collector (also the Firecracker guest observer)
collector/test_observer.py
tests/test_coordinator.py        local driver + stub collector + real abra, runs on macOS
tests/firecracker_e2e.sh         two guests on a KVM host, ssh driver
```

Python 3.9+, standard library only. The Daytona SDK is imported inside its
driver, so the other drivers work without it.

## Drivers

| Driver | `--driver-opt` keys | facts recorded | native |
|---|---|---|---|
| `ssh` | `host`, `user` (root), `key`, `port` (22), `known_hosts` (normal SSH configuration) | host, port, user | none |
| `daytona` | `sandbox=<id>` or `create=1` with `image`, `cpu`, `memory`, `disk`, `name`, `labels=k=v,k=v`, `auto_stop`; `delete=1` deletes on exit | sandbox id, name, snapshot, target, cpu, memory, disk, os user, state | none yet (a Daytona `snapshot()` builds an image; the hook is there) |
| `local` | `root` (temp dir; temp files go under `<root>/tmp`) | root path | none |
| e2b, modal | same shape, not written | | |

The Daytona API key comes only from `DAYTONA_API_KEY`. Daytona's `exec` returns
text, so that driver uses `fs.upload_file` / `fs.download_file` for bytes and
`exec` only for commands. No driver puts secrets on a remote command line.

SSH and SCP require a verified host key. Unknown or changed keys fail; there
is no automatic trust fallback. Populate known_hosts using a key verified
through a trusted channel, or pass `--driver-opt known_hosts=/path/to/known_hosts`.

A driver implements `run`, `put`, `get`, and optionally `facts`,
`native_capture`, `close`, `tmp_dir`. Tree transfer is tar over `put`/`get`
and works for every driver. Incoming archives are validated before writing:
absolute paths, traversal, special files, duplicate entries, and entries below
links are rejected. Relative symlinks must stay within the tree and cannot
traverse other symlinks; hardlinks must name regular archive members and are
materialized as independent files. Extraction requires an empty directory.
`native_capture` may return
`{"provider": ..., "handle": ..., "restorable_by": "same-provider"}`; that
handle is recorded in the snapshot's `host.facts.native` but never used to
restore across providers. Cross-provider restore is portable only: files,
recipes, browser bundles.

## Commands

```
abra-sandbox capture --driver D [--driver-opt k=v ...] --name N
    [--remote-workspace /workspace] [--membership all|workspace|cgroup:<p>|pgrp:<n>]
    [--browser-cdp ws://... | --browser-port 9222]
    [--abra PATH] [--abra-root ROOT] [--json]
```

Capture pushes the collector to `<tmp>/abra-collector-<barrier>/observer.py`,
runs it once with `--all` (default membership: every process in the sandbox's
PID namespace), pulls the workspace into `<root>/sandboxes/<name>/workspace`
(the mirror), runs `abra init` there the first time, and takes
`abra snapshot --observation-barrier <barrier> --observation-host <facts>`.
The mirror is made to match the sandbox: files deleted in the sandbox are
deleted in the mirror; local-only `.abra` files are kept. The pinned ledger is
removed from both sides after the snapshot. Output: `snapshot_id`,
`capsule_id`, `observation_barrier`, `mirror`, `recipes`, `service_candidates`
(count), `browser`, `native`, `collection_errors`.

With `--browser-*`, the adapter is pushed to `<tmp>/abra-browser-<barrier>/`,
`abra-browser export --from cdp` runs there with an ephemeral signing key in
`<tmp>/abra-browser-<barrier>/data`, and the bundle comes out to
`<root>/sandboxes/<name>/browser-<barrier>/`. `browser` reports the bundle
dir, the ephemeral key fingerprint, domains and tab URLs. Cookie values are in
the bundle only.

```
abra-sandbox restore --driver D [...] --name N --snapshot ID [--remote-workspace /workspace]
    [--browser BUNDLE_DIR --browser-cdp ws://... | --browser-port 9222]
    [--replace-workspace] [--start INDEX ...] [--abra PATH] [--abra-root ROOT] [--json]
```

Restore runs `abra accept ID <mirror>` (the snapshot must already be in this
root: you captured it, or received it with `abra send`), pushes the mirror into
the sandbox without `.abra/capsule_id` and `.abra/snapshot_id`, and lists the
service candidates from `.abra/received-observed.json` with their index,
restartability and missing requirements. Nothing runs unless `--start INDEX`
names one. A started candidate runs detached in `<remote-workspace>/<cwd>`
with the recipe's env over a minimal `PATH`; its pid and log path are
reported. Blocked candidates are refused. If the mirror already exists, accept
runs with `--replace --discard-local --allow-divergence`: the mirror is the
coordinator's copy, not a place for local edits.

The remote workspace must be empty or absent by default. Pass
`--replace-workspace` to replace all its contents, including files absent from
the snapshot. The coordinator validates and extracts into a private staging
directory before removing existing files, and preserves the workspace mount
point. Stop processes writing to that workspace before replacement: the final
file moves are not an atomic switch. A filesystem root or symlink destination
is refused. Restore also uploads a temporary Python extraction helper and
removes it and its archive afterward.

Moving a snapshot between devices is ordinary Abra:

```
abra send <peer> --snapshot <id> --wait
abra send <peer> --kind dev.abra.browser.session.v1 --source bundle:<root>/sandboxes/<name>/browser-<barrier>
# on the receiver
abra accept <bundle-id> <dir> --no-import
abra-sandbox restore --driver ... --name N --snapshot <id> --browser <dir> --browser-port 9222 --start 0
```

## Browser bundles and trust

A bundle is signed by the key that exported it. In a sandbox that key is
created for the run and thrown away; its fingerprint is in the bundle's
`manifest.json` and in the capture output. `restore --browser` passes that
fingerprint as `--trust-sender`. The trust decision is yours when you run
restore with a bundle you chose; the coordinator does not verify the sender
out of band. The import leaves `<tmp>/abra-browser-<id>/data` in the sandbox
(the receipt and registry a later `abra-browser revoke` needs); the bundle and
adapter copies are removed.

## Tests

```
python3 -m unittest discover -s adapters/sandbox/collector -p 'test_*.py'
python3 -m unittest discover -s adapters/sandbox/tests -p 'test_*.py'     # needs target/release/abra
tests/providers/daytona_sandbox_e2e.py                                  # live Daytona, see tests/providers/README.md
adapters/sandbox/tests/firecracker_e2e.sh                               # Linux KVM host
```

The Firecracker test requires verified guest keys in `FIRECRACKER_KNOWN_HOSTS`
(default `~/.ssh/known_hosts`) for 172.30.0.2 and 172.30.1.2. It explicitly
replaces the disposable guest workspace on restore.
