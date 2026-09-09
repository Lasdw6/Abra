# Abra

Abra is a portable snapshot and restore primitive for sandboxes and workspaces.
It lets a workload continue on another machine or CPU architecture by carrying
its files, application checkpoints, and descriptions of how to restart it.

A snapshot separates portable state from optional native VM state. A compatible
host can use the native state for fast resume. A different host restores the
portable state into a fresh environment with its own architecture-compatible
runtime. Abra signs snapshots, deduplicates their contents, and transfers them
between trusted devices over an encrypted connection.

## What can move across architectures

| State | Restore behavior |
|---|---|
| Workspace files and typed application checkpoints | Restore byte for byte; the receiving application must support their formats |
| Process observations and restart recipes | Remain data; the receiver resolves dependencies and chooses what to start |
| Firecracker memory, VM state and disk | Native resume only when the receiver fingerprint matches and every required object is verified |
| CRIU process memory and threads | Explicit process restore on compatible Linux hosts; never an x86-to-ARM memory conversion |
| Binaries, installed packages and external services | Supply or rebuild for the target architecture; Abra does not translate machine code or recreate external services |

For example, a Linux x86 sandbox can checkpoint a Python service's files and
application state, then continue from that checkpoint in an ARM sandbox running
Python. The service restarts from the application checkpoint; its x86 CPU
registers and live memory are not resumed on ARM. A service that keeps state only
in memory can use the optional CRIU backend on compatible Linux hosts.
Cross-architecture application continuation still requires saved state in a
format the destination application understands.

The [portability guide](docs/PORTABILITY.md) defines this contract and includes
an executable checkpoint example. The
[Firecracker adapter](adapters/firecracker/README.md) implements native resume
with portable fallback. The [sandbox coordinator](adapters/sandbox/README.md)
captures and restores through local, SSH and Daytona drivers.

## Concepts

- A snapshot is a typed, content-addressed JSON manifest plus its data.
- A capsule is a continuing workspace or sandbox with snapshot history.
- A lease records which device is driving a capsule.
- A full snapshot updates a capsule. A partial snapshot lands in the inbox as a
  one-time handoff.
- An adapter imports or exports one app's state through an NDJSON process.
- A sandbox collector records runtime facts and derives service recipes. It is
  pushed into a sandbox and run once, or installed in a Firecracker guest. Abra
  transports this ledger as data and never executes it.

## Repo layout

| Path | Contents |
|---|---|
| `crates/abra-core` | Identity, CAS, manifests, capsules, leases, and links |
| `crates/abra-net` | Pairing, authorization, transport, delivery, and control |
| `crates/abra-cli` | The `abra` command, including `abra daemon` |
| `crates/abra-runtime` | Rust process observer, sandbox helpers and optional CRIU backend |
| `crates/cadabra` | Daemon library used by `abra daemon` |
| `crates/abra-relay` | Sealed offline store-and-forward relay |
| `adapters/lib` | Shared JavaScript adapter helper |
| `adapters/reference-folder` | Python protocol reference adapter |
| `adapters/codex-session` | Codex session adapter |
| `adapters/browser-session` | Browser session adapter |
| `adapters/sandbox` | External sandbox coordinator and Daytona, SSH and local drivers |
| `adapters/firecracker` | Firecracker VM adapter |

## Quickstart

Requires Rust 1.91+ and Python 3. This local example pairs two disposable roots, sends a
workspace, checks its restore plan, and materializes it. It needs no cloud account.

Run these commands from a checkout of this repository. To install the CLI into
your Cargo bin directory afterward, run `cargo install --locked --path crates/abra-cli`.
For a release archive, unpack it and add its directory to `PATH`; keep the bundled
`adapters` directory. Register individual adapters with
`abra adapters add /absolute/path/to/adapters/reference-folder` while the daemon
is running. Python and JavaScript adapters need their own interpreters installed.

```sh
cargo build --locked -p abra-cli
ABRA="$PWD/target/debug/abra"
DEMO=$(mktemp -d)
printf 'Demo files: %s\n' "$DEMO"
mkdir "$DEMO/source"
printf 'portable state\n' > "$DEMO/source/checkpoint.txt"
"$ABRA" --root "$DEMO/a" daemon --background --yes
"$ABRA" --root "$DEMO/b" daemon --background --yes
TICKET=$("$ABRA" --root "$DEMO/b" pair ticket)
"$ABRA" --root "$DEMO/a" pair add "$TICKET"
PEER=$("$ABRA" --root "$DEMO/b" --json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer_id"])')
"$ABRA" --root "$DEMO/a" init "$DEMO/source"
SNAPSHOT=$("$ABRA" --root "$DEMO/a" --json snapshot "$DEMO/source" | python3 -c 'import json,sys; print(json.load(sys.stdin)["snapshot_id"])')
"$ABRA" --root "$DEMO/a" send "$PEER" --snapshot "$SNAPSHOT" --wait
"$ABRA" --root "$DEMO/b" --json restore-plan "$SNAPSHOT"
"$ABRA" --root "$DEMO/b" accept "$SNAPSHOT" "$DEMO/restored"
cat "$DEMO/restored/checkpoint.txt"
"$ABRA" --root "$DEMO/a" stop
"$ABRA" --root "$DEMO/b" stop
```

Use `--yes` only with disposable test roots or where ticket possession is enough
to authorize pairing. Normal pairing asks the receiving device for confirmation.
Keep the printed demo directory to inspect the snapshots; delete it when finished.

See [Add Abra to your sandbox](docs/INTEGRATE.md) for setup steps.
[Local API](docs/API.md) lists commands, fields, results, and events.
[Adapters](docs/ADAPTERS.md) defines the adapter process contract.
[Sandbox observations](docs/OBSERVATION.md) describes the ledger and capture contract.
[Live process checkpoints](docs/PROCESS_CHECKPOINTS.md) explains the optional CRIU path.
[Design](DESIGN.md) explains design choices. The [protocol specification](SPEC.md)
defines the wire format.

## Status

Developer alpha. Abra has local snapshot storage, restore planning, encrypted
iroh delivery, pairing and device revocation, scoped guest enrollment, leases,
capability links, adapters, and a durable sealed offline relay. The default n0
mode supports connections across NATs.

Portable-file verification does not prove a workload can run unchanged.
Application checkpoints, target runtimes, credentials and external data remain
the caller's responsibility. The observer reports best-effort consistency.
See [compatibility and recovery](docs/COMPATIBILITY.md) for version and failure
guarantees, and [release checks](docs/RELEASING.md) for validation and packaging.

## License

Licensed under either Apache License 2.0 or MIT, at your option. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
