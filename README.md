Abra is infrastructure for teleportation.

Abra moves files, workspaces, and app state between one user's devices and their
cloud agents. It is pure transport and materialization: it carries bytes and
structure, and it executes nothing.

The core principle is **carry the data, don't prescribe the experience**. A
snapshot carries the maximal amount of structured, parsable data about what it
is; the receiver decides what to do with it — render a card, open a deep link,
sync a workspace, resume a sandbox. The sender authors nothing extra.

## Concepts

- **Snapshot** is the noun: a typed, self-describing, content-addressed bundle.
  Its manifest is always JSON — a snapshot is never an opaque blob.
- **Teleport** is the verb: moving a snapshot end-to-end encrypted within one
  user's device mesh.
- **Capsule** is a continuing thing (a workspace, a sandbox) with a history DAG
  of snapshots. A **lease** says which device is currently driving it.
- **Scope** splits the one envelope format two ways. `full` is a new version of
  a capsule and syncs into the capsule store. `partial` is a delivery — a file,
  a folder, a browser session, a handoff link — and lands in an inbox.

See [DESIGN.md](DESIGN.md) for the settled design and [SPEC.md](SPEC.md) for the
wire format.

## Repo layout

```
crates/abra-core   library: identity, CAS, snapshots, capsule store, links
crates/abra-cli    thin `abra` UDS client
crates/cadabra     library-first daemon and `cadabra` binary
docs/API.md        local NDJSON control protocol
docs/ADAPTERS.md   external adapter contract
```

`abra-core` modules:

| module     | what it owns                                                        |
| ---------- | ------------------------------------------------------------------- |
| `identity` | Ed25519 device keypairs, `PeerId`, signing and verification          |
| `cas`      | blake3 blob store, tree objects, `snapshot_dir`, `materialize`       |
| `snapshot` | `Manifest`, scope, provenance, recipes, native blob refs, hashing    |
| `store`    | `SnapshotStore` (DAG walk) and `CapsuleRegistry` (local bookkeeping) |
| `enroll`   | scoped enrollment certificates                                      |
| `link`     | capability links: mint, parse, seal, open                           |

## Quickstart

Build the binaries, then start a daemon in the first terminal:

```console
$ cargo build --workspace
$ target/debug/abra --root /tmp/abra-a daemon --yes
```

Use a second terminal as the client:

```console
$ target/debug/abra --root /tmp/abra-a status
$ target/debug/abra --root /tmp/abra-a pair ticket
$ target/debug/abra --root /tmp/abra-a init ./my-workspace
$ target/debug/abra --root /tmp/abra-a snapshot ./my-workspace -m first
$ target/debug/abra --root /tmp/abra-a outbox
```

For a two-device demo, run two `Daemon` instances on one `LoopbackNetwork`
(the end-to-end test is an executable reference), redeem B's `pair ticket` on
A with `pair add`, then use `send <B-peer-id> --capsule <snapshot-id>`. On B,
`inbox` shows partial handoffs and `accept <id> --to <empty-path>` materializes
them; full capsule snapshots appear in `log` and can also be accepted by id.
The default loopback transport is deliberately in-process; build with the
optional iroh transport for separate-device routing.

## Status

Stages 1–3 include local primitives, authenticated transport, durable delivery,
the daemon, CLI, and end-to-end loopback tests. Relays, capability web viewers,
external adapter implementations, and iroh-path end-to-end tests remain out of
scope.

## Building

```console
$ cargo test
$ cargo clippy --all-targets -- -D warnings
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.
