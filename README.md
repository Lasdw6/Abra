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

See [docs/DESIGN.md](docs/DESIGN.md) for the settled design and
[docs/SPEC.md](docs/SPEC.md) for the wire format.

## Repo layout

```
crates/abra-core   library: identity, CAS, snapshots, capsule store, links
crates/abra        CLI binary (stub in phase 1)
crates/cadabra     daemon binary (stub in phase 1)
docs/DESIGN.md     settled design decisions, including later phases
docs/SPEC.md       envelope/manifest format, abra_spec 1
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

_Placeholder — the CLI lands with the transport phase._

```console
$ cargo run -p abra
abra 0.1.0 (abra-core 0.1.0, abra_spec 1)
```

Planned:

```console
$ abra enroll                 # admit a device into your mesh
$ abra send ./report.pdf      # teleport a partial to your other devices
$ abra capsule track ./work   # make a directory a capsule
$ abra push work              # snapshot it and teleport the new version
```

## Status

Phase 1: local primitives only. There is no network code yet — no transport, no
outbox, no relay. Everything here is on-disk and offline, and it is the
foundation the delivery loop is built on.

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
