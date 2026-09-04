# Abra

Abra moves typed snapshots between a user's trusted devices. It sends files,
workspaces, app state, and links over an authenticated, encrypted connection.
The receiver chooses how to use each snapshot.

## Concepts

- A snapshot is a typed, content-addressed JSON manifest plus its data.
- A capsule is a continuing workspace or sandbox with snapshot history.
- A lease records which device is driving a capsule.
- A full snapshot updates a capsule. A partial snapshot lands in the inbox as a
  one-time handoff.
- An adapter imports or exports one app's state through an NDJSON process.

## Repo layout

| Path | Contents |
|---|---|
| `crates/abra-core` | Identity, CAS, manifests, capsules, leases, and links |
| `crates/abra-net` | Pairing, authorization, transport, delivery, and control |
| `crates/abra-cli` | The `abra` command, including `abra daemon` |
| `crates/cadabra` | Daemon library used by `abra daemon` |
| `crates/abra-relay` | Sealed offline store-and-forward relay |
| `adapters/lib` | Shared JavaScript adapter helper |
| `adapters/reference-folder` | Python protocol reference adapter |
| `adapters/codex-session` | Codex session adapter |
| `adapters/browser-session` | Browser session adapter |

## Quickstart

```console
$ cargo build --release -p abra-cli
$ target/release/abra --root /tmp/abra-a daemon --background --yes
$ target/release/abra --root /tmp/abra-b daemon --background --yes
$ TICKET=$(target/release/abra --root /tmp/abra-b pair ticket)
$ target/release/abra --root /tmp/abra-a pair add "$TICKET"
$ target/release/abra --root /tmp/abra-a init ./work
$ target/release/abra --root /tmp/abra-a send <peer-b> --path ./work --wait
$ target/release/abra --root /tmp/abra-b accept --latest --kind dev.abra.workspace ./work
```

See [Add Abra to your sandbox](docs/INTEGRATE.md) for setup steps.
[Local API](docs/API.md) lists commands, fields, results, and events.
[Adapters](docs/ADAPTERS.md) defines the adapter process contract.
[Design](DESIGN.md) explains design choices. The [protocol specification](SPEC.md)
defines the wire format.

## Status

Abra has local snapshot storage, encrypted iroh delivery, pairing, scoped guest
enrollment, receive policies, leases, capability links, external adapters, and
a sealed offline relay. The default n0 mode supports connections across NATs.

## License

Licensed under either Apache License 2.0 or MIT, at your option. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
