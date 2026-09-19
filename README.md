# Abra

**AirDrop for agents.**

Agents can pass along a task and instructions, but the next agent often has to
rebuild the environment before it can start. Abra transfers working state between
devices and sandboxes so another agent can pick up the work.

## What it does

Abra captures state in a snapshot, transfers it over an encrypted connection,
and restores it in another environment. Adapters define what each application
can capture and restore.

- **Files and workspaces:** move project files and saved checkpoints.
- **Browser and agent sessions:** continue supported sessions on another machine.
- **Sandboxes:** capture and restore through local, SSH, Daytona, and Firecracker integrations.

Use it to hand a browser task to another agent, move a workspace between
sandboxes, or bring supported state from a user's device into a debugging sandbox.

## Get started

From a checkout of this repository, with **Rust 1.91+** installed:

```sh
cargo install --locked --path crates/abra-cli
abra daemon --background
```

Then follow [Pair two machines and send a workspace](docs/INTEGRATE.md).
To try a transfer on one machine without a cloud account, use the
[local demo](docs/QUICKSTART.md).

The CLI runs on Linux, macOS, and Windows. Individual adapters may also require
Node.js or Python and have their own platform requirements.

## What to expect

**Developer alpha.** Files restore as files; continuing an application requires
supported saved state and a compatible runtime at the destination. Abra does not
translate binaries or move live process memory between CPU architectures.
Native memory resume is a separate path for compatible hosts.

See [portability](docs/PORTABILITY.md) and
[compatibility and recovery](docs/COMPATIBILITY.md) for the details.

## Adapters and docs

- [Browser sessions](adapters/browser-session/README.md)
- [Codex sessions](adapters/codex-session/README.md)
- [Sandbox integration](adapters/sandbox/README.md) and [Firecracker](adapters/firecracker/README.md)
- [Build an adapter](docs/ADAPTERS.md) · [CLI and local API](docs/API.md)
- [Live process checkpoints](docs/PROCESS_CHECKPOINTS.md) · [Protocol specification](SPEC.md)

## License

[Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
