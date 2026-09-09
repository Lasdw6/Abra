# Core release checks

Release Abra as a developer alpha with an explicit version. Keep the core,
daemon, CLI and bundled adapters from the same source revision. The checks below
build and inspect artifacts; none publishes a package or pushes a Git tag.

The [2026-09-08 live validation record](../tests/providers/LAUNCH_VALIDATION.md)
records the current local artifacts, test scope and failures. Repeat the required
checks against the exact release revision before publishing.

## Validate the source

```sh
cargo fmt --all --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo package --workspace --locked
```

Run packaging from a clean checkout. For local review of authorized uncommitted
changes, `--allow-dirty` packages that working tree. Packaging also compiles each
packaged crate. Publish internal dependencies in dependency order.

When rechecking an edited unpublished version, Cargo 1.91 can report its internal
`no hash listed` error from the temporary package registry. If this happens,
repeat the command with `--target-dir` pointing to a new directory. Verification
must include the runtime crate as well as the core, daemon and adapters.

The `CI` workflow also checks `abra-net`, `cadabra` and `abra-cli` with no default
features, TCP only and iroh only. A CLI built without either transport reports
that no network transport is enabled. Adapter checks cover the JavaScript
adapters, viewer and sandbox coordinator. The Rust runtime tests cover the
observer, archive helpers and CRIU bundle validation.

## Prove the portability contract

The `File checkpoints across CPUs` workflow captures a signed file
checkpoint on Linux x86_64 and ARM runners and restores on the opposite CPU. It
requires the architectures to differ, verifies the snapshot and files, then
continues the sample application from its saved state. Planner tests separately
exercise native fingerprint mismatch, missing roles, absent or corrupt native
objects and an unavailable portable tree.

A passing simulated fingerprint test is not a substitute for a run on both
architectures. Record the CI run and source revision before making that claim
for a release. For Firecracker native resume and fallback, also run
`adapters/firecracker/tests/e2e.sh` on a dedicated Linux KVM host with compatible
images. Record the host, Firecracker version, target image and result. External
providers have their own network and environment requirements.

For CRIU process continuation, run the RAM-only test from
[process checkpoints](PROCESS_CHECKPOINTS.md) on a Linux host that permits
checkpoint operations. Record both capture and restore results. `process check`
passing is insufficient; the first Daytona attempt passed that check but failed
capture when the sandbox denied seccomp suspension. See the
[runtime validation record](../tests/providers/RUNTIME_VALIDATION.md).

## Build distributable binaries

The manually triggered `Build release artifacts` workflow builds native Linux
and macOS binaries for x86_64 and ARM. Its archives contain `abra`, `abra-relay`,
the adapters, documentation and licenses. Linux archives also contain `abra-fc`. `cadabra` is a
library used by `abra daemon`, not a separate executable.

The workflow uploads archives and SHA-256 files as CI artifacts without publishing
a release. Linux GNU artifacts require a compatible libc; their target triple is
part of the filename. Test the oldest supported distribution or build musl
artifacts before promising broader Linux compatibility. Native Windows core
distribution is not part of this workflow.

Before publishing, install an archive on a fresh machine and test pairing,
snapshot delivery, restore planning, materialization, restart and peer removal.
Use disposable identities and application fixtures. Verify that required
interpreters and application dependencies are documented. The core binary does
not install Python, Node, browser engines or target runtimes.

## Release notes

Record the source revision, Rust/MSRV, tested OS and CPU combinations, artifact
hashes and adapter versions. State whether a test used a real VM, two native CPU
architectures or synthetic fingerprints. Explain changes to signed formats,
local storage and trust behavior, including downgrade limits. Link the
[portability contract](PORTABILITY.md) and [recovery guide](COMPATIBILITY.md).
