# Portable snapshot and restore

Abra separates a workload's portable state from the native state used for fast
resume on a compatible host. The portable state consists of a file tree, typed
application checkpoints, and observations about processes and dependencies.
Native state is an optional cache with an explicit host fingerprint.

This lets a receiver continue a checkpointed workload on another CPU architecture
by restoring its files and application state into a suitable runtime. It does
not translate CPU instructions or resume x86 registers on ARM.

## Native resume and portable continuation

Firecracker snapshots contain guest memory and VM state, plus separately managed
disks. Native restore has CPU, VM configuration and snapshot-format compatibility
requirements. See [Firecracker's snapshot documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md).

Abra's Firecracker adapter carries `vmstate`, `memory` and `disk` references in a
signed snapshot. Each reference has a fingerprint containing OS, architecture,
hypervisor, snapshot-format major version, CPU template and CPU identity. The
receiver probes its own host. Exact fingerprint equality and verified required
objects make native resume eligible; Firecracker still performs the actual load.

When native state is incompatible, omitted, missing or corrupt, the adapter can
boot a fresh target image and materialize the portable tree. Native load or resume
failure also falls back if the portable tree is available. The result reports
`mode`, `fallback_reason` and `restore_plan`. Verification happens before replacing
a running slot, and portable files are staged before booting the fallback VM.

The target image must contain suitable runtimes and dependencies. Native
executables and dependency directories in the file tree are copied unchanged;
rebuild or reinstall them for the target architecture. A process's open sockets,
CPU registers, uncheckpointed memory and data outside the capture are not restored
by portable materialization. Databases and other stateful applications need
consistent application checkpoints. The process observer does not create these.

## Capture live Linux processes

`abra process capture` uses optional CRIU support to capture unsaved memory and
execution state without an application adapter. It leaves the source process
tree stopped while copying the workspace. `abra process restore` checks the
bundle and attempts continuation on a compatible Linux destination.

This mode requires the recorded CPU architecture, kernel release, CRIU version,
CPU features and user ID. The destination must also provide the files and
resources outside the workspace that the process used. Sandbox security rules
can prevent capture even when `criu check` passes.

The process bundle is a directory transferred through Abra's signed file path.
Transferring that directory across CPUs does not make its CRIU images portable.
Use portable application checkpoints for cross-CPU continuation. See the
[process checkpoint commands and test](PROCESS_CHECKPOINTS.md).

A standardized Linux image and cross-CPU emulation are deferred. Neither is
required by the current file transfer or process checkpoint implementation.

See the [2026-09-08 live validation record](../tests/providers/LAUNCH_VALIDATION.md)
for tested CPU/provider combinations and failures. Passing a saved-checkpoint
test does not establish cross-CPU live-memory continuation.

## Ask what a receiver can restore

After receiving a snapshot, inspect it without materializing or running it:

```sh
abra --json restore-plan <snapshot-id>
```

Without a target fingerprint, the planner verifies the portable file tree and
does not select native resume. With a receiver fingerprint and adapter roles:

```sh
TARGET=$(abra-fc --firecracker /usr/local/bin/firecracker fingerprint)
abra --json restore-plan <snapshot-id> --fingerprint "$TARGET" \
  --native-role vmstate --native-role memory --native-role disk
```

The same operation is available through the local API and
`abra_core::restore::plan_restore`. Other native adapters supply their own
fingerprint and required roles; the planner has no Firecracker dependency.

| Result | Meaning |
|---|---|
| `mode: native` | Exact target match and verified required native objects; the adapter can attempt native resume |
| `mode: portable` | Verified portable files are available; the receiving application handles its checkpoints and startup |
| `mode: unavailable` | Neither requested native resume nor portable-file restore is currently available |
| `portable.available` | File objects are hash-valid with matching sizes; tree limits, link targets and kind-specific checks pass |
| `portable.error` | Why the file tree cannot currently be restored |
| `native.status` | `eligible`, or a reason such as `fingerprint-mismatch`, `missing-roles`, or `unavailable-objects` |
| `recipes`, `observation` | Original suggestions, missing requirements and consistency limits; planning never executes them |

The plan is a read-only check of the local store at that moment. It does not
delete corrupt objects. The final restore must verify its inputs again because
the store can change after planning. `portable.available` does not mean that all
runtime dependencies, credentials, external services or application state are
available. It does not probe the adapter binary, KVM, privileges, disk space,
SSH access or fallback images. Native eligibility checks declared fingerprints;
the adapter must still load and verify native state. Observation schema versions that a consumer does not understand must
remain data.

A receiver that only needs portable state can avoid transferring native blobs:

```sh
abra config set skip_native true
abra stop
abra daemon --background
```

This setting applies to new daemon sessions. It does not delete native objects
already stored. Objects also referenced by the portable tree cannot be skipped.

## Run a portable application checkpoint

This small example uses the public Rust API. It creates a signed checkpoint with
a Python program and a counter saved at step seven. Restore verifies the signature
and file hashes and materializes the files. The next command explicitly runs the
application and continues at step eight.

```sh
cargo run --locked -p abra-core --example portable_checkpoint -- capture /tmp/abra-checkpoint
cargo run --locked -p abra-core --example portable_checkpoint -- restore /tmp/abra-checkpoint /tmp/abra-resumed
python3 /tmp/abra-resumed/resume.py
# {"completed_steps": 8}
```

Use new directory names for each run. To try a different CPU, move the checkpoint
directory to the receiving machine and run the restore command there with
`--require-arch-change`. Build the example natively on each machine. The fixture
contains signed manifest bytes and CAS objects, never the source identity's
private key. It is an example layout for testing the library, not a new transport
format or a general-purpose import command. The fixture signer is not enrolled
as a trusted peer; normal network transfers use Abra's pairing and authorization.

The `File checkpoints across CPUs` workflow captures on native Linux x86_64
and ARM runners and restores on the opposite architecture. It then runs the
sample counter program. This tests file-checkpoint portability; it does not
capture live process memory or exercise a running sandbox. Separate planner tests cover incompatible native
fingerprints and absent or corrupt native objects. Those fixture tests do not
claim to load a real Firecracker memory snapshot. Firecracker's real KVM proof
remains `adapters/firecracker/tests/e2e.sh` on a dedicated host.

## Integrate an application

1. Flush or checkpoint application state into a portable format. Arrange a
   consistent file capture if the application continues writing.
2. Capture files and typed checkpoints; retain missing requirements in the
   observation ledger. Attach native state when the provider supports it.
3. Send the signed snapshot through Abra. Its acknowledgement confirms storage,
   not application startup or compatibility.
4. Ask the receiving adapter for a live fingerprint and call `restore-plan`.
5. Attempt compatible native resume, or prepare target runtimes and materialize
   the portable files. Import application checkpoints explicitly.
6. Check health in the receiving application before declaring the workload ready.

`abra-sandbox restore` uses portable preflight before copying files through its
driver. It returns the plan, candidate services and any services explicitly
selected with `--start`. `abra accept` and the core library never run recipes.
