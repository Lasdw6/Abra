# Live Linux process checkpoints

`abra process` uses CRIU to capture a Linux process tree, including its memory
and threads. It does not need an application-specific checkpoint adapter. The
Rust observer remains a separate read-only source of process observations.

CRIU is an optional external executable. `abra observe`, workspace snapshots,
and file transfer do not require it. Abra never invokes sudo or grants itself
checkpoint privileges.

## Check the destination

```sh
abra --json process check
abra --json process check --criu /usr/local/bin/criu
```

The check runs CRIU's basic host preflight with
`criu check --no-default-config`. Its JSON reports
`"check_scope":"criu-default"` and `"capture_tested":false`. macOS can store
and transfer process bundles but cannot capture or restore Linux processes. A
`"supported":true` result means this default preflight passed. It does not
guarantee that a specific process or external resource can be captured; process
and sandbox restrictions may only surface during capture.

## Capture and transfer

Run capture as the owner of a process you intend to pause. The PID must identify
the root of that application's process tree. Use a new bundle directory outside
the absolute workspace path:

```sh
abra --json process capture <pid> --workspace /workspace/my-job --bundle /tmp/my-job-checkpoint
```

Capture asks CRIU to leave the process tree stopped. It copies the workspace
while that tree is frozen, then records hashes of the images and files. Other
processes must not write to the same workspace during capture. The bundle
contains live memory and must be treated as private application data.

The source remains stopped after success. To abandon the handoff and continue
locally, run `abra process resume-source /tmp/my-job-checkpoint`. This checks the
source machine, boot, PID and process start identities before resuming them. If
capture fails after CRIU stops the process tree, Abra verifies those identities
and attempts to resume the source automatically. The error says plainly whether
that resume succeeded or whether the source may still be frozen.

Transfer the bundle using ordinary paired Abra roots:

```sh
abra init /tmp/my-job-checkpoint
abra send <receiver-peer> --path /tmp/my-job-checkpoint --wait
```

The transfer acknowledgement confirms receipt, not successful process restore.
On the receiver, materialize the signed snapshot into a new bundle directory:

```sh
abra accept <snapshot-id> /tmp/received-checkpoint
abra --json process plan /tmp/received-checkpoint
abra --json process restore /tmp/received-checkpoint
```

Restore verifies the bundle again, recreates the workspace at its original
absolute path, and asks CRIU to restore the process tree detached. It reports the
restored PID. An existing destination workspace is refused. Within one PID
namespace, the original processes must be gone before their PIDs can be restored.
For a move, retire the source and confirm the destination's health before
allowing further external work from the restored process.

## Compatibility and limits

The first implementation conservatively requires the same Linux kernel release,
CPU architecture, CRIU version, and user ID, with the captured CPU features
available at the receiver. CRIU still performs its own load checks. This is
native process continuation, not x86-to-ARM memory conversion.

The bundle includes the selected workspace and CRIU images. It is not a root
filesystem image. Executables, shared libraries and files outside the workspace
must be available in a compatible destination environment. External mounts,
devices, sockets, terminals, namespaces, seccomp policies and cgroups can prevent
capture or restore. A sandbox may pass `criu check` and still deny checkpointing
one process. For example, the Daytona probe reached CRIU 4.2 but its sandbox
denied seccomp suspension with `Operation not permitted`.
Abra does not request established TCP reconnection or arbitrary external-resource
inheritance from CRIU.

The process planner is separate from `abra restore-plan`. The latter verifies
that the bundle's files can be materialized; only `abra process plan` checks
process compatibility. `accept` never starts a process, and process restore
never silently falls back to a file-only restart.

## Validation

The `memory_probe` Rust example holds a random nonce and task results only in
memory. A live test must advance it, capture it, remove the source process and
workspace, then restore and compare that nonce and progress. Starting the
program again generates a new nonce and fails the comparison. Logic tests with
a fake CRIU executable are not evidence that a kernel supports live restore.

Run the opt-in smoke test on a disposable Linux host with CRIU installed:

```sh
ABRA_RUN_CRIU_SMOKE=1 tests/providers/process_criu_smoke.sh
# Or use a specific build:
ABRA_RUN_CRIU_SMOKE=1 CRIU_BIN=/usr/local/sbin/criu \
  tests/providers/process_criu_smoke.sh
```

The script builds Abra and `memory_probe`, runs `abra process check`, advances
40 tasks, captures the process, kills and reaps that exact source, moves its
workspace aside, and restores at the recorded absolute path. It checks the
memory-only nonce, digest and task count, then advances 60 more tasks to reach
100. It uses a private temporary directory and signals only PIDs whose `/proc/<pid>/exe`
matches the fixture built for that run. A missing CRIU binary, failed preflight,
denied kernel operation, capture error, or restore error fails with the actual
diagnostic. The test does not add privileges or bypass seccomp.

The unit suite verifies bundle integrity, path handling, compatibility checks,
CRIU arguments and failure reporting with a fake executable. The real Daytona
run verified `criu check` and reached live dump, where the provider's seccomp
policy rejected the operation. A complete live capture and restore has not yet
passed in that environment.

The command transcript and host facts are recorded in
[`tests/providers/RUNTIME_VALIDATION.md`](../tests/providers/RUNTIME_VALIDATION.md).

## Deferred work

A minimal Linux image and an emulation-capable VM runtime are a separate future
project. They are not part of this backend or its compatibility promise.
