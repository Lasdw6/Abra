# Sandbox observation contract

The collector (`adapters/sandbox/collector/observer.py`) collects OS facts and
derives service candidates. It does not start services, flush databases,
capture browser sessions, or guarantee that a command will work on another
machine. Application adapters own those operations.

It has two modes. The primary one is one-shot: the
[sandbox coordinator](../adapters/sandbox/README.md) pushes the script into a
sandbox over the provider's exec, runs it once with a barrier id, and pulls the
pinned ledger out with the workspace files; nothing stays installed. The
Firecracker guest image also installs it as a periodic systemd service
(`install-rootfs.sh`), which `abra-fc` relies on; the coordinator never does.

The ledger uses `schema: "dev.abra.observed/3"` and `observer.version: 3`.
Abra carries it in `extensions["dev.abra.observed"]`. The top-level `recipes`
array is moved to `manifest.recipes`; service candidates keep their own recipe
and the reasons it is incomplete or unverified. Readers must check the schema
before interpreting fields. Unknown fields may be ignored. Unknown schema
versions must remain data, without deriving restart actions from them.

## Live observations and checkpoint captures

The periodic observer replaces `.abra/observed.json` every two seconds by
default. It never writes received `recipes.json` or `received-observed.json`.
One-shot runs never touch `observed.json`.

A checkpoint gets a separate file:

```sh
python3 observer.py --workspace /workspace --all --once --barrier capture_1
abra --json snapshot /workspace --observation-barrier capture_1
```

The coordinator runs exactly this inside the sandbox (from a temp dir), then
takes the snapshot on the mirror outside. In a Firecracker guest the same
script is `/usr/local/libexec/abra-observer`.

The first command returns `filename: "observed-capture_1.json"`, the barrier,
observation time, and process/recipe counts. It writes that file inside `.abra`
without overwriting an existing file or symlink. Reusing the ID fails. The
periodic observer cannot replace it. IDs contain 1 to 64 ASCII letters, digits,
underscores or hyphens. `--barrier` requires `--once`.

The snapshot operation reads the named capture before walking the workspace.
It requires schema 3, mode `once`, matching barrier, valid start/end times in
order, and an extension no larger than 256 KiB. Missing, mismatched, oversized,
or symlinked captures fail; it never falls back to live data for a named capture.
The result echoes `observation_barrier`. After success, the caller can delete
the capture file. Failed captures remain available for inspection.

`abra-sandbox capture` creates a random barrier, runs the collector once via
the driver, pulls the tree, and passes the driver's facts as the host object.
`abra-fc snapshot` creates a random barrier, collects host environment facts,
and runs the observer and snapshot through SSH. It checks the returned barrier
before pausing the VM. Its SSH command cleans up its own capture after the
snapshot attempt. Other callers manage their capture files themselves.

This pins the selected ledger to the snapshot. It does not stop applications
from changing files while Abra reads them. `coverage.consistency` is
`best-effort` and `applications_quiesced` is false. Start and finish timestamps
bound the guest collection, not the later file walk or native VM capture. A
coordinator that needs application consistency must arrange flushing or pausing
through application-specific operations. A matching barrier alone is not proof
of consistency.

## Fields

| Field | Meaning |
|---|---|
| `observer` | Version, mode, observation time, collection start/end, optional barrier, intervals and environment freshness |
| `platform` | Guest OS, architecture, kernel, hostname, OS release and optional `/etc/abra/image-id` |
| `resources` | Guest memory/CPU facts and effective cgroup v2 limits when readable |
| `runtimes` | Bounded version output from programs in the configured runtime directories |
| `processes` | Observed process records, with omissions and redactions preserved |
| `service_candidates` | Inferred service roots, member PIDs, recipe, reasons, requirements and restartability |
| `recipes` | Compatibility projection of complete, unredacted candidates whose cwd is portable; still unverified |
| `mounts` | Mount targets, filesystem types, sources, mutability and relationship to the workspace capture |
| `coverage` | Selection scope and known limitations; `complete` is false because this is a partial OS observation |
| `collection_errors` | Bounded records `{collector, code, count}` without raw exception text or command values |
| `limits` | Counts of process and service records dropped to fit the ledger |
| `host` | Optional host-adapter facts attached by the snapshot caller |

OS fields are guest observations, not verified claims about another device.
Runtime versions are program-reported. Service candidates identify their source
as `process-tree-inference`. Host data is caller-supplied and wrapped as
`{source: "host-adapter", facts: {...}}`. Snapshot signatures identify the peer
that authored the snapshot; they do not independently verify its observations.

Processes include PID, parent PID, start ticks, argv, cwd, state, executable,
user, safe environment values, sockets, membership and available start time.
`cwd` is workspace-relative, or null for a selected process outside it.
`external_cwd` and `external_open_files` describe dependencies whose contents
are not carried by the observer. Open-file paths are hints, not a complete
inventory of a process's dependencies.

A service candidate has `root_pid`, `source_pids`, `recipe`, `reasons`,
`missing_requirements`, `requirements`, and `requires_adapter_confirmation`.
Its `restartability` is either `unverified` or `blocked`. The observer never
claims `verified`. Ordinary workers group with their parent service; interactive
shells are excluded as service roots, while recognized agent processes form
boundaries for separately launched services. This is a heuristic, not an
application lifecycle contract.

`blocked` means a member has redacted or truncated data, an unreadable or
missing required environment value, or a cwd outside the workspace. Such a
candidate stays in the ledger but does not enter `manifest.recipes`. Receivers
must also resolve runtime, executable and external-file requirements before
using an unverified candidate. When a received ledger has no recipes, Abra
writes an empty received `recipes.json`, clearing older recipe suggestions.

## Scope, omissions and limits

The default scope selects processes in the workspace and their current
descendants, including children that changed cwd. It cannot rediscover an
orphaned process that already left the workspace before collection. For a
sandbox with a defined boundary, use one of:

```sh
abra-observer --workspace /workspace --all
abra-observer --workspace /workspace --cgroup /sandbox
abra-observer --workspace /workspace --process-group 1234
```

`--all` selects every process in `/proc` except the collector, tagged
`membership: "all"`, with `coverage.scope: "all"`. It is the right rule when
the sandbox is the whole PID namespace (containers, Firecracker guests) and is
the coordinator's default. Under `--all`, PID 1 with a cwd outside the
workspace (init, or a provider supervisor that adopts orphans) is a grouping
boundary: its children are their own service roots. PID 1 itself is still
listed, blocked.

`--cgroup` is a cgroup v2 path relative to the cgroup mount. It includes nested
cgroups without including similarly named siblings. `--cgroup-root` defaults
to `/sys/fs/cgroup` and locates the resource-limit files. Effective CPU and
memory limits include ancestors visible beneath that root. CPU capacity is
`effective_cpu_millicores`, so a half CPU is 500; `affinity_cpus` counts allowed
CPUs before quota limits. Durations use integer `interval_ms` and
`environment_refresh_interval_ms`. The ledger uses Abra's safe-integer JSON
profile, without floating-point numbers. Hidden ancestor
limits are not discoverable. Without an explicit cgroup, resource collection
uses the observer's own cgroup. Select a workload cgroup when it differs.

TCP listeners and UDP endpoints come from the observer's network namespace.
Different or unreadable process namespaces are reported; Unix sockets and
other namespaces are not collected. UDP records are bound endpoints, not a
claim that a service is listening for requests.

Permission errors, disappeared processes, unavailable collectors, and scan
limits appear in `collection_errors`. An empty process list with collection
errors must not be interpreted as an empty sandbox. The observer also checks
start ticks again after collection to avoid combining facts from a reused PID.

The observer considers at most 8,192 process metadata records and reads details
for at most 1,024 selected processes per cycle. It retains at most 512 process
records, 256 service candidates and 64 mounts. It scans at most 4,096 file
descriptors per process and keeps at most 64 external file paths per process.
Arguments and environments have independent bounds. The complete guest ledger
is limited to 240 KiB, leaving space for host facts under the 256 KiB extension
limit. Dropped process records may leave candidate source PIDs without retained
detail; `limits` makes this visible.

Mounts within the workspace are marked `workspace-file-tree`; others are
`not-captured`. This describes the capture boundary, not an independent proof
that volume contents are consistent. `contents_verified` remains false. The
observer does not copy volumes, open files, packages, or executable contents.

## Environment and secrets

Platform and runtime observations refresh every 300 seconds by default, using
`--environment-interval`. Process, mount and resource facts refresh each cycle.
`observer.environment_observed_at` preserves the environment collector's own
freshness. One-shot captures collect it anew. Version probes use the configured
runtime directories, never the workspace PATH, and have bounded output and
three-second deadlines. Treat `--runtime-dirs` as trusted executable locations.

Environment values use an allowlist. Secret-looking variable names are recorded
as missing requirements without their values. Redaction also handles known
token forms, authentication headers, secret flags, and URL credentials or
secret query parameters. Simple shell commands can be inspected; opaque shell
programs and interpreter evaluation arguments are omitted and marked redacted.
This is best-effort redaction, not a guarantee that arbitrary application data
contains no secrets. It does not filter the workspace's file contents or native
memory and disk blobs.

## Host and application state

A snapshot caller can pass `--observation-host '<JSON object>'` with a barrier.
The local API field is `observation_host`; it accepts at most 16 KiB. Abra adds
the object under the ledger's `host.facts` before signing the snapshot.

The coordinator supplies the driver's facts (provider name, sandbox id, cpu,
memory, and similar) plus `native`, which is the provider's snapshot handle or
null. Firecracker supplies BLAKE3 digests of the configured base-image file and kernel
file at capture time, configured memory and CPU count, and host architecture.
Unreadable configured artifacts produce `available: false` and
`error: "digest_unavailable"` rather than preventing capture of a running VM.
It sends no host paths, enrollment tokens or SSH keys in these facts. The
digests identify those configured files, not every modification to the running
guest disk, and the files themselves are not included in the portable capture.
A receiver still needs an appropriate image and dependencies.

Browser, Codex, database and other application checkpoints belong in typed
adapter snapshots. The observer does not infer them from process memory. A
portable restore may need new credentials, architecture-compatible dependencies,
and explicit service startup. It should report missing requirements rather than
claim that native state can always be discarded without losing application state.
