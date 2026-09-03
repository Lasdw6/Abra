# Abra Firecracker adapter

`abra-fc` is the host-side lifecycle shim for running portable Abra capsules in
Firecracker microVMs. Native VM state is an optional cache attached to a signed
child snapshot; the capsule file tree and observed recipes remain the source of
truth.

## Build and prepare an image

Build the workspace with Rust 1.91 or newer. A normal GNU build is supported
for Ubuntu guests; a musl build is preferred for vendor images:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p abra-cli -p cadabra
sudo adapters/firecracker/guest/install-rootfs.sh rootfs.ext4 \
  target/x86_64-unknown-linux-musl/release/abra \
  target/x86_64-unknown-linux-musl/release/cadabra
```

The installer adds `cadabra.service`, an observer, `/workspace`, the two
binaries, and the `os-desktop-init.sh` PID 1 handoff named in the boot arguments.
Before boot, the adapter injects the enrollment token into the private
per-slot disk as root-owned `/etc/abra/token` mode `0600`. The service reads only
that file. Tokens never appear in kernel arguments, adapter JSON, or Firecracker
configuration/logs; `/proc/cmdline` is treated as public.
The observer derives recipes from `/proc` (argv, workspace-relative cwd, a small
environment allowlist, listening TCP ports, and start time) and atomically writes
`/workspace/.abra/recipes.json`. Cadabra validates and embeds those recipes when
the workspace is snapshotted. Recipes are data and are never executed.

## Lifecycle

```sh
export ABRA_ROOT=/var/lib/abra-host
export ABRA_FC_SSH_KEY=/images/desktop_id_rsa
abra-fc up --slot 0 --rootfs /images/abra.ext4 --kernel /images/vmlinux \
  --mem 512 --vcpus 1 --token "$ENROLLMENT_TOKEN"
abra-fc snapshot --slot 0 --capsule "$CAPSULE_ID"
abra-fc down --slot 0
abra-fc restore --slot 0 --capsule "$CAPSULE_ID"
abra-fc ls
```

State lives under `$ABRA_ROOT/firecracker/slots/N` (mode `0700`): PID plus
process start time, API socket (mode `0600`), TAP and IP
identity, logs, the per-slot rootfs, and materialized restore files. Network
setup is idempotent: `osdtapN`, host `172.30.N.1/30`, guest `172.30.N.2`, MAC
`06:00:AC:1E:NN:02`, a permanent neighbor entry, IP forwarding, and one
`172.30.0.0/16` MASQUERADE rule. `down` terminates only the recorded PID and
removes only that slot's TAP; artifacts remain inspectable. When the final slot
stops, the adapter removes its MASQUERADE rule. Guests otherwise have routed
internet egress; deployments requiring restricted egress must install an
explicit FORWARD allowlist and metadata-service deny rules.

Firecracker's jailer is required for multi-tenant or untrusted guests. The slot
directory and socket permissions are defense in depth, not a substitute for
the jailer's uid/gid drop, chroot, cgroups, and seccomp. Unjailed operation is
suitable only for a dedicated trusted test host.

The cold-boot API sequence is `PUT /logger`, `PUT /machine-config` (dirty-page
tracking enabled), `PUT /boot-source`, `PUT /drives/rootfs`,
`PUT /network-interfaces/net1`, and `PUT /actions` with `InstanceStart`.
Snapshot is guest `sync`, `PATCH /vm` to `Paused`, `PUT /snapshot/create`, CAS
ingestion, signed native-child creation, then `PATCH /vm` to `Resumed`. Restore
starts a blank Firecracker process, performs `PUT /snapshot/load` with a File
memory backend, `resume_vm:false`, and `network_overrides`, patches the rootfs
drive while paused, then resumes and waits for SSH.

Full snapshots ingest three unchanged native blobs: `vmstate`, `memory`, and the
mutable `disk` required by Firecracker but not included in its state file. The
CAS file path is streamed and BLAKE3-verified, so multi-gigabyte artifacts are
not buffered in memory.

## Fingerprint and portability

The string form is conceptually
`linux/<arch>/firecracker/<snapshot-format-major>/<cpu-template-or-dash>/<cpu-identity>`;
`cpu-identity` is exactly
`vendor=<vendor_id>;family=<family>;model=<model>;stepping=<stepping>`. The
manifest stores its structured equivalent. After creation, `abra-fc` runs
`firecracker --describe-snapshot VMSTATE` and uses the major component of the
independent snapshot data-format version—not the Firecracker release number.
The remaining values come from the live host architecture, `/proc/cpuinfo`, and
configured `ABRA_FC_CPU_TEMPLATE` (`-` means none). Restore always computes a
fresh receiver fingerprint; capture-time `fingerprint.json` is never receiver
identity. `ABRA_FC_FAKE_FINGERPRINT` exists solely to exercise
the mismatch path.

Native restore is honestly same-host/same-CPU-model with no CPU template.
Firecracker also warns that host-kernel differences can matter. A static CPU
template such as `T2CL` can widen the compatible CPU set, but this adapter does
not enable it by default because it changes the guest CPU contract. Custom
`/cpu-config` probing and UFFD/CAS paging are deferred Tier 2 work. Tier 1 is
cold boot, full capture, File-backed native restore, and portable fallback.
Differential capture is rejected until chained restore is implemented.

`snapshot` prints both `portable_snapshot_id` and `native_snapshot_id`. Send the
native child to a compatible host. Abra streams its memory and disk objects and
the receiver verifies them on disk:

```sh
RESULT="$(abra-fc snapshot --slot 0 --capsule "$CAPSULE_ID")"
PORTABLE_ID="$(printf '%s' "$RESULT" | jq -r .portable_snapshot_id)"
NATIVE_ID="$(printf '%s' "$RESULT" | jq -r .native_snapshot_id)"
abra send "$OTHER_PEER" --capsule "$NATIVE_ID"
```

Native memory and disk objects are host-specific cache data. Each native-role
object may be up to 8 GiB. The receiver's default total offer budget is 16 GiB
and it checks free disk space before accepting. A receiver with a mismatched
fingerprint can request the portable tree without downloading native blobs.

On a new host, pass image settings on the first restore. The adapter writes
`$ABRA_ROOT/firecracker/config.json`; later restores keep its existing values.

```sh
abra-fc --root /var/lib/abra-new --firecracker /usr/local/bin/firecracker \
  --ssh-key /images/desktop_id_rsa restore --slot 0 \
  --capsule "$CAPSULE_ID" --snapshot "$PORTABLE_ID" \
  --kernel /images/vmlinux --rootfs /images/abra.ext4 --mem 512 --vcpus 1
```

The matching environment variables are `ABRA_FC_BINARY`, `ABRA_FC_SSH_KEY`,
`ABRA_FC_KERNEL`, `ABRA_FC_ROOTFS`, `ABRA_FC_MEM`, and `ABRA_FC_VCPUS`.

On mismatch, missing native roles, snapshot-load error, resume error, or guest
readiness timeout, the partial VM is torn down and a fresh base image is booted, the selected
snapshot's file tree is materialized into `/workspace`, and recipes are printed
without execution. Native blobs are never treated as source of truth.

E2B and other self-hosted orchestrators map directly onto this shim: allocate a
slot, inject an enrollment token, call the same Firecracker endpoints listed
above, and persist the resulting Abra snapshot id. Run the real-host proof with
`adapters/firecracker/tests/e2e.sh`; it writes `e2e-report.json` with cold boot,
capture, native restore, and total timings.
