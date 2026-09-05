# Track C review — Firecracker adapter (Grok 4.6)

Worktree: `/Users/vividh/Desktop/abra-fc` (branch `firecracker`, HEAD `a06e4ab`). Review by reading only; Firecracker was not executed here. The committed `tests/e2e-report.json` shows a Linux-host run that reported `ok: true` with `process_resumed: true`.

Native blobs are treated as an optional cache in the README and in the portable-fallback path. Several restore and test bugs below mean that promise is not actually enforced.

---

## Findings

### 1. High — `adapters/firecracker/src/main.rs:264-268` plus `guest/start-guest.sh:5-12`

**Defect.** The enrollment token is concatenated into Firecracker `boot_args` as `abra.token=<token>`. `start-guest.sh` parses that value from `/proc/cmdline` (world-readable in the guest). The same string can land in host `firecracker.log` (Info logger) and in any serial/console capture. The installer already has the safer fallback `/etc/abra/token`, but `up` never writes it.

**Failure scenario.** Workspace code (a capsule `postinstall`, the observed `python3 -m http.server`, a compromised recipe process) runs `cat /proc/cmdline` and obtains a still-valid enrollment token. That token binds a guest identity with `send`/`receive` on the capsule. The attacker enrolls a second process or exfiltrates through the real guest until expiry.

**Fix.** Never put secrets on the kernel command line. Before `InstanceStart`, loop-mount (or otherwise inject into) the per-slot `rootfs.ext4`, write the token to `/etc/abra/token` mode `0600`, and start cadabra from that file only. Redact boot_args from logs. Treat `/proc/cmdline` as public.

---

### 2. High — `adapters/firecracker/src/main.rs:397-466`, `481-517`, `500-506`

**Defect.** Native restore is attempted whenever the snapshot’s native fingerprint equals `local_fingerprint()`. That function prefers `$ABRA_ROOT/firecracker/fingerprint.json` written at capture time, and otherwise a probe that hardcodes `cpu_template: "-"`. It is not a live host identity. If the cached value matches the blobs, restore proceeds even on a different CPU/Firecracker. If `PUT /snapshot/load` then fails, `restore` returns `Err` and does **not** fall back to files+recipes. SPEC §1.3: use the blob only when **every** fingerprint field equals the receiver’s local value; otherwise skip. DESIGN §6: native blobs are an evictable cache, never source of truth.

**Failure scenario.**
- Copy `ABRA_ROOT` (or `fingerprint.json`) to a second Linux box with the same arch and a different CPU family. Restore sees a cache hit, loads the memory snapshot, and either crashes Firecracker or resumes with silent corruption. Portable fallback never runs.
- Capture on Firecracker format 10, upgrade the binary, load fails, operator gets an error instead of a working workspace from `files` + printed recipes.

**Fix.** Always compute a live fingerprint at restore (CPU model or a real Firecracker CPU template, OS, arch, hypervisor, **describe-snapshot format major**, template string even when `"-"`). Compare that to the blob refs; on any mismatch **or** load/resume/SSH failure, tear down the partial VM and take the existing portable path. Do not read `fingerprint.json` as the local value (cache is a hint, not an oracle). `ABRA_FC_FAKE_FINGERPRINT` must remain test-only.

---

### 3. High — `adapters/firecracker/tests/e2e.sh:89`

**Defect.** “Process resumed from memory snapshot” is `pgrep -f "python3 -m http.server 8123"`. On procps `pgrep -f`, the pattern matches **pgrep’s own argv**, so the check is true on any guest that can run pgrep. Combined with `test -f /workspace/native-marker.txt` (true for a disk-only restore *and* for portable materialize), a cold boot of the snapshotted ext4 — no memory resume — can pass the same assertions. `checks.process_resumed: true` in `e2e-report.json` is therefore not evidence of a resumed process.

**Failure scenario.** Native load is broken or skipped; restore only brings back the 2 GiB disk (or the e2e is later changed to `up` + disk). Marker file exists, pgrep matches itself, CI stays green, Track C ships as “proven.”

**Fix.** Record the server PID (or a nonce in `/proc/<pid>/environ`) before snapshot; after restore require that **same PID** still runs and `curl -sf http://127.0.0.1:8123/` succeeds. Bracket the pattern (`pgrep -f '[p]ython3 -m http.server 8123'`) is not enough by itself — prove live listeners, not argv.

---

### 4. High — `adapters/firecracker/guest/install-rootfs.sh:18-29`

**Defect.** The script loop-mounts an operator-supplied ext4 as root and `install`/`mkdir`s through `$MOUNT_DIR/...`. Absolute symlinks inside the image resolve on the **host**. There is no `chroot`, mount namespace, `nodev`/`nosuid`, or “refuse symlink” check. `cleanup` umounts only if `mountpoint -q` still succeeds; a busy mount is left behind.

**Failure scenario.** A malicious or compromised `rootfs.ext4` contains `usr/local/bin -> /etc` (absolute). `install -D … "$MOUNT_DIR/usr/local/bin/abra"` writes the host binary over `/etc/abra` or similar. Same for `var/lib/abra`, `etc/systemd/...`. This is a root host path traversal from an untrusted image.

**Fix.** Run the entire install in a private mount namespace, `pivot_root`/`chroot` into the image, or use `virt-copy-in`/`guestfish`. At minimum: `mount -o loop,nodev,nosuid`, reject absolute/escaping symlinks before any write, and `umount -l` in `cleanup`. Do not follow host paths when copying in.

---

### 5. High — `adapters/firecracker/src/main.rs:244-249` (spawn) and README lifecycle

**Defect.** The shim drives Firecracker as the calling user (typically root, because TAP/iptables use `sudo`) **without the jailer**, cgroups, seccomp extra policy, or a dropped-privilege VMM process. A guest-to-host breakout in Firecracker is then host root. The API unix socket is also never `chmod`’d after create (`:238-250`, `:409-416`); permissions follow umask.

**Failure scenario.** Untrusted capsule code plus a Firecracker/KVM bug yields host root. Or umask `000` makes `firecracker.sock` world-connectable: any local user `PUT /actions` / changes boot_args / dumps memory.

**Fix.** Document jailer as required for any multi-tenant or untrusted-guest use; better, invoke it. After `wait_path`, `chmod 0600` the API socket (and `0700` the slot dir). Do not run the VMM as root if jailer can own TAP setup instead.

---

### 6. Medium — `adapters/firecracker/src/main.rs:543-571`

**Defect.** Firecracker is controlled by `curl http://localhost… --unix-socket`. No `--noproxy '*'`, no `--config /dev/null`. `HTTP_PROXY`/`ALL_PROXY` and `~/.curlrc` apply to user-space curl. Boot_args (including the token from finding 1) are the POST body.

**Failure scenario.** Operator runs `abra-fc` with `HTTP_PROXY` set (corporate env, `sudo -E`). curl forwards the FC API JSON — token, paths, snapshot load — to the proxy. A malicious proxy returns HTTP 200 without applying the config; the shim believes the VM is started/paused/snapshotted.

**Fix.** Stop using curl. Speak HTTP/1.1 on the unix socket in-process (already have `UnixStream` for cadabra). Until then: `curl --silent --show-error --noproxy '*' --config /dev/null --unix-socket …`.

---

### 7. Medium — `adapters/firecracker/src/main.rs:604-634`

**Defect.** Every `up`/`restore` sets `net.ipv4.ip_forward=1` and, if missing, appends `iptables -t nat -A POSTROUTING -s 172.30.0.0/16 -j MASQUERADE`. There is no FORWARD restriction, no egress allowlist, no isolation between slots, and `down` never removes the NAT rule or resets forwarding. README mentions the MASQUERADE rule but does **not** say guests get unrestricted host-routed egress (and guest-to-guest via the host).

**Failure scenario.** Slot 0 agent `curl`s the cloud metadata endpoint or a sibling guest at `172.30.1.2`. After the last VM is down, the host still NATs any 172.30.0.0/16 source (including a later process that spoofs that range on another iface).

**Fix.** If sandbox egress is intended, document it as such. If not, default-deny FORWARD, allow only established/related plus an explicit allowlist, and drop inter-slot traffic. On last slot `down`, delete the MASQUERADE rule (and do not leave `ip_forward=1` unless it was already on).

---

### 8. Medium — `adapters/firecracker/src/main.rs:244-249`, `410-415`, `638-662`; `tests/e2e.sh:19-24`

**Defect.** `std::process::Child` is dropped without kill/wait. If API setup fails **before** `write_state`, Firecracker and the TAP leak; `down` cannot see them. `down` then `kill`/`kill -9` the PID in `state.json` with no identity check — PID reuse as root kills an unrelated process. e2e’s EXIT trap **does** call `down` on slots 0 and 1 after success, so a happy path should not leave VMs; it still leaves the global NAT/forwarding changes (finding 7) and cannot reap orphans that never got `state.json`.

**Failure scenario.** `wait_ssh` is after `write_state` (recoverable). A failed `PUT /boot-source` is not: FC keeps running, TAP is up, next e2e `ip tuntap add` is skipped, networking is wedged. Separately, a crashed FC’s PID is recycled by `sshd`; later `abra-fc down` sends SIGKILL to sshd.

**Fix.** Hold `Child`, kill it on every error path, `wait()`. `down`: kill only if `/proc/<pid>/comm` is `firecracker` (or match starttime). e2e: `pkill` leftover `firecracker` for the test sockets; remove NAT in cleanup. Do not claim success-path process leaks unless `down` failed — the trap is there; the leak is the error path and iptables.

---

### 9. Medium — `crates/cadabra/src/lib.rs:737-814` (`native-attach`)

**Defect.** Parent snapshot is `max(received_at)` across the capsule, not `main` and not the snapshot the guest just created. The new child always `apply_label`s `main`, unlike `snapshot()` which now respects `result.forked` (`:706-733`). Artifact `path` is any filesystem path cadabra can read (no allowlist under the slot dir). Roles are not required to be exactly `{vmstate,memory,disk}` or Full vs Diff.

**Failure scenario.** Two snapshots arrive close together; native blobs are attached to the wrong portable tree, so memory/disk and `files` diverge. Or a guest Diff snapshot is ingested as if it were a standalone Full; restore load fails (and then, per finding 2, does not fall back). Socket-equivalent callers can `put_file("/etc/shadow")` into the DAG (cadabra already documents the socket as full device authority; this is a new, easy exfil verb).

**Fix.** Parent = the snapshot id `abra-fc` just ensured exists (pass it in the control request), or `main` if that is the policy. If `receive_full` returns `forked`, record a fork label; do not move `main`. Allowlist paths, roles, and `snapshot_type`. Reject Diff unless the parent native Full is named and restored first.

---

### 10. Medium — `crates/abra-core/src/cas.rs:301-350`

**Defect.** Streaming `put_file` is the right idea for multi-GB artifacts, but it is weaker than `put()`: no parent-directory fsync after rename, so a crash can drop the directory entry. `copy_to_file` hashes the blob, then `fs::copy` to the destination **in place** (not temp+rename), and does not re-hash the destination. Restore of a 2 GiB disk can leave a truncated `rootfs.ext4` if interrupted.

**Failure scenario.** Host crash during native restore: slot disk is half-written; next restore or a manual boot of that file is a corrupted guest filesystem. CAS ingest crash: `fingerprint.json` and manifest may already point at a hash whose object never became durable.

**Fix.** Mirror `put()` durability (fsync file, rename, fsync dir). `copy_to_file`: write to `dest.tmp`, fsync, rename, then optional hash verify. Keep the “already present + `hash_file`” dedup path — that part is correct (unchanged 2 GiB disks will CAS-dedup; dirty disks will not, which is expected).

---

### 11. Medium — `adapters/firecracker/src/main.rs:312-341`, `520-540`

**Defect.** Disk native blob is the **per-slot clone** (`state.rootfs`), ingested while the VM is paused after guest `sync`. That is the right object (FC vmstate does not include disk). Ordering on restore is load (`resume_vm: false`) → `PATCH /drives/rootfs` → resume, which matches Firecracker gotchas, and `network_overrides` is passed. Remaining bugs: (a) guest snapshot SSH is `let _ = ssh(...)` so a failed `abra snapshot` still captures memory/disk against whatever newest host snapshot `native-attach` picks; (b) `Diff` vs `Full` is a JSON flag with no restore story; (c) `fingerprint_for_snapshot` takes the first `x.y.z` token in `--describe-snapshot` output and can confuse Firecracker release with data-format major; (d) VM stays paused for the entire multi-GB `put_file` (e2e ~8s at 512 MiB+2 GiB; worse at scale).

**Failure scenario.** Guest `abra snapshot` fails (cadabra not ready); native child still parents an older tree; portable fallback materializes stale files while native memory reflects newer disk. Or `--describe-snapshot` prints `1.7.0` before `10.0.0` and fingerprints as format 1, so same-host restore spuriously falls back — or the reverse on another build.

**Fix.** Fail the host snapshot if the guest files snapshot fails; pass that snapshot id to `native-attach`. Refuse `diff` until chained restore exists. Parse the data-format field explicitly, not “first dotted triple.” `fsync` the disk file after pause; consider ingest-after-resume only if FC guarantees freeze of the file (today pause-during-ingest is safer for consistency, but bound it).

---

### 12. Medium — `adapters/firecracker/tests/e2e.sh:91-95` plus `main.rs:481-484`, `509-512`

**Defect.** Portable fallback is exercised only by `ABRA_FC_FAKE_FINGERPRINT` with `snapshot_format_major: 999`. That **does** make `matching_native` fail (field-for-field `PartialEq`), so the mode check is real. It does **not** simulate a second physical host, a CPU-model mismatch, or a stale `fingerprint.json` (the env var short-circuits the cache). Given finding 2, the production mismatch path is the one that is wrong.

**Failure scenario.** CI stays green while copying `ABRA_ROOT` to another machine still native-restores.

**Fix.** Keep the fake-env test. Add a test that writes a lying `fingerprint.json` without the env var and asserts **portable** (once finding 2 is fixed, that test should pass). Optionally compare live `--version`/`cpuinfo` against blob fingerprints.

---

### 13. Low — `adapters/firecracker/src/main.rs:264-268`, `guest/start-guest.sh:5-8`

**Defect.** Token is interpolated into boot_args with no allowlist. `start-guest.sh` uses `for argument in $(cat /proc/cmdline)` (word-split and glob). A token containing space, `*`, or additional `key=value` fragments becomes extra kernel parameters (`init=`, `systemd.unit=`, …) or a truncated token.

**Failure scenario.** A buggy enroll CLI or a hand-passed `--token` with whitespace changes guest `init` or silently drops the token so cadabra starts inert while the operator believes it enrolled.

**Fix.** Reject tokens outside `abra-enroll/1/[A-Za-z0-9_-]+`. Parse `/proc/cmdline` without globbing (read bytes, split on space only, prefix match). Prefer the file-based injection in finding 1 so cmdline is not a parser at all.

---

### 14. Low — `adapters/firecracker/src/main.rs:685-706`, `196-201`

**Defect.** SSH uses `StrictHostKeyChecking=no` and `UserKnownHostsFile=/dev/null`. Default key is `rootfs.parent()/desktop_id_rsa` if `--ssh-key` is unset. Anyone on the TAP path (or who can occupy `172.30.N.2` before the permanent neigh entry) is accepted. The key path is convenience, not a secret store check (mode 0600 not verified).

**Failure scenario.** Weaker on a dedicated TAP; still a MITM of root SSH if another local process joins the bridge/TAP. A world-readable `desktop_id_rsa` next to the image is silently used.

**Fix.** Pin the guest host key generated at image-build into `known_hosts`. Require `--ssh-key` / `ABRA_FC_SSH_KEY`. `chmod` check 0600.

---

### 15. Low — `adapters/sandbox/collector/observer.py:12`, `47-53`, `79-104`

**Defect.** Recipes are data only (good): atomic write of JSON, never `exec`, cadabra embeds them on snapshot (`lib.rs:689-693`) and restore prints them (`main.rs:460-463`). Env is **not** the whole environment; it is `ENV_KEYS` plus `ABRA_RECIPE_*`. That is stricter than a naive reading of SPEC §1.2 and is the right security default. Residual: full **argv** is captured (secrets on command lines); `ABRA_RECIPE_*` is an intentional leak channel; a non-UTF-8 env entry drops the **entire** recipe (`UnicodeError`) instead of omitting that entry as SPEC §1.2 requires; no bound on argv string size; observer runs as root every 2s over all PIDs whose cwd is under `/workspace`.

**Failure scenario.** `git push https://user:pat@host/...` from `/workspace` is snapshotted into `recipes[].argv` and teleported. An agent sets `ABRA_RECIPE_AWS_SECRET=…` thinking it is private.

**Fix.** Keep the allowlist. Document that argv is unsanitized. Drop bad env entries, not the recipe. Cap argv bytes. Run the observer as a non-root user that can still read `/proc` for workspace children if the image allows.

---

### 16. Low — `crates/cadabra/src/lib.rs:706-733` vs `737-814`; `crates/abra-core/src/cas.rs` streaming ingest

**Defect.** The cadabra `snapshot` op now records a fork label instead of forcing `main` when `receive_full` returns `forked` — that **strengthens** the lease invariant. `native-attach` is the new weakening (finding 9). `put_file`/`copy_to_file` do not change blob id semantics (plain BLAKE3). `docs/API.md` correctly marks `native-attach` as adapter API and restates socket = device key; it does not mention path allowlisting or native-never-source-of-truth on restore failure. No other core invariant looked broken: `files` remains required on full snapshots; native refs are extra closure members.

**Failure scenario.** Integrators read API.md, call `native-attach` with arbitrary paths, and assume restore always falls back. It does not (finding 2).

**Fix.** Document restore fallback and path policy next to the new op. Keep the forked handling on `snapshot`; apply the same to `native-attach`.

---

## Cross-checks (prompt priorities)

| Topic | Result |
|---|---|
| Slot / capsule injection | Slot is `u8`; TAP/IP/MAC are formatted from integers. Capsule ids are parsed as `Hash`. Real injection surface is the **token** in boot_args and remote SSH strings, not slot numbers. |
| NAT egress | Yes: `MASQUERADE` 172.30.0.0/16 + `ip_forward=1` is unrestricted guest egress through the host, plus inter-slot routing if FORWARD is ACCEPT. Documented only as “one MASQUERADE rule,” not as a security posture. Should be explicit; default-deny unless product intent is “full internet.” |
| Disk blob | 2 GiB object in e2e is the **per-session slot clone** at pause, not the vendor base image. Consistent with memory **if** guest `sync` + pause flush hold (they `sync`; they do not `fsync` the host file). CAS dedup applies when bytes are identical; a dirty rootfs will not dedup. Disk includes `/var/lib/abra` guest keys — native closure therefore carries guest identity, not just RAM. |
| Restore order | Load paused → patch rootfs → resume + `network_overrides`: correct. Fingerprint mismatch handling: **incorrect** (findings 2, 12). |
| Cross-host | README is honest that restore is same-host/same-CPU without a template. `cpu_template` **is** present in the fingerprint struct even when `"-"`, and equality includes it — but it is a constant, so it never distinguishes CPUs. That is the gap. |
| E2E cleanup / idempotency | Start/end `down` + `rm -rf` of the e2e root is mostly idempotent. Trap runs on success. Leftover risk is orphan FC before `state.json`, sticky iptables, and TAP held by a leaked VMM. |
| Recipes executed? | No. Observer writes JSON; core stores; restore prints. |

---

## Verdict

**Must-fix first.** Do not merge as a claimed “native resume proven” adapter.

The portable fallback exists and recipes are not executed, but (1) the enrollment token is exposed to all guest processes via cmdline, (2) native restore can run when the live host does not actually match, and then will not fall back if Firecracker rejects the load, and (3) the e2e check that justified `process_resumed: true` does not prove a resumed process.

### Top-3 must-fix

1. **Stop putting the enrollment token on the kernel command line** (finding 1). Inject `/etc/abra/token` mode `0600` on the per-slot image; `start-guest.sh` already supports that path.
2. **Live fingerprint + fail closed to files+recipes** (finding 2). Include CPU identity (or a real CPU template, still recorded when `"-"`); never treat `fingerprint.json` as the local host; on mismatch **or** `snapshot/load` failure, portable restore only.
3. **Make e2e prove memory resume** (finding 3). Same PID + listening port (or HTTP fetch) after restore; keep the fake-fingerprint fallback test but do not let `pgrep -f` match itself.

Jailer/API socket mode (finding 5) and install-rootfs symlink escape (finding 4) should land before any untrusted-guest deployment; they are the next cut after the three above.
