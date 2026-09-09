# Launch validation, 2026-09-08

These tests use the uncommitted Abra core working tree. No package, Git commit,
tag or release was published. The Linux image and CPU emulation proposal remains
deferred.

## Results

| Test | Result | What the test proves |
|---|---|---|
| Native Linux ARM to x86 file checkpoint | Passed | Signed manifest and file objects restored on a different CPU; the program continued from saved step 7 to 8 after removal of its source workspace |
| Native Linux x86 to ARM file checkpoint | Passed | The same check passed in the opposite direction |
| Daytona x86 to AWS ARM, outside coordinator | Passed | Restored committed SQLite and file state at task 40, then reached task 100 with the same digest, task IDs and synthetic tool-call count as an uninterrupted run |
| AWS ARM to Daytona x86, outside coordinator | Passed | The same check passed in the opposite direction |
| AWS ARM to Daytona x86, inside source capture | Passed | Inside and outside capture produced identical final digests, task IDs and synthetic tool-call counts |
| Firecracker guest to Daytona, outside and inside capture | Passed | Both capture locations restored task 40 and reached task 100 with identical final results |
| Daytona to Firecracker guest, outside coordinator | Passed | The reverse provider transfer restored and continued the saved checkpoint |
| Daytona capture and send from inside the sandbox | Failed at pairing | `transport: timed out`; separate HTTPS probes to all four default iroh relay hosts failed with `Recv failure: Connection reset by peer` |
| Actual RAM capture on Daytona | Failed at capture | CRIU's basic check passed, but the sandbox denied required operations during the actual dump |
| Actual RAM restore on the AWS x86 host | Passed | After killing the original process, CRIU restored its memory-only nonce, digest and 40 completed tasks; it then advanced to 100 |
| Actual RAM restore inside the Firecracker guest | Passed | The same capture, kill, restore and continuation assertions passed inside the VM |
| Firecracker native snapshot and resume | Passed | Transferred VM state, memory and disk; resumed the same guest process PID and start time, with HTTP working afterward |
| Firecracker portable fallback | Passed | Restored portable files into a fresh VM and confirmed that the native marker process was absent |
| macOS ARM archive installation | Passed, 31 checks | Extracted binaries passed pairing, acknowledged transfer, restore planning, byte verification, daemon restart, persisted identities and peers, peer removal, and denial of a later transfer |
| AWS Linux ARM archive installation | Passed, 31 checks | The same installation checks passed on a newly created Ubuntu 24.04 ARM VM |
| Static Linux x86 CLI and runtime | Passed after a fix | The musl CLI runs, observes a real process and listening service, and passes all 22 runtime tests |

Testing is complete. All three Daytona inside-send attempts failed at pairing
with the same relay timeout. The provider scripts reported no cleanup errors.

Cleanup is complete and independently checked. The Daytona API no longer finds
the test sandbox. Both AWS instances are terminated, and the temporary security
group and EC2 key pair are gone. The retained Firecracker guest is stopped, with
no Firecracker processes, test TAP devices or test NAT rule remaining. The local
SSH tunnel and test daemons are also stopped. Existing AWS application hosts were
not used or changed.

## Firecracker and RAM scope

The dedicated AWS x86 host used nested KVM on a `c7i.xlarge`, Linux kernel
`7.0.0-1012-aws` and an Intel Xeon Platinum 8488C. The Firecracker
suite used Firecracker 1.16.1, guest kernel 6.1.182, an Ubuntu 24.04 headless
image, 512 MiB of guest memory and a 1 GiB disk. Its two Abra roots ran on the
same physical host. The native test does not establish migration between CPUs.
The fresh-root fallback check also ran on that host; it is not another provider.

The successful native suite took 107.102 seconds overall. Reported snapshot time
was 22.879 seconds and native restore time was 16.641 seconds. These are one-run
measurements, not a performance benchmark. An initial run with a 2 GiB disk hit
the test's fixed 60-second transfer wait. Cleanup then interrupted staged blob
transfer. The smaller-disk rerun passed; the original timeout is retained as a
failed attempt.

The RAM tests used CRIU 4.2.1 and the Rust `memory_probe`. The probe has no save
or load API. Each test saved the expected nonce and digest outside the process,
captured its RAM, killed and reaped the source, moved its workspace aside, then
restored and compared the live process's response. Host and guest tests each
restored within their original environment. They do not prove CRIU migration
between providers, different kernels or CPU architectures.

## Scope of the portable tests

The CPU-only example moved the signed manifest and object store in a tar archive.
It exercised the public Rust capture and restore API, not network pairing.

The provider tests used Daytona's SDK and SSH to collect and materialize files.
The outside-coordinator path sent the snapshot between two paired Abra daemons
on the coordinator machine. The inside path starts Abra inside the source
sandbox and connects to the receiver across the network. Those are different
network paths; an outside-path pass does not establish inside-path connectivity.

Before restore, the provider test stopped its original workload and renamed the
source workspace. It verified the restored checkpoint at task 40, continued to
100, and compared against an uninterrupted run. The tool calls are deterministic
test operations. This does not test recovery of external API side effects.

These are saved application checkpoints. They do not establish cross-CPU
continuation of unsaved process memory or arbitrary applications.

## Failures found

The initial static Linux link failed with `undefined reference to renameat2`.
The runtime now invokes the Linux syscall directly. A Linux regression test
checks that an existing destination cannot be overwritten, and the CI workflow
now builds the static CLI and runs its runtime tests. The workflow itself has
not run on GitHub; its build and test commands passed in the live Linux sandbox.

Daytona used Ubuntu 24.04.3 x86_64, kernel `6.8.0-138-generic`, and CRIU 4.2.
The actual dump reported:

```text
Can't setup RLIMIT_NOFILE for self: Operation not permitted
suspending seccomp failed: Operation not permitted
Dumping FAILED
```

The failed smoke test cleaned up its memory probe. `process check` passing alone
does not establish that capture works. The basic check and the actual dump are
reported separately. The CLI now includes `check_scope: "criu-default"` and
`capture_tested: false`, with a note explaining this limit. The listed Linux
binaries predate that output-only clarification; their capture logic is unchanged.

Daytona also reset HTTPS connections to the default relay hosts, with and without
the trailing DNS dot. GitHub HTTPS worked, while example.com and the AWS check-IP
endpoint failed the same way. The sandbox API reported `network_block_all=false`
and no explicit IP or domain allow list. These observations establish a network
restriction or failure in this environment; they do not establish its cause.
An independent AWS ARM probe paired to the same relay-ready local ticket in one
second. Its temporary daemon, state and ticket were cleaned up.

## Artifacts and evidence

Detailed local evidence is under `/tmp/abra-launch-tests-20260908/`:

- `cpu/report.json` records both native CPU runs and checkpoint archive hashes.
- `provider-arm/outside-run/report.json` records both successful provider runs.
- `provider-arm/run1/` retains the failed inside attempt and daemon logs.
- `provider-arm/inside-reverse-run/` records the successful AWS inside capture and the reverse Daytona pairing failure.
- `provider-arm/semantic-equality.json` compares the completed inside and outside AWS captures.
- `provider-firecracker/run1/` records both completed Firecracker capture modes and the reverse provider transfer.
- `daytona/report.json` and `daytona/summary.md` record the live CRIU failure and static builds.
- `local-install/` contains the macOS archive and installation report.
- `linux-arm-install/` contains the Linux ARM archive and installation report.
- `firecracker/firecracker-e2e.json` and its log record native restore and fallback.
- `firecracker/process-criu-smoke-{host,guest}.txt` record both successful RAM tests.
- `source-validation.json` records the Git base and hashes of the final changed test/runtime files.
- `aws/cleanup-verification.json`, `daytona/cleanup.json`, `firecracker/retained-cleanup.json` and `local-cleanup.json` record resource cleanup.

| Artifact | SHA-256 |
|---|---|
| macOS ARM archive | `f6621a012e954ade78f180137f3f79c94c71eef6e09b358d40aeec7938acbd44` |
| Linux ARM archive | `64f7533787a65d78ffd38a77cc55dc2f371cea4ff38800698b9705088193cf51` |
| Linux ARM GNU CLI | `db46be631a039b6d14597218fcbfc3cc9c951182af7eaf3df84f1bfacd2b7d4a` |
| Linux x86 GNU CLI | `cfb44088f8a787271b035bf8979d29f000629003dc17fb41fa4fe38a7274d61e` |
| Linux x86 static musl CLI | `968fa98fd2fa59a192e30506483f289e00028688724aa3769c8e0b3ef6da2050` |

The macOS installation test used a fresh prefix and isolated state on the existing
Mac. The Linux ARM test used a fresh AWS VM with build tools already installed,
then ran only extracted artifact binaries under a restricted PATH. Neither run
establishes support for every OS release or CPU combination.
