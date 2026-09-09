# Runtime validation, 2026-09-08

This is the initial restricted-sandbox run. The later full CLI, AWS, CPU
portability and installation results are in [launch validation](LAUNCH_VALIDATION.md).

The first live check used a disposable Daytona sandbox with Ubuntu 24.04,
x86_64, kernel `6.8.0-138-generic`, and CRIU 4.2 built from the official release
tag. The test ran exact Abra runtime source modules through a temporary Rust
CLI while macOS temporarily denied access to the full repository.

| Check | Result | What it establishes |
|---|---|---|
| `process check` | Passed | CRIU's initial kernel checks passed in that sandbox |
| Rust observer | Passed | Found the Rust fixture process and its listening service, and wrote a schema 3 capture |
| Rust archive and restore helpers | Passed | Transferred files, an executable and a relative symlink correctly |
| Detached Rust fixture | Passed | Started without a target Python helper and advanced to 40 tasks held only in memory |
| CRIU capture | Blocked | The sandbox rejected CRIU's attempt to suspend seccomp |
| Restore after terminating the source | Not reached | No claim of successful live memory restore |

The capture failure was:

```text
Error (compel/src/lib/ptrace.c:27): suspending seccomp failed: Operation not permitted
```

Abra reported that the source root was not stopped after the failed capture.
The test also found and fixed two CRIU argument errors, `--log-level` and a
separate value for the optional `--cpu-cap` argument. The final commands use
`--verbosity=4` and `--cpu-cap=all`. Early errors now retain bounded stderr,
and CRIU logs remain private.

The sandbox no longer existed when work resumed. No successful cross-provider
or cross-CPU live-memory restore was established by this run. A passing
`process check` alone is insufficient evidence of process capture support.

The repeatable RAM test is documented in
[process checkpoints](../../docs/PROCESS_CHECKPOINTS.md). A successful run must
terminate the original process, restore its random nonce and 40 in-memory task
results, and then continue to 100 tasks. It establishes process continuation
on the tested Linux environment. Cross-provider and cross-CPU claims need
their own runs and compatibility checks.
