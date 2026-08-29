# Stage 3 review — cadabra daemon + abra CLI (final round)

Reviewer: Claude Opus 5, security-focused. Repo `/Users/vividh/Desktop/abra` @ `2354ec9`.
Authoritative: SPEC.md (+errata), DESIGN.md, docs/API.md. No repo modifications were made.

Method: full read of `crates/cadabra/src/{lib,main}.rs`, `crates/abra-cli/src/main.rs`,
`crates/abra-net/src/{delivery,auth,outbox,transport,framing,control}.rs`, and the
security-relevant parts of `crates/abra-core/src/{cas,store,capsule}.rs`; plus
`cargo test --workspace` (all green, 0 failures) and live probes against the real
`abra daemon` binary over the real UDS. Findings marked **[probed]** were reproduced
empirically; the exact commands and outputs are quoted inline.

---

## Critical

### 1. The shipped binaries have no transport. Pairing and delivery are impossible between processes. **[probed]**
**Severity: critical** — `crates/cadabra/src/main.rs:25-29`, `crates/abra-cli/src/main.rs:121`, `crates/abra-net/src/transport.rs:100-103`

Both binaries construct their node with `Daemon::loopback(root, &LoopbackNetwork::default(), yes)`.
`LoopbackNetwork` is an `Arc<Mutex<BTreeMap<PeerId, mpsc::Sender<Connection>>>>` populated only by
`LoopbackTransport::bind` inside the same process, and `::default()` creates a *fresh, empty* one per
invocation. So every `abra daemon` process is alone on its own private network. `IrohTransport`
(`transport.rs:180-259`) exists but is behind `abra-net`'s off-by-default `iroh` feature, which
neither `crates/cadabra/Cargo.toml` nor `crates/abra-cli/Cargo.toml` re-exports — there is no
`[features]` table in either, and no `--transport` flag. Nothing outside tests ever calls
`Daemon::new` with a non-loopback transport.

Failure scenario (reproduced):
```
$ abra --root /tmp/a daemon --yes &     $ abra --root /tmp/b daemon --yes &
$ TK=$(abra --root /tmp/b --json pair ticket | jq -r .ticket)
$ abra --root /tmp/a pair add "$TK"
Error: "transport: peer unavailable"     exit=1
$ abra --root /tmp/a --json peers
[]
```
This is not a two-machine limitation — two daemons *on the same host* cannot pair. Everything
downstream (send, outbox drain, inbox, accept-from-peer, ack) is therefore unreachable from the CLI.
The product's entire premise ("teleport between one user's devices") does not function in the
artifact being reviewed. README.md:72-73 tells the user to "build with the optional iroh transport
for separate-device routing" — there is no such build.

**Fix:** add an `iroh` feature to `cadabra` and `abra-cli` that forwards to `abra-net/iroh`, and a
`--transport {loopback,iroh}` flag (default iroh when compiled in) that builds `IrohTransport` from
`store.keys` and passes it to `Daemon::new`. Until that lands, README/DESIGN must state plainly that
the binaries are single-process demos. Add one e2e test that pairs two daemons over two OS processes.

---

### 2. The README quickstart fails at step 3, and relative paths are resolved in the daemon's cwd. **[probed]**
**Severity: critical (usability contract)** — README.md:52-65; `crates/cadabra/src/lib.rs:239, 297-300, 333, 442`

`capsule-create` requires an already-existing directory (`lib.rs:298-300`), and the quickstart never
runs `mkdir`. Worse, the CLI forwards the path string verbatim (`abra-cli/src/main.rs:136`) and the
*daemon* resolves it — so a relative path is interpreted against the daemon's working directory, not
the user's shell. Reproduced running the README lines exactly, with the client in a different cwd:
```
$ abra --root /tmp/abra-a status         OK
$ abra --root /tmp/abra-a pair ticket    OK
$ abra --root /tmp/abra-a init ./my-workspace
Error: "capsule path must be a directory"    exit=1
# after `mkdir ./my-workspace` in the client's cwd — still fails:
Error: "capsule path must be a directory"    exit=1
# because daemon cwd = /Users/vividh/Desktop/abra
```
The same cwd trap applies to `snapshot <path>` (`lib.rs:333`) and `accept --to <path>` (`lib.rs:442`),
and it is a security-relevant surprise as well as a usability one: `abra accept x --to ./out` writes
somewhere the user did not name.

**Fix:** have the CLI canonicalize paths (`std::fs::canonicalize` / join against `std::env::current_dir()`)
before sending them, and reject non-absolute paths in `handle`. Make `init` create the directory or
say `run: mkdir -p <path>` in the error. Then make the quickstart a tested script (a `tests/` shell
or `assert_cmd` test that runs the exact README block).

---

### 3. No daemon singleton: a second daemon on the same root silently hijacks the socket and forks the store. **[probed]**
**Severity: critical** — `crates/cadabra/src/lib.rs:87-93`

`start()` unconditionally `fs::remove_file`s any existing `cadabra.sock` and rebinds. There is no
lock file, no pid check, no `flock` anywhere in the workspace. Reproduced:
```
$ abra --root /tmp/a daemon --yes &   # pid1
$ abra --root /tmp/a daemon --yes &   # pid2 — no error, no log
second daemon alive? yes    first daemon alive? yes
$ abra --root /tmp/a --json status    # served by pid2
```
Both processes now hold independent in-memory `AbraStore`, `TrustStore` and `Outbox` over the *same*
files. Every mutation path is read-modify-write-whole-file (`outbox.rs:88-98`, `auth.rs:240-250`),
so the two diverge and clobber each other last-writer-wins: a pairing recorded by pid1 vanishes when
pid2 saves `net/trust.json`; an outbox entry acked by pid1 is resurrected by pid2's stale copy; both
outbox workers dial the same peer with the same `offer_id`. The first daemon also keeps running with
a socket nobody can reach, so `abra` silently talks to the wrong instance.

This is also a local-attack primitive: any same-uid process can `abra daemon --yes` to displace the
user's interactive daemon with an auto-confirming one, so the next pairing request from *any* peer
is approved without a prompt.

**Fix:** take an exclusive `flock`/`O_EXCL` lock on `<root>/cadabra.lock` holding the pid before
binding; if held and the pid is alive, exit with "daemon already running at <root>". Only unlink a
stale socket after the lock proves the previous owner is gone.

---

### 4. `abra init` mints a 24-hour lease and nothing can ever renew it — capsules freeze permanently after one day.
**Severity: critical** — `crates/cadabra/src/lib.rs:316-325`, `crates/abra-core/src/capsule.rs:251-255, 430-436`

`capsule_create` grants itself `LeaseRecord::new(..., epoch 1, ..., format_time(now_ms() + 86_400_000), ...)`
— expiry fixed at +24h. `apply_label` for the `main` label requires `active_lease(now_ms)`
(`capsule.rs:432`), which filters the winning lease by `expires_at >= now` (`capsule.rs:251-255`).
`cadabra` never calls `AbraStore::accept_lease` — grep across `crates/cadabra` and `crates/abra-cli`
for `accept_lease`, `authorize_lease`, `LeaseMode::Acquire`, `LeaseMode::Takeover` returns nothing;
`LeaseRecord::new` appears exactly once, in `capsule_create`. There is no `abra lease` command.

Failure scenario: user runs `abra init ~/work` on Monday, snapshots happily; on Tuesday every
`abra snapshot ~/work` fails with `invalid: main requires lease`, and no CLI command can mint the
epoch-2 renewal that would fix it. The capsule is bricked for the life of the store. (Derived from
code, not clock-probed — the 24h wait was out of scope for this pass, but the path is unambiguous.)

Compounding: the failure is *after* the write. `snapshot` calls `receive_full` (persisting the
snapshot to `capsules/<id>/snapshots/`) at `lib.rs:370-374`, then `apply_label` at `lib.rs:391`.
When the label fails, the op returns an error but the snapshot is already on disk and unreferenced.

**Fix:** add lease renewal — either auto-renew inside `snapshot` when the local device is the current
holder and the lease is within, say, 25% of expiry, or an explicit `abra lease renew|acquire|release`
that wires `AbraStore::accept_lease` + `TrustStore::authorize_lease`. Also make `snapshot` atomic:
validate the lease *before* `receive_full`, or roll back on label failure.

---

## Major

### 5. UDS bind→chmod TOCTOU: the socket is world-connectable for the window between `bind()` and `set_permissions()`. **[probed]**
**Severity: major** — `crates/cadabra/src/lib.rs:93-98`; docs/API.md:3-4

```rust
let listener = UnixListener::bind(&socket)?;              // :93  created 0777 & ~umask
fs::set_permissions(&socket, Permissions::from_mode(0o600))?;  // :97
```
Measured directly under the default umask 022:
```
mode right after bind: 0o755
```
Any local process that wins the race and `connect()`s in that window holds a fully privileged control
connection *permanently* — AF_UNIX permission is checked at connect time only, never re-checked, and
`serve_client` loops for the life of the connection. The containing directory is 0755 (finding 6), so
the path is reachable. docs/API.md:3-4 asserts "created with mode 0600", which is true only after the
window closes.

**Fix:** `bind` inside an already-0700 directory, or set `umask(0o177)` around the bind and restore it,
or bind to a temp name in a 0700 dir and `rename` into place. Best: do all three — put the socket in
`<root>/run/` created `0700` first.

### 6. The store root and every content directory are world-readable (0755). **[probed]**
**Severity: major** — `crates/abra-core/src/store.rs:57-67`, `crates/abra-core/src/cas.rs:232-238`, `crates/abra-net/src/{outbox.rs:88-98, auth.rs:240-250}`

`AbraStore::open` chmods only `keys/` to 0700. Everything else is plain `create_dir_all`:
```
$ ls -ld /tmp/abraprobe/a ; ls -l /tmp/abraprobe/a
drwxr-xr-x  a
drwxr-xr-x  capsules      drwxr-xr-x  inbox      drwxr-xr-x  objects
drwxr-xr-x  outbox        drwxr-xr-x  tmp        drwx------  keys
srw-------  cadabra.sock
```
So every byte the user ever teleports (`objects/`), every received manifest (`inbox/`), the capsule
history, the outbox (which stores full manifest bytes), `net/trust.json` (peer list, x25519 keys,
guest scopes) and `net/pending-acks/` are readable by every user on the machine. The private key is
correctly protected, which makes the gap look deliberate — it isn't. SPEC.md:33 mandates 0600 for
keys and is silent on the rest; no doc claims anything about content confidentiality, which is itself
a spec gap for a product whose one job is moving a user's private workspace.

**Fix:** chmod the store root to 0700 in `AbraStore::open` (and create it with `DirBuilder::mode(0o700)`
so there is no window), and state the guarantee in SPEC §2.

### 7. Zero authentication of local control-API callers; every op is fully privileged.
**Severity: major** — `crates/cadabra/src/lib.rs:174-263`

`serve_client` reads a line, parses JSON, and dispatches. There is no `SO_PEERCRED`/`getpeereid`
check, no token, no per-op capability, no confirmation prompt. Any process running as the same uid
can:
- `pair-ticket` → mint a 10-minute ticket granting **Full** role, hand it to a remote attacker, who
  then becomes a fully trusted peer of the user's mesh (`lib.rs:206-219`);
- `pair-confirm <peer>` → approve a pairing the user was about to decline (`lib.rs:221-225`);
- `enroll-mint` → mint a wildcard enrollment token (see finding 14);
- `send` → exfiltrate any directory the user can read to any paired peer (`lib.rs:395-427`);
- `accept --to <path>` / `capsule-create <path>` → write attacker-influenced content anywhere the
  user can write (`lib.rs:440-457`, `lib.rs:297-330`).

This matters more here than for a typical daemon because Abra's stated audience is *agents*
(README.md:3-4, DESIGN.md). An agent sandboxed only by "runs as the user" — the common case — gets
the full authority of the device identity, including the ability to enrol itself a peer. The whole
guest/scope machinery in `abra-net/src/auth.rs` is bypassed by simply talking to the socket. Security
currently rests entirely on the 0600 mode that is set one syscall late (finding 5).

**Fix (v0.1 minimum):** (a) `getpeereid` the connection and refuse a uid != the daemon's;
(b) split ops into a read-only set and a mutating set, and gate the dangerous ones
(`pair-ticket`, `pair-confirm`, `enroll-mint`, `send`) behind a capability token written to a
0600 file at startup that the CLI reads — so a process must at least be able to read the store root;
(c) document the trust boundary in docs/API.md. Longer term this is a SPEC gap: SPEC.md has no local
control API section at all, so `docs/API.md` is unbacked by any normative text.

### 8. Unbounded NDJSON line length and unbounded connection count: trivial local OOM. **[probed]**
**Severity: major** — `crates/cadabra/src/lib.rs:174-191` (esp. `:176-177`), `:102-115`

`BufReader::new(read).lines()` buffers until a `\n` arrives, with no cap. Measured:
```
RSS before:                                    6,064 KB
after 300 MB sent on one connection, no \n:  315,504 KB
```
Linear, unbounded, and the connection is still open. `abra-net` gets this right —
`MAX_CONTROL_FRAME = 16 MiB` enforced on both read and write (`framing.rs:5-26`) — the local API
simply omits the equivalent. Additionally `:106-110` spawns a task per accepted connection with no
concurrency cap and no tracking, so an attacker opens N connections × M bytes.

Related, same site: a non-UTF-8 line makes `next_line()` return `Err`, which `?` propagates out of
`serve_client`, closing the connection with **no response at all** (probed: `reply: b''`). docs/API.md:6-7
promises `{"ok":false,"error":...}` for failures. (Good news: injection through the framing itself is
*not* possible — embedded newlines inside JSON strings are escaped on both encode and decode; probed
with `{"op":"accept","id":"x\ny",...}` → clean `{"ok":false,...}` error.)

**Fix:** replace `.lines()` with a length-limited reader (`AsyncBufReadExt::take(MAX_LINE)` or a manual
`read_until` with a 1 MiB cap), return `{"ok":false,"error":"request too large"}` and drop the
connection; add a semaphore capping concurrent control connections (say 64); reply with an error
object on invalid UTF-8 instead of hanging up silently.

### 9. Two broken background loops: the control listener dies permanently on any accept error; the transport listener hot-spins on any accept error.
**Severity: major** — `crates/cadabra/src/lib.rs:102-115` and `:118-130`

```rust
accepted = listener.accept() => match accepted {
    Ok((stream, _)) => { ... }
    Err(_) => break,                       // :111
}
```
A *transient* `accept()` failure — `EMFILE`/`ENFILE` when the process hits its fd limit, which
finding 8 makes easy to induce — permanently terminates the control-API accept loop. The process
keeps running (the other two tasks are alive) but every subsequent `abra` command gets
`ConnectionRefused` forever, with no log line. The daemon looks alive and is deaf.

The transport loop has the mirror-image bug:
```rust
incoming = daemon.transport.accept() => if let Ok(mut connection) = incoming { ... }   // :122
```
On `Err` there is no `break`, no backoff, no logging — the `select!` re-arms immediately and the task
busy-loops at 100% CPU. `IrohTransport::accept` returns `Err(Transport("endpoint closed"))`
persistently once the endpoint is down (`transport.rs:248-257`), so the moment finding 1 is fixed
this becomes a guaranteed CPU spin on network teardown.

**Fix:** in both loops, log the error, apply capped exponential backoff, and only break on errors that
are genuinely terminal (listener closed). Never `break` on a transient accept error; never continue
without backoff.

### 10. The node mutex is held across network I/O, so one peer stalls the entire daemon.
**Severity: major** — `crates/cadabra/src/lib.rs:125` and `:147-172`; `crates/abra-net/src/delivery.rs:629-863`

```rust
tokio::spawn(async move {
    let _ = node.lock().await.handle_connection(&mut connection, now_ms()).await;  // lib.rs:125
});
```
`handle_connection` is an unbounded `loop` that reads a frame with a 5-second per-frame timeout
(`delivery.rs:640, 866-871`) and never exits until the peer disconnects or errors. The lock is held
for the whole session, *including the handshake* — i.e. before the peer is authenticated at all. A
peer that sends `{"type":"ping"}` every 4 seconds holds the daemon's one global mutex indefinitely.
Everything else then blocks: `abra status` hangs forever (the control API takes the same lock at
`lib.rs:201`), the outbox worker cannot run, no other peer can be served.

The outbox worker has the same shape in the other direction (`lib.rs:154-161`): `send_offer` is
awaited *while holding* the lock, so a slow or hostile recipient freezes the control API for the
duration of a transfer (up to `MAX_OBJECT_SIZE` = 256 MiB per object).

The two combine into mutual starvation: daemon A's outbox worker holds A's lock while awaiting B,
whose inbound handler is blocked on B's lock held by B's outbox worker awaiting A. The 5s timeouts
prevent a hard deadlock, but the result is a retry storm with `fail_attempt` backoff on both sides.
Today this is only reachable in-process (finding 1); it becomes remotely reachable and
pre-authentication the moment a real transport is wired, which is why it belongs in this round.

**Fix:** don't hold the store mutex across I/O. Restructure `handle_connection` so the lock is taken
per-message around the store mutation only (the frame read/write must be outside it), and likewise
split `send_offer` into "prepare under lock → transfer unlocked → commit under lock". Cap concurrent
inbound connections and add an idle timeout for the whole session, not just per frame.

### 11. Outbox `cancel` and TTL expiry are silently undone by the worker — cancelled sends still get delivered.
**Severity: major** — `crates/abra-net/src/outbox.rs:171-190`, `crates/abra-net/src/delivery.rs:422-426, 457-468`, `crates/cadabra/src/lib.rs:147-172`

`fail_attempt` resets state unconditionally:
```rust
if e.attempts >= 20 { e.state = Failed } else { e.state = Queued; ... }   // outbox.rs:179-187
```
and `send_offer` calls it on *every* error, including illegal-transition and expired errors:
```rust
let result = self.send_offer_inner(id, connection, now, None).await;
if let Err(error) = &result { let _ = self.outbox.fail_attempt(id, error.to_string(), now); }  // delivery.rs:423-425
```
Two consequences, both live now that stage 3 added a worker that actually drives this loop every
100 ms (`lib.rs:133-140`):

- **Cancel race (lost update).** `work_outbox` snapshots `pending_ids` under the lock, releases it,
  dials, then re-locks to call `send_offer`. A user's `abra cancel <id>` landing in that window sets
  `Cancelled`; `send_offer_inner` then fails the `Queued → Healthcheck` transition (`outbox.rs:146-166`),
  the wrapper calls `fail_attempt`, and the entry is resurrected as `Queued`. The cancelled snapshot
  is then delivered on the next tick. For a "cancel that handoff, it had a secret in it" workflow this
  is a confidentiality failure, not a nit.
- **TTL never terminates.** `send_offer_inner:457-464` calls `outbox.expire(now)` and returns `Err`
  if the entry is now `Expired`; the wrapper immediately flips it back to `Queued`. The 7-day
  `OUTBOX_TTL_MS` therefore never sticks — entries keep retrying until the 20-attempt cap.

**Fix:** make `fail_attempt` state-aware — never move out of a terminal state (`Acked`/`Cancelled`/
`Expired`) and never out of `Failed`; return `Ok(())` instead. Have `send_offer` skip `fail_attempt`
for pre-flight errors (expired/cancelled/backoff) entirely. Add a regression test that cancels
between `pending_ids` and `send_offer`.

### 12. The daemon has no logging at all, and every background error is discarded.
**Severity: major (operability)** — `crates/cadabra/src/lib.rs:109, 125, 155-161, 164-169`, `crates/cadabra/Cargo.toml`

There is no `tracing`/`log` dependency anywhere in `cadabra` or `abra-cli`. Every fallible background
operation is `let _ = ...`: client sessions (`:109`), inbound peer connections (`:125`), offer sends
(`:155-161`), even the `fail_attempt` that records *why* a send failed (`:164`). The daemon writes
nothing to stdout/stderr in normal operation (the smoke test at `abra-cli/tests/smoke.rs:23-24` pipes
both to `/dev/null`, and there is nothing to lose).

Failure scenario: a user's send never arrives. `abra outbox` shows `state:"queued"` with a
`last_error` only if `fail_attempt` happened to be reached; a rejected offer, a failed handshake, or
a panic inside a spawned task produces no diagnostic anywhere. Combined with findings 9 and 11 this
makes the daemon effectively undebuggable in the field, which is a poor property for a v0.1 that
users are being asked to trust with their data.

**Fix:** add `tracing` + `tracing-subscriber` with `RUST_LOG`/`--log-level`, an `info` line per
lifecycle event (bind, peer connect, offer sent/acked/failed, shutdown) and `warn`/`error` on every
site currently swallowing a `Result`. Surface the last N events through a `status` field or a `log`
op so `abra` can show them.

### 13. Guest enrollment is unreachable end to end, and revocation has no path at all — the scope machinery is dead code.
**Severity: major** — `crates/cadabra/src/lib.rs:247, 473-523`; `crates/abra-net/src/delivery.rs:659-861`; `crates/abra-net/src/auth.rs:398-499, 1082-1090`

`abra enroll` mints a real, signed `EnrollmentToken`. Nothing can redeem it:
- `bootstrap_allowed` explicitly permits `"enroll-bind"` and `"enroll-ok"` on an untrusted session
  (`auth.rs:1082-1090`), but `handle_connection`'s match has **no arm for `enroll-bind`** — it handles
  only `ping`/`offer`/`plan`/`ack`/`control`/`pair-request`/`pair-confirm` and falls through to the
  `_` catch-all, replying `{"code":"unknown_type"}` (`delivery.rs:852-860`).
- `TrustStore::bind_enrollment` and `accept_bind_cert` (`auth.rs:398, 471`) have no callers outside
  `crates/abra-net/tests/net_spec.rs`. Same for `set_local_role`, so nothing can ever put a node into
  `LocalRole::Guest`.
- `revoke_token` / `apply_revocation` (`auth.rs:368, 377`) likewise have no callers outside tests, and
  there is no `revoke` control op or CLI command. **A leaked enrollment token cannot be revoked.**
- `authorize_offer` / `authorize_ack` / `authorize_fetch` / `authorize_lease` (`auth.rs:500-598`) are
  never called by the delivery loop either; `validate_incoming_offer` (`delivery.rs:350-414`)
  reimplements a subset inline. Two divergent copies of the same authorization rule is a latent
  correctness hazard even after enrollment is wired.

So for priority-5 "guest scope enforcement": the *enforcement* code in `validate_incoming_offer`
(`delivery.rs:372-412`) and `enqueue` (`delivery.rs:220-228`) is correct and the daemon does route
through the safe API (`Daemon::send` calls `node.enqueue`, `lib.rs:425`, not `outbox.enqueue`
directly) — but no peer can ever *become* a guest, so the invariant is vacuously true. Shipping
`abra enroll` implies a working agent-scoping feature that does not exist.

**Fix:** either implement the `enroll-bind`/`enroll-ok` arm in `handle_connection` plus `enroll-accept`
and `revoke` control ops and a guest mode for the daemon, or remove `abra enroll` from the CLI for
v0.1 and mark §7.2/§7.3 as unimplemented in README's Status section. Also collapse
`validate_incoming_offer`'s inline checks onto `authorize_offer` so there is one implementation.

### 14. `enroll-mint` silently defaults to wildcard scopes when a control-API caller omits fields.
**Severity: major** — `crates/cadabra/src/lib.rs:475-506`

```rust
capsules: request.get("capsules")... .unwrap_or_else(|| vec!["*".into()]),   // :485
kinds:    request.get("kinds")...    .unwrap_or_else(|| vec!["*".into()]),   // :495
```
The CLI marks both `required = true` (`abra-cli/src/main.rs:82-85`), so a human is forced to be
explicit — but the control API is the real boundary, and `{"op":"enroll-mint"}` with no fields mints
a 24-hour token (`:519`) scoped to **every capsule and every kind**. Any same-uid process (finding 7)
gets a maximally-broad delegation with one 25-byte request. `Scopes::validate` (`auth.rs:177-184`)
accepts `["*"]` by design, so nothing downstream catches it. docs/API.md:25 lists all five fields
without the `?` marker the table uses elsewhere, i.e. the doc says they are required and the code
says they are optional-and-wildcard.

**Fix:** make `capsules` and `kinds` mandatory in `handle` (`required_str`-style error if absent), and
refuse `["*"]` unless an explicit `"unsafe_wildcard": true` is passed. Fix the API.md row either way.

### 15. `pair_add` blocks forever on an unresponsive peer; no timeout on the accept frame.
**Severity: major** — `crates/cadabra/src/lib.rs:266-295`, esp. `:285`

```rust
write_frame(send, &request).await?;
let accept: PairAccept = read_frame(recv).await?;   // :285 — no timeout
```
Every other read in the codebase is timeout-wrapped (`delivery.rs:866-871` uses `HEALTH_TIMEOUT`;
`framing.rs:28-35` provides `read_frame_timeout`). This one is not. A peer that completes the
handshake and then goes silent hangs `abra pair add` — and the CLI process — indefinitely, with no
way to cancel other than Ctrl-C. Under a real transport this is the first thing a hostile or merely
NAT-stuck peer does. Today it happens to fail fast only because `dial` errors first (finding 1).

**Fix:** use `read_frame_timeout(recv, PAIR_TIMEOUT)`; 30s is generous. Same treatment for
`dial_handshake` at `:269`.

### 16. `snapshot` is non-atomic and mislabels local forks.
**Severity: major** — `crates/cadabra/src/lib.rs:332-393`, esp. `:370-374` and `:391`

Two defects in one op:
1. **Partial mutation on failure** (also noted in finding 4): `receive_full` persists the snapshot and
   its meta file to disk at `:374`; `apply_label` at `:391` can then fail (expired lease, lost lease,
   label-limit) and the op returns `Err` with the store already changed. The caller sees a failure and
   has no way to learn a snapshot was written.
2. **`fork_signer: None`.** `receive_full(raw, at, now, None)` at `:374` means that when the local
   write is classified as a fork (`result.forked`), the fork-label branch at `store.rs:185-192` is
   skipped entirely — no `fork/xxxxxxxx` label is created. The snapshot lands unreferenced by any
   label, and then `apply_label("main")` fails, so the user gets an error and an invisible orphan.
   The daemon holds the identity that should sign that label (`node.store.keys.identity`) and simply
   doesn't pass it.

**Fix:** pass `Some(&node.store.keys.identity)` as `fork_signer`; check `active_lease(now)` before
`receive_full` and fail early; return `{"forked":true,"label":"fork/xxxxxxxx"}` so the CLI can tell
the user where their work went.

### 17. No SIGTERM handling; the socket is never unlinked on shutdown; in-flight clients are cut off. **[probed]**
**Severity: major (lifecycle)** — `crates/cadabra/src/main.rs:31-32`, `crates/abra-cli/src/main.rs:123-124`, `crates/cadabra/src/lib.rs:45-51`

Both binaries await `tokio::signal::ctrl_c()` only — SIGINT. Under SIGTERM (systemd `stop`, launchd,
`kill`, container shutdown, `pkill`) the process dies immediately: `RunningDaemon::shutdown` never
runs. Even on the SIGINT path, `shutdown()` sends the watch signal and awaits the three loops but
never removes `cadabra.sock`, so a stale socket always survives. Probed: after `kill`, the socket file
is still present, and a client connecting to it gets `ConnectionRefused`.

`shutdown()` also only awaits the three loop tasks — the per-client tasks spawned at `lib.rs:109` are
untracked, so a client mid-`write_all` is dropped and reads a truncated response.

**Fix:** select over SIGINT *and* SIGTERM (`tokio::signal::unix::signal`); unlink the socket (and the
lock from finding 3) in `shutdown()`; track client tasks in a `JoinSet` and await them with a bounded
grace period.

---

## Minor

### 18. `--json` mode emits nothing parseable on failure. **[probed]**
**Severity: minor** — `crates/abra-cli/src/main.rs:116-157`

`main` returns `cadabra::Result<()>`, so errors are Debug-printed by the runtime:
```
$ abra --root R --json log --capsule deadbeef
stdout=[]  stderr=[Error: "malformed hash: expected 32 bytes (64 hex chars), got 4"]  exit=1
$ abra --root R --json status        # daemon down
stderr=[Error: Os { code: 61, kind: ConnectionRefused, message: "Connection refused" }]  exit=1
```
The quoted-string form (`Error: "…"`) and the raw `Os { … }` struct are both artifacts of boxing;
neither is a stable contract, and `--json` consumers must special-case exit codes and scrape stderr.
Exit codes are also undifferentiated (always 1) and undocumented.

**Fix:** catch the error in `main`, and in `--json` mode print `{"ok":false,"error":"..."}` on stdout;
use distinct exit codes (2 = usage, 3 = daemon unreachable, 4 = daemon error). Special-case
`ConnectionRefused`/`NotFound` on the socket with "no daemon at <root>; run `abra daemon`".

### 19. Pair approval is consumed before the ticket is validated.
**Severity: minor** — `crates/abra-net/src/delivery.rs:836-843`

```rust
let approved = self.auto_confirm_pairs || self.approved_pair_requests.remove(&request.peer_id);  // :836
let accept = self.trust.accept_pair_request(&request, connection.peer_id(), now, |_,_| approved)?;
```
`remove` fires before `accept_pair_request` checks ticket existence, single-use, and expiry
(`auth.rs:290-301`). If the retry arrives after the 10-minute ticket TTL, or with a mistyped ticket,
the user's approval is silently spent and they must run `abra pair confirm` again with no indication
why. (The good news, verified: the ticket itself is *not* consumed on a declined attempt —
`used_tickets.insert` at `auth.rs:305` is after the confirm callback — so the documented retry is at
least possible, and `pending_pair_requests` correctly survives a decline because the `?` at `:838`
skips the `remove` at `:844`. That part is well designed.)

**Fix:** peek with `contains` and only `remove` after `accept_pair_request` returns `Ok`.

### 20. Pending-pair and approval state is lost on restart.
**Severity: minor** — `crates/abra-net/src/delivery.rs:197-198, 211-212`

`pending_pair_requests` and `approved_pair_requests` are in-memory `BTreeMap`/`BTreeSet` rebuilt empty
by `DeliveryNode::open`. The comment at `:194-196` says this is intentional ("tickets remain the
durable, bounded authorization"), which is defensible — but the consequence is undocumented: if the
daemon restarts between `pair confirm` and the retry `pair add`, the approval evaporates and the user
sees `pairing declined` again with no explanation. Since the whole flow spans three separate CLI
invocations, this is more likely than it sounds.

**Fix:** either persist approvals with a short TTL alongside `pending_tickets`, or have
`pair-confirm`'s response note that the approval is valid only until the daemon restarts, and say so
in docs/API.md.

### 21. `send` silently ignores `--title`/`--note` and silently prefers `--capsule` over `--link`/`--path`.
**Severity: minor** — `crates/cadabra/src/lib.rs:395-427`; `crates/abra-cli/src/main.rs:65-78, 138-140`

`title` and `note` are read only inside the `link` branch (`:401, :405`), so
`abra send P --path ./x --title "Report"` drops the title without a word — while docs/API.md:21 lists
`title?`/`note?` as general `send` fields. Precedence is `snapshot_id` → `link` → `path` with no
conflict detection, so `abra send P --link L --path X` sends the link. And omitting all three yields
the internal `request lacks path` (`required_str`, `lib.rs:411`) rather than a clap usage error.

**Fix:** put the three sources in a clap `ArgGroup(required = true, multiple = false)`; apply
`title`/`note` to all branches or reject them where unsupported; fix the API.md row.

### 22. `--capsule` carries a snapshot id, and `id` means three different things.
**Severity: minor** — `crates/abra-cli/src/main.rs:139`; `crates/cadabra/src/lib.rs:222, 259, 441, 564-574`

`Command::Send` maps `args.capsule` onto the wire field `"snapshot_id"`. It works because
`find_snapshot_or_capsule_head` tries the capsule table first and falls back to snapshots
(`lib.rs:564-574`) — but neither README nor API.md describes that dual resolution, and the flag name
contradicts the field name. Separately, docs/API.md uses a bare `id` for three incompatible types:
`pair-confirm id` is a 64-hex **peer id** (`lib.rs:222`), `accept id` is a **snapshot hash**
(`lib.rs:441`), `cancel id` is a 32-hex **outbox entry id** (`lib.rs:259`).

**Fix:** rename to `--snapshot` with `--capsule` as a documented alias; rename the API fields to
`peer_id` / `snapshot_id` / `outbox_id`.

### 23. `capsule-create` and `accept` follow symlinks in the destination path. **[probed]**
**Severity: minor** — `crates/cadabra/src/lib.rs:298, 327-328, 442`; `crates/abra-core/src/cas.rs:418-438`

`materialize` is well hardened at the core: it rejects a symlink destination (`cas.rs:420-423`), a
non-directory destination, and a non-empty destination (`cas.rs:429-434`); tree entry names cannot
contain `/`, `\`, NUL, `.` or `..` (`cas.rs:202-218`); depth is capped at 512 and reconstructed path
length at 4096 (`cas.rs:448-458`). Probed and confirmed:
```
accept --to <non-empty dir>  → "materialization destination must be empty"   exit=1
accept --to <existing file>  → "materialization destination is not a directory"  exit=1
```
**So a hostile inbox manifest cannot escape the destination — that invariant holds through the daemon.**
The residual is the *parent* path: `accept --to /tmp/linkparent/out` where `linkparent` is a symlink
resolves through it and writes to the link target (probed, files landed in `/tmp/real_target/out`);
`capsule_create` uses `path.is_dir()` (follows symlinks) and then `create_dir_all(path/.abra)`.
Both are same-uid, caller-named paths, so the impact is low — but combined with finding 7 it means
any local process can plant a `.abra/capsule_id` or a materialized tree in a directory reached
through a symlink it controls.

**Fix:** `symlink_metadata` the final component in `capsule_create`, and optionally require that
`accept --to` not traverse a symlink (compare `canonicalize(parent)` against the requested parent).

### 24. Outbox persistence rewrites the whole file, including every queued manifest, on each transition.
**Severity: minor (performance/durability)** — `crates/abra-net/src/outbox.rs:88-98, 140-170`

`save()` serializes the entire `Disk` (every entry, each carrying full `manifest_raw` bytes) to a temp
file, `sync_all`s it, renames, then `sync_all`s the parent directory. `send_offer_inner` transitions
five times per successful send (`Healthcheck`, `Offered`, `Transferring`, `AwaitingAck`, plus
`expire`), and `expire()` itself saves unconditionally even when nothing changed (`outbox.rs:232-240`).
With the 100 ms worker tick and a few hundred queued items this is O(total outbox bytes) rewritten
and double-fsynced several times a second.

**Fix:** make `expire` save only when it changed something; batch transitions; consider one file per
entry (as the inbox and capsule stores already do) so a write touches only the affected entry.

### 25. Unused dev-dependencies advertise tests that do not exist.
**Severity: nit** — `crates/cadabra/Cargo.toml` (`assert_cmd`, `predicates`)

`crates/cadabra/tests/e2e.rs` uses neither. They were presumably added for CLI-level tests that were
never written (see finding 26).

---

## End-to-end honesty: what the tests actually cover

**The e2e test does not exercise the daemon.** `crates/cadabra/tests/e2e.rs:38-153`
(`daemons_pair_sync_handoff_and_resume_outbox`) drives everything through `a.handle(json!({...}))` —
the in-process library entry point at `lib.rs:194`. It never opens `cadabra.sock`. So the entire
socket layer is untested by it: `serve_client` framing (`lib.rs:174-191`), the accept loop
(`:102-115`), socket permissions, request parsing, error-response shape. The test is a good exercise
of the *delivery* layer (pairing, full-scope sync, symlink/exec-bit fidelity, partial handoff, inbox
read state, outbox resume across a B restart) — but the report's implication that it validates the
daemon is overstated: it validates `DeliveryNode` plus a thin dispatch function.

**The only test that touches the real binary and the real socket** is
`crates/abra-cli/tests/smoke.rs:18-42` (`real_cli_round_trips_status_over_uds`), and it issues exactly
one op: `status`. It asserts `running == true` and that `root` echoes back.

Concretely untested and plausibly broken (all confirmed broken above except where noted):
- **Cross-process anything.** No test starts two daemon *processes*. This is exactly why finding 1
  survived to the final round: `e2e.rs:30-34` hands both daemons the *same* `LoopbackNetwork` object,
  which is the one configuration the shipped binary can never produce.
- **`serve_client` framing** — oversized lines (finding 8), invalid UTF-8 (finding 8), multiple
  requests on one connection (documented at API.md:5-6, never tested), concurrent connections.
- **Socket lifecycle** — `daemons_pair_sync_handoff_and_resume_outbox` calls `b.start()` twice on the
  same root (`e2e.rs:36, 140`), which does exercise stale-socket removal, but nothing tests
  *concurrent* daemons (finding 3), SIGTERM (finding 17), or socket cleanup on shutdown.
- **`cancel`** — the op has no test at all in `e2e.rs`, `net_spec.rs`, or `smoke.rs`; finding 11 is
  the direct consequence.
- **Lease expiry / renewal** — no test advances the clock past a lease's 24h `expires_at` against a
  daemon-created capsule; finding 4 is the consequence.
- **`enroll-mint`** — the op is never called in any test, and `net_spec.rs:405-413` tests guest
  behavior by calling `set_local_role` directly, bypassing the (missing) bind path; finding 13 is the
  consequence. `net_spec.rs:271-292` tests `authorize_offer`, which the daemon never calls.
- **`accept` into a hostile destination** — `cas.rs:912-951` covers hostile symlink trees and symlink
  destinations at the *core* level (good), but no test drives that through the `accept` control op.
- **`log`, `peers`, `pending-pairs`, `pair-confirm`** — no coverage of the interactive pairing path at
  all; `e2e.rs:33-34` constructs both daemons with `yes = true`, so `auto_confirm_pairs` short-circuits
  the entire `pending_pairs`/`approved_pair_requests` mechanism (`delivery.rs:836`) that docs/API.md:29
  calls "the stable interactive API".

**Highest-value tests to add:** (1) two-process pairing over a real transport; (2) a CLI-level test
that runs the README quickstart verbatim; (3) a `cancel`-vs-worker race test; (4) a `serve_client`
fuzz/limit test; (5) an interactive-pairing test with `yes = false` exercising
`pair add → pending → confirm → pair add`.

---

## Whole-project spot check: do the daemon's wirings preserve earlier-stage invariants?

- **Byte authority on receive — HOLDS.** `receive_partial`/`receive_full` persist `raw.bytes()`
  verbatim (`store.rs:134, 148, 175, 194`), and the daemon always re-parses those stored bytes rather
  than re-serializing a struct: `inbox` uses `RawManifest::parse(entry.manifest.clone())`
  (`lib.rs:433-434`), `accept` uses `RawManifest::parse(entry.manifest)` (`lib.rs:445`), `find_snapshot`
  returns `record.raw.clone()` (`lib.rs:556-561`). `validate_incoming_offer` re-derives the snapshot id
  from the received bytes and rejects a mismatch (`delivery.rs:359-362`). No path reconstructs a
  manifest from parsed fields.
- **Verified-ack outbox clearing — HOLDS.** `apply_ack` requires state `AwaitingAck`, matching
  `offer_id` and `snapshot_id`, then calls `ack.verify(local_peer, e.peer_id)` — an Ed25519 check over
  `offer_id ‖ snapshot_id ‖ sender ‖ receiver` — *before* marking `Acked` (`outbox.rs:207-231`,
  `delivery.rs:139-169`). The daemon reaches this only through `send_offer` (`lib.rs:158-161`), never
  by poking `outbox` state directly. Good. Caveat: finding 11 shows the *inverse* transition (out of
  a terminal state) is not protected.
- **Guest scope enforcement — VACUOUS.** The daemon does call the safe API (`Daemon::send` →
  `node.enqueue` → the `LocalRole::Guest` check at `delivery.rs:220-228`, not `outbox.enqueue`
  directly), and `validate_incoming_offer` enforces guest scopes, expiry and revocation on receive
  (`delivery.rs:372-412`). But per finding 13 no peer can ever become a guest and no node can ever
  become a local guest through the daemon, so nothing exercises it in production. The invariant is
  preserved in code and unreachable in practice.
- **Local-caller authority — VIOLATED in spirit.** Every check above authenticates *peers*. The
  control API authenticates nobody (finding 7), so a same-uid process bypasses the whole model by
  asking the daemon nicely. This is the single largest gap between SPEC's threat model and the
  shipped artifact.

---

## Verdict

**Is it usable for the README quickstart? No — the quickstart fails at its third command** (finding 2,
reproduced), and the two-device demo it describes cannot be performed with the shipped binaries at all
(finding 1, reproduced). What *does* work today is: start a daemon, `status`, `pair ticket`,
`init`/`snapshot`/`log` against an absolute path resolved in the daemon's cwd, and `outbox`/`cancel`
on an outbox that can never drain. The library is in considerably better shape than the product — the
stage-1 and stage-2 invariants I spot-checked (byte authority, verified acks, materialization
hardening, canonical encoding, ticket single-use) all hold, and `cargo test --workspace` is green
(0 failures). Stage 3 is a thin, mostly faithful dispatch layer over that library, and its bugs are
concentrated in the parts the library did not already solve: process lifecycle, the local socket,
concurrency, and transport selection.

**Before this can be called v0.1**, in rough order:
1. Wire a real transport into the binaries and prove it with a two-process test (finding 1).
2. Fix the local API boundary: 0700 store root and socket directory, no bind→chmod window,
   `getpeereid`, line-length limits (findings 5, 6, 7, 8).
3. Daemon singleton lock + SIGTERM + socket cleanup + logging (findings 3, 12, 17).
4. Lease renewal, or capsules brick after 24h (finding 4).
5. Fix the outbox terminal-state resurrection so `cancel` means cancel (finding 11).
6. Stop holding the store mutex across network I/O before a real transport makes it remotely
   reachable pre-auth (finding 10).
7. Make the docs honest: either implement enrollment/revocation or remove `abra enroll` and mark
   §7.2–§7.4, §8, §9, §10 unimplemented in README Status (finding 13).
8. Rewrite the quickstart as a tested script (finding 2).

**Top 3 must-fix:**
1. **Finding 1 — no transport in the shipped binaries.** Nothing else matters until two daemons can
   reach each other; every other feature is currently untestable in the artifact.
2. **Finding 7 (with 5 and 6) — the local control API has no authentication, behind a socket with a
   chmod race, inside a world-readable store root.** For a daemon whose stated purpose is granting
   *agents* scoped access, "any same-uid process gets unscoped device authority, and any user on the
   box can read every teleported byte" is the defect that should block a public v0.1.
3. **Finding 3 — no daemon singleton.** A second `abra daemon` silently hijacks the socket and forks
   the store into two divergent copies with last-writer-wins on `trust.json` and the outbox. It is
   easy to trigger by accident (a stale terminal), it corrupts durable state, and it is a one-line
   local attack to swap in an auto-confirming daemon.

Honorable mention: **finding 4** (capsules brick after 24 hours) would be #3 on user impact alone — it
is a guaranteed, silent, unrecoverable failure on day two of any real use.
