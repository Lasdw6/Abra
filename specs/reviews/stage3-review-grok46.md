# Stage 3 review: cadabra daemon + abra CLI (commit 2354ec9, GPT-5.6 Sol)

Reviewer: Grok 4.6 (security-focused, final review round)
Repo: `/Users/vividh/Desktop/abra` @ `2354ec9`
Authoritative: `SPEC.md` (incl. errata), `DESIGN.md`, `docs/API.md`
Method: read-only review of `crates/cadabra`, `crates/abra-cli`, and the `abra-net` / `abra-core` APIs the daemon actually calls. No repo modifications.

Stage 2 left a real session driver (`send_offer` / `handle_connection`) that now *is* on the live path. Byte-authority parse, `apply_ack` signature checks, and guest-scope helpers exist in `abra-net`. This round asks whether the daemon exposes them safely, or whether the new UDS surface and process wiring undo that work.

---

## Findings

1. **critical** — `crates/cadabra/src/main.rs:25–29`, `crates/abra-cli/src/main.rs:120–124`, `crates/abra-net/src/transport.rs:100–124`
   **Defect:** Both shipped binaries construct a fresh in-process `LoopbackNetwork::default()` and never build `IrohTransport`. `LoopbackNetwork` is an `Arc<Mutex<BTreeMap<…>>>` that is not process-shared. `cadabra` does not enable `abra-net`'s optional `iroh` feature. Pairing dials `ticket.peer_id` on that private map (`cadabra/src/lib.rs:268`), so a second `abra daemon` is always `peer unavailable`.
   **Failure scenario:** Follow the README two-device demo: two terminals, two `--root`s, `pair ticket` / `pair add`, then `send`. `pair add` fails (or hangs until the control call errors) because B is not in A's loopback map. The only working two-node path is `crates/cadabra/tests/e2e.rs`, which shares one `LoopbackNetwork` inside a single process. Teleportation, the product, is not reachable from the binaries a user builds.
   **Fix:** Give the daemon a real `Transport` (iroh behind a flag, or at least a named loopback socket/shm so two processes can join). Persist dial addresses on pair tickets (`pair-ticket` currently passes `addresses: vec![]`). Refuse to claim a two-device CLI demo until `abra daemon` on two roots can complete pair+send.

2. **critical** — `crates/abra-core/src/store.rs:57–67`, `crates/abra-core/src/cas.rs:232–237`, README quickstart `--root /tmp/abra-a`
   **Defect:** Store root, `objects/`, `inbox/`, `outbox/`, and `net/trust.json` are created with the process umask (typically `0755`/`0644`). Only `keys/` is `0700` and `keys/device.json` is `0600` (`identity.rs:179–198`). DESIGN §8 and SPEC §3.3 sync secrets byte-for-byte into CAS. `docs/API.md` puts the control socket in that same root.
   **Failure scenario:** README writes the store under `/tmp`. Any other local user reads `objects/**` (workspace files, `.env`, SSH keys captured from a project), inbox manifests, and pending outbox `manifest_raw`. They cannot connect to `cadabra.sock` after chmod `0600`, but they do not need to — the bytes are on disk. Default `$HOME/.abra` is the same if `$HOME` is world-traversable.
   **Fix:** `chmod 0700` the store root (and every created subdir) at `AbraStore::open`, using a tight umask around `create_dir_all`. Document that `ABRA_ROOT` must not be a shared tmpdir. Add a startup check that refuses to run if the root is group/world-readable.

3. **critical** — `crates/cadabra/src/lib.rs:122–126` with `154–161`, `crates/abra-net/src/delivery.rs:416–427` and `629–636`
   **Defect:** One `tokio::sync::Mutex<DeliveryNode>` is held across the entire async session: incoming `handle_connection` (handshake, transfer, pairing wait) and outgoing `send_offer` (health-check, offer, object streams, ack). The UDS `handle` path needs the same lock. `LoopbackTransport::dial` + `accept` can therefore form a classic lock-order cycle.
   **Failure scenario:** (a) A and B `send` to each other in the same 100ms outbox tick: each holds its node lock inside `send_offer` waiting for the peer’s `handle_connection`, which cannot take the lock → deadlock; outbox never acks. (b) A single inbound capsule transfer blocks `abra status` / `inbox` / `pair confirm` for the whole transfer; a 5s `read_frame` stall (or a hung peer) freezes the local control API. There is no test that sends both directions at once (`e2e.rs` is A→B only).
   **Fix:** Do not hold the store mutex across await. Snapshot/clone the bits needed, perform IO unlocked, re-lock for durable mutations (or use a session lock distinct from the control-API lock). Fail-closed if the peer id of a connection changes. Add a bidirectional-send e2e and a “status during receive” e2e.

4. **major** — `crates/cadabra/src/lib.rs:86–98`
   **Defect:** `start` unlinks `cadabra.sock` unconditionally, binds, *then* `chmod 0600`. No live-socket probe, no pid/lock file, no `SO_PEERCRED`. Between `bind` and `chmod` the inode inherits umask (often world-writable on AF_UNIX). Shutdown (`RunningDaemon::shutdown`, `lib.rs:46–51`) never removes the socket; client tasks spawned at `lib.rs:109` are not joined.
   **Failure scenario:** (a) A second `abra daemon --root $SAME` unlinks the live socket, binds a new one, and steals the CLI. The first daemon keeps accepting on a deleted inode; the user now drives an attacker-controlled node (pair, `enroll-mint`, `accept --to`, `send`). Same-UID is enough. (b) On a shared host, another user connects during the umask window. (c) After a crash, a stale socket is not distinguished from a live one except by unlink-and-hope.
   **Fix:** Try connecting first; if a daemon answers `status`, refuse to start. Otherwise unlink. `fchmod` the listener fd immediately (umask `077` around bind). `flock` a `cadabra.lock` in the root. Unlink the socket on shutdown. Cap/track client tasks.

5. **major** — `crates/cadabra/src/lib.rs:221–225`, `266–285`, `crates/abra-net/src/delivery.rs:832–847`
   **Defect:** Interactive pairing is “decline immediately, remember approval in RAM, tell the joiner to retry the same ticket.” `pair-confirm` only inserts into `approved_pair_requests` (process-local, `delivery.rs:194–198`). On decline, `accept_pair_request` returns `pairing declined` via `?` with **no** `pair-accept`/`error` frame. Joiner `pair_add` then `read_frame`s with **no timeout** (`lib.rs:285`). Tickets are still pending (not consumed until a successful accept), so a retry *can* work — if the issuer process did not restart and the 10-minute ticket is still valid. `docs/API.md` never mentions the retry. README never mentions `pair confirm` / `pending`. `--yes` (README quickstart) skips the whole dance.
   **Failure scenario:** Daemon without `--yes`: `abra pair add $TICKET` fails with a raw IO/timeout-ish error when the issuer closes the bootstrap connection. User runs `pair pending`, `pair confirm <peer_id>` (must scrape JSON for `peer_id`; the CLI does not print short ids as SPEC §7.1 requires). Then retries `pair add`. If they confirmed but the issuer restarted, `approved_pair_requests` is empty and the retry is declined again. If accept succeeded and `pair-confirm` on the wire failed, the ticket is consumed and “retry the same ticket” cannot recover (SPEC’s intended recovery is a *new* ticket). Untested: e2e uses `yes: true` (`e2e.rs:33–34`).
   **Fix:** Keep the bootstrap connection open and wait on a `watch`/oneshot for `pair-confirm` (SPEC: prompt, then accept). Bound the wait (ticket expiry). Persist pending/approved set or document that restart invalidates it. On decline, write `error {code:"untrusted"}` or a dedicated waiting frame. Time out `read_frame` on the joiner. Document the flow in `docs/API.md` and README; change the instruction to “retry with a fresh ticket” after consume. Test `yes: false` end-to-end over UDS.

6. **major** — `crates/abra-net/src/delivery.rs:670–693`, `706–773`
   **Defect:** Offer accept is gated on sender-claimed `bytes_hint <= MAX_OBJECT_SIZE` (256 MiB). `object_count` is not bounded by that hint. After accept, every plan object not already in CAS is `accept_uni` + `commit_partial` into CAS. Only *after* that does the receiver require the verified manifest closure to be present (`775–778`). Extra digests stay in CAS. This was a stage-2 hole; the daemon’s listener now makes it live.
   **Failure scenario:** A paired full peer (or a guest, if bind is ever wired, with `send:true`) offers `bytes_hint: 1`, `object_count: 1000`, then a plan of 1000 × 256 MiB blobs. Disk fills. Ack is withheld if the real closure is incomplete, but the junk is already `cas.put`. Guest `have` is cleared (`717–724`) so this is not a CAS oracle, just a quota bypass. SPEC §6.4 `offer-reject: quota` is the intended control and is not computed from received bytes.
   **Fix:** Reject when `sum(plan.objects.bytes)` exceeds a real quota (and `bytes_hint` must match that sum). Drop objects not in `closure(verified_manifest)` *before* `cas.put`. Enforce `MAX_OBJECT_STREAMS`. Persist used-bytes per peer.

7. **major** — `crates/abra-net/src/delivery.rs:468`, `632–636`, `492–502`, `crates/abra-net/src/outbox.rs:219–224`
   **Defect:** SPEC §6.7 / §6.10: only a verified ack clears the duty; outstanding acks must flush on reconnect. `apply_ack` correctly verifies the Ed25519 `ack` domain against the outbox target (`outbox.rs:225`) — that stage-2 critical is fixed on the happy path. But `send_offer_inner` transitions to `Healthcheck` *before* handshake (`delivery.rs:468`). Reconnect flush sends pending acks immediately after `hello-ok` (`632–636`). The ping loop will `apply_ack` those frames while state is `Healthcheck`, so `apply_ack` returns `Ok(false)` and the outbox stays pending. Pending-ack files are never deleted after success (`persist_pending_ack` has no matching unlink).
   **Failure scenario:** Receiver committed and acked; sender crashed in `AwaitingAck` before `apply_ack`. On retry the receiver re-sends the pending ack during health-check; sender ignores it, re-offers, and may duplicate-receive. Not a forged-ack bypass (verify still runs when state matches), but the reconnect protocol the e2e claims to cover (`e2e.rs:119–154` waits for `acked` after B restarts — that path likely *re-transfers*, it does not prove pending-ack flush). A later handler that treats `Ok(false)` as success would be dangerous; today it is silent retry.
   **Fix:** Apply reconnect acks while still `Queued`/`AwaitingAck`, or accept `Healthcheck` as a legal `apply_ack` predecessor when ids match. Delete pending-ack files once the sender has seen them (or after TTL). Test crash-after-commit with the object already in receiver CAS (zero extra unis) and assert a single verified `apply_ack`.

8. **major** — `crates/abra-net/src/delivery.rs:659–861` (`enroll-bind` absent), `crates/cadabra/src/lib.rs:473–523`
   **Defect:** `enroll-bind` / `enroll-ok` are bootstrap-legal (`auth.rs:1082–1092`) but the session demux never calls `bind_enrollment` / `set_local_role`. `_` answers `unknown_type` and continues. The control API can `enroll-mint` tokens (default `send:false`, `receive:false`, capsules/kinds `*` if omitted — CLI requires flags, API.md does not). There is no guest start, no `--token`, `allow_agent_send` stays `false` (`delivery.rs:209`). SPEC §7.2 / §7.4 guest scope is implemented in `validate_incoming_offer` / `enqueue` and then unreachable from the daemon.
   **Failure scenario:** Integrator injects `abra-enroll/1/…` as the spec describes; the guest daemon has no way to present it. Host `abra enroll --send …` prints a token that nothing redeems. Conversely, if a future one-liner sets `LocalRole::Guest` without going through bind, `enqueue`’s guest gate would apply — but today a Full daemon will happily `send` anything, including to a peer id that is not yet trusted (`enqueue` does not check `trust.get(&peer)`). Outbox then fails at handshake (`session != "trusted"`), leaving durable queued entries.
   **Fix:** Handle `enroll-bind` on bootstrap: verify, `bind_enrollment`, `enroll-ok`, persist guest. Add `cadabra --token` to set `LocalRole::Guest` from the minted token. Default API mint must not emit `capsules:["*"]`/`kinds:["*"]` silently. Reject `send` to unknown peers at enqueue. E2E: mint → bind → scoped send denied / allowed.

9. **major** — `crates/cadabra/src/lib.rs:174–190`, `crates/abra-cli/src/main.rs:136–142`
   **Defect:** UDS framing is `BufReader::lines()` with no max line length, no request timeout, and no cap on concurrent `tokio::spawn` clients (`lib.rs:107–109`). `accept --to` and `capsule-create` / `snapshot` / `send.path` use the path string as seen by the **daemon process**, not the CLI; the CLI does not `canonicalize` (`abra-cli/src/main.rs:136–142`). `materialize` itself rejects `..` names, symlink destinations, and non-empty dests (`cas.rs:418–438`, `912–936`) — a hostile *inbox tree* cannot escape `to`. A hostile *control client* can still point `to` anywhere the daemon uid can write.
   **Failure scenario:** (a) Same-UID malware connects to `cadabra.sock` (mode 0600 = “any process of this user”) and `accept`s into `~/.config/…` or `enroll-mint`s a `*` token / `pair-add`s an attacker device. That is the actual TCB: the socket is equivalent to the device key, and nothing says so. (b) CLI `abra accept id --to ./out` from a different cwd than the daemon writes relative to the daemon cwd, or fails confusingly. (c) A client sends a multi-GB line without `\n` and grows the daemon RSS until OOM; listener `Err(_) => break` (`lib.rs:111`) then kills the control surface on `EMFILE`. (d) Invalid UTF-8 drops that connection (`next_line?`) — fine — but there is no equivalent bound for valid UTF-8.
   **Fix:** Canonicalize paths in the CLI (and/or require absolute paths in the API). Document the socket as full device authority; consider a cookie/token in the root created `0600` at first start. Cap NDJSON lines (API.md should state the cap; 1 MiB would match the adapter spec). Timeout idle UDS reads. Bound client tasks. Do not tear down the listener on one `accept` error. `materialize` is already the right primitive for tree escape — keep using it; do not reimplement writes in the daemon.

10. **major** — `crates/cadabra/src/lib.rs:297–300`, `README.md:50–73`
    **Defect:** `capsule-create` requires an existing directory and does not create it. README quickstart runs `init ./my-workspace` with no `mkdir`. `docs/API.md` says `capsule-create` / `path` with no existence rule. Human `pair ticket` prints a JSON object, not the raw `abra-pair/1/…` string `pair add` wants.
    **Failure scenario:** Fresh user: daemon starts (`--yes`), `status` works, `init ./my-workspace` returns `capsule path must be a directory`, snapshot never happens. The single-node quickstart is already broken before any teleport. Copy-pasting the pretty-printed ticket JSON into `pair add` fails parse.
    **Fix:** `init` creates the directory (or README `mkdir -p`). Print `result.ticket` as a bare line in human mode. Make `--json` the stable machine contract (it already dumps `result` only — good) and snapshot a golden fixture for `status` / `inbox` / `outbox` field names.

11. **minor** — `crates/cadabra/src/lib.rs:111`, `118–128`, `156–161`
    **Defect:** UDS `accept` error stops the control loop forever with no log. Transport `accept` `Err` is ignored and, if the loopback channel is closed, becomes a hot loop (`accept` returns immediately). `work_outbox` swallows `send_offer` errors (`let _ =`); `fail_attempt` inside `send_offer` usually records them, but a panic/cancel in the spawned incoming task (`lib.rs:124–126`, `let _ =`) is silent. `now_ms()` is sampled once per connection (`lib.rs:125`) and reused for every later offer/expiry check on that socket.
    **Failure scenario:** FD exhaustion disables the CLI until process restart while the outbox worker still runs. After shutdown races, the accept task can spin a core. A long-lived connection (if clients ever reuse p2p sessions) would not notice token expiry. Pending pair/enroll RAM state is lost on restart (documented in a comment, not in API.md).
    **Fix:** Log and continue on transient `accept` errors; back off on persistent transport errors. Use fresh `now_ms()` per frame. Surface outbox `last_error` in `status`. Persist pairing wait state or document restart semantics next to `pending-pairs`.

12. **minor** — `crates/cadabra/tests/e2e.rs:38–70`, `crates/abra-cli/tests/smoke.rs:18–42`
    **Defect:** The “e2e” drives `Daemon::handle` in-process (bypassing NDJSON, umask, relative paths, exit codes, `--json`). `start()` *does* run the listener, outbox worker, and `handle_connection`, so pair/send/inbox/resume are not pure library shortcuts — but they never go through `cadabra.sock` except `status` in the CLI smoke test. No test covers: `yes: false` pair retry; `enroll-mint`/bind; `cancel`; `accept --to` outside the tempdir / symlink dest; UDS oversized line; two OS processes; iroh; `send` of `path`/`link` via CLI; unknown-op / malformed UTF-8; simultaneous send.
    **Failure scenario:** A daemon that breaks UDS framing, path canonicalization, or interactive pair still ships green. The resume test (`e2e.rs:119–154`) can pass by re-transferring after B’s restart without ever exercising pending-ack flush (finding 7).
    **Fix:** One test that starts two `abra` binaries with a shared transport (once finding 1 exists), speaks only the CLI, and asserts pair-confirm, send, inbox, accept, outbox `acked`. Add named tests: `pair_confirm_retry_without_yes`, `uds_rejects_oversize_line`, `accept_refuses_symlink_destination`, `enroll_bind_enforces_scopes`, `bidirectional_send_does_not_deadlock`.

13. **nit** — `crates/cadabra/src/lib.rs:395–426`, `crates/abra-cli/src/main.rs:66–78`, `docs/API.md:21`
    **Defect:** CLI `--capsule` is stuffed into API `snapshot_id`, and `find_snapshot_or_capsule_head` also accepts a capsule id (HEAD `main`). API.md lists `snapshot_id` | `path` | `link` only. `log` without `--capsule` auto-picks when exactly one capsule exists (`lib.rs:461–466`) — undocumented. `print_human` pretty-prints arrays item-by-item (`abra-cli/src/main.rs:160–169`), so `--json` vs human shapes differ. Exit codes are 0 / 1 only (acceptable). `ABRA_ROOT` is wired on both binaries (`env = "ABRA_ROOT"`) — matches the task’s question; good.
    **Failure scenario:** Scripts using `--json` on `inbox` get one JSON array; without `--json` they get N pretty objects and cannot parse. Users pass a capsule id to `--capsule` and silently send HEAD, not the snapshot they copied from `log`.
    **Fix:** Freeze `--json` as “exactly the `result` object from API.md”. Document HEAD resolution or require snapshot ids. Give `log` the same required-capsule rule in the CLI help.

14. **nit** — `crates/abra-net/src/delivery.rs:779–791` with `crates/abra-core/src/capsule.rs:219–230`
    **Defect:** First full offer installs `offer.genesis` + `offer.genesis_grant` via `Capsule::new`, which *does* `genesis.verify()` and `grant.verify_with(creator)`. That matches the stage-2 erratum (SPEC.md:829–830). `authorize` is `|_, _| true` at construction; epoch-1 grant still requires `holder == created_by`. Fine for Full peers. A guest that someday sends a first full snapshot of an allowed capsule can install genesis — intended. No daemon bypass of `RawManifest::parse`.
    **Failure scenario:** None beyond guest/quota issues already listed. Noted so the whole-project check is explicit rather than assumed.
    **Fix:** None required for genesis verify; pass a real authorizer if guest `lease_takeover` is ever exposed.

---

## SPEC-critical invariants through the daemon

**Byte authority (SPEC §2 / §6.4).** The daemon does not re-serialize a parsed DOM for identity. Local `send` builds a `Manifest`, signs, then `RawManifest::parse(canonical bytes)` (`lib.rs:408–426`). `send_offer` puts `raw.bytes()` in `manifest_raw` (`delivery.rs:553`). `validate_incoming_offer` base64url-decodes, `RawManifest::parse`s (hash of stored bytes, strict sig), and checks `raw.snapshot_id() == offer.snapshot_id` (`delivery.rs:350–363`). `commit_manifest` → `receive_partial` / `receive_full` persists those bytes (`store.rs:126–206`). Floor cards for `inbox` are parsed from stored bytes (`lib.rs:432–435`). This is the safe API. **Preserved** on the live path.

**Verified-ack outbox clearing (SPEC §6.7 / §6.10).** `mark_acked` is gone. `Outbox::apply_ack` checks `offer_id`/`snapshot_id`/`AwaitingAck` and `Ack::verify` against the intended recipient (`outbox.rs:207–230`). Happy-path `send_offer` only clears after that (`delivery.rs:621–625`). **Preserved**, with the reconnect-flush hole in finding 7 (duty not *cleared* by a fake ack; it may fail to clear a *real* one).

**Guest scope (SPEC §7.4).** `enqueue` and `validate_incoming_offer` implement local-role + `send`/`receive` + guest-to-guest denial + kind/capsule lists (`delivery.rs:220–225`, `372–412`). The daemon never sets `LocalRole::Guest`, never handles `enroll-bind`, and `enroll-mint` is a token printer. **The checks are not bypassed; they are unwired.** A Full control-API client can still enqueue to anyone and mint `*` tokens.

**Materialize escape (SPEC §3.3).** `accept` calls `materialize` (`lib.rs:447`). Hostile trees with `..` names are rejected at `Tree::new`; symlink-escape is tested in `abra-core`. Destination emptiness / non-symlink is enforced. **Preserved** for inbox-driven writes. Control-API `to` remains caller-chosen (finding 9).

---

## CLI / docs contract (task item 3)

| Claim | Reality |
|---|---|
| `docs/API.md` ops / `{ok,result}` / `{ok,error}` | Match `handle` + `control_call`. |
| Socket `<root>/cadabra.sock` mode `0600` | After bind, yes; not at creation (finding 4). |
| `--json` stable | Dumps `result` only; field set is whatever serde emits for internal structs (`OutboxEntry` includes full `manifest_raw`). No fixture. |
| Exit code on failure | `main() -> Result` → tokio exits 1. No structured codes. |
| `ABRA_ROOT` | Implemented on `abra` and `cadabra`. |
| Pair retry | Implemented as in-memory approve + retry same ticket; not documented; broken across restart; untested without `--yes`. |
| README quickstart | `daemon --yes` + `status` work (smoke). `init ./my-workspace` fails if the dir does not exist. Two-device paragraph is the e2e test, not the CLI. |

---

## Overall verdict

**Not usable as the README teleportation product, and not ready to call v0.1.**

The single-process loopback e2e (`daemons_pair_sync_handoff_and_resume_outbox`) shows that *if* two `Daemon`s share a `LoopbackNetwork`, pair → full snapshot → accept (exec bits + symlink) → partial handoff inbox card → outbox retry after receiver restart can work. Stage 2’s session driver is actually invoked. Byte authority and verified `apply_ack` are on that path. `materialize` is the right accept primitive.

What a user can run after `cargo build --workspace` is a same-UID UDS frontend over an isolated loopback mesh that cannot see any other process, with a store that defaults to world-readable CAS (and the README puts it in `/tmp`), a mutex that can deadlock two senders and freezes the CLI during transfer, pairing that only works smoothly with `--yes`, and an enroll command that cannot enroll. Adapters (`docs/ADAPTERS.md`) are documentation only.

**Usable for the README quickstart?** Only the fragment “start daemon, `status`” is honest, and that is what `smoke.rs` tests. `init` / two-device send / accept as written will not succeed.

### Top-3 must-fix before v0.1

1. **A transport two OS processes can share**, wired into `abra daemon` / `cadabra` (finding 1). Without this there is no product, only a unit-test harness with a CLI.
2. **Store + socket lockdown**: `0700` root, no umask window, no unlink-hijack of a live daemon (findings 2, 4). The README `/tmp` root currently publishes every captured secret to other local users.
3. **Do not hold `DeliveryNode` across await** (finding 3), then land the interactive pair flow (finding 5) and real quota / enroll-bind (findings 6, 8) so the live listener cannot be used to fill disks or mint inert-looking tokens that later become a confused-deputy guest.

Until (1)–(3) land, keep the status line at “library + in-process demo,” not v0.1.
