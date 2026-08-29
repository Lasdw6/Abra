# Stage-2 review: `crates/abra-net` @ d29a621

Reviewer: Claude Opus 5, security-focused protocol review against `SPEC.md` v0.1 (§§6–8 primarily).
Method: full read of all 7 source files (2,219 LOC) + `tests/net_spec.rs`, cross-referenced against
`abra-core` semantics; `cargo test -p abra-net` (9 tests, all pass); two out-of-tree probe binaries to
confirm exploitability. The repository was not modified.

**Headline.** The crate implements the *message types* and a *local* state machine for §6, but the
delivery protocol never runs over the `Transport`. `DeliveryNode::deliver_limited` takes
`receiver: &mut Self` and calls the peer's private methods directly, in-process. As a result the
Transport trait, the framing layer, the handshake, the object-stream format, and the bootstrap
allowlist are an unwired parallel structure with zero execution coverage, and the receiver-side
verification that the SPEC's security rests on does not exist. Several enforcement points that *do*
exist are dead code because they key on a trust-store entry nothing ever creates.

Severity key: **critical** = exploitable or breaks a SPEC MUST that gates security/correctness;
**major** = SPEC violation, DoS, or defect that will bite stage 3; **minor**/**nit** = hardening.

---

## Critical

### 1. The §6 delivery protocol is never spoken over a transport; the wire types are dead code
**critical** — `crates/abra-net/src/delivery.rs:218-345`, esp. `:270`

`deliver_limited(&mut self, id, receiver: &mut Self, ...)` mutates both peers directly. The `Offer` is
constructed at `:270` into a binding named `_offer` and immediately dropped. Nothing is ever
serialized, framed, or sent. Grepping the whole workspace for use sites:

| Item | Defined | Used |
|---|---|---|
| `Offer` | delivery.rs:24 | built at :270, discarded |
| `OfferAccept`/`OfferReject` | delivery.rs:43,50 | never constructed |
| `Plan`/`Resume`/`TransferError` | delivery.rs:65,88,97 | never constructed |
| `ControlAck` | control.rs:27 | never constructed |
| `ObjectHeader`/`ObjectKind` (§6.1 binary object stream) | framing.rs:47 | never encoded or decoded |
| `open_uni`/`accept_uni` | transport.rs:39,62 | never called |
| `MAX_OBJECT_STREAMS = 8` | delivery.rs:20 | never read |
| `dial_handshake`/`accept_handshake`/`health_check` | auth.rs:920,956,985 | never called, incl. by tests |
| `bootstrap_allowed` | auth.rs:907 | only in a test asserting its own truth table |
| `confirm_pair` | auth.rs:252 | never called anywhere |
| `fail_attempt` | outbox.rs:133 | never called anywhere |
| `LoopbackTransport` / `Transport` | transport.rs:99 | **never used by any test or by delivery** |

Note that `loopback_teleport_preserves_files_exec_and_symlink` does not use `LoopbackTransport` — the
name refers to two `DeliveryNode`s in one process. The transport layer has literally zero coverage.

*Failure scenario:* stage 3 cannot build a daemon on this API at all. `deliver(&mut self, &mut Self)`
requires both peers to be `&mut` in one address space; there is no function that takes a `Connection`
and drives a delivery. The daemon author must write §6 from scratch, at which point every finding
below about missing receiver-side checks becomes a live vulnerability rather than latent.

*Fix:* invert the API. `async fn send_offer(&mut self, entry_id: &str, conn: &mut Connection, now)`
and `async fn handle_connection(&mut self, conn: &mut Connection, now)` with a real frame dispatch
loop (read `Value`, match `type`, enforce `bootstrap_allowed` per session, reply
`error {code:"unknown_type"}` and keep the connection alive per §6.1). Keep the in-process path only
as a test double built *on top of* a real `Connection` pair.

### 2. The receiver never verifies manifest bytes; the stage-1 byte-authority P0 does not survive the hop
**critical** — `crates/abra-net/src/delivery.rs:239, 281, 323`; SPEC §2 "Byte authority", §6.4

The sender does `RawManifest::parse(entry.manifest_raw)` at `:239` (which is the crate's only
verification: canonical form, schema, `canonical::to_vec(&m) == bytes`, strict Ed25519 over `U`, and
`snapshot_id = BLAKE3("abra-snap-v1"||0||U)`). It then base64s `raw.bytes()` into the discarded offer
at `:281` — and hands the **already-parsed `RawManifest` object** to `receiver.commit_manifest(...)`
at `:323`. There is no call to `RawManifest::parse` on the receiving side anywhere in the crate.

Two distinct defects:

(a) **No receiver-side verification path exists.** SPEC §6.4 requires the receiver to decode
`manifest_raw`, recompute `U`, verify the id, and verify the in-manifest signature strictly. When
stage 3 wires the wire, there is no function to call and no test that would catch its absence. The
P0 property is currently vacuous, not preserved.

(b) **The manifest signer is never checked against the trust store.** SPEC §6.4: "check the signer is
trusted and (for guests) in scope both directions". `authorize_offer` at `:241-262` is passed
`self.peer_id()` — the *connected transport peer* — never `manifest.origin.peer_id`.
`RawManifest::parse` only proves the signature is valid *for whatever key the manifest names*.

*Failure scenario for (b), live today:* paired peer B sends A a snapshot whose `origin.peer_id` is an
attacker key that A has never paired with. The signature verifies (it is the attacker's own key), the
transport peer B is trusted, so A commits it to the capsule store / inbox and renders it as authored
by the attacker. Combined with the fact that scope checks read `manifest.kind` and
`manifest.capsule_id` from that same unowned manifest, a guest can attribute content to a fabricated
identity. Worse under a relay (§8), where the forwarding peer is by design not the author.

*Fix:* in the receive path, decode `manifest_raw` → `RawManifest::parse(bytes)` → assert
`raw.snapshot_id() == offer.snapshot_id` → assert `raw.manifest().kind == offer.kind` etc. (offer
metadata must never be believed over the bytes) → look up `raw.manifest().origin.peer_id` in the
trust store and reject if absent → *then* scope-check. Store `raw.bytes()` verbatim (core's
`receive_partial`/`receive_full` already do). Add a test that mutates one byte of `manifest_raw` in
flight and asserts rejection, and a test that a manifest signed by an unpaired key is rejected.

### 3. Remote panic via non-ASCII timestamps (unauthenticated DoS)
**critical** — `crates/abra-net/src/auth.rs:32-41` and `crates/abra-net/src/control.rs:99`

Both time parsers check `s.len() != 24` (a **byte** length) and then slice by byte index:
`&s[4..5]`, `s[a..b].parse()`. Rust panics on a byte index that is not a UTF-8 char boundary. A
24-byte string containing a multi-byte character straddling one of the split points panics before any
validation runs. `control.rs:92-119` is worse: it has no format validation at all, only the length
check.

Confirmed by probe:

```
thread 'main' panicked at crates/abra-net/src/auth.rs:32:14:
start byte index 4 is not a char boundary; it is inside 'é' (bytes 3..5 of string)

thread 'main' panicked at crates/abra-net/src/control.rs:99:10:
end byte index 4 is not a char boundary; it is inside 'é' (bytes 3..5 of string)
```

The hostile value `"202\u{e9}-01-01T00:00:00.00Z"` is exactly 24 bytes and survives
`canonical::to_vec` unchanged (the canonicalizer emits non-ASCII as raw UTF-8, §2 rule 4), so it
round-trips the `canonical::to_vec(&x)? != b` check in `EnrollmentToken::parse`.

*Failure scenario (pre-trust, the serious one):* `TrustStore::bind_enrollment` (auth.rs:309) calls
`bind.verify(now)` → `EnrollmentToken::verify` → `parse_time(&self.expires_at)`. The signature is
checked first, but against `token.issuer` — a field the attacker chooses, signing with their own key.
So **any peer that can open a bootstrap session** (i.e. anyone, `enroll-bind` is in the bootstrap
allowlist) sends a self-signed token with a malformed `expires_at` and panics the listener task. Same
reachability through `PairTicket::parse` for anything that ingests a scanned/pasted ticket. Post-trust,
`ControlMessage::verify_and_record` gives any paired peer the same primitive via `at`.
With `panic = "abort"` this is process death; otherwise it kills the connection task and — because
`TrustStore` holds `&mut` state and `std::sync::Mutex` is used in `transport.rs:96` — risks poisoned
locks and `expect("loopback lock")` cascades.

*Fix:* one hardened parser. Reject any non-ASCII byte up front (`s.as_bytes()`, validate each
position against the `YYYY-MM-DDTHH:MM:SS.sssZ` grammar digit-by-digit, no `str::parse` which also
silently accepts `+`/`-` signs), validate the calendar date, and delete `parse_control_time` in favour
of it. Add a `#[test]` table of hostile time strings including multi-byte, signed, and out-of-range
fields. Consider `#![deny(clippy::string_slice)]` for the crate.

### 4. Full-scope delivery is structurally broken and completely untested
**critical** — `crates/abra-net/src/delivery.rs:459-466`; `abra-core/src/store.rs:184-188`;
`abra-core/src/capsule.rs:384-392`; SPEC §5.5

`commit_manifest` calls `self.store.receive_full(raw, at, now, None)` — `fork_signer: None`. Core
computes `forked = !active_lease(now).is_some_and(|l| l.holder == writer)` and, when `forked`, does
`fork_signer.ok_or_else(|| Error::invalid("forked write requires the writer identity..."))?`.

So a full snapshot commits **only** when the receiver's locally-known winning lease is active *and*
held by the exact peer that authored the manifest. Every other case errors:

- any snapshot authored by a peer that is not the current lease holder (SPEC §5.5: fork-on-write is
  "stored, valid, ... never an error");
- **any** full snapshot arriving after the receiver's cached lease has expired (default TTL 24h),
  including from the legitimate holder;
- any receiver that has not yet seen the lease chain.

The failure lands at `delivery.rs:323`, i.e. *after* the receiver has already installed the entire
object closure into CAS, and with the sender's outbox parked in `AwaitingAck` (see finding 8).

The structural problem underneath: the fork label-op must be signed by the writer, and the receiver
does not hold the writer's key — so a receiver **cannot** create it. `fork_signer` is the wrong shape
for the receive path.

Additionally `commit_manifest:461-463` hard-errors when the capsule genesis is unknown, while the
offer carries `genesis` (`delivery.rs:282-284`) that is never verified nor applied — SPEC §6.4's
"first send of a capsule to this peer" path cannot succeed. `add_capsule_from_peer` (`:471`) is a
manual helper with no signature or lease validation.

*This is entirely invisible to the test suite: all four delivery tests use `Scope::Partial`.*

*Fix:* give core a receive-side entry point that records the fork without minting a label-op
(e.g. return `WriteResult { forked: true, .. }` and let the daemon create the `fork/*` op later, or
allow the *receiver* to sign a locally-scoped pointer). Verify and install `offer.genesis` (signature
+ `capsule_id` match) before `receive_full`. Add tests: full delivery from a lease holder, from a
non-holder (must store as fork, not error), with an expired lease, and with an unknown capsule.

### 5. The `abra.allow_agent_send` gate is dead code
**critical** — `crates/abra-net/src/delivery.rs:206-214`; SPEC §7.4 "Send authority"

```rust
if self.trust.get(&self.peer_id()).is_some_and(|p| p.role == crate::Role::Guest) {
    ... if !self.allow_agent_send || !scopes.is_some_and(|s| s.send) { return Err(...) }
}
```

The gate fires only if the node finds **itself** in its own trust store as a guest. Nothing in the
crate ever inserts the local peer: `peers.insert` appears at auth.rs:191 (`insert`, called by tests
for remote peers), :258 (`confirm_pair`), :270 (`complete_pair_as_joiner`), :346 (`bind_enrollment`) —
all remote. There is no local-token storage of any kind, so a guest daemon has no way to know it is a
guest. `allow_agent_send` (default `false`) is therefore never consulted, and every guest can send.

*Failure scenario:* infra ships a guest binary with `send:true` in the token but deliberately leaves
`abra.allow_agent_send` off. The agent sends anyway. SPEC's "infra owns the switch; no token can
widen it" is unenforced.

*Fix:* store the node's own role explicitly (`DeliveryNode { local_role: Role, local_scopes: Option<Scopes> }`,
persisted from the enrollment token at bind time) rather than inferring it from the peer table. Make
the check unconditional for `Role::Guest` and add a test that a guest with `send:true` and
`allow_agent_send:false` is refused.

---

## Major

### 6. Guest-to-guest denial is unenforced at the receiving guest
**major** — `crates/abra-net/src/auth.rs:373`; SPEC §7.4

```rust
let other_role = self.get(&other).map(|p| &p.role).unwrap_or(&Role::Full);
```

Unknown peer ⇒ assumed **Full**. Since a node is never in its own trust store (finding 5), a guest
evaluating an inbound offer from another guest computes `other_role = Full` and the
`guest-to-guest forbidden` branch never fires. Probe result:

```
(b) guest->guest offer at receiving guest: Ok("ALLOWED")
```

`delivery.rs:241-262` mirrors this: the receiver checks the sender's `send` bit, and the *sender*
checks the receiver's `receive` bit only if the sender happens to know the receiver as a guest. Two
guests enrolled by the same user do not have each other in their trust stores, so neither side
enforces anything. Note also the receiver never checks its own `receive` bit at all.

*Fix:* default unknown peers to *deny*, not `Full` (`self.get(&other).ok_or(authz("unknown counterparty"))?`),
and check the local role from explicit local state per finding 5. The existing test
`scope_expiry_revocation_and_guest_to_guest_are_enforced` does not actually test guest-to-guest —
`other` is never inserted as a guest, so the assertion passes for the wrong reason (capsule scope).

### 7. `have` discloses possession of out-of-scope objects to guests
**major** — `crates/abra-net/src/delivery.rs:346-363`; SPEC §7.4 (explicit MUST NOT)

`compute_have` iterates the offered closure and reports `has()` for every digest with no reference to
the requester's identity or scopes.

*Failure scenario:* a guest scoped to capsule X offers a snapshot whose closure it populates with
digests it guesses/harvests from capsule Y (blob ids are plain BLAKE3 of content, so a guest that can
guess plaintext — a config file, a known dependency, a short secret — can confirm the victim holds
it). The `have` response is an oracle. This is the classic CAS-existence side channel and SPEC calls
it out by name.

*Fix:* pass the requesting peer into `compute_have`; for guests, answer `have` only for digests
reachable from the closures of snapshots inside `scopes.capsules` (maintain a per-capsule reachability
index), and report `false` otherwise — accepting the redundant re-transfer as the price.

### 8. Failure paths corrupt the outbox state machine; backoff/attempt limits are unreachable
**major** — `crates/abra-net/src/delivery.rs:218-345`, `crates/abra-net/src/outbox.rs:123-151`; SPEC §6.10

Every fallible step in `deliver_limited` uses `?` and returns without touching the entry. So a failure
after `transition(Offered)` leaves `state = offered`, `attempts = 0`, `last_error = None`,
`next_attempt_at` unchanged. `fail_attempt` — which owns the entire `attempts += 1`, 1s→5min ±20%
backoff, and `>= 20 → failed` logic — is never called from anywhere in the crate.

*Failure scenario:* a peer that reliably rejects (e.g. finding 4's fork error) yields an entry that
`pending_ids()` returns forever, with `next_attempt_at` permanently in the past. A scheduler built on
this API hot-loops on the failing delivery: no backoff, no attempt ceiling, no `failed` terminal
state, and `last_error` is never populated for the user. SPEC's "max 20 attempts → failed" and
"1s doubling to 5min" are both unreachable.

Compounding: `Outbox::transition` (`:123`) accepts **any** state from **any** state with no legality
check — including `Acked → Queued` and `Expired → Transferring`. `mark_acked` (`:168`) likewise does
not require the current state to be `AwaitingAck`, so it can resurrect a `Cancelled`/`Failed` entry
into `Acked`.

*Fix:* wrap the body in a closure and call `fail_attempt(id, e.to_string(), now)` on `Err`. Encode the
§6.10 transition table as a `fn allowed(from, to) -> bool` and reject illegal edges in `transition`;
require `AwaitingAck` in `mark_acked`. Test: force each failure point and assert `attempts` increments,
`next_attempt_at` moves, and 20 failures reach `failed`.

### 9. Unbounded memory on the object path (hostile peer and legitimate multi-GB blobs)
**major** — `crates/abra-net/src/transport.rs:39,62,77`; `delivery.rs:264-269,294,400`

- `Connection::open_uni(bytes: Vec<u8>)` / `accept_uni() -> Vec<u8>`: whole object in RAM by
  signature. The iroh arm does `stream.read_to_end(usize::MAX)` (`transport.rs:77`) — **a hostile peer
  streams until the receiver OOMs**, with no digest, no size check, no cap.
- `commit_partial` (`delivery.rs:400`) `fs::read`s the whole partial, then `cas.put` writes it again:
  every received object is fully buffered and written twice.
- `bytes_hint` (`delivery.rs:264-269`) calls `cas.get()` on **every object in the closure** purely to
  sum lengths — reading and (per core, `cas.rs:317`) re-hashing the entire snapshot into memory.
- `MAX_OBJECT_STREAMS = 8` is never enforced; loopback `accept_uni` holds an `AsyncMutex` across
  `recv().await`, so concurrent streams are impossible anyway.

SPEC §3.1 chose plain BLAKE3 specifically so multi-GB native blobs "can be verified as they stream
rather than after they land". This design cannot do that.

*Fix:* stream. `open_uni`/`accept_uni` should hand back the `AsyncWrite`/`AsyncRead` plus the parsed
`ObjectHeader`, cap `total_size` against the plan-declared `bytes`, and hash incrementally
(`blake3::Hasher::update`) into the partial file. Get object length from `fs::metadata` /
`cas.size(h)` rather than `cas.get`, and add a `BlobStore::size`/`has_cheap` to core.

### 10. `cas.has()` is O(size) and is called O(n²) times per delivery
**major** — `crates/abra-net/src/delivery.rs:318, 350`; `abra-core/src/cas.rs:258-267`

Core's `has()` is not a stat — it calls `get()`, which reads and re-hashes the whole blob, and
**deletes the file** if it fails to verify. `compute_have` calls it once per closure object; then
`deliver_limited:318` calls `closure.iter().any(|h| !receiver.store.cas.has(h))` **inside the
transfer loop**, i.e. after every single object.

*Failure scenario:* a 5,000-object snapshot re-hashes up to 25,000,000 blob-reads worth of I/O for one
delivery. Not a security bug, but it makes the delivery path unusable at real snapshot sizes and will
be mistaken for a hang.

*Fix:* hoist the completeness check out of the loop (track a counter of remaining objects), and add a
metadata-only existence check to core.

### 11. Partial-transfer storage is unbounded, unquota'd, and never reclaimed
**major** — `crates/abra-net/src/delivery.rs:364-366, 374-398, 410-417`

Partials live at `net/partials/<offer_id>/<digest>` and are removed only by `clear_partials` on a
*successful* delivery. Nothing prunes abandoned offers, and there is no cap on the number of concurrent
offers, on bytes per offer, or on total partial bytes.

Also, `append_partial` writes first and checks the size bound afterwards
(`f.write_all(bytes)` at `:392`, then `if f.metadata()?.len() > total` at `:394`), leaving the
over-length file on disk; and `total` is entirely peer-supplied — it is never cross-checked against
the `bytes` the sender declared in its `plan`.

*Failure scenario:* a paired-but-hostile peer (or a scoped guest) opens N offers, streams a few bytes
of each of many fabricated digests with `total = u64::MAX`, and abandons them. The victim's disk fills
with data that no code path will ever delete, and SPEC §4's GC ("unreferenced CAS objects MAY be
collected after 7 days") does not cover `net/partials` at all.

Related: on resume with a *new* `offer_id` (the SPEC §6.9 sender-lost-state case) the old partial
directory is orphaned permanently, and the resume benefit is lost because `compute_have` looks under
the new offer id only.

*Fix:* key partials by digest with an offer→digest index, or at minimum reap directories older than
the outbox TTL on startup and on each delivery. Enforce `total == plan_bytes[digest]` and reject the
write if `offset + len > total` **before** writing. Add a per-peer partial-bytes quota.

### 12. Bootstrap session restriction is never enforced; no frame dispatcher exists
**major** — `crates/abra-net/src/auth.rs:907-918`; SPEC §6.2 ("the single authoritative bootstrap rule"), §6.1

`bootstrap_allowed` is a pure predicate with exactly one caller: a test asserting
`bootstrap_allowed("pair-request")` and `!bootstrap_allowed("offer")`. There is no read loop that
consults it, because there is no read loop (finding 1). `accept_handshake` returns `HelloOk` with the
session string and the caller is on its own.

Consequently §6.1's "unknown `type` after handshake → `error {code:"unknown_type"}`, connection lives"
is also unimplemented: `read_frame::<T>` deserializes straight into a concrete type, so any unexpected
frame becomes a serde error that kills the connection. `health_check` reads `Pong` directly and will
fail on any interleaved frame.

*Fix:* a single `dispatch(session, value)` that reads `Value`, extracts `type`, refuses
non-allowlisted types with `error{code:"untrusted"}` + close in bootstrap, and replies
`error{code:"unknown_type"}` without closing in trusted. Add tests that a bootstrap peer sending
`offer`, `ping`, and `control` is refused in each case.

### 13. `confirm_pair` authenticates nobody
**major** — `crates/abra-net/src/auth.rs:252-260`; SPEC §7.1

```rust
pub fn confirm_pair(&mut self, confirm: &PairConfirm) -> Result<()> {
    let peer = self.disk.awaiting_pair_confirm.remove(&confirm.ticket_id)...
    self.disk.peers.insert(peer.peer_id, peer);
```

No authenticated peer id parameter, no signature, no check that the confirming connection belongs to
the peer being promoted to full trust. `pair-confirm` is in the bootstrap allowlist, so any peer that
learns a `ticket_id` (which travels in the plaintext of a QR/clipboard ticket) can drive it.

*Failure scenario:* the user approves pairing with B at the prompt; B then aborts or crashes before
sending `pair-confirm`, and the user believes pairing did not complete. An attacker who saw the ticket
(shoulder-surfed QR, clipboard-scraping process, screenshot) dials A in a bootstrap session and sends
`pair-confirm {ticket_id}`. A silently inserts B as a full `TrustedPeer`. The promoted identity is B's,
not the attacker's — so this is trust-state forcing rather than direct impersonation — but it defeats
the SPEC's "each side inserts the other ... only at its own final step, so a crash leaves at worst one
half-paired side that simply re-pairs" and there is no way to abort a pairing once approved.

Compounding: `awaiting_pair_confirm` entries have no expiry and are never pruned, so the window is
permanent and the map grows without bound. `pair-abort` is in the allowlist but has no handler.

*Fix:* `confirm_pair(&mut self, confirm: &PairConfirm, authenticated: PeerId)` asserting
`authenticated == peer.peer_id`; expire entries after the ticket's `expires_at` + skew; implement
`pair-abort` to drop the entry.

### 14. Pending-ack list is cleared immediately, defeating the §8 redelivery requirement
**major** — `crates/abra-net/src/delivery.rs:332-343`; SPEC §8 ("this v0.1 requirement is what lets
relays ship later without breaking outbox correctness")

The receiver persists the ack at `:332` and deletes it at `:343` within the same function, before any
evidence the sender received it. In-process this is invisible; over a real connection it is the whole
crash window.

*Failure scenario:* receiver commits durably, signs and persists the ack, sends it; the connection dies
before the sender reads it, or the sender crashes between reading and `mark_acked`'s `save()`. The
receiver has already deleted the pending ack, so it will never re-deliver. The sender re-offers under
the same `offer_id`; the receiver's `have` covers the whole closure so transfer is cheap, but
`commit_manifest` runs again — and for `Scope::Full` a second `insert_snapshot` of identical bytes is
handled (capsule.rs:348), while for `Scope::Partial` `receive_partial` overwrites the inbox record
(resetting `read: false`). The duty-to-deliver is only cleared by luck.

Note `pending_acks()` (`:437`) exists to re-emit them but is never called by anything.

*Fix:* clear the pending ack only when the sender confirms (or on the next successful connection where
the sender no longer has the entry), and drive `pending_acks()` from the connection-established path.
Add tests for both crash windows: crash-after-commit-before-ack-sent, and crash-after-ack-sent-before-
`mark_acked`.

### 15. `mark_acked` takes the signature on trust
**major (API shape)** — `crates/abra-net/src/outbox.rs:168-189`

`mark_acked(id, offer_id, snapshot_id, sig, now)` stores `sig` and sets `Acked` without verifying
anything. Today `deliver_limited:333` calls `ack.verify(sender, entry.peer_id)` immediately before, so
the live path is correct — the ack is bound to `offer_id || snapshot_id || sender || receiver` and
verified against `entry.peer_id` (the *intended* recipient from the outbox, not a peer id taken from
the message), which is exactly right and defeats both cross-offer and cross-recipient replay.

But the outbox is `pub` and the verification is one call away in a different module. SPEC §6.10:
"**Only a verified ack clears the duty to deliver**" is an invariant the type system should carry.

*Failure scenario:* a stage-3 daemon reads an `Ack` frame off the wire and calls
`outbox.mark_acked(...)` directly. Any peer — or the transport itself if it were not authenticated —
clears an arbitrary outbox entry by echoing a known `offer_id`/`snapshot_id` with 64 random bytes.

*Fix:* change the signature to `mark_acked(&mut self, id: &str, ack: &Ack, sender: PeerId) -> Result<bool>`
and do the `ack.verify(sender, entry.peer_id)` **inside**, so the unverified path is unrepresentable.
Also assert `state == AwaitingAck`. The existing test
(`outbox_survives_restart_and_old_ack_cannot_clear_fresh_attempt`) passes a deliberately fake
signature and asserts `false` — but it would pass identically with *no* signature checking at all,
since the rejection comes from the `offer_id` mismatch. Add a test where the `offer_id` matches and
only the signature is wrong.

### 16. Control-nonce store is an unbounded, unvalidated, write-amplifying sink
**major** — `crates/abra-net/src/auth.rs:458-467`; `control.rs:89`

`consume_control_nonce` prunes entries older than 10 minutes, then inserts the nonce **as an arbitrary
string** and calls `save()` — which re-serializes and fsyncs the *entire* trust store (peers, tickets,
bound tokens, revocations, every nonce). The nonce is never validated as 32 hex chars; `ControlMessage`
has no length bound on it (`nonce: String`) and none on `text` either.

*Failure scenario:* a paired peer sends control messages with 1 MiB unique nonces at line rate. Each
one appends to `control_nonces` and rewrites + `sync_all`s the whole trust.json. Within the 10-minute
retention window this is unbounded memory and disk plus an fsync amplification attack that stalls
every other trust operation. Correctly-signed and correctly-timestamped, so no other check fires.

*Fix:* validate `nonce` is exactly 32 lowercase hex chars (16 bytes per §6.8) and `text` ≤ some bound
before recording; move the nonce set to its own append-only file with a size cap; rate-limit control
messages per peer.

### 17. `parse_control_time` is a second, weaker time parser
**major** — `crates/abra-net/src/control.rs:92-119`; SPEC §0 ("Only legal form inside hashed/signed
documents"), §12

Beyond the panic (finding 3), it validates nothing: no check for `-`/`T`/`:`/`.`/`Z` separators, no
range check on month/day/hour, and `str::parse::<i64>` accepts leading `+`/`-`. `"+123-99-99T99:99:99.999Z"`
is accepted and folded into some epoch value. The comment claims it exists to "reuse enrollment
validation without exposing its parser" — but `parse_time` is already `pub(crate)` and directly
callable from `control.rs`.

Separately, `unsigned()` (`control.rs:43`) re-serializes the parsed struct through
`serde_json::to_value` → `canonical::to_vec`, so the signature is verified over a *re-canonicalized
DOM*, not the received bytes. That is tolerable for control (`deny_unknown_fields` blocks the §12
smuggling case) but means a non-canonical wire encoding is silently accepted where §2 says receivers
must reject noncanonical bytes. Same applies to `Ack`, `EnrollBind`, and `BindCertificate` frames —
`PairTicket::parse` and `EnrollmentToken::parse` get this right (`canonical::to_vec(&x)? != b`), so
the inconsistency is the tell.

*Fix:* delete `parse_control_time`, call `crate::auth::parse_time`. Read signed control frames as raw
bytes, `validate_canonical` them, and verify over the byte-derived preimage.

### 18. Durability: no parent-directory fsync after rename
**major** — `crates/abra-net/src/auth.rs:172-182`; `crates/abra-net/src/outbox.rs:73-82`

Both `save()` implementations do write-tmp → `sync_all(tmp)` → `rename`, but never fsync the
containing directory. `abra-core`'s `atomic_write` (store.rs:374-391) and `BlobStore::put`
(cas.rs:288-296) both **do** fsync the parent — so the net crate is strictly weaker than the layer it
sits on, for the two files that carry "only a verified ack clears the duty to deliver" and the trust
store.

*Failure scenario:* power loss shortly after `mark_acked`. The rename is not durable; on reboot the
outbox reads back as `awaiting_ack`/`transferring` and the sender re-delivers a snapshot the receiver
already committed. Conversely a lost `bind_enrollment` save re-opens a bind-once window.

Also: `Outbox::save` rewrites every entry — including each entry's full `manifest_raw` — on every one
of the five state transitions per delivery. With a few hundred queued snapshots this is O(total
manifest bytes) fsynced five times per delivery.

*Fix:* add a shared `atomic_write` helper with directory fsync (or reuse core's). Split the outbox
into per-entry files, as core already does for snapshots.

---

## Minor

19. **`read_frame` preallocates before reading** — `framing.rs:23`: `vec![0; len]` with `len` up to
    16 MiB from an unauthenticated length prefix, before `read_exact`. N concurrent connections ⇒ 16N
    MiB. Fix: cap per-connection in-flight bytes, or read in chunks.
20. **`write_frame` is not canonical JSON** — `framing.rs:8` uses `serde_json::to_vec`. Key order comes
    from struct declaration order, not byte-sorted. Harmless while every verifier re-canonicalizes,
    but it violates §12's "every persisted record and message carries its schema version" spirit and
    guarantees interop drift with a second implementation. Fix: `canonical::to_vec`.
21. **`bind_enrollment` requires the intro peer to be the issuer** — `auth.rs:311-315`. SPEC §7.2 says
    the intro peer binds "as the issuer, **or after verifying an issuer-signed certificate**". The
    second path is unimplemented; `BindCertificate` is minted (`:359`) but never transmitted, stored,
    gossiped, or consumed by `verify` at any call site. So enrollment only works when `intro[0]` is
    the minting device, and "other full peers accept a guest only via a valid bind certificate" is not
    implemented at all — other full peers accept guests via nothing, because there is no gossip.
22. **Revocation is minted but never flooded or ingested** — `RevocationRecord` (`auth.rs:800-826`) has
    no call site. `verify(&self, full_peer: PeerId)` takes the claimed signer as a parameter with no
    trust-store lookup, so a caller that passes the record's own claimed author verifies nothing.
    SPEC §7.3's flood + "retained until token expiry + 7d" is absent; `revoked` is a `BTreeSet<String>`
    that never expires. Fix: store the signed record, check the signer is a known full peer, prune at
    expiry+7d.
23. **Expired-token guests still get a `trusted` session** — `auth.rs:967`: `trust.get(&remote).is_some()`.
    `revoke_token` removes the peer entry so revocation downgrades correctly, but expiry does not. The
    per-operation checks catch it, so this is defense-in-depth only.
24. **`bootstrap_allowed` includes `pair-confirm`** — `auth.rs:907`, not in §6.2's "single
    authoritative" list. The implementation is arguably right (the §7.1 flow needs it) and the SPEC
    list looks incomplete; flag it for erratum rather than silently diverging.
25. **`check_hello` does not validate the nonce** — `auth.rs:883-905` echoes `hello.nonce` verbatim
    with no hex/length check, so it is an arbitrary-length reflection into the response. Also
    `hello-reject.reason` is hardcoded `"wire"` (`:976`) regardless of the actual cause, losing the
    `busy`/`protocol` distinction §6.2 defines.
26. **Loopback transport hygiene** — `transport.rs:106-118`: `bind` inserts into the shared map and
    never deregisters on drop, so a dropped node keeps receiving; `expect("loopback lock")` on a
    `std::sync::Mutex` turns one panic into a cascade; `accept_uni` (`:62`) holds an `AsyncMutex`
    across `recv().await`, serializing all uni streams; the `mpsc::channel(8)` in `dial` will deadlock
    if both sides fill their queues with no reader.
27. **Control receive path doesn't re-check message invariants** — `control.rs:72-90` never checks
    `message_type == "control"`, and never re-applies `new`'s `(op == Instruct) == text.is_some()`
    rule, so a signed `{op:"pause", text:"..."}` is accepted. It also does not check that the signer
    has any relationship to `capsule_id`.
28. **`expire()` overwrites `Failed`** — `outbox.rs:190-198` sets `Expired` on any non-terminal entry
    older than 7d, including `Failed`, destroying the user-retryable distinction. SPEC's diagram is
    `queued → expired`. Also `pending_ids` (`:115`) ignores `next_attempt_at`, so the backoff it
    computes has no effect on scheduling.
29. **`EnrollmentToken::parse` has no size cap** — `auth.rs:679-700`. `PairTicket::parse` enforces
    8 KiB (`:529`); enrollment tokens are decoded and deserialized with no bound, and `intro` is an
    unbounded `Vec`.
30. **`Offer.fork` is hardcoded `false`** — `delivery.rs:278`, so the receiver can never be told the
    snapshot is a fork.
31. **`object_kind` guesses by trial-decode** — `delivery.rs:480-486`: a blob whose contents happen to
    be a valid `abra.tree.v1` encoding is labelled a tree. The kind should come from the closure walk
    (which already knows), not from sniffing.
32. **`Scopes` list entries are unvalidated** — `auth.rs:113-120` checks wildcard mixing and
    non-emptiness but not that `capsules` entries are 64-hex or that `kinds` entries match the §1.1
    reverse-DNS grammar. A token with `kinds: ["*x"]` is well-formed but matches nothing.
33. **Unimplemented §6.8 messages** — `lease-update` push, `control-ack` emission, `transfer-error`,
    and `offer-reject` reason plumbing all have no code (`control-ack`/`transfer-error`/`offer-reject`
    exist only as unused types).

---

## Test adequacy

The 7 integration tests are well-chosen for the happy path but test the in-process shortcut, not the
protocol. Specific gaps, roughly in priority order:

**Untested SPEC-required behaviour**

1. **Anything at `Scope::Full`.** All four delivery tests use `partial()`. Capsule delivery, genesis
   propagation, fork-on-receive, orphan storage (§5.2), and lease interaction have zero coverage —
   which is why finding 4 is invisible.
2. **Byte authority across the hop.** No test flips a byte in `manifest_raw`, truncates it, re-orders
   its keys into non-canonical form, or substitutes a manifest whose `snapshot_id` disagrees with the
   offer. Needed: `tampered_manifest_bytes_are_rejected`,
   `noncanonical_manifest_bytes_are_rejected`, `offer_metadata_disagreeing_with_manifest_is_rejected`.
3. **Untrusted manifest signer.** No test that a manifest signed by a key not in the trust store is
   refused (finding 2b).
4. **Ack verification.** The one ack test rejects via `offer_id` mismatch and would pass with
   signature checking removed entirely. Needed: same `offer_id`, wrong signature; ack signed by a
   third party; ack whose payload names a different `receiver_peer_id`; ack replayed from offer A onto
   offer B.
5. **Pairing.** `PairTicket`/`PairRequest`/`accept_pair_request`/`confirm_pair`/
   `complete_pair_as_joiner` have **no tests at all**. Needed: full two-sided flow; expired ticket;
   ticket reuse (strict single-use); `pair-request` whose `peer_id` ≠ transport peer;
   `pair-confirm` from a third party (finding 13); declined prompt.
6. **Enrollment.** Only `enrollment_token_validation` (mint/expiry) exists. Untested: `enroll-bind`
   end to end; **bind-once** (audience-less token bound twice to different guests); `bind_by` window
   expiry; `audience` mismatch; bind of a revoked token; bind-cert verification; scope enforcement at
   an actual offer from a real guest node.
7. **Revocation at each enforcement point.** The existing test calls `authorize_offer` directly;
   nothing checks revocation is consulted on bind, on lease ops, or mid-session (a peer revoked
   between offer and ack).
8. **Guest-to-guest at the delivery level** (finding 6) and **`have` scope leakage** (finding 7).
9. **The `allow_agent_send` gate** (finding 5) — no test at all.
10. **Bootstrap enforcement.** `handshake_versions_and_bootstrap_allowlist` asserts the predicate's
    truth table, not that a bootstrap peer sending `offer`/`control`/`ping` is refused.
11. **Outbox failure semantics.** No test drives `fail_attempt`, backoff growth, the 20-attempt
    ceiling, TTL expiry, cancellation, or an illegal transition.
12. **Crash windows.** `outbox_survives_restart...` restarts only at `queued`. Needed: restart at
    `transferring` with partials on disk; crash between `commit_manifest` and `mark_acked`; crash
    after ack with the pending-ack file present (finding 14).
13. **Corrupt object.** `commit_partial`'s hash-mismatch branch (`delivery.rs:402-405`) is never
    exercised; nor is the `non-contiguous resume offset` guard (`:388`), nor `partial exceeds total`
    (`:394`).
14. **Hostile inputs.** No fuzz/table tests for time strings (finding 3), oversized frames, unknown
    frame types, or malformed base64 in `manifest_raw`.

**Does the loopback transport hide real-transport failure modes?**

Worse than that — `LoopbackTransport` is not used by a single test, so the question is currently moot
and every transport-level failure mode is unhandled by construction. Once wired, the loopback as
written would still hide:

- **Partial writes / short reads.** `tokio::io::duplex` plus `write_all`/`read_exact` make framing
  look atomic. A real QUIC stream splits a 49-byte `ObjectHeader` across reads; `ObjectHeader::decode`
  takes `[u8; 49]` and has no incremental path.
- **Connection death mid-frame.** Loopback closes cleanly between messages via channel drop. There is
  no test where the peer vanishes after the length prefix but before the body, mid-object-stream, or
  between `commit_manifest` and the ack. The `partial exceeds total` and resume-offset guards are
  exactly the code that a mid-frame death exercises.
- **Reordering and concurrency.** `open_uni`/`accept_uni` are a FIFO `mpsc<Vec<u8>>`, so uni streams
  arrive whole and in order. Real QUIC delivers 8 concurrent unidirectional streams interleaved and
  out of order relative to control frames — meaning the receiver must correlate object streams to
  offers by digest and tolerate an object arriving before the `plan` that mentions it. No code
  handles this.
- **Backpressure and deadlock.** `duplex(64 * 1024)` plus `channel(8)` will deadlock if both peers
  write without reading; no test has both directions in flight simultaneously.
- **Authentication.** Loopback lets any node bind any `PeerId` — the "transport-authenticated Ed25519
  key MUST equal every `peer_id` claimed" property (§6) is only real under iroh, and the iroh path has
  no test coverage (it is behind an off-by-default feature).

Recommended additions: a `FaultyTransport` decorator over `LoopbackTransport` that can chop writes at
arbitrary offsets, reorder uni streams, inject a mid-frame close, and stall to force backpressure —
plus at least one `#[ignore]`d two-endpoint iroh test to keep the feature honest.

---

## Verdict

**Not sound enough to build the stage-3 daemon/CLI on top of.** This is not a matter of patching a few
checks: the layer stage 3 needs — "drive a delivery over a `Connection`" — does not exist. What exists
is a faithful set of §6/§7 data types plus a local state machine, validated by tests that exercise
in-process function calls between two `DeliveryNode`s. The parts that would carry the security
properties over a real hop (receiver-side manifest verification, bootstrap message-set enforcement,
the frame dispatcher, object streaming, the send-authority gate) are either absent or present as
unreachable code. Building a daemon on `deliver(&mut self, &mut Self)` means rewriting §6 anyway, and
doing so against the current API would silently inherit findings 2, 6, 7, 12 and 15 as live
vulnerabilities.

The cryptographic core is, to be fair, mostly right where it is exercised: the ack preimage binds
`offer_id || snapshot_id || sender || receiver` exactly as §6.7 specifies and is verified against the
outbox's intended recipient rather than a peer id lifted from the message, which correctly defeats
cross-offer and cross-recipient ack replay; `retry_fresh` rotates the `offer_id` so a stale ack cannot
clear a new attempt; `offer_id` is stable across resumes of one attempt; domain separation is used
consistently; `PairTicket`/`EnrollmentToken` parsing enforces canonical bytes before verifying;
bind-once is correctly enforced for audience-less tokens. The delta/resume logic is also sound in
isolation — `have` is recomputed against the receiver's own CAS, resume offsets are validated
contiguous-from-zero against the receiver's own file length rather than trusting the sender, and
`commit_partial` re-hashes before `cas.put` so no unverified prefix can reach the CAS. Those are the
right instincts and they should survive the rework intact.

Stage 2 is best read as a solid type-and-state-machine skeleton that has not yet met a network.

### Top 3 must-fix

1. **Implement §6 over `Transport`, with receiver-side `RawManifest::parse` of `manifest_raw` and a
   trust-store check on `origin.peer_id`** (findings 1, 2). Nothing else can be validated until the
   bytes actually cross a boundary; this also unblocks meaningful tests for everything below.
2. **Eliminate the timestamp panics and wire up the enforcement points that are currently dead code**
   (findings 3, 5, 6, 12): one hardened ASCII-only time parser used everywhere; explicit local
   role/scopes state so the `allow_agent_send` gate and guest-to-guest denial can fire; unknown
   counterparties default to deny; the bootstrap allowlist consulted by a real dispatch loop. Finding
   3 is remotely reachable by an unauthenticated peer and should be fixed first regardless of the
   rework schedule.
3. **Make full-scope delivery work and make failure a state transition** (findings 4, 8): a
   receive-side commit path that stores forked and orphan snapshots instead of erroring, genesis
   verification and installation from the offer, and `fail_attempt` on every error path with a
   validated §6.10 transition table. Add full-scope delivery tests — their absence is what let a
   total functional break ship green.
