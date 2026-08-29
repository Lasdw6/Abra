# Stage 2 review: `abra-net` (commit d29a621, GPT-5.6 Sol)

Reviewer: Grok 4.6 (security-focused protocol review)
Repo: `/Users/vividh/Desktop/abra`
Spec: `SPEC.md` §§6–7 (delivery, pairing/enrollment); `DESIGN.md` for product decisions
Method: read-only review of `crates/abra-net` against SPEC.md; cross-checked `abra-core` byte-authority / CAS / identity primitives. No repo modifications.

## Ack verification path (end to end)

What is signed: Ed25519 domain `ack` over `offer_id(16) || snapshot_id(32) || sender_peer_id(32) || receiver_peer_id(32)` raw bytes (`delivery.rs:116–131`, `Ack::sign` at `delivery.rs:132–154`). `received_at` and `shelf` are **not** in the signed payload (matches SPEC §6.7).

Who verifies against whom: `Ack::verify` checks the signature with `intended_receiver.verify(...)` (`delivery.rs:155–162`). In `deliver_limited` the signer is the receiver's device identity and the intended receiver is `entry.peer_id` (`delivery.rs:333–336`).

What it gates: `Outbox::mark_acked` is the **only** transition to `acked` (`outbox.rs:168–188`). It does **not** verify the signature. It only compares `offer_id` and `snapshot_id`, then stores whatever `sig` bytes the caller passed. `authorize_ack` (`auth.rs:404–414`) is never called on this path.

So the cryptographic ack exists as a helper, but the state machine that clears the duty to deliver is not bound to a verified recipient signature. A replay across a fresh `offer_id` is rejected by the id check (good); a garbage signature for the *current* id is accepted by `mark_acked` (bad).

---

## Findings

1. **critical** — `crates/abra-net/src/delivery.rs:221–345` (`deliver_limited`)
   **Defect:** There is no wire protocol. Delivery is an in-process method that mutates the receiver directly. Handshake, framing, bootstrap allowlist, offer JSON, object-stream headers, ping/pong, offer-accept/reject, plan/have frames, and session type are never executed on this path. The constructed `Offer` is bound to `_offer` and dropped (`delivery.rs:270–285`). `bootstrap_allowed` (`auth.rs:907–918`) is dead code except a unit test. `dial_handshake` / `accept_handshake` / `health_check` are never called from delivery.
   **Failure scenario:** Stage 3 builds a daemon on these APIs and assumes SPEC §6 is enforced. A bootstrap (unknown) peer that can complete the unused hello helpers can still never be stopped by this crate from offering, because nothing in the live path consults `session`. Conversely, pairing/enrollment message types have no receive loop to handle them on a real connection. The loopback transport tests in `net_spec.rs` never construct a `LoopbackTransport`.
   **Fix:** Implement a single session driver: hello → session tag → demux by `type` with the bootstrap allowlist → offer/plan/have/object/ack on trusted sessions only. Drive `deliver` through `Transport` + `read_frame`/`write_frame` + `ObjectHeader`. Delete or test-gate the in-process shortcut.

2. **critical** — `crates/abra-net/src/delivery.rs:239–285` and `delivery.rs:322–331`
   **Defect:** SPEC §6.4 / §2 P0: the receiver MUST decode `manifest_raw`, hash the received bytes (remove `signature` from those bytes, not a re-parsed DOM), verify id + strict signature, then persist those exact bytes. The receiver never sees `manifest_raw`. `commit_manifest` is handed a cloned `RawManifest` from the sender's outbox (`delivery.rs:323`). Byte authority does not survive a network hop because there is no hop and no independent verify.
   **Failure scenario:** A malicious paired peer (or a buggy stage-3 encoder) sends an offer whose `snapshot_id` / floor fields do not match `manifest_raw`, or whose `manifest_raw` is noncanonical. The current receiver cannot notice. If stage 3 naively `serde`s the offer's parsed `kind`/`title` for the floor and separately stores a re-serialized manifest, stage 1's P0 is lost.
   **Fix:** `accept_offer` must: base64url-decode `manifest_raw`; `RawManifest::parse` on those bytes (this already hashes stored bytes, not a reserialized DOM — `abra-core` `manifest.rs:372–397`); require `raw.snapshot_id() == offer.snapshot_id`; require `origin.peer_id` trusted and in-scope; persist `raw.bytes()`; ignore every other copy of manifest fields for identity.

3. **critical** — `crates/abra-net/src/delivery.rs:201–217`
   **Defect:** The local agent-send gate (SPEC §7.4: `send:true` AND `abra.allow_agent_send`, default false) only runs if the local peer id is present in **its own** trust store as `Role::Guest`. Enrollment (`bind_enrollment`, `auth.rs:297–360`) inserts the guest on the *intro* peer, not on the guest. `allow_agent_send` defaults to `false` (`delivery.rs:193`) but the check is skipped for a node that is not self-registered.
   **Failure scenario:** Infra injects a guest binary + token with `send:false` (or `send:true` but the host flag off). The guest daemon opens a `DeliveryNode`, never inserts itself as a guest, and `enqueue` succeeds. A token cannot be relied on to disable send; the local flag cannot be relied on either. This is the stated “no token can widen it” control, inverted: absence of self-identification widens it.
   **Fix:** First-class local role (e.g. `LocalRole::{Full,Guest}` persisted from the enrollment token at guest start). Gate `enqueue` on that role, `token.scopes.send`, and `allow_agent_send`. Fail closed if role is guest and either bit is false. Never infer role by looking up `self` in `TrustedPeer`.

4. **critical** — `crates/abra-net/src/outbox.rs:168–188` with `delivery.rs:333–336`
   **Defect:** Clearing the outbox does not require a valid ack. `mark_acked` accepts any 64-byte `sig` if `offer_id` and `snapshot_id` match. Those two values are in the offer itself (not secret). `Ack::verify` is a separate call the in-process path happens to make; it is not atomic with the state change, and `authorize_ack` is unused.
   **Failure scenario:** Stage 3 calls `mark_acked` from an ack-frame handler and forgets `verify` (the public API invites this). A malicious paired peer sends `{type:ack, offer_id, snapshot_id, sig: 00..00}`. The sender drops the duty to deliver. Same for a replayed ack *body* with a replaced `sig` field if the handler only checks ids. The test `outbox_survives_restart_and_old_ack_cannot_clear_fresh_attempt` (`tests/net_spec.rs:131–153`) only proves a *stale offer_id* is rejected; it uses a fake signature and never shows that a fake sig for the *current* id is rejected.
   **Fix:** Replace `mark_acked` with `apply_ack(&Ack, local_peer, now)` that (1) verifies domain `ack` against the outbox target identity, (2) checks `sender`/`receiver` bytes equal this attempt, (3) checks `offer_id`/`snapshot_id`, (4) then persists `acked` + `ack_sig`. Do not expose an unverified clear.

5. **major** — `crates/abra-net/src/delivery.rs:322–331` (`commit_manifest` / ack)
   **Defect:** SPEC §6.7: ack only after atomic durable commit of **all verified closure objects**, manifest bytes, snapshot/inbox record, and CAS refs. `commit_manifest` (`delivery.rs:452–468`) writes the inbox/capsule record and does not check that `closure(cas, manifest)` is fully present and verified. No CAS-ref accounting is added. Genesis from the offer is ignored (`delivery.rs:282–284`, `461–463`).
   **Failure scenario:** (a) First send of a capsule: receiver returns `receiver lacks capsule genesis` even though the offer carried `genesis`. (b) A future wire `have` that lies (or a partial transfer that skips `commit_partial`) still reaches `Ack::sign`. Sender outbox clears; receiver is missing blobs. (c) Crash after `receive_partial`/`receive_full` and before `persist_pending_ack` (`delivery.rs:323` then `332`): receiver has the record, sender has no ack, pending-ack list is empty. Retry may work for duplicates, but there is no flush-on-reconnect of outstanding acks (SPEC §8: “every receiver MUST keep a pending-ack list and deliver outstanding acks on the next live connection”). `pending_acks()` (`delivery.rs:437–451`) is unused by any protocol path.
   **Fix:** Before `Ack::sign`, recompute closure from the **verified** manifest against local CAS (`cas.has` already re-hashes). Require genesis install (verify genesis sig, `add_capsule`) on first full offer. Persist pending ack **before** the sender can observe it, and on every trusted reconnect send `pending_acks()` first. Treat crash-before-ack as retry with same `offer_id`.

6. **major** — `crates/abra-net/src/auth.rs:373–377` and `delivery.rs:241–262`
   **Defect:** Guest-to-guest denial looks up `other` in the trust store and **defaults missing to Full**. The receiver typically does not store itself. A guest receiver therefore treats itself as Full and skips the denial. Scope “both directions” (SPEC §6.4, §7.4) is only applied on the sender if the sender already classified the receiver as guest (`delivery.rs:249–262`). Guest self-enforcement of `receive` is absent. `authorize_offer` for a Full actor returns `Ok` with no scope check, even when the other party is a guest.
   **Failure scenario:** Two guests that somehow have each other as `TrustedPeer` (bind-cert gossip, copied trust file, stage-3 insert) will accept guest-to-guest offers. A full peer with a stale/missing guest entry will send to a `receive:false` guest and the guest will accept. The test named `scope_expiry_revocation_and_guest_to_guest_are_enforced` (`tests/net_spec.rs:156–211`) never creates a second guest and never asserts guest-to-guest denial; it only checks wrong capsule, expiry, and revoke.
   **Fix:** Deny guest-to-guest using *local* role (see finding 3) plus `actor.role == Guest`. On every offer involving a guest, the **full** peer must check kind/capsule/`send`/`receive`/revocation/expiry. Guests must still self-check `receive` as defense in depth.

7. **major** — `crates/abra-net/src/auth.rs:297–360` (`bind_enrollment`)
   **Defect:** Bind requires `issuer.peer_id() == token.issuer` (`auth.rs:311–315`), so only the token issuer can enroll. SPEC §7.2: guest dials `intro[0]`, which need not be the issuer; intro binds, then gossips an issuer-signed bind certificate; **other full peers accept a guest only via that cert**. There is no `accept_bind_cert`, no `enroll-ok` mesh payload, no gossip. `BindCertificate` (`auth.rs:767–798`) is produced and then discarded by callers (only returned, never applied elsewhere). Audience-less bind-once allows the *same* guest to rebind (`auth.rs:334–341`); different guest is denied. Revocation is checked at bind (`316–318`) and in `authorize_*`, but `revoke_token` (`auth.rs:287–293`) takes a bare id — no `RevocationRecord` verify — and does not clear `bound_tokens`. Full-peer removal (`peer_id` in place of `token_id`, §7.3) has no representation (`RevocationRecord` is token-only, `auth.rs:800–826`).
   **Failure scenario:** Token `intro[0]` is the laptop, issuer is another box: enrollment fails. Guest bound on the issuer is unknown to every other device, so offers from the guest are `untrusted peer`. A stage-3 handler that applies `revoke` frames without verifying a full-peer signature can be made to drop guests (or, if inverted, ignore real revokes). Re-enroll after revoke still fails via `revoked` set (good), but `bound_tokens` leftover complicates any future “reissue same token_id” story.
   **Fix:** Split “verify token + bind locally” from “sign bind-cert as issuer”. Add `accept_bind_cert` that verifies issuer sig, loads scopes from a carried/cached token (the cert as specified does not include scopes — this is also a spec gap; carry scopes+expiry or the token). `apply_revocation` must verify signer is a full trusted peer. Clear `bound_tokens` on revoke. Persist revocation until `expires_at + 7d`.

8. **major** — `crates/abra-net/src/auth.rs:638–671` (`EnrollmentToken::mint` / `parse` / `verify`)
   **Defect:** `bind_by ≤ 15 minutes after issued_at` is not enforced on parse/verify (only mint clamps with `ttl_ms.min(900_000)`, `auth.rs:653–655`). Token expiry uses the caller-supplied `now` with **no** 60s skew (pairing tickets do use `CLOCK_SKEW_MS`, `auth.rs:224`, `538`). `EnrollmentToken::parse` has no 8 KiB cap (tickets do, `auth.rs:529–531`). Clock is whatever the caller passes — not `SystemTime` — which is good for tests and dangerous if stage 3 passes a stale `now` (expiry never fires) or a future `now` (bind window always dead).
   **Failure scenario:** A crafted audience-less token (issuer-signed, so a compromised full device) with `bind_by` = +30d still verifies; first-use bind window is unbounded. A guest whose clock is 1s behind a token’s `expires_at` is locked out while pairing would still allow 60s skew — operational footgun, not a bypass. Infra that forgets to pass wall-clock `now` into `authorize_offer` disables expiry/revocation-by-time.
   **Fix:** Reject `bind_by > issued_at + 15m` (and `bind_by` missing when `audience` is missing) in `verify`. Document that all authz calls MUST use a monotonic-enough UTC clock; consider 60s skew on token expiry for the same reason pairing has it. Cap decoded enrollment size.

9. **major** — `crates/abra-net/src/transport.rs:62–80` (and `39–60`)
   **Defect:** Iroh `accept_uni` does `read_to_end(usize::MAX)`. The `Transport` API itself takes/returns a whole `Vec<u8>` per object. SPEC §6.1: max 8 concurrent object streams; hash on EOF; commit atomic. `MAX_OBJECT_STREAMS` (`delivery.rs:20`) is unused. No object-size quota (`offer-reject: quota` is specified, never implemented). `append_partial` trusts sender `total` (`delivery.rs:374–397`).
   **Failure scenario:** A hostile paired peer (or the transport) opens one uni stream and sends until RAM/disk is gone. With `--features iroh` this is trivial. Loopback hides it by delivering whole in-memory chunks from an honest `cas.get`. Partial files grow to claimed `total` without a cap. Eight-stream limit is not enforced, so a peer can also open unbounded unis.
   **Fix:** Stream into a bounded temp file; refuse `total` above remaining quota / a hard max; count in-flight unis and reset if > 8; hash incrementally (or at EOF) *before* `cas.put`; never `read_to_end(usize::MAX)`.

10. **major** — `crates/abra-net/src/outbox.rs:123–132`, `133–151`, `delivery.rs:238`
    **Defect:** Outbox state machine does not match SPEC §6.10. `transition` allows any state to any state (including `acked → queued`). `deliver_limited` writes `Healthcheck` without calling `health_check` (5s ping). `next_attempt_at` is persisted but never consulted. `fail_attempt` is never called from `deliver`. No `cancelled` API. First backoff after one failure is ~2s not ~1s (`1000 << attempts` with `attempts` already incremented, `outbox.rs:145`). `Failed` is non-terminal (`outbox.rs:30–32`) but `pending_ids` excludes it (`outbox.rs:115–122`) — OK — yet `expire` can still flip `Failed` to `Expired`. Offer-id is stable across `deliver_limited` interrupts (good) and rotated only in `retry_fresh` (good).
    **Failure scenario:** Stage 3 retries in a loop, ignores `next_attempt_at`, hammers a down peer (no ping, no 5s timeout on the delivery path). A crash in `Offered`/`Transferring` resumes with the same `offer_id` only if the caller reinvokes `deliver` without `retry_fresh` — not documented. A caller that `transition`s to `acked` without an ack bypasses SPEC’s “only a verified ack clears the duty”.
    **Fix:** Encode legal edges in `transition`. Run ping with `HEALTH_TIMEOUT` before offer; on failure `fail_attempt` and return. Honor TTL (`expire`) and backoff before dial. Add `cancel`. Keep `offer_id` stable until `retry_fresh` / user retry after `failed`.

11. **major** — `crates/abra-net/src/framing.rs:7–26`, `transport.rs:136`
    **Defect:** Post-handshake control reads have no timeout. `write_frame` can emit 16 MiB; loopback control is a 64 KiB `duplex`. Simultaneous large writes without reads deadlock. Unknown `type` after handshake is specified to return `error {code:unknown_type}` and keep the connection; no demux exists to do that. Object streams are not `u8 kind || digest[32] || u64be size || u64be offset || bytes` on the live path — `ObjectHeader` (`framing.rs:46–78`) is unused by delivery; `object_kind` (`delivery.rs:480–486`) sniffs tree vs blob.
    **Failure scenario:** Hostile peer sends `u32be` length = 16 MiB and stalls; the node blocks forever in `read_exact` (handshake is the only timed read, `auth.rs:937–939`). Two sides send 16 MiB offers at once on loopback → deadlock. A real iroh peer can reorder unis (QUIC streams are independent); delivery assumes sequential `commit_partial` in sender closure order and never associates a stream header digest with the plan.
    **Fix:** Timeout every frame read (reuse 5s idle / longer for bulk). Cap in-flight control writes. Parse `ObjectHeader` on every uni; require `kind/digest/offset` to match the want-set; allow concurrent unis up to 8. Reply `unknown_type` without closing.

12. **major** — `crates/abra-net/src/auth.rs:142`, `481`, `554`, `712` (`x25519_pk: [u8; 32]`, `relay_key: Option<[u8; 32]>`)
    **Defect:** SPEC §7.1 tickets encode `"x25519_pk":"<hex 64>"` (and optional `relay_key` hex). Serde will emit JSON arrays of integers. Signatures are over that non-spec CJSON (`unsigned`, `auth.rs:23–29`), so two `abra-net` nodes interop with each other and **not** with the spec/QR format. Pair-request signs only `ticket_id || nonce` (matches the domain table) so `name` / `x25519_pk` / `relay_key` are unsigned; transport authentication is supposed to cover this, but the ticket QR is the enrollment of the X25519 key for sealed boxes (§8) and is now a different encoding.
    **Failure scenario:** A spec-compliant peer cannot parse `abra-pair/1/...` minted here. A future relay path seals to the wrong key layout if one side hex-decodes and the other takes serde bytes. `complete_pair_as_joiner` (`auth.rs:261–286`) never checks `PairAccept.nonce` against the request nonce; `PairAccept`/`PairConfirm` are unsigned (spec-legal) so the joiner will insert `ticket.peer_id` as soon as *any* accept with that issuer id is parsed, even a stale one from an earlier attempt on the same bootstrap connection.
    **Fix:** Hex-newtype (or explicit hex serde) for X25519 and relay keys. Check accept nonce. After `pair-confirm`, either reconnect or upgrade the session from `bootstrap` to `trusted` — a strict reading of §6.2 otherwise keeps the connection in bootstrap and would reject the first offer (see finding 1).

13. **major** — `crates/abra-net/src/delivery.rs:346–362` (`compute_have`)
    **Defect:** `have` is recomputed against `cas.has` (verified CAS — good, `cas.rs:258–267`). Partial resume offsets are **file lengths**, not verified prefixes (`delivery.rs:367–372`). SPEC §6.5: contiguous-from-zero *committed* prefixes; this review’s P3: corrupt prefixes must not be committed (CAS install is protected by `commit_partial`, `delivery.rs:399–408`) but resume will continue appending onto a corrupt prefix until the final hash fails. `have` is also computed from the **sender-supplied closure**, not from a receiver-computed closure of a verified manifest. There is no filtering when the peer is a guest (SPEC §7.4: do not disclose possession of objects outside scoped capsules). Plan frames (`seq`, 50k split, `eof`) are never sent.
    **Failure scenario:** Sender (guest) includes extra digests in a future `plan`; receiver’s `compute_have` as written would answer from that set and become a CAS-existence oracle for out-of-scope blobs. Corrupt 4 KiB prefix on disk → resume sends the rest → hash fail → delete; bandwidth DoS, not CAS poison. Interrupted test (`tests/net_spec.rs:236–258`) only covers honest in-process truncation.
    **Fix:** Derive the object set only from `closure(local_cas_view_of_verified_manifest)`. For guests, omit (or refuse) hashes not in scoped capsules. Store partials with a running hash / length that is only advertised after fsync of a prefix that matches the sender’s bytes so far; on mismatch wipe the partial.

14. **minor** — `crates/abra-net/src/control.rs:72–90`
    **Defect:** Control checks full-peer role, 5-minute past / 60s future window, and durable nonce persist-before-return (`consume_control_nonce`, `auth.rs:458–467`) — this part matches §6.8. Duplicate civil-date parser (`parse_control_time`, `control.rs:92–119`) does not require canonical `T`/`.`/`Z` separators or calendar ranges (unlike `auth::parse_time`). Nonces are global, not per-signer (stricter; OK). Guests are denied. There is no session handler, so none of this runs on the wire. `lease-update` is unspecified in code. `text` for `instruct` is enforced at construct time, not at verify.
    **Failure scenario:** A full peer sends a control frame with a noncanonical `at` that this parser still turns into a timestamp inside the window; another implementation rejects it (split-brain). Stage 3 never calls `verify_and_record` and will execute unsigned `op`s. Replay after 10 minutes is allowed by spec; the retain window matches.
    **Fix:** Reuse `auth::parse_time`. Verify `message_type == "control"` and instruct-text in `verify_and_record`. Wire into the trusted-session demux; reject guests before parsing `op`.

15. **minor** — `crates/abra-net/src/auth.rs:199–250` (pairing)
    **Defect:** Tickets are single-use via `used_tickets` + pending removal (good) and persisted (good). `register_ticket` does not refuse ids already in `used_tickets` (still rejected at accept). No `pair-abort` type. User prompt is a callback `confirm` (good). Joiner inserts the issuer as Full **before** sending confirm (`complete_pair_as_joiner`); issuer inserts only on confirm (`confirm_pair`) — matches “each side inserts at its own final step”. Crash after accept-before-confirm: issuer has `awaiting_pair_confirm`, joiner may already trust the issuer — half-paired, spec-accepted. Pairing is untested in `net_spec.rs`.
    **Failure scenario:** Re-pair after crash uses a new ticket (old is used). If the joiner thinks it is paired and the issuer does not, offers from joiner get `untrusted` until a new ticket. No automated recovery path.
    **Fix:** Integration test the crash windows. On timeout, drop `awaiting_pair_confirm` and require a fresh ticket. Implement `pair-abort`.

16. **minor** — `crates/abra-net/src/outbox.rs:73–81` / `auth.rs:172–181`
    **Defect:** Trust and outbox durability is tmp + `sync_all` + rename, but the directory is not fsynced and the whole DB is one JSON object. `manifest_raw: Vec<u8>` inside outbox CJSON expands to a number array (huge, easy to hit memory on `open`). No fsync after rename.
    **Failure scenario:** Crash mid-rename: one missing outbox file → all pending deliveries forgotten (or the reverse: old file kept). Not a protocol bypass; it is a durability hole SPEC §6.10 cares about (“persisted”).
    **Fix:** Per-entry files (like inbox), fsync dir, store `manifest_raw` as base64url or a sidecar of exact bytes M.

17. **nit** — `crates/abra-net/src/delivery.rs:480–486`, `auth.rs:907–918`, `HelloOk.session`
    **Defect:** `bootstrap_allowed` includes `pair-confirm`, which §6.2’s list omits. That is the correct behavior (confirm happens before either side is trusted) and should be treated as a spec erratum, not removed. `object_kind` heuristic can classify a blob that happens to parse as a tree as `Tree`. `Have.message_type` defaults if missing (`delivery.rs:76–77`). `Ack.shelf` is a free string, not `capsule|inbox`.
    **Failure scenario:** Interop with a strict peer that rejects `pair-confirm` during bootstrap — pairing cannot finish without reconnect tricks. Wrong `kind` in a future object header if this heuristic is reused.
    **Fix:** Keep `pair-confirm` on the allowlist; add spec erratum. Take kind from the plan/header. Enum for `shelf`.

---

## What is actually sound (so stage 3 does not re-break it)

- Ack *payload layout* and domain separation match §6.7 (`delivery.rs:116–131`); replay across a new `offer_id` is blocked by id equality.
- `RawManifest::parse` in core still hashes received bytes and strict-verifies Ed25519; if finding 2 wires it to `manifest_raw`, P0 can hold.
- `cas.has` / `cas.get` re-hash; `commit_partial` refuses mismatch and deletes the partial (`delivery.rs:399–408`); CAS will not install corrupt objects on the in-process path.
- `append_partial` refuses non-contiguous offsets (`delivery.rs:387–389`).
- Enrollment signature domains `enroll` / `enroll-bind` / `bind-cert` / `revoke` match the table; audience mismatch is checked; wildcard `*` mixed with other entries is rejected (`Scopes::validate`, `auth.rs:113–119`).
- Transport-authenticated peer id is bound on hello, pair-request, and enroll-bind (`check_hello`, `accept_pair_request`, `bind_enrollment`).
- Outbox fields include spec-required columns plus `manifest_raw` (necessary to resume). `retry_fresh` rotates `offer_id`.

These are helpers. They are not a protocol until finding 1 is fixed.

---

## Test adequacy

`crates/abra-net/tests/net_spec.rs` is 7 tests, all in-process except a framing unit test in `framing.rs`. SPEC-required behaviors with **no** test:

- Hello on a real `Transport`; bootstrap session rejecting `offer`/`ack`/`control`/`ping`; trusted session allowing them.
- Decode/verify `manifest_raw` bytes (noncanonical reject; id mismatch reject; persist verbatim).
- `Ack::verify` required to clear outbox (fake sig + **current** offer_id must fail).
- Pending-ack retransmit after crash-between-commit-and-sender-mark.
- Guest-to-guest (two guests); `receive:false`; `allow_agent_send` default deny; bind-once; audience mismatch; `bind_by` window; revoke at bind; guest `have` non-disclosure.
- Pairing single-use, expiry+skew, decline callback, half-pair crash.
- Control: guest deny, skew, nonce replay, persist-before-act.
- Ping 5s timeout; backoff/jitter; 20-attempt `failed`; 7d TTL `expired`; `cancelled`.
- Full-snapshot + genesis first send; `offer-reject` reasons (`quota|scope|duplicate|invalid|busy`).
- Object-stream header, hash mismatch discard, corrupt-prefix resume, max 8 unis, 16 MiB frame cap, mid-frame disconnect.
- Iroh path: identity = node id, ALPN `abra/1`, unbounded-read refusal.

Loopback hides: partial writes, uni reordering, connection death mid-frame, flow-control deadlock, and any bootstrap enforcement. It is not an adequate stand-in for iroh.

---

## Verdict

**Not sound enough for stage 3 daemon/CLI on top.** Crypto primitives and several SPEC data structures are present, but the delivery path never crosses an adversarial boundary, the send gate does not fire for real guests, and a verified ack is not what clears the outbox. A daemon that “just calls `deliver` / `mark_acked` / `enqueue`” will ship a pairing-looking stack that does not implement §§6–7.

## Top-3 must-fix

1. **Put the protocol on the wire** — session driver with hello/bootstrap allowlist, framed offer whose `manifest_raw` is independently `RawManifest::parse`d and stored verbatim, object streams with headers and caps, ping timeouts, pending-ack flush. No in-process `deliver(&mut other)` as the production path.
2. **Bind outbox `acked` to `Ack::verify`** (and closure-complete CAS check) in one API; never clear on id match alone.
3. **First-class local role** so `allow_agent_send` + token `send`/`receive`, guest-to-guest, and expiry/revocation actually apply without self-insertion into `TrustStore`.
