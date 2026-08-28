# Cross-review of the Abra spec drafts — by Claude Opus 5

Reviewer wrote `draft-opus5.md`. Reviewed: `draft-gpt56-sol.md` and `draft-grok46.md`.
Authority: `/tmp/abra-prompts/design-context.md` (settled decisions) and `/Users/vividh/Desktop/abra/DESIGN.md`.

Two notes before the substance:

- **A conflict in the source material.** The design context (decision 14) names the built-in
  kinds `dev.abra.workspace` and `dev.abra.handoff.v1`; `DESIGN.md` §4 names them
  `abra.workspace` / `abra.handoff.v1` / `abra.file`. Both reviewed drafts chose `dev.abra.*`,
  which is what the authoritative context says. **My own draft is wrong here.** The final spec
  should use `dev.abra.*` and `DESIGN.md` §4 should be corrected.
- **Where my draft loses, I say so.** My draft is a wire-format document only; it has no
  delivery protocol, no pairing, no enrollment, no adapter contract, no relay, and no
  versioning chapter. In those six areas it is not a contender and I do not pretend otherwise.

---

# Part 1 — `draft-gpt56-sol.md` (GPT-5.6 Sol)

Overall: the most *disciplined* of the three. Densest per line, strongest on canonicalization,
versioning, authorization-at-receipt, and adapter safety. Its failures are concentrated in
two places — the bulk data path, and lease liveness — and both are serious.

## 1.1 Defects

### D1. `snapshot_id` includes the signature, and strict Ed25519 is never required (§2 "Canonical JSON and snapshot ID", §4 "Identity and signatures")

The id is `BLAKE3(canonical manifest *including* `signature`)`. Consequences:

- **Ed25519 malleability forks the id.** RFC 8032 verification as implemented by many
  libraries accepts a signature whose scalar `S` has had the group order `L` added
  (non-canonical `S`), and accepts small-order/mixed-order `A`. §4 says "RFC 8032" nowhere
  and says nothing about canonical-`S` or ZIP-215-style checks. So a third party can take a
  valid manifest, mutate the signature bytes, and produce a *second valid manifest with the
  same content, same signer, and a different `snapshot_id`*. That breaks DAG identity
  (`parents` now has two names for one commit), breaks dedup, and breaks "fetch it, hash it,
  compare".
- **Content identity is entangled with authorship.** The same bytes signed under a rotated
  key are a different snapshot. There is no key-rotation story in the draft, so this is latent
  rather than immediate, but it is the wrong shape.

Grok's split (`snapshot_id` = hash of the manifest; signature is over the 32-byte id, stored
outside) does not have this problem. The fix is not to drop the in-manifest signature — see
B1, it is GPT's best idea — but to define `snapshot_id` over the manifest *minus* `signature`,
and to mandate strict verification.

### D2. Live lease takeover is impossible — this contradicts settled decision 9 (§5 "Capsules, history, and leases")

§5: "The signer MUST be the prior unexpired holder, except the capsule creator signs epoch 0
and **an expired lease may be acquired** by any peer authorized for that capsule."

Settled decision 9 says "takeover = grabbing the lease **from another device**", with the
integrator contract "on lease loss, agent stops acting". In GPT's rules there is no such
operation. If a device holding a 24-hour lease goes to sleep, crashes, or is on a plane, the
only paths are (a) wait up to 24 hours, or (b) fork every write. The design treats takeover as
a first-class user action ("grab the lease from my laptop, I'm on my phone now"); this draft
makes it structurally unavailable.

### D3. Same-epoch lease conflict is a stall with no escape hatch (§5, plus Open Questions)

"Competing valid records at the same epoch are a lease conflict: neither authorizes
canonical-head writes until an authorized device issues a higher epoch referencing one selected
record." But the only signers permitted at epoch N+1 are the *prior unexpired holder* — and
during a conflict there are two of those, each with a valid epoch-N record. The rule that
resolves the conflict requires the conflict to already be resolved. The draft's own Open
Questions admits it ("Define an administrator-mediated resolution record for same-epoch lease
conflicts"). Net effect: a two-device race locks the capsule until expiry — up to 24h.

D2 and D3 compound: no takeover *and* no conflict resolution means the failure mode of GPT's
lease is "the capsule is read-only for a day". Grok's failure mode is the opposite and also
wrong (see G4), which makes this the clearest place where synthesis beats either draft.

### D4. Bulk bytes go base64-in-JSON as the interoperable baseline (§6 "Secure delivery protocol")

"Blob chunks are base64url without padding inside JSON... maximum frame length is 16 MiB...
Chunks are at most 8 MiB decoded. Implementations MAY use an equivalent binary data stream
only after negotiating an extension."

Abra's headline cargo is whole workspaces and **Firecracker memory files** — routinely
512 MiB–8 GiB. This mandates:

- ~33% wire inflation plus JSON string-escape scanning on every byte;
- a JSON parse of a 16 MiB frame per 8 MiB of payload (≈256 frames and 256 full-frame
  buffers for a 2 GiB memory blob), all through the control stream;
- head-of-line coupling between control messages and bulk data on one framed channel.

Grok's dedicated unidirectional object streams (`u8 kind | digest[32] | u64be total | u64be
offset | bytes`) are simpler *and* correct. There is no upside to the JSON path here; the
"interoperable baseline" argument does not apply when the binary framing is 26 bytes of header.

### D5. Per-object signed `object_ack` (§6)

Every object gets `{delivery_id, object_id, size, hash, signature}` with domain
`abra-object-ack-v1`. A 100k-file workspace is 100k Ed25519 signatures and 100k control
frames on the receive path, to establish a property that the single `snapshot_ack` already
establishes ("sent only after all objects and the manifest are durable"). The design context
asks for one thing: "ACK (cryptographic; only then clear outbox)." Make `object_ack`
unsigned progress reporting, or drop it.

### D6. No `.abra`/metadata carve-out — the daemon captures itself (§3, §10, §11)

The draft never specifies the local materialization layout, and never exempts daemon metadata
from capture. Decision 12 and `DESIGN.md` §8 forbid ignore logic, but *Abra's own state
directory is not user files*. As written, snapshotting a capsule folder whose daemon state
lives inside it captures the lease records, the outbox, and — depending on layout — the
device private key, then teleports them. Grok's `.abra/` carve-out (§3.4) and mine both
handle this; GPT does not. This is both a correctness bug (self-referential capture) and a
key-exfiltration path.

### D7. Enrollment tokens have no distribution mechanism (§6 `hello`, §7 "Pairing and enrollment")

`hello` carries `"grants":[<token-id>...]` — **token IDs only**. §7 requires the receiver to
verify issuer, audience, expiry, scopes and revocation, i.e. to have the *token document*.
Nothing in the draft ever transmits a token document between peers. A non-issuing full device
therefore cannot authorize a guest at all. Implementer-blocking.

Related: §7's revocation records are "distributed over the same durable delivery channel",
but that channel (§6) only carries snapshots; no message type carries a revocation.

### D8. `audience` binding has an unaddressed chicken-and-egg (§7)

`audience` binds the token to the sandbox peer key at mint time. This is the right security
property (see B3) — but decision 7 says infra "adds the binary AND the token", and a fresh
sandbox generates its keypair on first start. The issuer cannot know `audience` before the
sandbox exists unless the key is pre-provisioned. The draft never addresses this, so the
deployment story it implies (infra generates the keypair and injects it alongside the token)
is invisible to an implementer.

### D9. Parents sorted lexicographically, capped at 2 (§1 manifest table)

"0–2 distinct IDs, **ordered lexicographically**." Sorting destroys first-parent semantics:
after a reconciliation you can no longer tell which parent was the mainline and which was the
fork being merged in. Every history UI (`log --first-parent`, "what changed on main") depends
on that ordering. Grok's "Order is significant and MUST be preserved" is correct. The cap at
2 is defensible; the sort is not.

### D10. "Every parent MUST be a known full snapshot in the same capsule" (§5) blocks incremental sync

There is no orphan/pending state and no mechanism to fetch missing ancestors. A device that
receives snapshot N without N-1 must reject it, and nothing in §6 lets it ask for N-1. So
enrolling a new device or catching up after a long offline period is unspecified — in practice
you would have to replay the entire history in topological order via repeated offers, which
the outbox model does not describe. Grok explicitly stores such records as `orphan`.

### D11. `hello_auth` claims a channel binding it does not provide (§6)

"each sends `hello_auth` with ... both peer IDs and nonces ... This binds peer authentication
to the encrypted channel." It binds to *nonces exchanged inside* the channel, not to the
channel — there is no TLS/QUIC exporter value, no transcript hash. Since §6 already states
the transport is mutually authenticated with the same Ed25519 identities, `hello_auth` is
redundant; and if it is kept for defence in depth, the stated property requires an RFC 5705 /
QUIC-TLS exporter in the signed input. As written it is a false claim in a security section.

### D12. Smaller items

- **`payload` is required on every manifest** (§1) but the draft never says whether `{}` is
  legal for a kind with no registered schema. An implementer receiving an unknown kind cannot
  tell whether to reject. (Grok explicitly allows `{}`.)
- **`dev.abra.handoff.v1` duplicates `title` and `link` into the payload** (§11) with a MUST
  that they be equal. Two sources of truth for a floor field, one more validation rule, zero
  gain. Grok deliberately removes the duplicate; that is right.
- **Capability-link AEAD uses empty associated data** (§9). Bind at least the version and the
  hosted-object header; Grok binds `magic||alg||nonce||expires_at`, mine binds `abra.link.v1`.
- **The viewer "MUST verify ... signature before display"** (§9) without any trust anchor. It
  should be stated that this verifies integrity and *self-asserted* authorship only; a link
  viewer has no basis to trust `signer`.
- **`mode` as decimal `420`/`493`** in tree JSON (§3) is legible-hostile in an inspectable
  format; `"file"`/`"exec"` (mine) or a kind byte (Grok) reads better and admits no invalid values.
- **The capsule creator who signs epoch 0 is undefined** (§5) — with no genesis record there is
  nothing that binds a random capsule id to a creator, so a receiver cannot verify that the
  epoch-0 signer was entitled. Grok's genesis record (§5.1) fixes exactly this.

## 1.2 Best ideas worth adopting

**B1. The signature lives inside the manifest, and `signer` is a required field (§1, §2).**
This is the single most valuable idea in either draft and it is **better than my draft**, which
has no manifest signature at all. It means a manifest is self-authenticating *wherever it
travels* — through a relay, inside a capability-link bundle, re-hosted on a third-party server,
parsed server-side by a developer who skipped the viewer. Grok's out-of-band `record_sig`
authenticates only on the mesh hop; its capability-link pack (§9.2) carries no signature at
all, so a shared link's `origin.peer_id` is an unauthenticated claim. Adopt GPT's placement,
with D1's fix (hash excludes the signature field).

**B2. "Receivers MUST reject noncanonical manifest bytes rather than silently reserialize
them" + "MUST retain original canonical manifest bytes, not reconstruct them" (§2, §12).**
Precise, cheap, and it eliminates the entire class of cross-implementation id drift. Grok has
the second half (§2.2 persistence rule) but not the first as a hard receiver obligation.

**B3. `audience`-bound enrollment tokens (§7).** A stolen token is inert because it names the
guest key it may be used by. Grok's first-use TOFU bind (§7.2) means **a leaked token binds to
whoever presents it first — i.e. the attacker** — and Grok's own rationale misstates this as a
strength. GPT's property is the right one; it just needs D8's deployment note.

**B4. Rollback as a new one-parent snapshot carrying `{name:"rollback", value:<target>}` (§5).**
Elegant: rollback replicates through the existing signed DAG with no mutable-pointer gossip,
and the history shows that a rollback happened rather than silently rewinding a label. Better
than a bare pointer move.

**B5. `labels` as an array of `{name, value}` in the *hashed* manifest, with reserved names
`agent-turn`, `fork`, `rollback`, `checkpoint` (§1).** A single `label` string (mine) can't
express `rollback=<snapshot_id>`; a bare tag list (Grok's `tags`) can't either. The
name/value shape is strictly more expressive at no cost.

**B6. `origin` as an object: `{peer_id, device_name, adapter, captured_at}` (§1).** Renders
"from Vividh's laptop" with no directory lookup, records which adapter produced the capture,
and separates capture-start from capture-complete. **Better than my bare `origin` peer-id
string.** Grok has the equivalent.

**B7. Daemon-created `staging_dir` for adapter export, with "Adapters MUST NOT write outside
`staging_dir`" and "adapters never choose IDs or origin" (§10).** See G9 — this is a real
security boundary that Grok's contract gives away.

**B8. `snapshot_ack.shelf` (`capsule`|`inbox`) (§6).** One extra field, and the sender learns
where its delivery landed. Cheap and useful; neither other draft has it.

**B9. `want.resume` as a *map* of object-id → offset (§6).** Resumes many objects in parallel;
Grok allows at most one partial object, which throttles resume on a 100k-file transfer.

**B10. §12 in its entirety.** "Unknown top-level fields outside `extensions` are rejected when
validating canonical signed records; this prevents different implementations assigning
different meaning to signed data." Exactly right, and the reasoning is the reasoning. Also:
`extensions` as the single open namespace, unknown enum values rejected, minor versions may
only add feature-gated optionals. Best versioning treatment of the three by a wide margin.

**B11. The Open Questions section is honest.** It names the four things that are genuinely
unfinished (relay HPKE suite, tree metadata, revocation freshness, lease-conflict recovery)
instead of hiding them. That is worth more to a synthesizer than false completeness.

---

# Part 2 — `draft-grok46.md` (Grok 4.6)

Overall: the most *implementable* of the three. It is the only draft where an engineer could
sit down and write the daemon end to end — every record has a field table, every signature has
a domain, the outbox has a state diagram, the handshake has reject reasons. It pays for that
breadth with several concrete security and fidelity errors, and one of them is the worst
single defect in either draft.

## 2.1 Defects

### G1. The relay tag is keyed by the recipient's *public* key — blind addressing is not blind (§8.1)

```
tag = HMAC-SHA256(key = recipient_ed25519_pk (32 bytes), msg)
```

The HMAC key is public information. In this very draft:

- `peer_id` **is** the Ed25519 public key (§4.1), by design, so it is in every manifest's
  `origin`, in every pairing ticket (§7.1), in the `enroll-ok` mesh list handed to guests
  (§7.2), and in the token's `intro` array;
- it is the **iroh NodeId**, so it appears in QUIC handshakes and is known to iroh's own relay
  infrastructure.

Therefore anyone who has ever seen the recipient's peer id — a revoked guest, a paired device
that was later removed, a third party who received a capability link, the relay operator if
they run any peer — can compute every future daily tag, poll the relay for that recipient's
traffic, and enumerate, correlate across days, and (with delete-on-fetch, §8.4) **drop** their
messages. Decision 6 requires "blind: E2E + HMAC(recipient-key, epoch-day) addressing so the
relay can't read or **correlate**". This satisfies the letter and inverts the intent.

Fix is GPT's: a separate, randomly generated 32-byte **relay discovery key** per recipient,
distributed at pairing/enrollment, never derived from the identity key. Grok's envelope format
is otherwise the better one — keep it, rekey it.

### G2. Capability-link bundles carry no signature and no signer (§9.2, §4.3)

The capability pack is `{spec, type, snapshot_id, manifest, blobs}`. The viewer "MUST re-encode
Abra-CJSON and verify `snapshot_id` before trusting the card" — which proves only that the
bytes hash to the id printed next to them, i.e. nothing. Because Grok's authorship signature
(`record_sig`, domain `snapshot`) lives in the *snapshot record* and not in the manifest, it is
dropped the moment a snapshot leaves the mesh. Anyone can mint a link whose `origin.peer_id`
is your key, and the viewer will render it as from you. Same problem for relay packs and for
"developers may skip the viewer and parse snapshots server-side" (decision 10) — the
server-side parser has no way to authenticate anything.

Adopt GPT's in-manifest `signer`/`signature` (B1).

### G3. Lease `prev_hash` is required but explicitly not enforced, and "highest `seq` wins" is hijackable (§5.4)

The record requires `prev_hash` = BLAKE3 of the previous lease's full CJSON. Then:

> **`prev_hash` mismatch.** If `prev_hash` does not match the local winning lease's hash,
> accept the new record only if its `seq` is still greater.

So the chain is decorative: any record with a bigger `seq` is accepted regardless of what it
claims to follow. Combined with "**Winning lease.** Highest `seq` wins" and `seq` being a u53,
a peer with `scopes.lease_acquire` (which the draft **defaults to `true` for agents**) can
issue `seq = 9007199254740991` and hold the capsule forever — no other device can ever outbid
it, and no expiry helps because the holder can refresh. A compromised or merely buggy cloud
agent locks the user out of their own capsule permanently. The per-mode check `seq == old+1`
does not save this, because the *acceptance* rule never re-checks it against a known-good chain.

Fix: enforce the chain (`prev_hash` MUST match a locally known winning record, `seq` MUST equal
that record's `seq + 1`); reject gaps; treat an unmatched `prev_hash` as a fork to be resolved,
not as a promotion.

### G4. Same-`seq` tiebreak on `acquired_at` is trivially gamed (§5.4, Open Question 1)

"compare `acquired_at` lexicographically (later wins)". `acquired_at` is chosen by the signer.
Any peer that wants to win a lease race sets it a year in the future. The draft's Open Question
frames this as a UX surprise about clock skew; it is an authorization bypass. Tiebreak on
something the claimant cannot choose to its advantage — e.g. lexicographically greater
signature bytes (which Grok already uses for label-ops, §5.3) — or refuse and require an
explicit resolution. Never on a self-asserted timestamp.

### G5. NFC normalization of path components breaks byte-for-byte fidelity (§0.2, §3.2, §2.3)

"NFC ... applied before hashing or path comparison"; tree entry names are "UTF-8 **NFC**, path
component". On a filesystem that stores names as bytes (ext4, xfs, zfs), `café.txt` (NFC)
and `café.txt` (NFD) are **two different files that legitimately coexist**. Under this
rule they normalize to the same name, the tree has duplicate names — which §3.2 makes illegal —
and the workspace becomes unsnapshottable. In the non-colliding case, the file materializes on
the receiver under a different byte sequence than it had on the sender, which is exactly the
"byte for byte" guarantee of decision 12 being violated by the core.

Normalization is a *comparison/display* concern. Store names as the bytes they are; if you want
a portability warning, warn.

(Related, and true of all three drafts including mine: mandating valid UTF-8 for names makes a
Linux workspace containing a non-UTF-8 filename unsnapshottable. The final spec should carry
names as opaque bytes with a UTF-8 hint, or state the limitation explicitly rather than by
implication.)

### G6. Windows reserved names are a *format validity* rule (§3.2)

"Component MUST NOT be `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`
(case-insensitive)". This means a Linux user with a file named `aux` or a Go project with
`nul.go`... cannot produce a valid snapshot at all — on *any* platform, for the benefit of a
Windows receiver that may never exist. The draft's own Open Question 2 notices the pain and
still keeps the rule. Wrong layer: this is import-time host policy (materialize with an escape,
or refuse *on Windows*), not a constraint on what bytes may exist in a tree.

### G7. Domain-tagged, length-prefixed blob ids forfeit verified streaming (§3.1)

```
blob_id = BLAKE3("abra-blob-v1" || 0x00 || u64be(len) || bytes)
```

Two costs, one of them significant:

- **No bao / iroh-blobs interop.** iroh's blob layer verifies large content incrementally
  against a *plain* BLAKE3 root using the bao tree. Prefixing the preimage makes Abra blob ids
  incompatible with it, so a multi-GB Firecracker memory blob can only be verified **after the
  whole object arrives** — which §6.1 confirms ("After EOF, receiver computes `blob_id`"). On a
  flaky link, an 8 GiB transfer that is corrupted at byte 3 is detected 8 GiB later, and the
  resume logic can't do better because a resumed prefix cannot be verified either.
- The stated benefit — preventing blob/tree confusion — is obtainable for free: in both my
  draft and GPT's the object kind comes from the referencing field, and a magic prefix
  *inside the tree body* separates tree bytes from file bytes without touching file hashing.

Decision 15 says "content addressing with blake3", which reads as plain BLAKE3. Use plain
BLAKE3 for file/native blobs.

### G8. The bootstrap handshake is specified three incompatible ways (§4.4, §6.2, §7.1)

- §4.4: "Unlisted authentic-transport peers: handshake `hello-reject` with `reason:
  "untrusted"`."
- §6.2: "Unknown peer: send `hello-ok` with `session: "bootstrap"` ... `reason: "untrusted"` is
  reserved for a bootstrap that then fails". Allowed types after bootstrap: `pair-request`,
  `pair-abort`, `pair-accept`, `enroll-bind`, `enroll-ok`, `error`.
- §7.1 step 3: "Handshake `hello` will fail `untrusted` — **exception**: ... only permits
  `type` in `{hello, hello-ok, pair-request, pair-abort}` until trusted."

§4.4 rejects unknown peers outright, which makes pairing and enrollment impossible. §7.1's
allow-list omits `enroll-bind`, which makes **enrollment specifically** impossible. §6.2 is
presumably the intended rule. An implementer cannot proceed without picking one; pick §6.2 and
delete the other two.

### G9. The adapter chooses the directory the daemon hashes (§10.3)

`export` returns `dir` — "Staging directory the daemon will hash into a tree. Absolute." The
daemon then hashes whatever path it is handed, stores it in CAS, and teleports it. A
compromised or sloppy adapter returns `dir: "/home/user"` or `"/home/user/.ssh"` and the daemon
exfiltrates it, signed, to the mesh — and with the flat client model (decision 11) plus
capability links (decision 10), onward to anywhere. Adapters are third-party executables by
construction (decision 14, `DESIGN.md` §11 "run under their own permissions"), so this is a
real boundary, not a hypothetical.

GPT's inversion is correct: the **daemon creates** an empty writable `staging_dir`, passes it
in, and the adapter may only write inside it.

### G10. `spec` §12.2: "Unknown **required-looking** field ... it is optional by definition; ignore for semantics, preserve bytes"

This is the exact rule GPT correctly forbids. Inside a signed record, silently ignoring an
unknown field lets a future version's semantics-changing field (`redacted: true`,
`parents_extended: [...]`, `encrypted_payload: ...`) be dropped by an old node that still
verifies the signature and renders the card as authentic. Grok is partly saved by rejecting any
`spec` other than `abra/0.1` outright — but that protection disappears the moment `1.x` is
declared "additive". Replace with GPT's rule; add a critical-extensions mechanism if
forward-compatible semantics changes are ever needed.

### G11. Core validation is conditional on payload kind (§1.1, §1.2)

"`tree` ... **Required for `dev.abra.workspace`**." `DESIGN.md` §12 lists "Interpreting payload
semantics in core" as a non-goal, and decision 4/5 put all kind knowledge in receivers. A core
validator that must know what `dev.abra.workspace` means to decide manifest validity has a
built-in registry. GPT's kind-agnostic version of the same constraint — "`files` required for
every `full`; an empty tree is used when a full snapshot has no files" — achieves the intent
without the layering violation. (Grok's `native` ⇒ `tree` rule is kind-agnostic and good; keep
that one.)

### G12. `offer` carries the manifest twice (§6.4)

`manifest` (parsed object) **and** `manifest_raw` (hex of the exact bytes), with "receiver
re-canonicalizes *or* uses `manifest_raw`". That doubles the manifest on the wire (and hex is
2× where base64 is 1.33×), and the "or" creates precisely the divergence class §2.2's
persistence rule exists to prevent. Send `manifest_raw` only; parsing is the receiver's job.

### G13. Smaller items

- **`tags` sorting rule is muddled** (§1.1): "producers MUST emit sorted; consumers MUST reject
  unsorted when verifying a signature over the canonical bytes — verification is of bytes, so
  producers canonicalize". Canonical JSON preserves array order (§2.1 rule 3), so an unsorted
  `tags` array is perfectly canonical and hashes fine. State it plainly: tags MUST be sorted and
  duplicate-free; receivers MUST reject manifests that are not.
- **`control` replay window undefined** (§6.8): a 16-byte `nonce` is "anti-replay" but nothing
  says how long a receiver must remember nonces. Without a window (or a timestamp inside the
  signed payload), replay protection does not exist.
- **`control` is not durable** (§6.8): it is a live message, not an outbox entry, so "pause"
  sent to a sleeping agent is simply lost — for the one message class where delivery matters
  most. GPT models control as a typed partial snapshot and gets outbox durability for free
  (though GPT never defines the kind, so neither draft actually ships this).
- **X25519 derived from the Ed25519 identity key** (§4.2): key reuse across signature and DH
  algorithms, flagged by the draft's own Open Question 5 as an interop risk. §4.2's heading
  says "for capability links and relays" but capability links (§9) use a fresh random key, so
  the derivation is only needed for relays. Cleanest fix: carry a separate X25519 public key in
  the pairing/enrollment record and delete the derivation.
- **Dead scope fields** (§7.2): `pair` and `control` "MUST be **false** in v0.1" and receivers
  must reject `pair: true`. A field whose only legal value is `false` should be absent.
- **`head` is defined as an alias of `main`** (§5.3) and then Open Question 6 asks whether it
  should ever differ. Delete `head` from v0.1; it is a name with no referent.
- **Fork label spam**: any writer, including a guest, can create `fork/<8hex>` labels up to the
  128-label cap. Bound per-peer, or make `fork/*` local-only.

## 2.2 Best ideas worth adopting

**G-B1. §4.3's signature table.** One table mapping every domain (`snapshot`, `ack`, `lease`,
`genesis`, `label`, `control`, `pair-ticket`, `pair-request`, `enroll`, `revoke`,
`enroll-bind`, `cap-mint`) to its exact payload bytes and where it's stored. This is the single
most useful artifact in any of the three drafts — it makes domain-separation auditable at a
glance and makes it obvious when a new record type forgets one. **My draft defines exactly one
domain and no table.** Adopt this wholesale.

**G-B2. Binary unidirectional object streams (§6.1).** 42 bytes of header, one object per
stream, resume by `offset`, chunking delegated to QUIC. Simple, fast, and it keeps bulk data
off the control channel. Strictly better than GPT's base64 frames.

**G-B3. The outbox state machine (§6.10) with a stable `offer_id` across resume.** The diagram
plus the rule that a *new user-initiated attempt* gets a new `offer_id` while a *resume* keeps
the old one is the detail that makes the ack signature (`offer_id || snapshot_id`) actually
prevent stale-ack clearing. GPT's `delivery_id` does the same thing; Grok's presentation is the
one an implementer can build from. Adopt Grok's machine with GPT's retry policy (1s → 5min
doubling, ±20% jitter).

**G-B4. Capability link: viewer origin decoupled from ciphertext host (§9.1).**

```
https://<viewer-origin>/#v=1&u=<base64url(ciphertext_https_url)>&k=<base64url(key)>
```

Everything — including *which object is being fetched* — is in the fragment. The viewer's own
server learns nothing at all, not even that a view happened, and the ciphertext can live on any
host with permissive CORS. **This is better than my draft and better than GPT's**, both of
which put the object id in the path of the viewer's URL and thereby leak per-link access
patterns to whoever hosts the viewer. It is also the most faithful reading of decision 10
("encrypted blob hosted **anywhere**"). Adopt, together with §9.2's AEAD-bound header
(`AAD = magic||alg||nonce||expires_at`) and the plaintext `expires_at` for CDN TTL.

**G-B5. Two distinct history vocabularies (§1.1 `tags`, §5.3 labels).** Immutable annotations
inside the hashed manifest (`tags`: `agent-turn`) *and* mutable signed pointers outside it
(`main`, `fork/<8hex>`, via an appended, signed `label-op` log). Both concepts are needed and
Grok is the only draft that separates them cleanly. Note the vocabulary collision to be
resolved in synthesis: GPT's `labels` are Grok's `tags`, and Grok's `labels` are what GPT
leaves undefined as "one optional preferred head".

**G-B6. Fork-on-write as a first-class, non-error path (§5.5).** The writer's snapshot is
*valid and stored*, `main` does not move, a `fork/<id>` label is created, and the SDK is told
`forked: true`. Reconciliation is an explicit two-parent commit by a lease holder. This is
decision 9 implemented exactly, and it protects the case that actually matters: an agent that
did an hour of work while its lease quietly expired does not have that work discarded.

**G-B7. The capsule genesis record (§5.1).** A signed binding of the random `capsule_id` to its
creator, plus a root for the lease chain's `prev_hash`. It fixes a hole GPT has: "the capsule
creator signs epoch 0" is unverifiable when nothing attests who the creator is.

**G-B8. Enrollment `intro` list + `enroll-bind` handshake (§7.2).** The token names peers the
guest should dial, the guest proves possession of its key by signing `token_id ||
guest_peer_id`, the intro peer persists the binding and replies with the mesh list. This is the
only complete bootstrap story in any draft — GPT's guest has a credential and no defined way to
present it (D7). Adopt the mechanism; replace the TOFU binding rule with GPT's `audience` (B3).

**G-B9. `abra.allow_agent_send`, a *local* flag the token cannot widen (§7.4).** "the guest
daemon SHOULD expose send only when the token has `send: true` **and** a local policy flag ...
is enabled (default false)." Decision 8 asked for exactly this two-key structure and Grok is
the one that names the flag and its default.

**G-B10. `native` present ⇒ `tree` present (§1.1).** One line that makes "native blobs are never
the source of truth" structurally true instead of merely asserted. Neither GPT nor I have it.

**G-B11. The `.abra/` carve-out with its justification (§3.4).** "the only v0.1 exception to
'no ignore logic'; it is Abra's own metadata, not user file exclusion." Correct, and correctly
argued against decision 12 rather than around it.

**G-B12. Empty directories are representable** (§3.2, kind-4 entry → zero-entry tree with a
fixed known id). Mine and GPT's both support it structurally; Grok is the only one that states
the fixed id of the empty tree, which is the kind of detail that stops two implementations
disagreeing on day one.

---

# Part 3 — Verdict per major area

Judging all three, mine included.

| Area | Strongest | One-line reason |
|---|---|---|
| **Manifest schema** | **Grok** | Complete field tables with bounds and a correct full/partial asymmetry, plus `native ⇒ tree`; but must take GPT's in-manifest `signer`/`signature` and `origin` object. |
| **Canonical serialization / ids** | **GPT** | Only draft with both a full string-escape table *and* the "reject noncanonical bytes, never reserialize" receiver obligation — though its id must stop covering the signature (Grok's split is right). |
| **Content addressing** | **GPT** | Inspectable JSON trees with per-entry `size` and plain-BLAKE3 object ids; Grok's trees are more complete but its NFC/reserved-name rules break fidelity and its tagged blob ids kill verified streaming. |
| **Identity / signatures** | **Grok** | §4.3's domain→payload table is the best security artifact in any draft; mine has one domain, GPT's rule is uniform but untabulated. |
| **Capsule / DAG / lease** | **Grok** | Genesis + fork-on-write + `lease-update` notification is the only end-to-end model, but its `seq` acceptance rule is exploitable and needs GPT's chain discipline. |
| **Delivery protocol** | **Grok** | Binary object streams, stable `offer_id` across resume, and a usable state machine; take GPT's backoff/jitter, `shelf`, multi-object resume map, and receiver-recomputes-`have` rule. |
| **Pairing / enrollment** | **Grok** | Ticket → live round-trip → user confirm, plus `intro`/`enroll-bind`/revocation flooding; GPT's `audience` binding is the better credential inside Grok's mechanism. |
| **Relay** | **GPT** | The only draft whose blind addressing is actually blind (separate discovery key); Grok's envelope format is better but keyed with the recipient's public key. |
| **Capability links** | **Grok** | Fragment-carried ciphertext URL decouples viewer host from content host — better than mine and GPT's; needs GPT's manifest signature so the card has an authenticated origin. |
| **Adapter contract** | **GPT** | Daemon-owned staging dir, "adapters never choose IDs or origin", cursor semantics, cancel + 5s kill, real error taxonomy; Grok's adapter-chosen `dir` is a hole. |
| **Payload kinds** | **GPT** | Tighter schemas (`vcs` metadata, `default_cwd` must resolve in the tree), minus the `title`/`link` duplication, which Grok correctly refuses. |
| **Versioning** | **GPT** | Reject unknown fields in signed records, `extensions` as the only open namespace, feature-gated minors, retain original bytes — no contest. |

My own draft wins none of these outright. Its only defensible edges are the tree-object
encoding (a magic-prefixed byte format that keeps file blobs on plain BLAKE3 while still
separating trees from blobs) and the worked examples with concrete hashes — which neither
other draft provides and which are the fastest way to catch a canonicalization disagreement
between implementations. Its `mode` names (`file`/`exec`/`link`/`tree`) also read better than
decimal `420`/`493`. Everything else is thinner than one or both alternatives, and it is
missing six chapters they have.

---

# Part 4 — Synthesis guidance: ranked top 10

1. **Rekey the relay. Take GPT's separately-provisioned 32-byte discovery key, put it in
   Grok's envelope format.** Grok's `HMAC(recipient_ed25519_pk, epoch-day)` is computable by
   anyone who has ever seen the recipient's peer id — which, because `peer_id` *is* the iroh
   NodeId, means every paired device, every revoked guest, every capability-link recipient, and
   the QUIC layer itself. Generate a random `relay_key` per device, hand it out at
   pairing/enrollment alongside the public key, and keep Grok's `ABRAREL1`/`ABRABL1` split
   (with its rule that object envelopes must not expose the digest in plaintext). Also keep
   Grok's §8.3 requirement that a receiver holds a pending-ack list and delivers acks on the
   next live dial — that is what lets relays ship later without breaking outbox correctness.

2. **Put the signature in the manifest (GPT), but hash the manifest without it (Grok).**
   `signer` and `signature` become required manifest fields, so a snapshot self-authenticates
   inside a capability-link bundle, a relay pack, or a developer's server-side parser.
   `snapshot_id = BLAKE3(domain || canonical_manifest_minus_signature)`. Mandate strict
   Ed25519 verification (canonical `S`, reject small-order `A`) so no third party can produce a
   second valid encoding. This fixes GPT's D1 and Grok's G2 in one move, and fixes my draft,
   which has no manifest signature at all.

3. **Lease = Grok's records and state model + GPT's chain discipline + a clock-free tiebreak.**
   Keep Grok's genesis root, four modes, `lease-update` push to the loser, and fork-on-write.
   Replace the acceptance rule: a record is accepted only if `prev_hash` matches a locally
   known winning record **and** `seq == that.seq + 1` — no gap promotion, which closes the
   `seq = 2^53-1` capsule-lock (G3). Tiebreak equal `seq` on greater signature bytes, never on
   the self-asserted `acquired_at` (G4). Keep live takeover as a first-class mode (Grok) rather
   than GPT's expiry-only acquisition, which contradicts decision 9 (D2) and deadlocks (D3);
   the deterministic tiebreak is what lets you have takeover without GPT's stall.

4. **Bulk transfer: Grok's binary object streams; delete GPT's base64 `blob_chunk` and its
   per-object signed `object_ack`.** Keep exactly one cryptographic ack (decision 6's "ACK
   (cryptographic; only then clear outbox)"), signed over `offer_id || snapshot_id` (Grok) plus
   the recipient and sender peer ids, and add GPT's `shelf` field. Layer on GPT's `resume` map
   (object-id → offset, many objects in parallel) instead of Grok's single-partial limit, and
   GPT's retry policy (1s doubling to 5min, ±20% jitter) on Grok's state machine.

5. **Blob ids are plain `BLAKE3(bytes)`.** Drop Grok's `"abra-blob-v1" || 0x00 || u64be(len)`
   prefix (G7): it forfeits bao/iroh-blobs verified streaming, which is the difference between
   detecting corruption at byte 3 and detecting it after 8 GiB of Firecracker memory file. Get
   blob/tree separation the way GPT and I do — kind comes from the referencing field, plus a
   magic prefix inside the tree body — not by poisoning file hashing.

6. **Enrollment: GPT's credential inside Grok's mechanism.** `audience`-bound tokens (a leaked
   token is inert) delivered through Grok's `intro` → `enroll-bind` → `enroll-ok` flow, which is
   the only working bootstrap in any draft. Because decision 7 has infra injecting binary and
   token before the sandbox generates its key, permit an `audience`-less token **only** with a
   short (minutes, not the 24h/30d expiry) first-bind window and issuer-side approval; then
   Grok's TOFU bind stops meaning "leaked token = attacker's guest device". Specify token
   *distribution* explicitly — GPT's `hello.grants: [token_id]` cannot work (D7) — and give
   revocation records their own message type. Keep Grok's `abra.allow_agent_send` local flag
   that no token can widen (decision 8).

7. **Delete every rule that trades byte-for-byte fidelity for portability.** Drop NFC
   normalization of tree path components (G5) — it makes NFC/NFD siblings collide into an
   illegal duplicate-name tree and changes bytes in transit. Move the Windows reserved-name
   check from format validity to Windows-side import policy (G6). Keep exactly one exclusion,
   Grok's `.abra/` carve-out with its justification (G-B11), and add it to GPT, which has none
   and would otherwise capture the daemon's own state including the device key (D6). Also state
   plainly what is lost: mtimes, ownership, non-exec mode bits, xattrs, non-UTF-8 names.

8. **Adopt GPT's §12 versioning chapter verbatim and delete Grok's §12.2 exception.** Unknown
   top-level fields in signed records are rejected; `extensions` (reverse-DNS keys) is the only
   open namespace and round-trips unmodified; unknown enum values rejected; minors add only
   feature-gated optionals; implementations retain original canonical bytes rather than
   reconstructing them. Grok's "unknown required-looking field ... is optional by definition"
   (G10) is a semantics-substitution hazard in exactly the documents where it matters.

9. **Adapter contract: GPT's, plus two things from Grok.** The daemon creates the empty
   `staging_dir` and the adapter may only write inside it — never Grok's adapter-supplied
   absolute `dir`, which lets a third-party executable make the daemon hash, sign, and teleport
   `~/.ssh` (G9). Keep GPT's cursor semantics, cancel-then-kill, and error taxonomy, and its
   rule that adapters never choose ids or origin. From Grok, keep the `register` argv
   self-description (nice ergonomics) and the explicit per-verb timeouts.

10. **One history vocabulary, assembled from three pieces.** Immutable, in-manifest annotations
    using GPT's `{name, value}` shape with Grok's name `tags` (so `agent-turn`, and
    `rollback=<snapshot_id>` are both expressible); mutable branch pointers *outside* the
    manifest via Grok's signed `label-op` log (`main`, `fork/<8hex>`), which is the only defined
    head-selection mechanism in any draft (GPT's "one optional preferred head" is undefined);
    and GPT's rollback-as-a-new-one-parent-commit so a rewind replicates through the signed DAG
    instead of a silent pointer move. Keep `parents` ordered and up to 16 (Grok) — GPT's
    lexicographic sort destroys first-parent semantics (D9) — and keep Grok's orphan state so
    out-of-order arrival and incremental catch-up work (GPT forbids it, D10). Add Grok's
    genesis record so "the creator" is a verifiable claim.

**Also fold in, below the top ten:** GPT's `origin` object and `snapshot_ack.shelf`; Grok's
§4.3 domain table as a normative appendix; Grok's fragment-carried ciphertext URL for
capability links (better than mine and GPT's); Grok's `native ⇒ tree` invariant; a redaction
option for `origin.device_name`/`host_*` in link-minted bundles, since a capability link
currently hands the recipient's device name, host OS/arch, and public key to anyone with the
URL; a defined removal path for a *full* peer (both drafts revoke guest tokens only, so a lost
laptop has no answer); a rule limiting `have` disclosure to objects within the offering peer's
scope, so an enrolled cloud agent cannot probe the CAS for the existence of files it guesses at;
and worked examples with concrete hashes for at least one full and one partial manifest, which
is the cheapest possible way to catch a canonicalization disagreement between two
implementations.
