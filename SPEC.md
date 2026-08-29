# Abra Specification v0.1

**Abra is infrastructure for teleportation.**

This document is the implementable contract for Abra: the snapshot format, content
addressing, identity, capsule history, delivery protocol, pairing/enrollment,
optional relay, capability links, and the adapter contract. It was synthesized from
three independently authored drafts (`specs/drafts/`) and their cross-reviews; where
this document disagrees with a draft, this document wins.

Scope: one user's devices and cloud agents. Not a mesh of strangers. Not a general
p2p framework. `MUST`/`SHOULD`/`MAY` per RFC 2119.

---

## 0. Conventions and primitives

| Primitive | Definition |
|---|---|
| Hex | lowercase `[0-9a-f]`, no prefix. 32-byte values are 64 chars. |
| base64url | RFC 4648 §5, **no padding**. |
| UTF-8 | well-formed only; no BOM, no surrogates. **No Unicode normalization is ever applied** — strings and names are carried as the bytes they are. |
| Time | canonical string `YYYY-MM-DDTHH:MM:SS.sssZ` (UTC, exactly 3 fractional digits). Only legal form inside hashed/signed documents. |
| BLAKE3 | unkeyed BLAKE3-256, 32-byte digest. |
| Ed25519 | RFC 8032. Verifiers MUST use strict verification: reject non-canonical `S` (S ≥ L) and small-order/mixed-order public keys or `R`. This guarantees signature bytes are unique for a given (key, message). |
| X25519 | RFC 7748. Each device holds a **separate** X25519 keypair (not derived from the Ed25519 key), used only for sealed boxes (§8). |
| HMAC | HMAC-SHA256 (RFC 2104). |

**Identity.** A **peer id** is the device's 32-byte Ed25519 public key, 64 hex chars.
(It is also the iroh `NodeId`, so transport identity and Abra identity are the same
bytes.) The **short id** — first 8 hex chars of `BLAKE3(pubkey)` — is display-only
and MUST NOT be used for authorization. Keys are generated on first start and stored
with mode 0600.

**Signatures.** Every signature is Ed25519 over a domain-separated preimage:

```
preimage  = "abra-sig-v1" || 0x00 || domain || 0x00 || payload
signature = Ed25519_Sign(sk, preimage)      // 64 bytes, 128 hex chars in JSON
```

Domain table (normative; every signed object in this spec appears here):

| Domain | Payload | Where |
|---|---|---|
| `snapshot` | canonical manifest bytes minus `signature` (§2) | manifest `signature` field |
| `ack` | `offer_id(16) \|\| snapshot_id(32) \|\| sender_peer_id(32) \|\| receiver_peer_id(32)` | `ack` message (§6.7) |
| `genesis` | CJSON of genesis record minus `sig` | genesis record (§5.1) |
| `lease` | CJSON of lease record minus `sig` | lease record (§5.4) |
| `label` | CJSON of label-op minus `sig` | label-op (§5.3) |
| `control` | CJSON of control message minus `sig` | `control` (§6.8) |
| `pair-ticket` | CJSON of ticket minus `sig` | pairing ticket (§7.1) |
| `pair-request` | `ticket_id(16) \|\| nonce(16)` | `pair-request` (§7.1) |
| `enroll` | CJSON of token minus `sig` | enrollment token (§7.2) |
| `enroll-bind` | `token_id(16) \|\| guest_peer_id(32)` | `enroll-bind` (§7.2) |
| `bind-cert` | CJSON of bind certificate minus `sig` | bind certificate (§7.2) |
| `revoke` | CJSON of revocation minus `sig` | revocation record (§7.3) |
| `cap-mint` | CJSON of mint record minus `sig` (never includes the key) | minter store (§9.4) |

---

## 1. The manifest (envelope)

A **snapshot** is one JSON object, the manifest. It is self-describing and never an
opaque blob. One envelope format; `scope` splits behavior:

- `full` — a version of a continuing thing. Belongs to a capsule, has parents,
  subject to the lease. Lands in the **capsule store**.
- `partial` — a one-shot delivery. No lineage, no lease. Lands in the **inbox**.

### 1.1 Fields

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `spec` | string | required | `"abra/0.1"`. |
| `scope` | string | required | `"full"` or `"partial"`. |
| `kind` | string | required | Reverse-DNS payload kind, `^[a-z0-9]+(\.[a-z0-9]+)+$`, ≤ 128 chars. Built-ins: `dev.abra.workspace`, `dev.abra.handoff.v1`. |
| `title` | string | required | Floor card title. Non-empty, ≤ 512 scalars, no U+0000–U+001F. |
| `origin` | object | required | `{ "peer_id": <64-hex full pubkey>, "name": <string ≤80 scalars, optional>, "adapter": <adapter name, optional> }`. `origin.peer_id` is the signer. |
| `created_at` | string | required | Canonical time; capture completion. |
| `summary` | string | optional | ≤ 4096 scalars. |
| `link` | string | optional | Absolute URI (any scheme, incl. `http`), RFC 3986, ≤ 4096 bytes. |
| `thumbnail` | object | optional | `{ "blob": <blob id>, "media_type": "image/png"\|"image/jpeg"\|"image/webp", "bytes": <1..524288> }`. Blob MUST be in the closure. |
| `capsule_id` | string | full: required; partial: forbidden | 32 random bytes, hex (§5.1). |
| `parents` | array | full: required (may be `[]`); partial: forbidden | Parent snapshot ids. 0..16 entries, no duplicates. **Order is significant and preserved** (first parent = mainline). `[]` only for a capsule's root. |
| `labels` | array | full: optional; partial: forbidden | Immutable annotations `{ "name": <`[a-z][a-z0-9._-]{0,63}`>, "value": <string ≤512 scalars \| null> }`, sorted by `(name, value)` (null before strings), no duplicate pairs, ≤ 16. Reserved names: `agent-turn`, `fork`, `rollback`, `checkpoint`. |
| `provenance` | object | partial only, optional | `{ "capsule_id", "snapshot_id", "turn": <string ≤64, optional> }`. A back-reference, never membership; receivers MUST NOT treat it as a parent or fail when the capsule is unknown. |
| `files` | string | full: **required**; partial: optional | Root tree id (§3). A full snapshot with no files uses the empty tree. This rule is kind-agnostic. |
| `recipes` | array | full only, optional | Recipe objects (§1.2), ≤ 256. |
| `native` | array | full only, optional | Native blob refs (§1.3), ≤ 32. Because `files` is required on full, native blobs can never be a snapshot's only cargo. |
| `payload` | object | required | Kind-specific JSON; `{}` is legal (also for unknown kinds). Integers may be negative here (§2). |
| `extensions` | object | optional | Keys MUST be reverse-DNS; values arbitrary JSON. The only open namespace (§12). |
| `signature` | string | required | 128 hex; domain `snapshot` over the canonical manifest **minus this field**. Signer is `origin.peer_id`. |

Floor rule: `kind`, `title`, `origin`, `created_at` are always present; a receiver
that understands nothing else MUST still render a card. Optional fields are omitted,
never `null` (except fields explicitly typed nullable).

### 1.2 Recipe

Recipes are **observed** (by an ambient observer at the sandbox boundary), not
declared, and they are data only — the core never executes one; a receiver may run
one only on explicit user/integrator action.

```json
{"argv":["npm","run","dev"],"cwd":"app","env":{"NODE_ENV":"development"},
 "ports":[5173],"started_at":"2026-08-28T13:00:00.000Z"}
```

`argv`: non-empty, 1..256 entries. `cwd`: **relative** path from the workspace root,
`/`-separated, no leading `/`, no `..`, no NUL (`"."` allowed). Processes whose cwd
cannot be expressed relative to the captured root are omitted by the observer.
`env`: string→string map (canonically key-sorted like all objects); entries whose
name or value is not valid UTF-8 are omitted — recipes are lossy where files are
not, and this is stated rather than hidden. `ports`: sorted unique integers
1..65535 (TCP listen ports observed). `started_at`: optional canonical time.

### 1.3 Native blob ref

```json
{"role":"memory","blob":"<blob id>","bytes":2147483648,
 "fingerprint":{"os":"linux","arch":"x86_64","hypervisor":"firecracker",
                "snapshot_format_major":11,"cpu_template":"-"}}
```

`role`: `[a-z][a-z0-9._-]{0,63}` (`memory`, `vmstate`, `disk`, ...). Fingerprint
fields are required strings (`snapshot_format_major` is an integer ≥ 0;
`cpu_template` is `"-"` when none). A receiver MUST use the blob only if **every**
fingerprint field equals its local value; otherwise it skips the blob without
failing the import. Native blobs are stored byte-for-byte unchanged (e.g.
Firecracker memory + vmstate files) and are an evictable optimization — **never the
source of truth**. Restoring from them is always explicit, never implicit.

### 1.4 Validation matrix (reject on violation)

- `spec` ≠ `abra/0.1` → reject (§12).
- `scope` ∉ {`full`,`partial`} → reject; unknown enum values in core fields → reject.
- `full` missing `capsule_id`, `parents`, or `files` → reject.
- `partial` containing `capsule_id`, `parents`, `labels`, `recipes`, or `native` → reject.
- `full` containing `provenance` → reject.
- `title` empty/over-long/control-chars → reject.
- Any id field not 64 hex → reject (format check only; parent existence is not
  required at validation time — see orphan state, §5.2).
- `signature` invalid under strict Ed25519 for `origin.peer_id` → reject.
- Unknown top-level fields outside `extensions` → reject (§12).

---

## 2. Canonical JSON and the snapshot id

**Abra-CJSON**, applied to every hashed or signed JSON document:

1. Single UTF-8 JSON value, no BOM, no insignificant whitespace.
2. Object keys in strictly ascending raw-UTF-8-byte order; duplicate keys illegal.
3. Arrays preserve element order.
4. Strings: escape `"` as `\"`, `\` as `\\`; escape U+0008/09/0A/0C/0D as
   `\b`,`\t`,`\n`,`\f`,`\r`; remaining U+0000–U+001F as lowercase `\u00xx`; never
   escape `/`; never `\uXXXX` for anything ≥ U+0020; non-ASCII is raw UTF-8.
   Unpaired surrogates are illegal. No normalization.
5. Numbers: integers only, no leading zeros (`0` alone excepted), no `.`/exponent.
   In core envelope fields the range is `0..=9007199254740991`; **inside `payload`
   and `extensions` negative integers down to `-9007199254740991` are legal.**
   Floats, NaN, Infinity: illegal everywhere.
6. `true`/`false`/`null` literals.

**Snapshot id.** Let `U` be the CJSON bytes of the manifest with the `signature`
member removed, and `M` the CJSON bytes of the complete manifest.

```
snapshot_id = hex( BLAKE3( "abra-snap-v1" || 0x00 || U ) )
signature   = sign(domain "snapshot", payload U)
```

The id covers content and authorship claim but **not** the signature bytes, so the
id is computable before signing, and re-signing or signature malleability can never
fork the id (strict verification additionally makes signatures unique). The
manifest still travels with `signature` inside it, so it self-authenticates through
relays, capability links, and server-side parsers.

**Byte authority.** Implementations MUST persist and forward the exact bytes `M`;
verification hashes stored bytes, never a re-serialized DOM. Receivers MUST reject
noncanonical manifest bytes rather than silently reserializing. On the wire the
manifest appears only as raw bytes (`manifest_raw`), never as a parsed-object copy
alongside them.

Implementations MUST ship test vectors (at least: one full and one partial manifest
with canonical bytes and ids, the empty tree id, a signed lease chain) generated
from this spec; `abra-core`'s vectors under `spec-vectors/` are authoritative once
committed.

---

## 3. Content addressing

### 3.1 Blob objects

A blob is raw bytes (file contents, symlink target, thumbnail, native artifact),
stored unchanged:

```
blob_id = hex( BLAKE3( bytes ) )        // plain, undomained
```

Plain BLAKE3 keeps blob ids compatible with bao/iroh-blobs incremental
verification, so multi-GB native blobs can be verified as they stream rather than
after they land. Object *type* comes from the referencing field plus the tree
magic below.

On disk: `<root>/objects/<hex[0..2]>/<hex[2..64]>`, written to a temp file and
atomically renamed; a path either doesn't exist or holds complete verified content.

### 3.2 Tree objects

One directory per tree, git-style:

```
tree      := "abra.tree.v1\n" entry*
entry     := mode 0x20 name 0x00 hash[32] u64be(size)
mode      := "file" | "exec" | "link" | "tree"
name      := UTF-8 bytes, 1..255 bytes, no NUL, no "/", not "." or ".."
size      := blob byte length for file/exec/link; 0 for tree
tree_id   = hex( BLAKE3( tree_bytes ) )
```

Entries sorted strictly ascending by `name` bytes; duplicates illegal. `link`'s
hash refers to a blob holding the symlink target as raw bytes; symlinks are stored
and materialized as links, never followed. `exec` records any-execute-bit set.
The empty directory is the zero-entry tree, `"abra.tree.v1\n"` alone; empty dirs
are representable (a `tree` entry pointing at it). Max reconstructed path 4096
bytes; max depth 512.

Not captured in v0.1 (stated, not implied): mtimes, ownership, non-exec mode bits,
xattrs, ACLs, sparse layout, special files (capture error), non-UTF-8 names
(capture error). There are **no** platform-portability validity rules (e.g.
Windows reserved names): a tree that cannot materialize on some host is rejected
**at import on that host**, never at capture.

### 3.3 Capture and materialization

`snapshot_dir` walks a folder, storing every file as a blob and every directory as
a tree, and returns the root tree id. **It skips exactly one thing: the `.abra/`
metadata directory** — the sole v0.1 exception to "no ignore logic" (it is Abra's
own state, not user files; without this the daemon would capture and teleport its
outbox, lease records, and device key). `.git` and everything else is captured
byte-for-byte; no ignore files, no secret scanning (settled decision).

`materialize` writes a tree to a folder: files 0644, executables 0755, symlinks
with stored targets, creating parents as needed and never following a stored
symlink out of the destination. In v0.1 the destination MUST be nonexistent or
an empty directory and MUST NOT itself be a symlink. Round-trip preserves contents, structure, exec
bits, and symlink targets exactly.

Local layout of a materialized capsule (folder = the local sandbox):

```
<folder>/            # tree contents
<folder>/.abra/      # daemon-owned: capsule id, lease cache, recipes.json,
                     # native/<digest> blobs for matching hosts
```

### 3.4 Closure

A snapshot's object closure = root tree and all children (transitively) ∪ thumbnail
blob ∪ every `native[].blob`. Transfer moves the closure minus what the receiver
already has.

---

## 4. Store shelves

| Shelf | Contents |
|---|---|
| **Capsule store** | genesis records, snapshot records, lease records, label-ops, CAS refs |
| **Inbox** | partial snapshots `{snapshot_id, manifest bytes, from, received_at, read}` + CAS refs |
| **Outbox** | pending deliveries (§6.10) |

GC roots: every snapshot record, inbox entry, outbox entry, in-flight offer, and
unexpired capability mint. Unreferenced CAS objects MAY be collected after 7 days.
Snapshot records are never GC'd in v0.1.

---

## 5. Capsules, history, leases

### 5.1 Genesis

A capsule is created explicitly, before its first snapshot. Genesis record
(CJSON, signed domain `genesis` by `created_by`):

```json
{"spec":"abra/0.1","type":"capsule-genesis","capsule_id":"<32 random bytes hex>",
 "created_at":"<time>","created_by":"<peer id>","kind":"dev.abra.workspace",
 "title":"<capsule title>","sig":"<hex>"}
```

The signature binds the random id to a verifiable creator. The first snapshot has
`parents: []`; every later snapshot names ≥ 1 parent.

### 5.2 Snapshot records and orphans

The capsule store keeps, per snapshot: the exact manifest bytes `M`, `snapshot_id`,
and local metadata (`received_at`). The DAG is implied by `manifest.parents`
(inside the hash, so history is immutable). A record whose parents are unknown
locally is stored as **orphan** — valid, transferable, never eligible to be `main`
— until its ancestors arrive; a device MAY request missing ancestors by offering/
pulling in reverse topological order. Out-of-order arrival is normal, not an error.

### 5.3 Labels: immutable tags and mutable pointers

Two vocabularies, deliberately distinct:

- **In-manifest `labels`** (§1.1): immutable annotations, hashed with the snapshot
  (`agent-turn`, `checkpoint`, `rollback=<snapshot_id>`, `fork=<lease info>`).
  Rollback is performed as a new one-parent snapshot carrying a `rollback` label,
  so a rewind replicates through the signed DAG.
- **Label-ops**: signed mutable pointers outside the hash, in a per-capsule log.
  `main` is the canonical head. `fork/<first 8 hex of tip id>` marks branch tips.

Label-op (CJSON, signed domain `label`):

```json
{"spec":"abra/0.1","type":"label-op","capsule_id":"<hex>","seq":<int>,"by":"<peer id>",
 "op":"set","name":"main","snapshot_id":"<hex>","lease_epoch":<int>,
 "at":"<time>","sig":"<hex>"}
```

**Authorization:** an op that sets `main` MUST be signed by the holder of the
winning lease and carry that lease's `epoch`; receivers MUST reject a `main` move
whose signer/epoch don't match their winning lease. `fork/*` ops may be signed by
the forking writer. Per-`(capsule, name)` the highest `seq` wins; equal `seq` ties
break on lexicographically greater `sig` bytes (deterministic, not claimable).
Other user labels: `[a-z0-9._:-]{1,64}`, not starting with `fork/`; ≤ 128 labels
per capsule; `fork/*` creation is limited to 32 per peer per capsule.

### 5.4 Lease

Exclusive writer per capsule. Integrator contract: **on lease loss, the agent
stops acting.** Lease record (CJSON, signed domain `lease`):

```json
{"spec":"abra/0.1","type":"lease","capsule_id":"<hex>","holder":"<peer id>",
 "epoch":<int ≥1>,"mode":"grant|refresh|transfer|takeover",
 "acquired_at":"<time>","expires_at":"<time>","prev_hash":"<hex>","sig":"<hex>"}
```

`prev_hash` = BLAKE3 of the previous winning lease record's full CJSON (including
`sig`); for `epoch` 1 it is BLAKE3 of the genesis record's full CJSON.

| Mode | Signer | Checks |
|---|---|---|
| `grant` | capsule creator | epoch 1, holder = creator, issued with genesis |
| `refresh` | current holder | same holder, epoch = prev + 1 |
| `transfer` | current holder | names a trusted new holder, epoch = prev + 1 |
| `takeover` | the **new** holder | signer is a full peer (guests only with `lease_takeover` scope), epoch = prev + 1. Live takeover is first-class: it does not wait for expiry. |

**Acceptance (fail closed):** a record is accepted only if `prev_hash` matches the
locally known winning record **and** `epoch` equals its epoch + 1. No gap
promotion: a record claiming a distant epoch is stored as evidence but never wins.
Equal-epoch races: neither moves `main`; the tie breaks deterministically on
lexicographically greater `sig` bytes for *who may issue epoch+1*, never on a
self-asserted timestamp. The losing holder is pushed `lease-update` (§6.8) and
MUST stop acting; its subsequent writes are forks.

TTL: default 24h, min 60s, max 7d. Holders refresh at least every 5 minutes while
actively writing. Writing without the winning lease is **fork-on-write** (§5.5),
never an error.

### 5.5 Fork-on-write and reconciliation

A full snapshot authored without the winning lease: stored, valid, `main`
untouched, `fork/<8hex>` label-op created, writer told `forked: true`. An agent
whose lease was taken over loses nothing — its work lands on a fork.
Reconciliation is deliberate: a lease holder materializes both tips, resolves in
the folder, commits a snapshot with `parents: [main_tip, fork_tip]` (first parent
= mainline), and moves `main`. The core never merges silently.

---

## 6. Delivery protocol

```
OUTBOX (persisted) → HEALTH-CHECK → TRANSFER (have/want delta) → ACK (cryptographic)
```

Pure p2p is the default and MUST work with no third-party infrastructure. The
Transport trait supplies mutually authenticated, encrypted, reliable streams;
preferred implementation is iroh (QUIC, hole-punching), ALPN `abra/1`. The
transport-authenticated Ed25519 key MUST equal every `peer_id` claimed in
application messages.

### 6.1 Framing

**Control stream** (first bidirectional stream): `u32be length || JSON bytes`,
length 1..16 MiB, one object per frame with a string `type`. Unknown `type` after
handshake → `error {code:"unknown_type"}`, connection lives.

**Object streams** (unidirectional, sender→receiver): binary, one object each —

```
u8 kind (1=blob, 2=tree) || digest[32] || u64be total_size || u64be offset || bytes...
```

Chunking is QUIC's job. On EOF the receiver hashes and MUST discard on mismatch;
commit to CAS is atomic. Bulk bytes never travel as JSON/base64. Max 8 concurrent
object streams.

### 6.2 Handshake

Dialer sends `hello`, listener answers `hello-ok` (or `hello-reject`):

```json
{"type":"hello","wire":1,"spec":"abra/0.1","peer_id":"<hex>","name":"laptop",
 "features":["resume","control"],"nonce":"<16 bytes hex>"}
{"type":"hello-ok","wire":1,"peer_id":"<hex>","features":[...],"nonce":"<echo>",
 "session":"trusted|bootstrap"}
{"type":"hello-reject","reason":"wire|busy|protocol","message":"..."}
```

v0.1 speaks `wire` 1 only; `resume` and `control` are mandatory features, `relay`
optional. Unknown peers get `session:"bootstrap"`, in which the only legal types
are `pair-request`, `pair-abort`, `pair-accept`, `enroll-bind`, `enroll-ok`,
`error` — anything else → `error {code:"untrusted"}` and close. (This is the single
authoritative bootstrap rule.) The transport already authenticates both keys;
there is no separate channel-binding message.

### 6.3 Health check

`ping {nonce, ts}` / `pong {nonce, ts}`. 5s timeouts on dial and ping. Failure
leaves outbox entries queued with backoff.

### 6.4 Offer

```json
{"type":"offer","offer_id":"<16 bytes hex>","snapshot_id":"<hex>",
 "scope":"full","kind":"dev.abra.workspace","title":"...",
 "capsule_id":"<hex, full only>","fork":false,
 "bytes_hint":123456,"object_count":42,
 "manifest_raw":"<base64url of exact bytes M>",
 "genesis":{...optional, first send of a capsule to this peer...}}
```

`manifest_raw` is the **only** representation of the manifest on the wire.
Receiver MUST: decode, verify `BLAKE3("abra-snap-v1"||0x00||U) == snapshot_id`
(recomputing `U` by removing `signature` from the received bytes), verify the
in-manifest signature strictly, check the signer is trusted and (for guests) in
scope both directions (§7.4), then render the floor immediately (inbox preview /
notification may show before blobs arrive) and reply `offer-accept {offer_id}` or
`offer-reject {offer_id, reason: "quota"|"scope"|"duplicate"|"invalid"|"busy"}`.
If the receiver already holds the full closure it MAY skip transfer and ack
directly.

### 6.5 Delta negotiation

Sender lists the closure in `plan` frames (`{type:"plan", offer_id, seq, eof,
objects:[{digest, kind, bytes}]}`, split above 50k objects). Receiver answers
`have`:

```json
{"type":"have","offer_id":"...","have":["<digest>",...],
 "resume":{"<digest>":<offset>,...},"eof":true}
```

The receiver MUST recompute `have` against its own verified CAS — sender
assumptions are never trusted. `resume` maps any number of partially received
objects to committed offsets (contiguous-from-zero prefixes only). Sender then
streams `plan − have`, resuming partials from their offsets.

### 6.6 Transfer errors

`transfer-error {offer_id, digest, reason: "hash"|"size"|"io"}`. Sender may retry
an object once, then fails the attempt. There are **no per-object signed acks**;
progress is observable from stream completion.

### 6.7 The ack

Sent only after **atomic durable commit** of: all closure objects (verified), the
manifest bytes, the snapshot/inbox record, and CAS references. A crash after ack
must not lose the delivery.

```json
{"type":"ack","offer_id":"...","snapshot_id":"...","received_at":"<time>",
 "shelf":"capsule|inbox","sig":"<hex>"}
```

`sig` domain `ack`, payload `offer_id || snapshot_id || sender_peer_id ||
receiver_peer_id` (raw bytes). The sender verifies against the intended
recipient's key; only then does the outbox entry clear. Acks never transfer
across `offer_id`s; a replayed ack cannot clear a new attempt. The ack proves
receipt, not import or execution.

### 6.8 Control (same pipe, user → agent)

```json
{"type":"control","capsule_id":"<hex>","op":"pause|stop|instruct",
 "text":"<instruct only>","at":"<time>","nonce":"<16 bytes hex>","sig":"<hex>"}
```

Signed domain `control`. Receivers MUST reject: signers that are not full peers
(guests never send control), `at` older than 5 minutes or in the future beyond
60s skew, and reused nonces (nonce set persisted for 10 minutes **before**
acting). Reply `control-ack {nonce, ok, error?}`. Control is a live message in
v0.1: senders retry while the peer is reachable, and an unreachable agent misses
it — a stated limitation, not an accident.

`lease-update {lease: <full record>}` is pushed to a losing/previous holder on
takeover or transfer; on receipt the integrator stops acting on that capsule.

### 6.9 Resume

On reconnect after an interrupted transfer, whichever side retains state sends
`resume {offer_id, complete: [digests], partial: {...}}`; the sender continues
from there under the **same** `offer_id`. If the sender lost state it re-offers
with a new `offer_id` and the receiver's `have` makes it cheap. `offer_id` is
stable across resumes of one attempt; a user-initiated retry after failure is a
new attempt with a new id.

### 6.10 Outbox

Persisted per entry: `id`, `offer_id`, `peer_id`, `snapshot_id`, `state`,
`created_at`, `updated_at`, `attempts`, `last_error`, `ack_sig`,
`next_attempt_at`.

```
queued → healthcheck → offered → transferring → awaiting_ack → acked
   ↑         │ ping fail (backoff)      │ disconnect → resume
   └─────────┘                          ▼
             offer-reject → failed (retryable) / duplicate-with-ack → acked
any non-terminal → cancelled (explicit)   queued → expired (TTL 7d)
```

Backoff: 1s doubling to 5min cap, ±20% jitter. Max 20 attempts → `failed`
(user-retryable). Terminal: `acked`, `cancelled`, `expired`. **Only a verified
ack clears the duty to deliver.** Ephemeral senders (a VM about to be torn down)
MUST either wait for acks or push to a configured relay (§8) before exit.

---

## 7. Pairing and enrollment

### 7.1 Pairing (device ↔ device, full peers)

Ticket (CJSON signed domain `pair-ticket`; conveyed as
`abra-pair/1/<base64url(CJSON incl sig)>`, ≤ 8 KiB decoded, via QR/clipboard):

```json
{"v":1,"type":"pair-ticket","peer_id":"<issuer>","name":"laptop",
 "ticket_id":"<16 bytes hex>","issued_at":"<time>","expires_at":"<+10 min max>",
 "x25519_pk":"<hex 64>","relay_key":"<hex 64, optional>",
 "addresses":["<transport hints>"],"sig":"<hex>"}
```

Flow: B verifies the ticket (signature, expiry with 60s skew), dials the issuer,
completes a bootstrap hello, sends `pair-request {ticket_id, peer_id, name,
nonce, x25519_pk, relay_key?, sig}` (domain `pair-request`). A verifies, checks
the ticket is pending and unused, **prompts the user** (display both short ids),
atomically consumes the nonce, replies `pair-accept {peer_id, name, nonce}`, and
B replies `pair-confirm {ticket_id}`; each side inserts the other as a full
`TrustedPeer` only at its own final step, so a crash leaves at worst one
half-paired side that simply re-pairs. Tickets are strictly single-use.
Pairing exchanges each device's X25519 public key and (optional) relay discovery
key alongside the Ed25519 identity.

### 7.2 Enrollment (cloud sandbox / guest)

A tokenless guest binary is **inert**. Only full devices mint tokens. Token
(CJSON signed domain `enroll`; delivered as
`abra-enroll/1/<base64url>` via argv/env — infra injects binary **and** token):

```json
{"v":1,"type":"enrollment","token_id":"<16 bytes hex>","issuer":"<peer id>",
 "issued_at":"<time>","expires_at":"<default +24h, max +30d>",
 "label":"cloud-agent-1","intro":[{"peer_id":"<hex>","name":"laptop"}],
 "audience":"<guest peer id, optional>","bind_by":"<time, required iff no audience>",
 "scopes":{"capsules":["<hex>"]|["*"],"kinds":["dev.abra.workspace"]|["*"],
           "send":true,"receive":true,"lease_acquire":true,"lease_takeover":false},
 "sig":"<hex>"}
```

`audience` binds the token to a pre-generated guest key (a leaked token is inert).
When infra lets the sandbox generate its own key, `audience` is absent and
`bind_by` (≤ 15 minutes after `issued_at`) bounds the first-use bind window.
Mixing `"*"` with other entries in a scope list is forbidden. There are no
`pair`/`control` scope fields: guests can never pair, never send control.

**Bind:** on first start the guest dials `intro[0]`, bootstrap hello, then
`enroll-bind {token: <full token incl sig>, guest_peer_id, name?, x25519_pk,
sig}` (domain `enroll-bind`). The intro peer verifies token signature/expiry/
revocation and either `audience == guest_peer_id` or (audience-less) now ≤
`bind_by` and the token is unbound. It persists the guest as
`TrustedPeer {role:"guest", token_id, scopes}`, replies
`enroll-ok {mesh:[{peer_id,name,role}]}`, and — as the issuer, or after verifying
an issuer-signed certificate — gossips a **bind certificate** (CJSON signed
domain `bind-cert` by the issuer): `{type:"bind-cert", token_id, guest_peer_id,
bound_at, sig}`. Other full peers accept a guest only via a valid bind
certificate, so competing binds resolve deterministically to the issuer's one
choice.

### 7.3 Revocation

`{spec,type:"revoke",token_id,revoked_at,sig}` (domain `revoke`, any full peer)
floods to all trusted peers and is retained until token expiry + 7d. On revoke:
drop the guest, refuse binds/offers both directions. Revocation is fail-open
until the record propagates (stated limitation); guests MUST re-validate against
a full device at enrollment and before any `lease` operation, which bounds the
window for the operations that matter most. Full-peer removal (lost laptop) is a
local trust-store deletion flooded the same way as a revocation with
`peer_id` in place of `token_id`.

### 7.4 Scope enforcement (receiver-side, every operation)

For any offer, ack target, lease op, or fetch involving a guest: token unexpired
and unrevoked; `kind` ∈ `scopes.kinds`; full snapshots' `capsule_id` ∈
`scopes.capsules`; direction bit (`send`/`receive`) set; lease ops gated by
`lease_acquire`/`lease_takeover`; guests send only to full peers, never to other
guests; provenance-free partials are allowed if their `kind` is in scope
(provenance is informational and grants nothing). Full peers are the gate;
guests self-enforce as defense in depth only. `have` responses to a guest MUST
NOT disclose possession of objects outside that guest's scoped capsules.

**Send authority:** the guest daemon exposes send only when the token has
`send:true` **and** the local flag `abra.allow_agent_send` (default false) is
enabled — infra owns the switch; no token can widen it.

---

## 8. Optional relay (store-and-forward)

Optional; pure p2p MUST remain sufficient. Self-hosted; format pinned now so it
cannot fork later.

**Blind addressing.** Each device generates a random 32-byte **relay discovery
key** (`relay_key`), distributed only at pairing/enrollment — never derived from
or equal to any public key.

```
day = floor(unix_seconds_utc / 86400)              // decimal ASCII, no leading zeros
tag = HMAC-SHA256(key = relay_key, msg = "abra-relay-v1" || 0x00 || day)
```

Recipients poll tags for {day−1, day, day+1}. The relay indexes only tags; it
cannot compute them (the key is secret), read payloads, or correlate across days.
Within-day correlation of a single recipient's envelopes is accepted and stated.

**Envelopes** (binary): `ABRAREL1` (control pack: `magic[8] || tag[32] ||
u64be expires_at || u32be ct_len || ciphertext`, ct ≤ 16 MiB) and `ABRABL1\0`
(one object per envelope, u64be ct_len; the plaintext is `kind u8 || digest[32]
|| raw bytes` — the digest is never exposed to the relay). TTL sender-chosen:
default 72h, max 7d; relay deletes at expiry.

**Sealing:** libsodium sealed box to the recipient's **X25519 key from §7**
(`crypto_box_curve25519xchacha20poly1305_seal` layout: `eph_pk[32] || ct`).
No Ed25519→X25519 derivation anywhere. `ABRAREL1` plaintext is a CJSON
`relay-pack {type, v:1, from, offer:{...}, objects?:[...small only...]}`.

**Acks:** recipients ack directly p2p when possible, else deposit an `ABRAREL1`
ack pack to the sender's tag. Independently of relays, every receiver MUST keep a
pending-ack list and deliver outstanding acks on the next live connection — this
v0.1 requirement is what lets relays ship later without breaking outbox
correctness. Relay HTTP endpoints are informative in v0.1; envelope bytes are
normative.

---

## 9. Capability links (zero-install receive)

Deliberately minted, TTL'd, revocable. Mesh E2E remains the default between
enrolled devices; links are the interop escape hatch. Developers MAY skip the
viewer and parse the (signed) manifest server-side to mint their own deep links.

### 9.1 URL

```
https://<viewer-origin>/#v=1&u=<base64url(ciphertext https URL)>&k=<base64url(32-byte key)>
```

Everything lives in the **fragment** — the viewer origin learns nothing, not even
which object was viewed; the ciphertext can live on any host with CORS
(`Access-Control-Allow-Origin` permitting the viewer, `Content-Type:
application/octet-stream`). The compact form
`https://<host>/s/<ct-hash>#<base64url key>` (viewer = host) and the app form
`abra://s/<ct-hash>#<key>` are also legal.

### 9.2 Hosted blob

```
magic[8]="ABRACAP1" || alg u8 (1=XChaCha20-Poly1305) || nonce[24] ||
u64be expires_at || u64be ct_len || ciphertext
AAD = magic || alg || nonce || expires_at
```

Key = `k` (32 random bytes per link; never a user identity key). Plaintext is a
CJSON capability pack:

```json
{"spec":"abra/0.1","type":"capability-pack","snapshot_id":"<hex>",
 "manifest_raw":"<base64url of M>","blobs":[{"digest":"<hex>","data":"<base64url>"}]}
```

`blobs` MUST include the thumbnail if referenced; full tree closure is an
explicit mint mode (`floor` is the default — a floor pack is a projection, not a
complete snapshot bundle, and the viewer labels it as such). The viewer decodes
`manifest_raw`, verifies the snapshot id and the in-manifest signature, and
renders — noting that a link viewer verifies integrity and *self-asserted*
authorship (it has no trust store). Past `expires_at` the viewer MUST NOT
decrypt; the minter SHOULD delete the ciphertext at expiry (client-clock expiry
is advisory; deletion is the enforcement). Revocation = delete or replace with
`ABRACAPX`.

### 9.3 Viewer floor (MUST render, zero integration)

`kind` (text), `title`, origin short-id/name, `created_at` (localized),
`summary?`, `link?` (as anchor), `thumbnail?`. Static JS; no backend; needs only
CJSON, BLAKE3, Ed25519, XChaCha20-Poly1305. MUST NOT send `k` anywhere, MUST NOT
execute recipes or native blobs, MUST NOT derive deep links beyond
`manifest.link` (derivation belongs to consumers).

### 9.4 Mint record

Kept by the minter: `{link_id, snapshot_id, expires_at (≤ 30d), mode:
"floor"|"full", url, revoked, sig}` (domain `cap-mint`; the key is never stored
beside the ciphertext and never signed over).

---

## 10. Adapter contract

Adapters are separate executables speaking newline-delimited JSON over stdio
(UTF-8, one object per line ≤ 1 MiB, stderr = diagnostics). The daemon owns CAS,
identity, hashing, and the envelope; adapters only translate app state ⇄ staged
bytes. **Adapters never choose snapshot ids, origin, or recipes** (recipes come
from the observer).

**Registration:** file `abra-adapter.json` beside the binary:

```json
{"spec":"abra-adapter/1","name":"com.example.browser","version":"1.0.0",
 "kinds":["com.example.session"],"verbs":["export","import","watch"]}
```

Two adapters claiming one kind is a **configuration error** requiring explicit
user selection — never first-registered-wins.

**Envelope:** request `{"protocol":"abra-adapter/1","request_id":"<hex>",
"verb":"...", ...}`; response repeats `request_id` with `ok:true` + fields or
`ok:false, error:{code,message,retryable}`. Codes: `invalid_request`,
`unsupported_kind`, `unsupported_verb`, `not_found`, `permission_denied`,
`busy`, `cancelled`, `internal`. One process per operation; `cancel
{request_id}` then kill after 5s. Timeouts: export/import 10 min.

- **`export`** `{kind, source, staging_dir, options}` — the daemon creates the
  empty writable `staging_dir` and the adapter MUST write only inside it (it may
  read `source` under its own permissions). Success: `{payload, files_path|null,
  floor?:{title?,summary?,link?,thumbnail_path?}}`. The daemon hashes the staged
  tree, attaches observer recipes/native blobs, authors and signs the manifest.
- **`import`** `{kind, payload, materialized_files|null, destination, options}` —
  files are already verified and materialized by the daemon. Success: `{result,
  deep_link?}`. Never runs recipes implicitly.
- **`watch`** `{kind, source, options}` — replies `{ok:true,watching:true}` then
  emits `{request_id, event:"changed", cursor, hint}` until cancelled. Events are
  hints; the daemon debounces and re-exports.

---

## 11. Built-in payload kinds

### 11.1 `dev.abra.workspace` (full)

`scope` MUST be `full` (so `files` is required as always). Payload:

```json
{"schema":"dev.abra.workspace/1","name":"irisgo-hermes","default_cwd":".",
 "vcs":{"kind":"git","commit":"<hex>","dirty":true,"remote":"https://..."}}
```

`name` ≤ 255 scalars; `default_cwd` a normalized relative path resolving to a
tree in `files`; `vcs` optional and descriptive only (never used to fetch
bytes). No derived counters (`file_count` etc.) — receivers derive.

### 11.2 `dev.abra.handoff.v1` (partial)

Payload `{"url": <absolute URI, any scheme incl. http/localhost>, "note":
<string ≤ 16384 scalars, optional>}`. `manifest.link` MUST equal `payload.url`.
The handoff's title lives only in the floor `title` (no duplicate). `files` MAY
carry attachments. Lands in the inbox; `provenance` may point at the source
turn.

---

## 12. Versioning and evolution

- Every persisted record and message carries its schema version (`abra/0.1`,
  `abra-adapter/1`, `wire: 1`). `0.x` MAY break; a future `1.x` MUST be additive.
- For recognized schemas, **unknown top-level fields outside `extensions` are
  rejected** when validating signed records — never "unknown means optional";
  this prevents two implementations assigning different meanings to signed
  bytes. `extensions` (reverse-DNS keys) is the only open namespace and
  round-trips byte-exactly. Unknown enum values in core fields are rejected.
- Unknown `kind`s are stored, transferred, and floor-rendered; unknown payload
  fields are preserved and ignored. Kind evolution: prefer optional fields;
  bump the kind name when semantics change.
- Implementations retain original canonical bytes for identity and forwarding,
  always.

---

## 13. Open questions (deliberate)

1. Relay HTTP endpoints and relay-operator rate limiting (envelope bytes are
   pinned; the HTTP shell is v-next).
2. Tree metadata extensions (xattrs, non-UTF-8 names) without breaking
   portability.
3. Durable control delivery (v0.1 control is live-only).
4. Revocation freshness guarantees beyond re-validate-on-lease.
5. A packed multi-object stream for snapshots with very many tiny files.

---

### Errata applied

- Stage-1 review erratum: label-op records require a signed `by` peer id so they
  remain independently verifiable after persistence, gossip, or relay.
- Stage-1 review clarification: v0.1 materialization requires a nonexistent or
  empty, non-symlink destination.
- Stage-2 review erratum: `pair-confirm` is permitted on bootstrap sessions;
  otherwise the pairing flow cannot reach either side's final trust insertion.
- Stage-2 review erratum: bind certificates carry the guest name, X25519 key,
  effective scopes, and token expiry so non-issuer intro peers can verify and
  install the same bounded guest authority without an out-of-band token cache.
- Stage-2 review clarification: a first full-capsule offer carries both signed
  genesis and its signed epoch-1 grant, since capsule installation verifies both.
