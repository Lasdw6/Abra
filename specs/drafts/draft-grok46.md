# Abra Technical Specification v0.1

**Status:** independent draft (v0.1)
**Tagline:** Abra is infrastructure for teleportation.
**Scope:** one user's devices and cloud agents. Not a mesh-of-strangers. Not a general p2p framework.

This document is the implementable contract for a Rust core. A competent engineer should need no further wire-level decisions. Settled product decisions from the design context are treated as constraints, not proposals.

---

## 0. Conventions

### 0.1 Keywords

`MUST`, `MUST NOT`, `SHOULD`, `MAY` as RFC 2119.

### 0.2 Encoding primitives

| Primitive | Definition |
|---|---|
| Hex | lowercase `[0-9a-f]`, no `0x` prefix, no separators. 32-byte values are 64 hex chars. |
| UTF-8 | well-formed UTF-8 only. No CESU-8, no UTF-16, no BOM. |
| NFC | Unicode Normalization Form C (UAX #15), applied before hashing or path comparison. |
| Time | UTC only. Canonical lexical form: `YYYY-MM-DDTHH:MM:SS.sssZ` (exactly 3 fractional digits, `Z` suffix). This is the only legal form inside hashed documents. |
| Integers in JSON | base-10, no sign prefix except `-` for negatives, no leading zeros (`0` is the only exception), no decimal point, no exponent. Range: \([-2^{53}+1, 2^{53}-1]\). |
| BLAKE3 | unkeyed BLAKE3-256 (32-byte digest) as specified by the BLAKE3 paper / reference impl. |
| Ed25519 | RFC 8032 pure Ed25519 (not Ed25519ph, not Ed25519ctx). Signature is 64 bytes. |
| HMAC | HMAC-SHA256, RFC 2104, 32-byte output. |

Floats, `NaN`, `Infinity`, and duplicate object keys are illegal in every Abra JSON document that is hashed or signed.

### 0.3 Domain-separated hashes

Every content hash and every signed preimage is prefixed with a domain tag and a NUL:

```
H(tag, data)  = BLAKE3( tag || 0x00 || data )
```

Tags are ASCII, no NUL. Defined tags:

| Tag | Used for |
|---|---|
| `abra-blob-v1` | blob object id |
| `abra-tree-v1` | tree object id |
| `abra-snap-v1` | snapshot id (hash of canonical manifest) |
| `abra-sig-v1` | signature preimage wrapper (see §4) |
| `abra-peer-v1` | unused for v0.1 peer id (peer id IS the public key; tag reserved) |
| `abra-relay-v1` | HMAC message prefix for relay tags |

### 0.4 Rust core / transport

The core is Rust. The wire layer is abstracted behind a `Transport` trait. The preferred implementation is iroh (QUIC, hole-punching, Ed25519 node identities). ALPN for the iroh / QUIC handshake: `abra/1`.

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    fn local_peer_id(&self) -> PeerId;
    async fn listen(&self, h: ConnHandler) -> Result<(), TransportError>;
    async fn dial(&self, peer: PeerId) -> Result<Box<dyn Conn>, TransportError>;
}

#[async_trait]
pub trait Conn: Send {
    fn peer_id(&self) -> PeerId;
    /// Write one framed control message or open an object stream.
    async fn send_control(&mut self, json: &[u8]) -> Result<(), TransportError>;
    async fn recv_control(&mut self) -> Result<Vec<u8>, TransportError>;
    async fn open_object_stream(&mut self) -> Result<Box<dyn ObjectStream>, TransportError>;
    async fn accept_object_stream(&mut self) -> Result<Box<dyn ObjectStream>, TransportError>;
}
```

Identity of a connection is the transport-authenticated Ed25519 public key. Application messages MUST still carry `peer_id` and MUST be rejected if it disagrees with `Conn::peer_id()`.

---

## 1. Manifest / envelope schema

A **snapshot** is one JSON object: the **manifest** (envelope). It is self-describing. It is never an opaque blob. Snapshot identity is *not* a field inside the manifest; it is `H("abra-snap-v1", canonical_utf8_bytes)` (see §2).

All field names are `snake_case`. Unknown fields: see §12.

### 1.1 Top-level fields

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `spec` | string | required | Spec identifier. This version: `"abra/0.1"`. |
| `scope` | string | required | `"full"` or `"partial"`. |
| `kind` | string | required | Payload kind, reverse-DNS. Must match `^[a-z0-9]+(\.[a-z0-9]+)+$` and be ≤ 128 chars. Built-ins: `dev.abra.workspace`, `dev.abra.handoff.v1`. |
| `title` | string | required | Floor card title. NFC. Non-empty. ≤ 200 Unicode scalars. No CR/LF. |
| `origin` | object | required | Producer identity. Schema §1.3. |
| `created_at` | string | required | Canonical time. Set by the producing daemon at export. |
| `summary` | string | optional | One-paragraph description. NFC. ≤ 2000 Unicode scalars. |
| `link` | string | optional | URI the receiver may open. Absolute URI, RFC 3986, ≤ 4096 bytes UTF-8. |
| `thumbnail` | object | optional | Floor image. Schema §1.4. |
| `capsule_id` | string | full: required; partial: MUST be absent | 32-byte capsule id, hex. |
| `parents` | array of string | full: required (may be `[]`); partial: MUST be absent | Parent snapshot ids (hex), 0..16 entries. Order is significant and MUST be preserved. No duplicates. |
| `tags` | array of string | optional; full only; MUST be absent on partial | Immutable annotations on this snapshot (e.g. `"agent-turn"`). Each ≤ 64 chars `[a-z0-9._:-]+`. Sorted lexicographically by UTF-8 bytes in the canonical form (producers MUST emit sorted; consumers MUST reject unsorted when verifying a signature over the canonical bytes — verification is of bytes, so producers canonicalize). Max 16 tags. |
| `provenance` | object | optional; partial only; MUST be absent on full | Back-reference into a capsule. Schema §1.5. |
| `tree` | string | conditional | 32-byte tree object id, hex. Required for `dev.abra.workspace`. Optional for other kinds (file attachments). |
| `recipes` | array of object | optional; full only; MUST be absent on partial | Observed process recipes. Schema §1.6. Max 256 entries. |
| `native` | array of object | optional; full only; MUST be absent on partial | Host-specific blobs. Schema §1.7. Max 32 entries. |
| `payload` | object | required | Kind-specific JSON. May be `{}`. Subject to canonicalization. MUST NOT contain floats. |

**Scope rules**

- `full`: a version of a continuing thing. Always belongs to a capsule. Lands in the **capsule store**. Subject to the lease (§5).
- `partial`: a one-shot delivery. Lands in the **inbox**. No DAG, no lease. May carry `provenance`.

**Hard floor rule.** `kind`, `title`, `origin`, `created_at` are always present. A receiver that understands nothing else MUST still render a card.

**Native-never-truth.** If `native` is present, `tree` MUST also be present. A snapshot whose only cargo is native blobs is invalid.

### 1.2 Validation matrix (reject the snapshot if violated)

- `spec` ≠ `abra/0.1` → reject (unknown major) or ignore-extra (§12).
- `scope` not in `{full, partial}` → reject.
- `full` missing `capsule_id` or `parents` → reject.
- `partial` containing `capsule_id`, `parents`, `tags`, `recipes`, or `native` → reject.
- `title` empty / over-long / containing U+0000–U+001F → reject.
- `tree` present but not 64 hex chars → reject.
- `parents[i]` not a known 64-hex snapshot id *format* (existence is not required at hash time; dangling parents are allowed until fetch) → format reject only.

### 1.3 `origin` object

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `peer_id` | string | required | 32-byte Ed25519 public key, hex. Producer's device id. |
| `name` | string | optional | Human device name. NFC. ≤ 80 scalars. |
| `adapter` | string | optional | Adapter `name` from its registration manifest. ≤ 64 chars `[a-z0-9._-]+`. |
| `host_os` | string | optional | `"linux"` \| `"macos"` \| `"windows"` \| `"unknown"`. |
| `host_arch` | string | optional | `"x86_64"` \| `"aarch64"` \| `"unknown"`. |

No other `host_*` keys in v0.1. Extra keys preserved (§12).

### 1.4 `thumbnail` object

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `digest` | string | required | Blob object id (hex) of the image bytes. |
| `media_type` | string | required | `"image/jpeg"` \| `"image/png"` \| `"image/webp"` only. |
| `bytes` | integer | required | Exact raw image size in bytes. 1..524288 (512 KiB). |

The thumbnail blob MUST exist in the snapshot's object closure. Receivers MAY skip decoding if `media_type` is unknown to them (v0.1: those three are the only legal values, so reject others).

### 1.5 `provenance` object (partials)

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `capsule_id` | string | required | Capsule the sender was looking at. |
| `snapshot_id` | string | required | Snapshot id within that capsule. |
| `turn` | string | optional | Label/tag the sender associates with that turn (e.g. `"agent-turn-12"`). ≤ 64 chars. |

Provenance is informational. Receivers MUST NOT treat it as a DAG parent and MUST NOT fail if the referenced capsule is unknown.

### 1.6 Recipe object (`recipes[]`)

Recipes are **observed**, not declared. An ambient observer at the sandbox boundary captures them. The core stores what it is given; it does not start processes unless the user explicitly runs a recipe.

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `argv` | array of string | required | Argument vector, `argv[0]` included. 1..256 entries. Each entry ≤ 8192 bytes. |
| `cwd` | string | required | Working directory as observed. If it is inside the tree, producers SHOULD emit a path relative to the tree root using `/` separators and no leading `/`. Otherwise an absolute host path. ≤ 4096 bytes. |
| `env` | array of object | required | Environment. Each element `{ "name": string, "value": string }`. Names unique, `[A-Za-z_][A-Za-z0-9_]*`, ≤ 256 chars. Values ≤ 65536 bytes. Array MUST be sorted by `name` UTF-8 bytes. Max 4096 entries. |
| `listen` | array of object | required | Listening sockets observed. May be `[]`. Element: `{ "proto": "tcp"\|"udp", "addr": string, "port": integer }`. `port` in 1..65535. `addr` is the bind address as observed (`"0.0.0.0"`, `"::"`, `"127.0.0.1"`, …), ≤ 128 chars. Sorted by `(proto, addr, port)`. Max 256 entries. |
| `started_at` | string | optional | Canonical time the process was observed to have started. |

No pid, no uid, no cgroup path: those are host-specific and not portable. Recipes exist so a capable OS can *recreate* the process, not restore memory.

### 1.7 Native blob object (`native[]`)

Native blobs (e.g. Firecracker memory + vmstate) are stored **byte-for-byte unchanged** as blob objects. They are an optimization for instant resume on a matching host, never source of truth.

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `role` | string | required | `"memory"` \| `"vmstate"` \| `"disk"` \| `"other"`. |
| `digest` | string | required | Blob object id (hex). |
| `bytes` | integer | required | Raw size. 0..`2^53-1`. |
| `host` | object | required | Fingerprint. See below. |

**`host` fingerprint**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `os` | string | required | `"linux"` \| `"macos"` \| `"windows"`. |
| `arch` | string | required | `"x86_64"` \| `"aarch64"`. |
| `hypervisor` | string | required | e.g. `"firecracker"`. `[a-z0-9._-]+`, ≤ 64 chars. |
| `snapshot_format_major` | integer | required | Major format of the hypervisor snapshot. ≥ 0. |
| `cpu_template` | string | required | CPU template name, or `"-"` if none. ≤ 64 chars. |

**Match string** (not stored; derived for comparisons):

```
{os}/{arch}/{hypervisor}/{snapshot_format_major}/{cpu_template}
```

On import, the daemon compares the local host fingerprint to each native entry. Mismatches: skip the blob, do not fail the import, do not materialize the file. Matching: materialize next to the folder as `.abra/native/{digest}` (see §5.6). Running from native blobs is always an explicit user/integrator action, never implicit.

---

## 2. Canonical serialization and snapshot id

### 2.1 Canonical JSON (Abra-CJSON)

Abra-CJSON is a strict subset of RFC 8259 plus a deterministic encoding, aligned with RFC 8785 (JCS) except that **numbers are integers only** and key order is **UTF-8 byte lexicographic** (not UTF-16 code units). For the ASCII key set used in this spec the two orders coincide.

Rules, applied recursively:

1. Encode the document as a single UTF-8 JSON value. No BOM, no insignificant whitespace (no U+0020 / U+0009 / U+000A / U+000D between tokens).
2. Object members appear in strictly ascending order of key as raw UTF-8 bytes. Duplicate keys are illegal.
3. Arrays preserve element order.
4. Strings:
   - Quote with `"`; escape `"` as `\"` and `\` as `\\`.
   - Escape U+0008 `\b`, U+0009 `\t`, U+000A `\n`, U+000C `\f`, U+000D `\r`.
   - Escape remaining U+0000–U+001F as `\u00XX` (four hex digits, lowercase).
   - Do **not** escape solidus `/`.
   - Do **not** emit `\uXXXX` for any code point ≥ U+0020 other than the required `"` and `\`. Non-ASCII is raw UTF-8.
5. Numbers: integers as in §0.2. The lexical form is unique.
6. `true` / `false` / `null` as those literals.
7. Payload objects, recipe objects, origin, etc. are all in the same form.

Implementors SHOULD serialize via a BTree map + a compact JSON writer that follows the escape table above. Do not round-trip through a parser that emits spaces.

### 2.2 What bytes are hashed

Let `M` be the Abra-CJSON encoding of the manifest (the exact UTF-8 byte string produced by §2.1).

```
snapshot_id = BLAKE3( "abra-snap-v1" || 0x00 || M )
```

`snapshot_id` is stored and transmitted as 64 hex chars. It MUST NOT appear inside `M` (circular). Signatures (§4) sign the 32-byte digest, not `M` itself.

**Persistence rule.** Daemons MUST store `M` (the canonical bytes) alongside the parsed form. Re-canonicalizing from a parsed DOM is allowed only if the writer is a bit-exact Abra-CJSON implementation; the stored bytes are authoritative. When verifying, hash the stored `M`.

### 2.3 Canonical time and strings inside `M`

Producers MUST emit `created_at` / `started_at` / similar hashed timestamps in the §0.2 lexical form. `title`, `summary`, `origin.name`, and tree path components are NFC-normalized before insertion into `M`.

---

## 3. Content addressing

The content-addressed store (CAS) holds **blob objects** and **tree objects**. Digests are 32 bytes. The on-disk value is the raw payload described below; the digest is domain-separated so a blob cannot be confused with a tree.

### 3.1 Blob objects

Raw file bytes, or symlink target bytes, or thumbnail bytes, or native blob bytes. **Unchanged.**

```
blob_id = BLAKE3( "abra-blob-v1" || 0x00 || u64be(len) || bytes )
```

`u64be(len)` is the length of `bytes` as an 8-byte big-endian integer. `len` MUST equal `bytes.len()`. Empty file: `len = 0`, `bytes` empty.

CAS stores `bytes` only (not the domain tag, not the length prefix). The tag and length exist solely in the hash preimage.

### 3.2 Tree objects

A tree is a sorted list of entries. Nested (git-style): each entry name is a single path component.

**Tree body** (binary):

```
tree_body:
  u32be  count                 // number of entries, 0..1_048_576
  entry  count times

entry:
  u8     kind                  // 1=file, 2=file+exec, 3=symlink, 4=directory
  u16be  name_len              // 1..255
  u8     name[name_len]        // UTF-8 NFC, path component
  u8     digest[32]            // blob_id (kinds 1–3) or tree_id (kind 4)
  u64be  size                  // blob byte length for 1–3; 0 for kind 4
```

```
tree_id = BLAKE3( "abra-tree-v1" || 0x00 || tree_body )
```

CAS stores `tree_body`.

**Kind values**

| `kind` | Meaning | `digest` points to | Metadata captured |
|---|---|---|---|
| 1 | regular file, non-executable | blob of file bytes | none besides size |
| 2 | regular file, executable | blob of file bytes | exec bit only |
| 3 | symlink | blob of target (UTF-8, no NUL, NFC, ≤ 4096 bytes) | target |
| 4 | subdirectory | child tree | empty dirs are zero-entry trees |

No other kinds in v0.1. mtime, uid/gid, unix mode bits other than exec, xattrs, resource forks, Windows ACLs: **not captured**.

**Entry ordering.** Entries MUST be sorted by `name` as raw UTF-8 bytes, ascending, strictly increasing (duplicate names illegal).

**Name / path rules**

- Component is NFC UTF-8, length 1..255 bytes, no `0x00`, no `/`, not `.`, not `..`.
- MUST NOT be `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` (case-insensitive ASCII) so a tree can materialize on Windows. (This is a v0.1 materialization constraint; the bytes are still as named if a producer violates it — receivers on Windows MUST reject the import rather than rename.)
- Full reconstructed path (join with `/`) ≤ 4096 bytes.
- Trees always use `/`. Windows `\ ` is not a separator inside the object.

**Empty directories** are stored (kind-4 entry pointing at a zero-entry tree). The zero-entry tree has a fixed id: `BLAKE3("abra-tree-v1" || 0x00 || 4 zero bytes)`.

**Symlinks.** Blob contents are the target string as UTF-8. Relative targets are preserved verbatim (after NFC). Receivers MUST NOT follow symlinks when hashing or exporting.

### 3.3 Object closure of a snapshot

Reachable objects = thumbnail blob (if any) ∪ tree root and its recursive children ∪ every `native[].digest` ∪ (no extra objects for recipes). Transfer (§6) moves this closure, minus objects the receiver already has.

### 3.4 Materialization (local folder)

A capsule materializes as a plain folder (the local sandbox). Layout:

```
<folder>/                 # tree contents
<folder>/.abra/           # daemon metadata; not part of the tree
            capsule.json  # capsule_id, labels, lease seq
            native/       # matching native blobs, named by digest hex
            recipes.json  # copy of recipes for UI; running is explicit
```

`.abra/` is daemon-owned. Export of the folder MUST omit `.abra/` from the tree (the only v0.1 exception to “no ignore logic”; it is Abra’s own metadata, not user file exclusion). Byte-for-byte fidelity otherwise: no secret scanning, no `.gitignore`.

---

## 4. Identity

### 4.1 Device keypair

Each peer generates an Ed25519 keypair on first start, persisted with mode 0600.

- **Secret key:** 32-byte seed (RFC 8032).
- **Public key:** 32 bytes.
- **Peer id:** the public key itself (32 bytes; 64 hex chars in JSON). This matches iroh `NodeId` so dialing needs no extra map.

**Short-id** (UI only, never on the wire as an identifier): first 8 hex characters of `peer_id`. Display form `a1b2c3d4`. If two trusted peers share a prefix (astronomically unlikely in a single-user mesh), UI expands to 16 hex chars.

### 4.2 Encryption key (for capability links and relays)

Ed25519 is a signing key. For AEAD we need a DH key. Each device **derives** an X25519 keypair from the Ed25519 keypair using the libsodium maps:

- `x25519_sk = crypto_sign_ed25519_sk_to_curve25519(ed25519_sk)`
- `x25519_pk = crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)`

(Equivalent: RFC 7748 scalar = SHA-512(ed25519_seed)[0..32] with clamping, as in libsodium; implementations MUST match libsodium’s `crypto_sign_ed25519_*_to_curve25519`.)

v0.1 sealed boxes use X25519 + XChaCha20-Poly1305 (IETF construction as in libsodium `crypto_box_curve25519xchacha20poly1305` / equivalent: ephemeral X25519, XChaCha20-Poly1305 with key = HChaCha20(X25519(eph_sk, recip_pk))). See §8 and §9 for packet layout.

### 4.3 What is signed

All signatures are Ed25519 over:

```
preimage = "abra-sig-v1" || 0x00 || domain || 0x00 || payload
signature = Ed25519_Sign(sk, preimage)
```

`domain` is ASCII, no NUL. `payload` is raw bytes (not hex). JSON documents that are signed are Abra-CJSON **without** a `sig` field.

| Domain | Payload | Where stored |
|---|---|---|
| `snapshot` | 32-byte `snapshot_id` | snapshot record (§5.2) |
| `ack` | 16-byte `offer_id` \|\| 32-byte `snapshot_id` | ack message (§6.7) |
| `lease` | Abra-CJSON of the lease record minus `sig` | lease record (§5.4) |
| `genesis` | Abra-CJSON of the genesis record minus `sig` | genesis (§5.1) |
| `label` | Abra-CJSON of the label-op minus `sig` | label-op (§5.3) |
| `control` | Abra-CJSON of the control message minus `sig` | `control` (§6.8) |
| `pair-ticket` | Abra-CJSON of the ticket minus `sig` | pairing ticket (§7.1) |
| `pair-request` | 16-byte `ticket_id` \|\| 16-byte `nonce` | `pair-request` (§7.1) |
| `enroll` | Abra-CJSON of the token minus `sig` | enrollment token (§7.2) |
| `revoke` | Abra-CJSON of the revocation minus `sig` | revocation list (§7.3) |
| `enroll-bind` | 16-byte `token_id` \|\| 32-byte `guest_peer_id` | binding (§7.2) |
| `cap-mint` | Abra-CJSON of the capability mint record minus `sig` (MUST omit the raw key) | minter store (§9) |

JSON `sig` fields are 64-byte signatures as 128 hex chars.

### 4.4 Trust store

After pairing / enrollment, each daemon holds:

```
TrustedPeer {
  peer_id:    [u8; 32],
  name:       String,
  added_at:   Time,
  role:       "full" | "guest",
  token_id:   Option<[u8; 16]>,  // guests only
  scopes:     Option<Scopes>,    // guests only
}
```

Single-user-ness is this allowlist (authz policy), not a cryptographic mesh property. Unlisted authentic-transport peers: handshake `hello-reject` with `reason: "untrusted"`.

---

## 5. Capsules and history

The core owns history: CAS + a per-capsule snapshot DAG + labels + a lease.

### 5.1 Capsule genesis

A capsule is created explicitly (UI / SDK `capsule_create`) before its first full snapshot.

**Genesis record** (Abra-CJSON, signed with domain `genesis`):

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `spec` | string | required | `"abra/0.1"` |
| `type` | string | required | `"capsule-genesis"` |
| `capsule_id` | string | required | 32 cryptographically random bytes, hex. **Identity, not a hash.** |
| `created_at` | string | required | Canonical time. |
| `created_by` | string | required | Creator `peer_id`. |
| `kind` | string | required | Default payload kind (typically `dev.abra.workspace`). |
| `title` | string | required | Capsule title (floor-quality). NFC, ≤ 200 scalars. |
| `sig` | string | required | Ed25519, domain `genesis`, signed by `created_by`. |

`capsule_id` is random so two capsules with the same title are distinct. The genesis signature binds the random id to the creator.

The first snapshot of a capsule MUST have `parents: []` and `capsule_id` equal to this id. Subsequent snapshots MUST have at least one parent that is already in the capsule DAG (or a fork parent the writer holds locally — §5.5).

### 5.2 Snapshot record (DAG node)

Stored in the capsule store. Distinct from the manifest: the record is metadata *about* a hashed manifest.

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `snapshot_id` | string | required | Hex of §2.2. |
| `capsule_id` | string | required | Must equal `manifest.capsule_id`. |
| `manifest` | bytes | required | Exact Abra-CJSON bytes `M`. |
| `signer` | string | required | `peer_id` of the producer. Must equal `manifest.origin.peer_id`. |
| `sig` | string | required | Domain `snapshot`, payload = 32-byte snapshot_id. |
| `received_at` | string | required on a replica | Local receive time (not hashed). |

Parents live **inside** the manifest so they affect `snapshot_id`. The DAG is implied by `manifest.parents`. A record whose parent ids are unknown is stored as `orphan` until parents arrive; it MUST NOT be made `head`.

### 5.3 Labels

Labels are **mutable pointers** stored per capsule, not inside the manifest.

| Label | Semantics |
|---|---|
| `main` | The lease-holder’s current line. Created at genesis, pointing at the first snapshot once it exists. |
| `head` | Alias of the snapshot the current lease holder last committed. In v0.1 `head` ALWAYS equals `main` unless a lease-holder rename is introduced later. Implement `head` as an alias of `main`. |
| `fork/<8-hex>` | Auto-created on branch-on-write (§5.5). The suffix is the first 8 hex chars of the fork’s tip `snapshot_id`. |

Additional user labels: `[a-z0-9._:-]{1,64}`, not starting with `fork/`. Max 128 labels per capsule.

Label updates are signed by the current lease holder (or, for `fork/*` creation, by the writer who forked) as a **label-op** appended to a per-capsule log:

```
{
  "spec": "abra/0.1",
  "type": "label-op",
  "capsule_id": "<hex>",
  "seq": <integer, per-capsule label log>,
  "op": "set",
  "name": "main",
  "snapshot_id": "<hex>",
  "at": "<time>",
  "sig": "<hex>"
}
```

Signature domain: `label`. Gossip: label-ops with highest `seq` per `(capsule_id, name)` win; tie-break lexicographic greater `sig` (arbitrary but deterministic). Lease holder SHOULD be the only writer of `main`.

### 5.4 Lease record

Exclusive writer per capsule. Integrator contract: on lease loss, the agent **stops acting**.

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `spec` | string | required | `"abra/0.1"` |
| `type` | string | required | `"lease"` |
| `capsule_id` | string | required | |
| `holder` | string | required | `peer_id`. |
| `seq` | integer | required | Monotonic per capsule, start at 1. |
| `mode` | string | required | `"grant"` \| `"refresh"` \| `"transfer"` \| `"takeover"`. |
| `acquired_at` | string | required | Canonical time. |
| `expires_at` | string | required | Canonical time. Must be > `acquired_at`. |
| `prev_hash` | string | required | BLAKE3 of the previous lease’s **full** Abra-CJSON including `sig`, as hex. For seq=1: BLAKE3 of the genesis record’s full CJSON including `sig`. |
| `sig` | string | required | Domain `lease`, payload = CJSON minus `sig`. |

**Who may sign**

| Mode | Signer | Extra checks |
|---|---|---|
| `grant` | capsule `created_by` | `seq == 1`, holder = creator. Issued with genesis. |
| `refresh` | current holder | same holder, `seq == old+1`, extends `expires_at`. |
| `transfer` | **previous** holder | new holder is a trusted peer, `seq == old+1`. |
| `takeover` | **new** holder | signer `role == full` (not a guest unless scope `lease_takeover`), `seq == old+1`. |

**TTL.** Default 24 hours from `acquired_at`. Min 60 seconds, max 7 days. While acting, the holder MUST refresh at least every 5 minutes (new seq). Expired lease: any `full` peer MAY issue `takeover` (or `grant` is not reused). Guests MUST NOT takeover unless `scopes.lease_takeover == true`.

**Winning lease.** Highest `seq` wins. If two records share `seq` (race): compare `acquired_at` lexicographically (later wins); if equal, compare `holder` hex (greater wins). Store the loser. Notify the losing holder with `lease-update` (§6.8). Writes from a loser after notification are forks, not commits to `main`.

**`prev_hash` mismatch.** If `prev_hash` does not match the local winning lease’s hash, accept the new record only if its `seq` is still greater (takeover/refresh after gossip lag). If `seq` is equal or less, ignore.

### 5.5 Fork semantics (write without the lease)

If a peer produces a full snapshot for a capsule and is **not** the holder of the unexpired winning lease (or its `lease.seq` at send time is stale):

1. The snapshot is **valid** and stored.
2. `parents` is whatever the writer set (typically the tip they based on).
3. The daemon MUST NOT move `main`.
4. The daemon MUST create or update label `fork/<8-hex-of-this-snapshot-id>` to this snapshot.
5. The writer’s UI/SDK is told `forked: true`.

Reconciliation is **deliberate**: a lease holder (human or integrator) materializes both tips, resolves in the folder, exports a new snapshot with `parents: [main_tip, fork_tip]` (2 parents = explicit merge commit), and moves `main` to it. The core never silent-merges.

Maximum `parents` length 16 to allow octopus merges after many forks; v0.1 UIs MAY only expose two-parent merges.

### 5.6 Rollback

A lease holder MAY set `main` to any snapshot already in the capsule DAG (including older). This does not delete objects. GC (§5.7) may eventually drop unreferenced snapshots if they are unlabelled and older than the GC grace period; v0.1 default is **no GC of snapshot records**, only unreferenced CAS objects after 7 days.

### 5.7 Capsule store vs inbox

| Shelf | Contains |
|---|---|
| Capsule store | genesis, lease, label-ops, snapshot records, CAS refs |
| Inbox | partial snapshots: `{snapshot_id, manifest bytes, signer, sig, from, received_at, read: bool}` plus CAS refs |

GC mark roots: every snapshot record, every inbox entry, every outbox entry, every in-flight offer, every capability-link mint that is unexpired.

---

## 6. Delivery protocol

Default transport is pure p2p and MUST work with no third-party infra. Delivery semantics:

```
OUTBOX (persisted) → HEALTH-CHECK → TRANSFER (have/want vs receiver CAS) → ACK (cryptographic)
```

E2E encryption is always on (QUIC/iroh). Relays (§8) are optional and add a second E2E layer.

### 6.1 Framing

**Control stream** (one client-initiated bidirectional QUIC stream, first stream):

```
u32be  length           // payload size, 1..16_777_216 (16 MiB)
u8     payload[length]  // UTF-8 JSON object, not necessarily canonical
```

`length` includes only the JSON bytes. JSON MUST be a single object with a string field `type`. Unknown `type`: send `error` `{ "code": "unknown_type", "ref": <type> }` and continue (do not kill the connection), except during handshake before `hello-ok`.

**Object streams** (unidirectional QUIC streams, sender → receiver):

```
u8     kind             // 1 = blob, 2 = tree
u8     digest[32]
u64be  total_size       // raw CAS payload length (file bytes or tree_body)
u64be  offset           // 0 for a fresh object; resume offset otherwise
u8     data[]           // remaining bytes of the object from offset; stream end = EOF
```

Chunking is QUIC’s problem; the object is one stream. Max object size in v0.1: `2^53-1` bytes (JSON-safe). Receivers MAY refuse objects > a local quota.

After EOF, receiver computes `blob_id` / `tree_id` and MUST discard on mismatch. `total_size` MUST equal the payload length. For resume, `offset` is the number of bytes already committed; sender transmits `data` for `[offset, total_size)`.

### 6.2 Versioning / handshake

Either peer, immediately after the control stream opens, sends `hello`. The dialer sends first; the listener replies.

**`hello`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"hello"` |
| `wire` | integer | required | This spec: `1`. |
| `spec` | string | required | `"abra/0.1"` |
| `peer_id` | string | required | Must match transport identity. |
| `name` | string | optional | Device name. |
| `features` | array of string | required | Subset of `"resume"`, `"relay"`, `"control"`. v0.1 daemons MUST advertise `["resume","control"]` and MAY add `"relay"`. |
| `nonce` | string | required | 16 random bytes, hex. |

**`hello-ok`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"hello-ok"` |
| `wire` | integer | required | Selected version. MUST be `1` if both offered `1`. |
| `peer_id` | string | required | |
| `name` | string | optional | |
| `features` | array of string | required | Intersection of the two `features` sets. |
| `nonce` | string | required | Echo of the peer’s nonce. |
| `session` | string | required | `"trusted"` if the peer is in the trust store; `"bootstrap"` otherwise. |

**`hello-reject`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"hello-reject"` |
| `reason` | string | required | `"untrusted"` \| `"wire"` \| `"busy"` \| `"protocol"` |
| `message` | string | optional | Human, ≤ 200 chars. |

Rules:

- `wire` mismatch (no overlap): reject `wire`. v0.1 only speaks `1`.
- Unknown peer: send `hello-ok` with `session: "bootstrap"`. Until the peer becomes trusted on this connection, the only legal types after handshake are `pair-request`, `pair-abort`, `pair-accept`, `enroll-bind`, `enroll-ok`, `error`. Any other type → `hello-reject` is not used; send `error` `{ "code": "untrusted" }` and close. `reason: "untrusted"` is reserved for a bootstrap that then fails (bad ticket, expired token, bind denied).
- Feature intersection may drop `relay`; `resume` and `control` SHOULD remain. Bootstrap sessions MUST advertise `features: []` regardless of intersection (no snapshot transfer until trusted).

A connection without `hello-ok` MUST NOT send other types.

### 6.3 Health-check (`ping` / `pong`)

Used by the outbox worker to decide if a peer is up before offering.

**`ping`**: `{ "type": "ping", "nonce": "<16 bytes hex>", "ts": "<canonical time>" }`
**`pong`**: `{ "type": "pong", "nonce": "<echo>", "ts": "<canonical time>" }`

Timeout: 5 seconds. Dial timeout: 5 seconds. Failure → outbox remains `queued` with backoff 5s, 15s, 45s, 2m, 5m, 15m (cap).

### 6.4 Snapshot offer

Sender → receiver, after health-check succeeds.

**`offer`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"offer"` |
| `offer_id` | string | required | 16 random bytes, hex. Unique per outbox attempt. |
| `snapshot_id` | string | required | |
| `scope` | string | required | `"full"` \| `"partial"` |
| `kind` | string | required | Floor. |
| `title` | string | required | Floor. |
| `capsule_id` | string | full only | |
| `lease_seq` | integer | full only | Sender’s lease seq at offer time, or omitted if forking. |
| `fork` | boolean | full only | `true` if this will not move `main`. |
| `bytes_hint` | integer | required | Sum of unique object sizes in the closure (upper bound if unknown). |
| `object_count` | integer | required | Number of objects in the closure. |
| `manifest` | object | required | The parsed manifest (receiver re-canonicalizes *or* uses `manifest_raw`). |
| `manifest_raw` | string | required | Hex of exact bytes `M`. Receiver MUST hash this and match `snapshot_id`. |
| `genesis` | object | first full snapshot to a peer that may lack the capsule | Genesis record including `sig`. |
| `record_sig` | string | required | Snapshot record signature (domain `snapshot`). |
| `signer` | string | required | |

Receiver MUST:

1. Decode `manifest_raw`, check `H("abra-snap-v1", raw) == snapshot_id`.
2. Verify `record_sig` with `signer`.
3. Verify `signer` is trusted (or a guest whose scopes allow this `kind` / `capsule_id`).
4. Enforce enrollment scopes (§7.4) on **both** sides.
5. Render the floor immediately (inbox preview / notification) even before blobs arrive.
6. Proceed to have/want.

**`offer-reject`**: `{ "type": "offer-reject", "offer_id": "...", "reason": "quota"|"scope"|"duplicate"|"invalid"|"busy" }`

**`offer-accept`**: `{ "type": "offer-accept", "offer_id": "..." }` — ready for plan/have.

Duplicate `snapshot_id` already fully present: `offer-reject` `duplicate` is allowed, **or** `offer-accept` followed by an immediate `ack` with no object transfer. Sender MUST treat a valid ack as success. Preferred: if receiver already has the full closure, skip to ack.

### 6.5 Have / want delta negotiation

Goal: only missing CAS objects travel.

After `offer-accept`:

**Sender → receiver `plan`** (may be a single message; if `object_count > 50_000`, split with `seq` / `eof`):

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"plan"` |
| `offer_id` | string | required | |
| `seq` | integer | required | 0-based chunk index. |
| `eof` | boolean | required | Last chunk. |
| `objects` | array | required | Each: `{ "digest": "<hex>", "kind": "blob"\|"tree", "bytes": <int> }`. |

Sender MUST list the full closure, trees and blobs. Order SHOULD be trees before blobs (receiver can walk), but is not required.

**Receiver → sender `have`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"have"` |
| `offer_id` | string | required | |
| `have` | array of string | required | Digests (hex) from the plan that the receiver already has **and has verified**. |
| `partial` | object | optional | `{ "digest": "<hex>", "offset": <int> }` at most one in-progress object for resume. `offset` is committed bytes. |

If `have` would exceed 1_000_000 entries, the receiver MAY send multiple `have` messages with `"eof": false` except the last; add field `eof` boolean required, default interpret missing as true for v0.1 single-message.

**Receiver → sender `want`** (optional explicit; default = plan minus have):

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"want"` |
| `offer_id` | string | required | |
| `digests` | array of string | required | Subset of plan. Empty = nothing to send (go to ack). |

If the receiver sends `have` and does not send `want`, the sender MUST treat `want` as plan − have (− partial digest, which is sent from `offset`).

Sender then opens one object stream per wanted digest (or resumes the partial). Concurrency: at most 8 in-flight object streams in v0.1.

### 6.6 Blob / tree transfer

See object-stream layout §6.1. After all wanted objects are received and verified, the receiver issues `ack`. If verification fails: `transfer-error` `{ "type": "transfer-error", "offer_id": "...", "digest": "...", "reason": "hash"|"size"|"io" }`. Sender MAY retry that object once, then fail the outbox entry.

### 6.7 Cryptographic ack

**`ack`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"ack"` |
| `offer_id` | string | required | 16 bytes hex, matching the offer. |
| `snapshot_id` | string | required | |
| `received_at` | string | required | Receiver’s canonical time. |
| `objects_ok` | integer | required | Count of objects now present (have + newly received). |
| `sig` | string | required | Domain `ack`, payload = `offer_id_raw` (16 bytes) \|\| `snapshot_id_raw` (32 bytes). |

Verify: `sig` is valid for the **intended recipient** `peer_id` (the outbox target). Only then:

- Outbox entry → `acked` → delete or archive.
- Sender MAY drop the outbox payload. CAS objects remain if referenced elsewhere.

Acks are not reusable across `offer_id`s. Replay of an old ack MUST NOT clear a new outbox entry.

### 6.8 Control messages (same pipe)

Control is user → agent, not a snapshot (so it does not land in the inbox). Requires feature `control`.

**`control`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"control"` |
| `capsule_id` | string | required | |
| `op` | string | required | `"pause"` \| `"stop"` \| `"instruct"` |
| `text` | string | `instruct` required, else optional | NFC, ≤ 8000 scalars. |
| `lease_seq` | integer | optional | Informational. |
| `nonce` | string | required | 16 bytes hex, anti-replay. |
| `sig` | string | required | Domain `control`, payload = Abra-CJSON of this object minus `sig`. |

Receiver (agent side) MUST ignore `control` from a peer that is not `role=full` (guests cannot pause the user’s other agents unless scoped later — v0.1: guests MUST NOT send `control`).

**`control-ack`**: `{ "type": "control-ack", "nonce": "...", "ok": true|false, "error": optional string }`

**`lease-update`**: `{ "type": "lease-update", "lease": {<full lease record including sig>} }` — pushed to the previous holder on takeover/transfer. On receipt, integrator MUST stop acting on that capsule.

### 6.9 Resume of interrupted transfers

Requires feature `resume` (mandatory in v0.1).

If the connection dies in `transferring`:

- Receiver persists complete verified objects in CAS immediately (not after ack).
- Receiver MAY persist a partial object as `{ digest, tmp_path, offset }` only if the prefix is contiguous from 0.
- On redial, sender sends a new `hello` then **`resume`**:

**`resume`** (sender or receiver may send; receiver SHOULD send first if it still has the offer)

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `type` | string | required | `"resume"` |
| `offer_id` | string | required | Original offer. |
| `complete` | array of string | required | Digests fully verified. |
| `partial` | object | optional | `{ "digest", "offset" }` |

If the sender’s outbox still has this `offer_id` in `transferring` or `awaiting_ack`, it continues: skip `complete`, send `partial` from `offset`, send remaining wanted objects. If the sender already dropped state, it MUST send a fresh `offer` with a **new** `offer_id` (receiver then `have`s almost everything and acks quickly).

Outbox `offer_id` is stable across resume of the same attempt. A new attempt (user retry after `failed`) gets a new `offer_id`.

### 6.10 Outbox entry: states and transitions

Persisted structure:

| Field | Type | Semantics |
|---|---|---|
| `id` | string | 16 random bytes hex, local. |
| `offer_id` | string | 16 bytes hex, set when offering. |
| `peer_id` | string | Target. |
| `snapshot_id` | string | |
| `state` | string | see below |
| `created_at` | string | |
| `updated_at` | string | |
| `attempts` | integer | Incremented each health-check cycle that fails, and each failed transfer. |
| `last_error` | string \| null | |
| `ack_sig` | string \| null | Set on success. |
| `next_attempt_at` | string \| null | Backoff. |

```
                 ┌──────────┐
                 │  queued  │
                 └────┬─────┘
                      │ start / retry
                      v
               ┌─────────────┐  ping fail
               │ healthcheck │──────────────► queued (backoff)
               └──────┬──────┘
                      │ pong
                      v
               ┌─────────────┐  reject duplicate (no ack needed)
               │   offered   │──────────────► acked   [only if receiver already has + sends ack]
               └──────┬──────┘  offer-reject (not duplicate)
                      │ accept                    └──► failed
                      v
               ┌──────────────┐
               │ transferring │◄──── resume
               └──────┬───────┘
                      │ all objects sent
                      v
               ┌──────────────┐
               │ awaiting_ack │
               └──────┬───────┘
                      │ valid ack
                      v
                   acked

Any non-terminal --cancel--> cancelled
transferring --disconnect--> transferring (stay; retry dial as resume)
awaiting_ack --timeout 10m--> transferring (resume path; receiver may already be able to ack)
queued --TTL 7d--> expired
failed --user/sdk retry--> queued
```

Terminal: `acked`, `cancelled`, `expired`. `failed` is retryable (not terminal). Max `attempts` before `failed`: 20.

Clearing: **only** `acked` (valid sig) clears the duty to deliver. `cancelled` is explicit user/SDK. The snapshot remains in CAS.

### 6.11 Partial vs full delivery

Same protocol. Difference is the receiver shelf (inbox vs capsule store) and lease/fork checks on full snapshots. Partials never consult the lease.

---

## 7. Pairing and enrollment

### 7.1 Pairing ticket (device ↔ device)

Pairing is out-of-band (QR, pasted string) plus a live p2p round-trip. v0.1 pairing does **not** complete through a relay.

**Ticket document** (Abra-CJSON, signed domain `pair-ticket` by the issuing device):

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `v` | integer | required | `1` |
| `type` | string | required | `"pair-ticket"` |
| `peer_id` | string | required | Issuer public key hex. |
| `name` | string | optional | Issuer device name. |
| `ticket_id` | string | required | 16 random bytes hex. |
| `issued_at` | string | required | |
| `expires_at` | string | required | `issued_at` + 600 seconds (10 minutes). Longer is invalid. |
| `relay_hint` | array of string | optional | iroh relay URLs to help the scanner dial. Not required for trust. |
| `sig` | string | required | |

**Exchange encoding** (the QR / clipboard payload):

```
abra-pair/1/<base64url(Abra-CJSON including sig)>
```

base64url: RFC 4648 §5, **no padding**. Max decoded size 8 KiB.

**Protocol**

1. Device A mints a ticket, displays QR, keeps `ticket_id` in a pending map until `expires_at`.
2. Device B parses, checks `expires_at` > now (plus 60s skew), verifies `sig` with `peer_id`.
3. B dials A (`peer_id`). Handshake `hello` will fail `untrusted` — **exception**: a connection that will immediately send `pair-request` is allowed from unknown peers. Implement as: listener accepts `hello` from anyone but only permits `type` in `{hello, hello-ok, pair-request, pair-abort}` until trusted.
4. B sends **`pair-request`**:

| Field | Type | Presence |
|---|---|---|
| `type` | string | `"pair-request"` |
| `ticket_id` | string | required |
| `peer_id` | string | B’s id (must match transport) |
| `name` | string | optional |
| `nonce` | string | 16 bytes hex |
| `sig` | string | Domain `pair-request`, payload = `ticket_id` (16 bytes) \|\| `nonce` (16 bytes). |

5. A verifies ticket pending and unexpired, verifies B’s sig, **prompts the user** (or a `--yes` pairing flag on the daemon). On deny: `pair-abort` `{ "reason": "denied" }`.
6. On accept, A sends **`pair-accept`**: `{ "type": "pair-accept", "peer_id": A, "name": ..., "nonce": <echo> }` and both insert `TrustedPeer { role: "full" }`.
7. Ticket is one-time: A deletes `ticket_id` from pending. A second `pair-request` with the same id fails.

Trust is TOFU-with-prompt: the ticket’s signature proves A intended to be paired *now*; the live check proves B can speak as that transport key. There is no CA.

### 7.2 Enrollment token (cloud sandbox / guest)

A tokenless guest binary is **inert**: it can generate a keypair and listen, but every `hello` from it is `untrusted` and it MUST refuse to export/import/send.

Minted only by `role=full` devices.

**Token document** (Abra-CJSON, signed domain `enroll` by `issuer`):

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `v` | integer | required | `1` |
| `type` | string | required | `"enrollment"` |
| `token_id` | string | required | 16 random bytes hex. |
| `issuer` | string | required | Minting device `peer_id`. |
| `issued_at` | string | required | |
| `expires_at` | string | required | Default `issued_at`+24h; max `issued_at`+30d. |
| `label` | string | optional | `"cloud-agent-xyz"`, ≤ 80 scalars. |
| `intro` | array of object | required | At least one `{ "peer_id", "name"? }`. Peers the guest should dial. Usually the issuer. |
| `scopes` | object | required | See below. |
| `sig` | string | required | |

**`scopes`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `capsules` | array of string | required | List of capsule ids hex, or a single-element list `["*"]` meaning all current and future capsules. |
| `kinds` | array of string | required | Allowed payload kinds. Empty list = none (inert). |
| `send` | boolean | required | May place items in an outbox targeting a **full** peer. |
| `receive` | boolean | required | May accept offers. |
| `lease_acquire` | boolean | required | May `grant`/`refresh`/`transfer` as holder if otherwise allowed. Default for agents: `true` so they can drive a capsule. |
| `lease_takeover` | boolean | required | May issue `mode: "takeover"`. Default **false**. |
| `pair` | boolean | required | May mint pairing tickets. MUST be **false** for guests in v0.1. Receivers MUST reject tokens with `pair: true`. |
| `control` | boolean | required | May send `control` messages. MUST be **false** in v0.1 for guests. |

**Encoding:** `abra-enroll/1/<base64url(CJSON including sig)>`. Delivered as argv `--enroll` or env `ABRA_ENROLLMENT_TOKEN`. Infra adds the binary **and** the token; the agent never controls whether Abra exists.

**Bind (one token, one guest key)**

On first start the guest generates a device keypair, then dials `intro[0]`, completes `hello` (`session: "bootstrap"`), then sends `enroll-bind`.

**`enroll-bind`** (guest → intro peer):

| Field | Type | Presence |
|---|---|---|
| `type` | string | `"enroll-bind"` |
| `token` | object | the full token including `sig` |
| `guest_peer_id` | string | must match transport |
| `name` | string | optional |
| `sig` | string | domain `enroll-bind`, payload = `token_id` (16 bytes) \|\| `guest_peer_id` (32 bytes) |

Intro peer MUST:

1. Verify token `sig` against `issuer` (issuer is a known `full` peer, or the intro peer is the issuer).
2. Check not expired, not revoked (§7.3).
3. If `token_id` already bound to a different `guest_peer_id` → reject.
4. Persist bind `{ token_id, guest_peer_id, bound_at }` and `TrustedPeer { role: "guest", token_id, scopes, name }`.
5. Reply `enroll-ok` `{ "type": "enroll-ok", "mesh": [ {peer_id, name, role} ] }` listing full peers the guest may contact.
6. Gossip the bind to other full peers.

Send authority: even with `scopes.send == true`, destinations MUST be `role=full` peers in this user’s trust store. Guests MUST NOT send to other guests. (Safe: the cert can only send to the one user.)

### 7.3 Revocation

**Revocation record** (signed domain `revoke` by any `full` peer):

| Field | Type | Presence |
|---|---|---|
| `spec` | string | `"abra/0.1"` |
| `type` | string | `"revoke"` |
| `token_id` | string | required |
| `revoked_at` | string | required |
| `sig` | string | required |

Flood to all trusted peers. Store until `token.expires_at + 7d` (if token unknown, store 37 days). On revoke: drop the guest from `TrustedPeer`, refuse binds, refuse offers to/from that `peer_id`.

### 7.4 Receiver-side scope enforcement

Every offer, ack-target, lease op, and CAS fetch from a `guest` MUST pass:

1. Token not expired and not revoked.
2. `manifest.kind` ∈ `scopes.kinds`.
3. If `scope == full`: `capsule_id` ∈ `scopes.capsules` or `capsules == ["*"]`.
4. If guest is **sending**: `scopes.send` and destination `role == full`.
5. If guest is **receiving**: `scopes.receive`.
6. Lease takeover: `scopes.lease_takeover`.
7. Lease acquire/refresh: `scopes.lease_acquire`.
8. `pair` / `control` from guest: always deny in v0.1.

A `full` peer enforcing this is the gate; guests also self-enforce (defense in depth) but are not trusted to.

Infra/harness owns send by default: the guest daemon SHOULD expose send only when the token has `send: true` **and** a local policy flag `abra.allow_agent_send` is enabled (default false). The token cannot override that local flag. (Vendor-enabled policy.)

---

## 8. Optional relay (store-and-forward)

**Status: optional / v-next for daemon enablement; the format is specified now so it does not fork later.** Pure p2p MUST remain sufficient. Relays are self-hosted. Hybrid: a device may have a list of relay URLs and use them when dial fails for `relay_after` seconds (config, default 15s).

### 8.1 Blind addressing

The relay MUST NOT be able to read plaintext or stably correlate a recipient across days.

```
day = floor(unix_seconds_utc / 86400)    // integer
msg = "abra-relay-v1" || 0x00 || decimal_ascii(day)   // no leading zeros; day 0 is "0"
tag = HMAC-SHA256(key = recipient_ed25519_pk (32 bytes), msg)
```

`tag` is 32 bytes. Recipients poll with `{tag_yesterday, tag_today, tag_tomorrow}` to absorb clock skew.

The relay indexes envelopes by `tag`. It cannot compute `tag` without the recipient public key. (It can correlate envelopes that share a tag within a day — accepted.)

### 8.2 Store-and-forward envelope (what the relay stores)

Binary, not JSON:

```
magic[8]     = "ABRAREL1"
tag[32]      = HMAC tag
expires_at   = u64be unix seconds
ct_len       = u32be
ciphertext[ct_len]
```

Max `ct_len` for `ABRAREL1`: 16 MiB. Large snapshots MUST split into a small **manifest envelope** (`ABRAREL1`) plus **object envelopes** (`ABRABL1`) — one encrypted object per envelope. Object envelopes MUST NOT expose the content digest in plaintext (that would let the relay correlate the same blob across senders).

**`ABRAREL1`** — control package (offer + plan + optional small objects whose total ciphertext is ≤ 16 MiB).

**`ABRABL1`** (magic 8 bytes: `ABRABL1` + NUL):

```
magic[8]     = "ABRABL1\0"
tag[32]      = HMAC tag
expires_at   = u64be unix seconds
ct_len       = u64be
ciphertext[ct_len]
```

TTL: sender-chosen `expires_at`. Default now+72h, max now+7d. Relay MUST delete after `expires_at`. Relay MUST NOT inspect ciphertext.

### 8.3 Ciphertext

X25519-XChaCha20-Poly1305 sealed box to the recipient’s derived X25519 public key (§4.2).

Plaintext for `ABRAREL1`:

Abra-CJSON:

```
{
  "type": "relay-pack",
  "v": 1,
  "from": "<peer_id hex>",
  "offer": { ... same fields as offer ... },
  "objects": [ { "digest": "<hex>", "kind": "blob"|"tree", "data": "<base64>" } ]
}
```

`objects` only included if the whole pack ≤ 16 MiB ciphertext. Otherwise `objects` is omitted and the sender deposits `ABRABL1` envelopes; plaintext of each:

```
kind u8 | digest[32] | raw_cas_bytes[]
```

Recipient decrypts, verifies digest, inserts CAS, then acks **directly p2p** if possible, else deposits an `ABRAREL1` ack pack addressed to the sender’s tag.

**Ack via relay** uses the same envelope addressed to the sender. Without this, store-and-forward cannot complete the outbox. v-next MUST implement relay-ack; until then, outbox stays `awaiting_ack` and completes when the recipient next dials (the receiver MUST keep a pending-ack list and send `ack` on next live connection even without `resume`).

This last sentence is **v0.1 required** (pending-ack on next dial) so relays can ship later without breaking outbox correctness.

### 8.4 Relay HTTP (informative, v-next)

Self-hosted relay MAY expose:

- `POST /v1/enqueue` body = raw envelope, response `{ "id": "<opaque>" }`
- `POST /v1/poll` body `{ "tags": ["<hex>", ...] }` response `{ "envelopes": ["<base64>", ...] }` then delete-on-fetch or `DELETE /v1/item/<id>`

Auth to the relay is **not** the user’s identity (blind). Rate-limit by IP / deployed secret. Spec of HTTP is v-next; the envelope bytes are stable.

---

## 9. Capability links

Zero-install receive. Deliberately minted, TTL’d, revocable. Mesh E2E remains the default between enrolled devices. Developers MAY skip the viewer and decrypt/parse server-side to mint their own deep links. Rendering is derived at receive time: the link carries data, not a prescribed UX beyond the floor.

### 9.1 URL structure

```
https://<viewer-origin>/#v=1&u=<base64url(ciphertext_https_url)>&k=<base64url(32-byte-key)>
```

All of `v`, `u`, `k` are in the **fragment**. The fragment is never sent to the viewer origin. `ciphertext_https_url` is an `https://` URL of the hosted blob (any host).

`k` is 32 random bytes, base64url no padding.

Optional fragment params: `a=xchacha20poly1305` (default). Unknown `v` → viewer shows “unsupported link”.

CORS: the ciphertext host MUST serve `Access-Control-Allow-Origin: *` (or the viewer origin) and `Content-Type: application/octet-stream`.

### 9.2 Hosted blob format

```
magic[8]   = "ABRACAP1"
alg        = u8  // 1 = XChaCha20-Poly1305, key = k from fragment
nonce[24]  = random
expires_at = u64be unix seconds   // plaintext so CDNs / viewers can TTL without decrypting
ct_len     = u64be
ciphertext[ct_len]                // XChaCha20-Poly1305 (IETF 24-byte nonce), AAD = magic||alg||nonce||expires_at
```

If `now > expires_at`, the viewer MUST NOT decrypt (treat as expired). The minter SHOULD delete the blob at expiry. Revocation = delete or replace the blob with 8 bytes `"ABRACAPX"` (viewer message: revoked).

**Plaintext** (inside AEAD): Abra-CJSON

```
{
  "spec": "abra/0.1",
  "type": "capability-pack",
  "snapshot_id": "<hex>",
  "manifest": { ... },
  "blobs": [
    { "digest": "<hex>", "data": "<base64 of raw file bytes>" }
  ]
}
```

`blobs` MUST include the thumbnail if the manifest references one, and MAY include the full tree closure (minter choice: `floor` vs `full`). Floor-only is the default. `manifest` is the parsed object; the viewer MUST re-encode Abra-CJSON and verify `snapshot_id` before trusting the card.

### 9.3 What the static viewer must render

The static JS viewer, with zero integration, renders a **card**:

- `kind` (as text; map known kinds to a small icon if desired)
- `title`
- `origin.name` or short-id of `origin.peer_id`
- `created_at` (localize for display; do not rehash)
- `summary` if present
- `link` if present, as an `<a href>`
- `thumbnail` if present and decryptable from `blobs`

It MUST NOT require a backend. It MUST NOT send `k` anywhere. Deep links beyond `manifest.link` are derived by whoever consumes the snapshot — not by this viewer.

### 9.4 Mint record (minter device)

| Field | Type | Presence |
|---|---|---|
| `link_id` | string | 16 random bytes hex (may equal the blob’s object name on the host) |
| `snapshot_id` | string | |
| `expires_at` | string | canonical |
| `mode` | string | `"floor"` \| `"full"` |
| `url` | string | ciphertext https URL |
| `revoked` | boolean | |
| `sig` | string | domain `cap-mint`, payload = CJSON minus `sig` minus the key |

The 32-byte key is stored only if the minter wants to re-display the URL; it MAY be shown once and discarded. It MUST NEVER be uploaded next to the ciphertext.

---

## 10. Adapter contract

Adapters are separate executables. They speak **newline-delimited JSON** over stdio (UTF-8, one JSON object per line, `\n` terminator, no `\r`). The daemon launches the adapter, writes requests to stdin, reads stdout. stderr is logs. The daemon MUST flush each request line.

### 10.1 Registration manifest

File `abra-adapter.json` beside the binary, **or** the adapter may be invoked with argv `register` and print a single JSON object to stdout.

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `spec` | string | required | `"abra-adapter/1"` |
| `name` | string | required | `[a-z0-9._-]{1,64}` |
| `version` | string | required | Semver, informational. |
| `kinds` | array of string | required | Payload kinds this adapter handles. |
| `verbs` | array of string | required | Subset of `"export"`, `"import"`, `"watch"`. |
| `exec` | string | optional | If the manifest is not beside the binary: absolute path. |

The daemon indexes adapters by `kind`. Two adapters claiming the same kind: first registered wins; the daemon logs a warning.

### 10.2 Request / response envelope

**Request:** `{ "id": <integer ≥ 1>, "verb": "<name>", "kind": "<kind>", "params": { ... } }`

**Success:** `{ "id": <same>, "ok": true, "result": { ... } }`

**Error:** `{ "id": <same>, "ok": false, "error": { "code": "<code>", "message": "<string>" } }`

`id` matches request to response. `watch` MAY emit multiple `{ "id", "ok": true, "result": { "event": ... } }` lines until cancelled.

**Error codes:** `invalid_params`, `unsupported_kind`, `io`, `canceled`, `internal`. Unknown codes treated as `internal`.

Timeouts: `export` 10 minutes, `import` 10 minutes, `register` 5 seconds. `watch` runs until stdin EOF, process exit, or `{ "id": <new>, "verb": "cancel", "params": { "id": <watch id> } }`.

### 10.3 `export`

**params**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `path` | string | required | Absolute path of the local folder / app state root. |
| `hint` | object | optional | Kind-specific, ignored if unknown. |

**result**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `dir` | string | required | Staging directory the daemon will hash into a tree. Absolute. Adapter MUST NOT modify it after the result line. Daemon copies/hashes then MAY delete. |
| `payload` | object | required | Kind-specific; becomes `manifest.payload`. Integers only. |
| `title` | string | required | Floor title. |
| `summary` | string | optional | |
| `link` | string | optional | |
| `thumbnail_path` | string | optional | Absolute path to a jpeg/png/webp ≤ 512 KiB. Daemon ingests as blob. |
| `recipes` | array | optional | Recipe objects as in §1.6. Usually filled by an ambient observer, not the kind adapter; if present, daemon includes them. |

The daemon fills `origin`, `created_at`, `scope`, `kind`, hashes `dir` into `tree`, attaches native blobs from the observer if any.

### 10.4 `import`

**params**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `dir` | string | required | Materialized tree (plain folder). |
| `payload` | object | required | |
| `manifest` | object | required | Full manifest (floor + payload + origin). Adapter uses what it needs. |

**result:** `{ "opened": true }` or `{ "opened": false, "reason": "..." }`. Non-fatal `opened: false` still leaves files on disk; the daemon has already materialized.

### 10.5 `watch`

**params:** `{ "path": "<absolute>" }`

**result events:** `{ "event": "change"|"ready"|"error", "path": "<string, optional>", "message": "<optional>" }`

The daemon MAY debounce and export. Watch is best-effort.

### 10.6 Process lifecycle

- argv: the verb is **not** necessarily argv; v0.1 sends all verbs via NDJSON after spawn. Spawn: `adapter-binary` with no required args. Optional `register` argv for discovery.
- Exit nonzero: all in-flight ids fail `internal`.
- Adapter MUST treat unknown JSON keys in params as ignorable.

---

## 11. Built-in payload kinds

### 11.1 `dev.abra.workspace`

**Intent:** full folder snapshot of a continuing workspace/sandbox. `scope` MUST be `"full"`. `tree` MUST be present.

**`payload`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `root_name` | string | required | Last path component of the folder, NFC, ≤ 255 bytes, same name rules as tree components where possible. |
| `file_count` | integer | required | Number of kind 1–3 entries in the whole tree (not directories). |
| `total_bytes` | integer | required | Sum of file/symlink blob sizes (not tree body sizes). |
| `has_recipes` | boolean | required | Whether `recipes` is non-empty. Redundant but useful for floor UIs that do not parse recipes. |
| `has_native` | boolean | required | Whether `native` is non-empty. |

No ignore list. The tree is the workspace.

Reference adapter: exports/imports/watches a filesystem directory. Recipes and native blobs come from the sandbox observer if present; the filesystem adapter MAY return empty `recipes`.

### 11.2 `dev.abra.handoff.v1`

**Intent:** partial one-shot handoff (a link, with optional note). `scope` MUST be `"partial"`. `tree` MAY be present (attachments). `recipes` / `native` MUST be absent.

**`payload`**

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `url` | string | required | Absolute URI, ≤ 4096 bytes. |
| `note` | string | optional | NFC, ≤ 4000 scalars. |

`manifest.link` MUST equal `payload.url` if `link` is present; producers MUST set both to the same string. `manifest.title` is the handoff title (the floor); there is no duplicate title in payload.

Reference adapter: `export` from `{ "path" ignored or a json file, "hint": { "url", "title", "note" } }`; `import` opens `url` via the OS or returns `opened: true` and lets the host UI show the card.

---

## 12. Spec versioning and evolution

### 12.1 Fields

- Manifest `spec`: `"abra/<major>.<minor>"`. This document: `abra/0.1`.
- Wire `hello.wire`: unsigned integer. This document: `1`.
- Adapter manifest `spec`: `"abra-adapter/1"`.

`0.x` MAY break. `1.x` (when declared) MUST be additive on the manifest and wire: new optional fields, new message types that can be ignored, new payload kinds.

### 12.2 Compatibility rules

| Situation | Behavior |
|---|---|
| Unknown **optional** manifest field | Preserve in stored `M`. Do not strip. Hash uses original `M`. |
| Unknown **required-looking** field | If it is unknown, it is optional by definition; ignore for semantics, preserve bytes. |
| Unknown `kind` | Transfer cargo, render floor, pass `payload` through. Do not run an adapter. |
| Unknown `scope` value | Reject snapshot. |
| Unknown control `type` after handshake | `error unknown_type`, connection lives. |
| `hello.wire` no overlap | `hello-reject` `wire`. |
| `spec` major ≠ `0` when we are `abra/0.1` | Reject snapshot (v0.1 only understands `abra/0.1`). Minor: `abra/0.2` is unknown — reject in 0.1 (0.x is allowed to break). |
| Extra `features` | Ignore. |
| Unknown thumbnail `media_type` | Reject in 0.1 producers; 0.2 receivers would ignore thumbnail. |

### 12.3 Forward-compatible hashing

Because `snapshot_id` is the hash of exact bytes `M`, a v0.2 producer that adds a field produces a different id (correct). A v0.1 node MUST NOT re-serialize a foreign manifest; it stores `manifest_raw`. If a v0.1 node cannot parse `M` as JSON, it rejects.

Adding a field to a kind payload is a new kind (`dev.abra.handoff.v2`) **or** an optional field in `v1` that old nodes preserve. Prefer optional fields for compatible evolution; bump the kind when semantics change.

---

## Open Questions

1. **Lease race with equal `seq`:** last-`acquired_at` wins is simple and may surprise a user whose takeover lost a clock skew contest. A stricter `prev_hash` chain that rejects branches would stall the capsule until manual `lease_resolve`. Not specified here.
2. **Windows reserved names in trees:** reject-on-import vs rewrite. Currently reject. Painful for a file actually named `aux.c` on Linux.
3. **Object-stream multiplexing vs 8-stream cap:** large snapshots of tiny files may want a packed multi-object frame. Not in v0.1.
4. **Relay HTTP and authentication to a self-hosted relay** are sketched, not normative.
5. **Derivation of X25519 from Ed25519** must match libsodium exactly; a test vector suite is needed before multiple implementations interoperate on capability links.
6. **Whether `head` should ever diverge from `main`** (per-device local checkout pointer) is left to the SDK; the core treats `main` as the only first-class label besides `fork/*`.
7. **Control-message encryption beyond QUIC** for a future honest-but-curious transport: not specified; QUIC is assumed.
8. **Quota / max capsule size** is a local daemon policy, not a protocol field, except thumbnail 512 KiB and control-frame 16 MiB.

---

## Design Rationale

- **Snapshot id hashes canonical bytes, not a JSON DOM.** Stored `M` is authoritative so two implementations cannot disagree on whitespace or key order after parse.
- **Integers only, no floats, and sizes inside JSON stay in the 2^53-1 safe range.** Eliminates the worst canonical-JSON footgun. Tree/blob sizes on the binary side use `u64`.
- **Peer id is the Ed25519 public key** so iroh `NodeId` and Abra identity are the same bytes; no parallel identifier space.
- **Capsule ids are random, not content-addressed.** Capsules are identities (like inodes), not documents. Genesis is signed to bind the random id.
- **Parents live in the hashed manifest** so history cannot be rewritten without creating a new snapshot. The DAG record is just a signed pointer + stored bytes.
- **Labels are mutable and outside the hash** so `main` can move for rollback without rewriting snapshots. Forks get their own labels instead of silently moving `main`.
- **Writing without the lease is a first-class fork, not an error.** Matches the settled “branch-on-write / no silent merge” rule and keeps agent work from being discarded on takeover.
- **Ack signs `offer_id || snapshot_id`.** Outbox cannot be cleared by a replayed ack from an earlier attempt, and the receiver cannot be confused with a different snapshot.
- **Have/want is plan − have with trees as ordinary objects.** Simpler than bloom filters; 100k files of digest+kind+size is still well under the 16 MiB control cap.
- **Enrollment tokens bind to one guest key on first use** so a leaked token cannot mint an unbounded set of inert-looking devices after bind.
- **Guests cannot pair or send control in v0.1.** Limits blast radius of a stolen cloud token to scoped capsules/kinds, not the whole mesh.
- **Native blobs are extra CAS objects with a host fingerprint, never valid without a portable tree.** Instant resume stays an optimization; mismatched hosts still get a folder.
- **Capability-link key lives only in the URL fragment; ciphertext is AEAD with a random key, not the user’s identity key.** Anyone with the URL can read the floor — that is the point of a capability — and the hosting server cannot.
- **Relay tags are HMAC(pk, epoch-day), not a static recipient id.** Blind to content and to long-term correlation; within-day correlation is the explicit tradeoff.
- **Adapters never hash and never speak p2p.** The daemon owns CAS, identity, and the outbox. Adapters only shape app state into a directory + payload JSON, which keeps the stdio contract small and the security boundary obvious.
