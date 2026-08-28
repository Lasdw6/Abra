# Abra Protocol Specification v0.1

Status: independent implementable draft. The key words MUST, MUST NOT, REQUIRED, SHOULD, and MAY are normative.

## 1. Data model and manifest

Abra stores and transmits a snapshot as a canonical JSON manifest plus content-addressed objects. JSON field names are case-sensitive. IDs are lowercase, unpadded base32 (RFC 4648 alphabet `a-z2-7`) encodings of 32-byte BLAKE3 digests. Timestamps are RFC 3339 UTC strings with exactly three fractional digits, for example `2026-08-28T19:04:05.123Z`.

The top-level manifest is an object with these fields:

| Field | Type | Presence | Semantics |
|---|---|---|---|
| `spec_version` | string | required | Exactly `abra.snapshot/0.1`. |
| `scope` | string enum | required | `full` or `partial`. |
| `kind` | string | required | Reverse-DNS payload kind, lowercase ASCII segments; built-ins are defined below. |
| `title` | string | required | Human-readable card title; nonempty, UTF-8, at most 512 Unicode scalar values. |
| `origin` | object | required | Capture origin, defined below. |
| `created_at` | timestamp | required | Time capture completed. |
| `summary` | string | optional | Plain-text card summary, at most 4096 Unicode scalar values. |
| `link` | string | optional | Absolute `https` or registered application URI representing captured data; never a prescribed receive action. |
| `thumbnail` | object | optional | `{ "blob": <blob-id>, "media_type": <string>, "width": <u32>, "height": <u32> }`; media type MUST be `image/png`, `image/jpeg`, `image/webp`, or `image/avif`; dimensions are intrinsic pixels. |
| `capsule_id` | string | conditional | Required for `full`, forbidden for `partial`; stable capsule ID. |
| `parents` | array of snapshot IDs | conditional | Required for `full`, forbidden for `partial`; 0–2 distinct IDs, ordered lexicographically. Empty creates a root; two denotes an explicit reconciliation commit, not an automatic merge. |
| `labels` | array of label objects | conditional | Required for `full`, forbidden for `partial`; may be empty. |
| `provenance` | object | optional/conditional | Allowed only on `partial`: `{ "capsule_id": <id>, "snapshot_id": <id>, "turn_label": <string|null> }`. `turn_label` is null or 1–256 scalar values. |
| `files` | tree ID | conditional | Required for every `full`; optional for `partial`. Root of portable file cargo. An empty tree is used when a full snapshot has no files. |
| `recipes` | array of recipe objects | conditional | Required for `full`, forbidden for `partial`; may be empty. Derived by the sandbox observer. |
| `native_blobs` | array of native-blob objects | conditional | Required for `full`, forbidden for `partial`; may be empty and never authoritative. |
| `payload` | object | required | Kind-specific structured JSON. |
| `extensions` | object | optional | Extension keys MUST be reverse-DNS names; values are arbitrary JSON. Unknown extensions are retained but ignored. |
| `signer` | peer ID | required | Peer that created the manifest. |
| `signature` | string | required | Ed25519 signature as lowercase unpadded base32, as specified in Identity. |

`origin` is `{ "peer_id": <peer-id>, "device_name": <string>, "adapter": <string|null>, "captured_at": <timestamp> }`. `device_name` is nonempty and at most 128 scalar values. `adapter` is null for core capture or an adapter registration ID. `captured_at` is when capture began and MUST NOT be later than `created_at`. `origin.peer_id` MUST equal `signer`.

A label is `{ "name": <string>, "value": <string|null> }`; `name` matches `[a-z][a-z0-9._-]{0,63}`, `value` is null or at most 512 scalar values. Labels are sorted by `(name, value)`, with null before strings. Duplicate pairs are forbidden. Reserved names are `agent-turn`, `fork`, `rollback`, and `checkpoint`.

A recipe is:

```json
{"argv":["program","arg"],"cwd":"relative/path","env":{"KEY":"value"},"listen":[{"host":"127.0.0.1","port":8080,"protocol":"tcp"}],"observed_start_at":"2026-08-28T19:04:05.123Z"}
```

`argv` is a nonempty string array; `cwd` is a normalized relative POSIX path (`"."` allowed; no empty, `.` other than the whole value, `..`, NUL, or leading slash); `env` is a string-to-string map capturing the observed environment byte-for-byte where valid UTF-8 (non-UTF-8 entries are omitted); `listen` is sorted by `(protocol,host,port)` and uses `tcp` or `udp`, a literal IP address or `*`, and ports 1–65535. `observed_start_at` is a timestamp or null. Recipes are sorted by the canonical bytes of each recipe. Importers MUST display recipes and MUST NOT execute them without explicit user action.

A native blob is `{ "role": <string>, "blob": <blob-id>, "media_type": <string>, "host": <fingerprint> }`. `role` matches `[a-z][a-z0-9._-]{0,63}`. The fingerprint is `{ "os": <string>, "arch": <string>, "hypervisor": <string>, "fc_snapshot_format_major": <u32|null>, "cpu_template": <string> }`. Every string is lowercase ASCII and nonempty. Entries sort by `(canonical host bytes, role, blob)`. A receiver MUST use the object only if every fingerprint field equals its locally reported fingerprint; otherwise it skips it. Files and recipes remain the source of truth.

No manifest may contain JSON `null` except at fields explicitly permitting it. Optional fields are omitted, never null.

## 2. Canonical JSON and snapshot ID

Canonical JSON is UTF-8 with no BOM. Objects have keys sorted by raw UTF-8 byte order; arrays preserve their specified order; there is no whitespace outside strings; literals are lowercase. Strings use shortest JSON escaping: escape quotation mark, reverse solidus, and U+0000–U+001F (using `\b`, `\t`, `\n`, `\f`, `\r` where applicable and lowercase `\u00xx` otherwise); emit every other Unicode scalar directly as UTF-8. Input MUST be valid Unicode and MUST NOT contain unpaired surrogates. Unicode is not normalized.

Numbers MUST be integers in `0..=9007199254740991`; negative values and floating-point/exponent forms are forbidden throughout protocol JSON. Emit decimal digits with no leading zero except `0`. Protocol quantities requiring signed or larger values must be decimal strings defined by their field.

To sign and identify a manifest, remove the `signature` member and canonicalize the resulting object. The signature input is the ASCII domain `abra-snapshot-signature-v1`, one zero byte, then those canonical bytes. Insert `signature`, canonicalize the complete manifest, and define:

`snapshot_id = base32_lower_no_pad(BLAKE3(canonical_complete_manifest_bytes))`.

The exact bytes hashed are the entire canonical complete JSON document, from `{` through `}`, with no trailing newline. Receivers MUST reject noncanonical manifest bytes rather than silently reserialize them and MUST verify both signature and claimed/out-of-band snapshot ID.

## 3. Content-addressed objects

An object ID is `base32_lower_no_pad(BLAKE3(object_bytes))`. Object kind is known from the referencing field and transfer descriptor. Blob object bytes are exactly the file/native/thumbnail payload bytes; zero-length blobs are valid.

A tree object is canonical JSON with no signature:

```json
{"entries":[{"kind":"file","mode":420,"name":"README.md","object":"...","size":123},{"kind":"symlink","name":"current","target":"releases/v1"},{"kind":"tree","name":"src","object":"..."}],"version":"abra.tree/0.1"}
```

Entries are sorted by raw UTF-8 bytes of `name`. Names are nonempty valid UTF-8, contain neither `/` nor NUL, and are not `.` or `..`; duplicate names are forbidden. `kind=file` requires `object`, `size`, and `mode`; mode is exactly 420 (`0644`) or 493 (`0755`), preserving only the owner executable bit normalized to all executable bits. `size` is the blob length. `kind=tree` requires only `name`, `kind`, `object`. `kind=symlink` requires `target`, an arbitrary nonempty UTF-8 path without NUL; links are stored and materialized as links and MUST NOT be followed during capture. Other filesystem metadata (ownership, timestamps, ACLs, xattrs, sparse layout, and non-executable permission bits) is not captured in v0.1. Special files are an export error. Tree bytes use the canonical rules above; tree ID hashes the complete bytes without a trailing newline.

Object descriptors are `{ "id": <object-id>, "kind": "blob"|"tree", "size": <u53> }`. A receiver MUST verify byte count and hash before committing an object atomically to CAS.

## 4. Identity and signatures

Each peer has an Ed25519 keypair generated from 32 cryptographically random bytes and stored in platform-protected storage. Public keys are 32 bytes. A peer ID is `p_` plus unpadded lowercase base32 of the public key. A display-only short ID is the first 10 base32 characters of `BLAKE3("abra-peer-short-v1" || 0x00 || public_key)`; it MUST NOT be used for authorization.

All signature fields encode the 64 signature bytes as unpadded lowercase base32. Unless specified otherwise, signed inputs are `ASCII-domain || 0x00 || canonical-JSON-with-signature-field-removed`. Verification uses the public key embedded in the peer ID. Possession of a key establishes identity, not authorization; the local trust store or enrollment grant supplies authorization.

## 5. Capsules, history, and leases

A capsule ID is `c_` plus lowercase unpadded base32 of 16 random bytes. It is minted once and is not content-addressed. Full manifests themselves are DAG records: `capsule_id`, `parents`, and `labels` define history. Every parent MUST be a known full snapshot in the same capsule. A normal commit has one parent; a root has none; an explicit reconciliation has two. A rollback creates a new one-parent snapshot whose content may equal an ancestor and includes `{name:"rollback",value:<target-snapshot-id>}`. History is immutable.

If a writer lacks the current valid lease, its new snapshot MUST parent the last snapshot it observed and include `{name:"fork",value:<lease-record-id-or-null>}`. It MUST NOT advance the capsule's canonical head. Reconciliation is an explicit two-parent snapshot created by a lease holder. The store tracks zero or more heads and one optional preferred head; labels never change IDs.

A lease record is canonical signed JSON:

```json
{"capsule_id":"c_...","epoch":7,"expires_at":"2026-08-28T19:14:05.123Z","holder":"p_...","issued_at":"2026-08-28T19:04:05.123Z","previous":"...","signature":"...","spec_version":"abra.lease/0.1"}
```

`epoch` is a u53 and strictly increases; `previous` is the prior lease-record ID or null. The lease-record ID is the BLAKE3 ID of complete canonical bytes. The signer MUST be the prior unexpired holder, except the capsule creator signs epoch 0 and an expired lease may be acquired by any peer authorized for that capsule by signing epoch+1. Transfer is a new record signed by the current holder naming a new holder. An issued record MUST have `issued_at < expires_at` and duration at most 24 hours. Receivers compare expiry to their wall clock with a 120-second grace only for rejecting premature takeover; writers treat local expiry with no grace. Competing valid records at the same epoch are a lease conflict: neither authorizes canonical-head writes until an authorized device issues a higher epoch referencing one selected record. On lease loss, integrations MUST stop mutation. Control messages are typed partial snapshots, not lease operations.

## 6. Secure delivery protocol

The Transport supplies a mutually authenticated, reliable byte stream with forward-secret encryption (QUIC/iroh is preferred). Peers authenticate the handshake with their Ed25519 identity and MUST reject keys absent from the trust/grant store. Abra frames messages as `u32` big-endian byte length followed by one canonical JSON object; maximum frame length is 16 MiB. Blob chunks are base64url without padding inside JSON. Implementations MAY use an equivalent binary data stream only after negotiating an extension; v0.1 baseline remains interoperable JSON framing.

The first message in each direction is `hello`:

`{"type":"hello","versions":["0.1"],"peer_id":...,"nonce":<base64url-32-random-bytes>,"features":[...],"grants":[<token-id>...]}`.

Versions are descending preference; select the highest common version or send `error` code `unsupported_version` and close. Features are sorted unique strings. After both hellos, each sends `hello_auth` with `version`, both peer IDs and nonces in lexicographic peer-ID order, and a signature over domain `abra-hello-v1` plus canonical unsigned message. This binds peer authentication to the encrypted channel. Common fields on every later message are `type`, `version:"0.1"`, and random `message_id` (16-byte base32).

Message types and required fields:

- `ping`: `sent_at`, `nonce`. Reply `pong`: same `nonce`, `received_at`. A 10-second timeout marks peer unavailable but does not delete queued work.
- `snapshot_offer`: `delivery_id` (16-byte random base32), `snapshot_id`, `manifest_size`, `manifest` (base64url canonical bytes), `objects` (sorted descriptors), and `expires_at|null`. Receiver validates manifest and authorization, then replies `want`.
- `want`: `delivery_id`, `snapshot_id`, `have` (sorted object IDs), `want` (sorted object IDs), `resume` map from object ID to offset. Every offered object MUST occur exactly once in `have` or `want`. `resume` contains only wanted blobs and offsets no greater than advertised size; trees always resume at zero.
- `blob_chunk`: `delivery_id`, `object_id`, `kind`, `offset`, `data`, `final`. Chunks are at most 8 MiB decoded, contiguous from the negotiated offset, and `final=true` iff the chunk ends at advertised size. Despite the name it carries blob or tree bytes. Receiver persists partial bytes keyed by `(sender,delivery_id,object_id)`, verifies final size/hash, then atomically installs.
- `object_ack`: `delivery_id`, `object_id`, `size`, `hash`, `signature`. Signature domain is `abra-object-ack-v1`; `hash` equals `object_id`. It confirms durable CAS storage.
- `snapshot_ack`: `delivery_id`, `snapshot_id`, `received_at`, `shelf` (`capsule` or `inbox`), `signature`. Signature domain is `abra-snapshot-ack-v1`. It is sent only after all objects and the manifest are durable and authorization/referential checks pass.
- `resume_request`: `delivery_id`, `snapshot_id`. Receiver replies with `want` containing current durable/partial state. A sender may re-offer when receiver lost state.
- `error`: `in_reply_to`, `code`, `message`, `retryable`; codes are `bad_request`, `unauthorized`, `unsupported_version`, `not_found`, `hash_mismatch`, `quota`, `expired`, `conflict`, and `internal`.

The receiver MUST recompute `have`; sender-provided assumptions are never trusted. Transfers may interleave by `delivery_id`. Duplicate offers, chunks entirely below the persisted offset, object acknowledgements, and snapshot acknowledgements are idempotent. An overlapping chunk with differing bytes is `hash_mismatch` and discards that partial object. Snapshot ack proves receipt, not import or execution.

Each persistent outbox entry contains `delivery_id`, recipient peer ID, snapshot ID, creation/expiry times, attempt count, next-attempt time, and state. States are `queued -> health_check -> negotiating -> transferring -> awaiting_ack -> delivered`; any pre-delivered state may move to `retry_wait` on retryable failure and then `health_check`, preserving the delivery ID and partial progress. Permanent error or local cancellation moves to `failed` or `cancelled`. Only a verified `snapshot_ack` from the intended recipient moves to `delivered`; only then may the active entry be cleared, while its delivery receipt SHOULD remain. Exponential retry starts at 1 second, doubles to 5 minutes, and applies ±20% jitter. Expiry moves an entry to `failed`.

## 7. Pairing and enrollment

A pairing ticket is canonical JSON encoded as unpadded base64url and normally conveyed as `abra-pair:<encoding>` in a QR code or copy/paste string:

```json
{"addresses":["..."],"expires_at":"...","inviter":"p_...","nonce":"<base64url 32 bytes>","signature":"...","spec_version":"abra.pair/0.1"}
```

Addresses are transport hints, sorted and limited to 16. The inviter signs domain `abra-pair-ticket-v1`. Tickets expire within 10 minutes and are single-use; the inviter persists a hash of the nonce until expiry. The joiner connects over encrypted transport, verifies the ticket signature and inviter peer ID, displays both peers' short IDs, and sends `pair_accept` containing the ticket nonce, joiner peer ID, device name, and its signature over domain `abra-pair-accept-v1`. The inviter MUST require local user confirmation matching the displayed joiner short ID, consume the nonce atomically, then both store the other public key as a full mesh peer. Ticket possession alone does not enroll a peer.

An enrollment token is canonical signed JSON, encoded as `abra-enroll:<base64url>`:

```json
{"audience":"p_...","capsules":["c_..."],"expires_at":"...","issued_at":"...","issuer":"p_...","kinds":["dev.abra.workspace"],"nonce":"<base64url 16 bytes>","permissions":["receive","send","lease"],"signature":"...","spec_version":"abra.enrollment/0.1","token_id":"<32-byte-id>"}
```

The issuer is a trusted full device and signs domain `abra-enrollment-v1`. `audience` binds the token to the sandbox peer key. Arrays are sorted unique. `capsules` or `kinds` may contain `"*"`; mixing `*` with other entries is forbidden. Permissions are a subset of `receive`, `send`, `lease`; absence means denial. Expiry MUST be after issuance and no more than 30 days later. `token_id` is the BLAKE3 ID of the canonical unsigned token excluding both `token_id` and `signature`, preventing self-reference.

Revocation is a signed record `{spec_version:"abra.revocation/0.1",token_id,revoked_at,issuer,reason,signature}` with domain `abra-revocation-v1`. Devices distribute records over the same durable delivery channel and retain them at least until token expiry. Receivers MUST reject expired, revoked, wrong-audience, unknown-issuer tokens. For every offered snapshot they enforce kind, capsule (partials use provenance capsule if present; a provenance-free partial requires capsule `*`), and direction permission. Lease records require `lease` and matching capsule. A token grants no pairing, minting, or revocation authority. A tokenless, unpaired peer is inert. Local policy may further restrict agent-initiated sends and can never be widened by a token.

## 8. Optional relay (v-next extension)

Relays are optional; direct peer delivery MUST work without them. Feature `relay-v1` carries opaque store-and-forward items:

`relay_item = u32be(header_length) || canonical_header || ciphertext`

The header is `{ "version":"abra.relay/0.1", "tag":<base64url 32 bytes>, "item_id":<object-id>, "created_at":<timestamp>, "expires_at":<timestamp>, "ciphertext_size":<u53> }`. `item_id` is BLAKE3 of ciphertext. Ciphertext is an application-sealed delivery stream using an ephemeral X25519 key derived through an Ed25519-to-X25519 implementation fixed by the negotiated extension; its precise HPKE suite remains v-next and therefore relay interoperability is not required by v0.1.

For UTC epoch day `D = floor(unix_seconds/86400)` encoded as signed decimal ASCII, the upload tag is `HMAC-SHA256(K_recipient_static, "abra-relay-tag-v1" || 0x00 || D)`, where `K_recipient_static` is a separately provisioned 32-byte relay discovery key, not the Ed25519 private key. Receivers query current and previous day tags. TTL is at most 7 days; relays delete expired items, cap item size, and learn neither manifest nor peers. Reusing a daily tag permits same-day correlation; no stronger unlinkability is claimed.

## 9. Capability links

A capability URL is `https://<host>/v/0.1/<object-id>#k=<base64url-key>&id=<snapshot-id>`. The path names an opaque hosted object; the fragment is never sent to the server. `key` is 32 random bytes. The hosted bytes are `nonce || ciphertext || tag` from XChaCha20-Poly1305 with a 24-byte random nonce, key `key`, empty associated data, and plaintext a bundle defined as `u32be(manifest_length) || canonical_manifest || u32be(object_count) || repeated(object_kind_byte || object_id_32 || u64be(object_length) || object_bytes)`. Objects include every transitively referenced tree and blob exactly once and sort by `(object_kind_byte, object_id_32)`; kind byte is `0x01` for tree and `0x02` for blob, and `object_id_32` is the decoded digest. The URL path `<object-id>` is the lowercase base32 BLAKE3 digest of the complete hosted bytes. The viewer verifies snapshot/object hashes and signature before display.

The static viewer needs only the URL fragment key, encrypted bundle, canonical JSON parser, BLAKE3, Ed25519, XChaCha20-Poly1305, and renderers for the floor fields `kind`, `title`, `origin`, `created_at`, optional `summary`, `link`, and `thumbnail`. It MUST render these without a kind integration and MUST NOT execute recipes or native blobs. Minting requires an explicit action, expiry at most 30 days, and a server-side revocation handle. URL revocation/TTL is hosting policy; cryptographic erasure is achieved by deleting ciphertext. Anyone with the complete URL has read capability.

## 10. Adapter contract

An adapter is an executable registered by a canonical JSON manifest:

```json
{"exec":["/absolute/adapter"],"id":"com.example.adapter","kinds":["com.example.state"],"protocol":"abra.adapter/0.1","verbs":["export","import","watch"]}
```

`id` and kinds are reverse-DNS strings; `exec` is nonempty and arguments are literal; verbs are sorted unique. Registration files are configuration, not snapshot content.

Core starts one process per operation. stdin and stdout are UTF-8 newline-delimited JSON, one canonical object per line, maximum 1 MiB; stderr is diagnostic only. Every request has `protocol`, random `request_id`, and `verb`. Every response repeats `request_id` and contains either `ok:true` plus verb fields, or `ok:false,error:{code,message,retryable,details}`. Unknown fields are ignored; malformed lines, mismatched IDs, output after terminal response, or EOF before terminal response fail the operation. Core sends `cancel` with `request_id`; after 5 seconds it may terminate the process.

- `export` request: `kind`, `source` (absolute local path or adapter-defined URI), `staging_dir` (empty writable directory), `options`. Success: `payload`, `files_path` (relative path within staging dir or null), and optional `floor` containing any of `title`, `summary`, `link`, `thumbnail_path`. Core validates, imports staged bytes into CAS, and authors/signs the envelope; adapters never choose IDs or origin.
- `import` request: `kind`, `payload`, `materialized_files` (absolute path or null), `destination`, `options`. Success: `result` object and optional `deep_link`. Core materializes verified files before invocation. The adapter MUST NOT be asked to run recipes implicitly.
- `watch` request: `kind`, `source`, `options`. It first responds `ok:true,watching:true`, then emits events `{request_id,event:"changed",cursor:<string>,hint:<object>}` until cancellation. Cursors are opaque and monotonically advance within that process. Events are hints; core performs export and may debounce/coalesce them.

Standard error codes are `invalid_request`, `unsupported_kind`, `unsupported_verb`, `not_found`, `permission_denied`, `busy`, `cancelled`, and `internal`. Adapters MUST NOT write outside `staging_dir` during export unless the user has independently granted access to the source.

## 11. Built-in payload kinds

### `dev.abra.workspace`

Scope MUST be `full`; `files` is required. Payload is:

```json
{"default_cwd":".","name":"project","schema":"dev.abra.workspace/1","vcs":{"commit":"<hex>","dirty":true,"kind":"git","remote":"https://..."}}
```

`schema`, `name`, and `default_cwd` are required. `name` is nonempty, at most 255 scalar values. `default_cwd` is a normalized relative path and MUST resolve to a tree in `files`. `vcs` is optional; if present, `kind` is required (`git` in v0.1), while `commit`, `remote`, and `dirty` are optional. `commit` is lowercase hex; `remote` is an absolute URI; metadata is descriptive and never used to fetch missing bytes. Recipes and native blobs remain top-level cargo.

### `dev.abra.handoff.v1`

Scope MUST be `partial`. Payload is `{ "url": <string>, "title": <string>, "note": <string|null> }`. `url` is an absolute `https` URI, `title` is nonempty and at most 512 scalar values, and `note` is null or at most 16,384 scalar values. Top-level `title` MUST equal payload `title`; top-level `link` MUST equal `url`. Files are optional attachments. This kind lands in the inbox and has no lineage, though provenance may point to a source turn.

## 12. Versioning and evolution

Every persisted record and protocol message carries the exact version shown by its schema. The major component changes for any incompatible semantic, cryptographic, or encoding change; a future minor version may only add optional fields, enum values gated by a negotiated feature, or new message/kind types. `0.1` implementations accept exactly major 0/minor 1 unless a later minor is explicitly advertised in `hello`.

For recognized schemas, unknown top-level fields outside `extensions` are rejected when validating canonical signed records; this prevents different implementations assigning different meaning to signed data. Unknown `extensions` entries are retained byte-semantically through parse/canonical reserialization and ignored. Unknown payload fields are retained and ignored unless the registered kind schema says otherwise. Unknown kinds remain storable, transferable, and floor-renderable but cannot be imported without an adapter. Unknown enum values in core fields are rejected. Implementations MUST retain original canonical manifest bytes, not reconstruct them, for identity and forwarding.

## Open Questions

- Fix the optional relay's precise sealed-box/HPKE suite and Ed25519-to-X25519 conversion before promoting `relay-v1` into the baseline.
- Decide whether a later tree format should preserve xattrs, ACLs, non-UTF-8 names, and sparse extents without weakening portability.
- Specify a scalable revocation-distribution freshness policy for intermittently connected agents; v0.1 is fail-closed only when a known revocation exists or a token expires.
- Define an administrator-mediated resolution record for same-epoch lease conflicts; v0.1 requires an authorized higher-epoch selection but leaves its recovery UI out of scope.

## Design Rationale

- Canonical JSON keeps manifests inspectable while making IDs and signatures deterministic.
- The signature is inside the hashed manifest, so a snapshot ID commits to both content and author attestation.
- Rejecting noncanonical bytes prevents signature-valid alternate encodings and cross-implementation ID drift.
- Trees use normalized portable modes and preserve symlinks without following them.
- Full snapshots always include an empty-or-populated file tree, making portable state the invariant source of truth.
- Random capsule IDs preserve identity across content changes; immutable snapshot IDs form the DAG.
- Two parents are reserved for deliberate reconciliation; ordinary lease violations visibly fork.
- Lease epochs plus signed predecessor links make takeover auditable without pretending clocks provide consensus.
- Receiver-computed have/want makes CAS delta negotiation safe and naturally resumable.
- Only a recipient-signed durable snapshot acknowledgement clears the outbox.
- Pairing combines possession of a short-lived ticket with local confirmation; enrollment is narrower and non-transitive.
- Kind, capsule, direction, audience, expiry, and revocation are all enforced at receipt, not trusted to senders.
- Adapter staging lets the core own fidelity, hashing, envelope validity, and identity.
- Capability fragments preserve zero-install use without exposing decryption keys to hosting servers.
- Relay details remain explicitly optional until their cryptographic suite is fully pinned.
