# Abra wire format — `abra_spec: 1`

This document specifies the on-disk and on-the-wire encoding of Abra snapshots.
It is normative for `abra-core` 0.1.

Everything here is version-tagged with `"abra_spec": 1`. A receiver MUST reject
a manifest whose `abra_spec` it does not implement.

## 1. Primitives

### 1.1 Hashes

All content addressing uses **BLAKE3-256**. A hash is encoded in JSON as a
lowercase hex string of exactly 64 characters.

### 1.2 Public keys, peer ids, signatures

- A public key is an Ed25519 public key: 32 bytes, lowercase hex (64 chars).
- A **peer id** is the first 8 bytes of `blake3(pubkey_bytes)`, lowercase hex
  (16 chars). It is a display and indexing convenience; verification is always
  against the full public key, which is stored alongside.
- A signature is 64 bytes, lowercase hex (128 chars).

### 1.3 Timestamps

Unix milliseconds since the epoch, as an unsigned JSON integer.

### 1.4 Domain separation

Every signature is over `domain_bytes || 0x00 || payload`, where the domain for
enrollment certificates is `abra.enroll.v1`. Signatures are never computed over
a bare payload.

### 1.5 Canonical JSON

The **canonical form** of a manifest (or any Abra object that is hashed or
signed) is JSON with:

1. UTF-8 encoding, no byte-order mark;
2. no insignificant whitespace;
3. object keys sorted ascending by their UTF-8 byte sequence;
4. absent optional fields **omitted**, never emitted as `null`;
5. empty arrays and empty maps for optional collection fields omitted;
6. integers written with no fraction and no exponent;
7. array element order preserved as given.

Canonicalization is a pure function of the value, so two implementations that
agree on the value agree on the bytes, and therefore on the hash.

### 1.6 Snapshot hash

```
snapshot_hash = blake3(canonical_json(manifest))
```

A snapshot id is self-verifying: fetch it, canonicalize, hash, compare. Note
that the hash covers the manifest only — the manifest in turn commits to the
file tree and every blob by hash, so the whole bundle is covered transitively.

## 2. Blob store

Blobs are stored sharded by the hex of their hash:

```
<root>/blobs/<hex[0..2]>/<hex[2..64]>
```

Blob content is stored exactly as given. There is no header, no compression,
and no transformation — the file's bytes hash to its name. Tree objects (§3)
and manifests (§4) are stored in this same namespace; what an object *is* comes
from how it was referenced, not from anything inside it.

Writes are atomic: content is written to a temporary file in the store and
renamed into place, so a blob path either does not exist or holds complete,
correct content.

## 3. Tree objects

A tree object encodes one directory. It is a byte string:

```
tree   := "abra.tree.v1\n" entry*
entry  := mode SP name NUL hash
mode   := "file" | "exec" | "link" | "tree"
SP     := 0x20
NUL    := 0x00
name   := UTF-8 bytes, non-empty, no NUL, no "/", not "." or ".."
hash   := 32 raw bytes (not hex)
```

Entries MUST be sorted ascending by `name`'s UTF-8 bytes, and names MUST be
unique within a tree. Sorting plus content addressing means a directory state
has exactly one encoding, and therefore exactly one hash.

Modes:

| mode   | `hash` refers to                                     |
| ------ | ---------------------------------------------------- |
| `file` | a blob: the file's bytes                             |
| `exec` | a blob: the file's bytes; the file is executable     |
| `link` | a blob: the symlink's target path, as raw bytes      |
| `tree` | another tree object                                  |

A directory state is identified by its **root tree hash**. That hash is what a
manifest's `files` field carries.

### 3.1 Walking a directory

`snapshot_dir` walks a directory and stores every file as a blob and every
directory as a tree, returning the root tree hash.

**It skips nothing except the `.abra` metadata directory.** `.git` is walked
and stored like any other directory. There is no ignore-file logic and no
secret exclusion: v1 syncs byte for byte (see DESIGN §8). Symlinks are stored as
links, not followed.

A file is `exec` if any execute bit is set in its mode.

### 3.2 Materializing

`materialize` writes a tree out to a path. Files are created with mode `0644`,
executables with `0755`, and symlinks with the stored target. Round-tripping
`snapshot_dir` then `materialize` reproduces file contents byte for byte, the
directory structure, symlink targets, and the executable bit. It does not
preserve mtimes, ownership, or non-execute permission bits — the tree object
does not carry them.

## 4. The manifest

One envelope format. A `scope` field splits behaviour.

### 4.1 Fields

| field        | type          | presence                     | meaning                                        |
| ------------ | ------------- | ---------------------------- | ---------------------------------------------- |
| `abra_spec`  | integer       | required, MUST be `1`        | format version                                 |
| `scope`      | `"full"` \| `"partial"` | required           | version-of-a-capsule vs. delivery              |
| `kind`       | string        | required, non-empty          | payload type, e.g. `abra.workspace`            |
| `title`      | string        | required, non-empty          | human label                                    |
| `origin`     | peer id       | required                     | sending peer                                   |
| `created_at` | timestamp     | required, non-zero           | when the snapshot was authored                 |
| `summary`    | string        | optional                     | one-line description                           |
| `link`       | string (URL)  | optional                     | a URL the receiver may render or open          |
| `thumbnail`  | hash          | optional                     | blob: preview image                            |
| `files`      | hash          | optional                     | root tree object (§3)                          |
| `recipes`    | array<Recipe> | optional, omitted if empty   | how to recreate processes (§4.3)               |
| `native`     | array<NativeBlobRef> | optional, omitted if empty | acceleration artifacts (§4.4)           |
| `extra`      | object        | optional, omitted if empty   | payload-specific structured data               |
| `capsule_id` | capsule id    | required iff `full`          | the continuing thing this versions             |
| `parents`    | array<hash>   | `full` only, omitted if empty | parent snapshot hashes (history DAG)          |
| `label`      | string        | `full` only, optional        | e.g. an agent turn label                       |
| `lease`      | Lease         | `full` only, optional        | who was driving (§4.5)                         |
| `provenance` | Provenance    | `partial` only, optional     | back-reference to a capsule version (§4.2)     |

`kind`, `title`, `origin`, and `created_at` are the **floor fields**: any device
can render a card from them without understanding the payload. A manifest is
always JSON — a snapshot is never an opaque blob.

`extra` is the extension point. It is structured data, not a rendering: carry
the data, don't prescribe the experience.

### 4.2 Provenance

```json
{ "capsule_id": "<capsule id>", "snapshot_hash": "<hash>", "label": "optional string" }
```

A reference, not membership. A partial carrying provenance is still not part of
the capsule's DAG.

### 4.3 Recipe

```json
{
  "argv": ["npm", "run", "dev"],
  "cwd": "app",
  "env": { "NODE_ENV": "development" },
  "ports": [5173],
  "started_at": 1756300000000
}
```

- `argv` — required, non-empty; `argv[0]` is the program.
- `cwd` — required; a **relative** path from the workspace root. Absolute paths
  and `..` components are rejected, so the receiver decides where the root
  lands.
- `env` — map of string to string; canonically key-sorted.
- `ports` — TCP ports the process was observed listening on.
- `started_at` — optional timestamp.

Recipes are **derived by an observer, not declared**, and they are **data
only**. Abra core never executes a recipe.

### 4.4 Native blob ref

```json
{
  "fingerprint": "linux-kvm-x86_64/fc-snap-v11/cpu-template-none",
  "role": "memory",
  "hash": "<blob hash>",
  "size": 2147483648
}
```

Opaque acceleration artifacts, carried unchanged (e.g. a Firecracker memory
file and VM state file). `fingerprint` identifies the host class that can use
them; a receiver whose fingerprint differs MUST NOT attempt to restore from
them. `role` distinguishes multiple blobs sharing a fingerprint (`memory`,
`vmstate`, ...).

Native blobs are an evictable cache and **never the source of truth**. Dropping
them costs time, not data.

### 4.5 Lease

```json
{ "holder": "<peer id>", "acquired_at": 1756300000000, "expires_at": 1756303600000 }
```

Coordination, not enforcement. A device that authors against a stale lease
creates a fork, which is representable: `parents` is a list.

### 4.6 Validation

A manifest is valid iff:

- `abra_spec == 1`;
- `kind` and `title` are non-empty and `created_at != 0`;
- `scope == "full"` ⇒ `capsule_id` is present;
- `scope == "partial"` ⇒ `capsule_id`, `parents`, and `lease` are absent
  (`parents` empty);
- `scope == "full"` ⇒ `provenance` is absent;
- every `recipe.argv` is non-empty and every `recipe.cwd` is relative and free
  of `..`;
- every `native.fingerprint` and `native.role` is non-empty.

## 5. Capsules and the DAG

A **capsule id** is 16 random bytes, lowercase hex (32 chars). A capsule's
history is the DAG reachable from its head through `parents`. Multiple children
of one parent are a fork; a manifest with two parents is a merge. `log` orders a
capsule's reachable snapshots newest first by `created_at`, breaking ties by
hash so the order is deterministic.

Capsule *metadata* — name, local home path, head, lease holder — is local
bookkeeping. It is not part of the wire format and is not hashed.

## 6. Capability links

```
abra://s/<blob-hash>#<base64url-nopad key>
https://<host>/s/<blob-hash>#<base64url-nopad key>
```

The 32-byte key lives in the URL **fragment**, which browsers do not send to
the server. `<blob-hash>` addresses the **sealed bundle**, not the manifest: a
host serving links sees a hash and a ciphertext and learns nothing else.

### 6.1 Bundle plaintext

```json
{
  "abra_spec": 1,
  "manifest": { "...": "the manifest" },
  "blobs": { "<hash>": "<base64-nopad bytes>" }
}
```

`blobs` carries every blob the manifest references, transitively through tree
objects (tree objects themselves included), so a bundle opens without any
further fetches.

### 6.2 Sealing

```
key        = 32 random bytes
nonce      = 24 random bytes
ciphertext = nonce || XChaCha20-Poly1305(key, nonce, aad = "abra.link.v1", plaintext)
link hash  = blake3(ciphertext)
```

Each seal uses a fresh key, so a link is a bearer capability for exactly one
bundle and revocation is deletion of the ciphertext.

## 7. Worked example: a full workspace snapshot

Pretty-printed for readability; the canonical form is the same value minified
with sorted keys.

```json
{
  "abra_spec": 1,
  "capsule_id": "9f2c1d7a4b8e0355a6d1c4e7f0b93a26",
  "created_at": 1756300000000,
  "files": "1b0f3c5d8e7a29406f1d2c3b4a59687706f5e4d3c2b1a09f8e7d6c5b4a392817",
  "kind": "abra.workspace",
  "label": "turn 14: fix the flaky test",
  "lease": {
    "acquired_at": 1756299000000,
    "expires_at": 1756302600000,
    "holder": "3fa9c17b2e5d0846"
  },
  "native": [
    {
      "fingerprint": "linux-kvm-x86_64/fc-snap-v11/cpu-template-none",
      "hash": "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900",
      "role": "memory",
      "size": 2147483648
    },
    {
      "fingerprint": "linux-kvm-x86_64/fc-snap-v11/cpu-template-none",
      "hash": "bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900aa11",
      "role": "vmstate",
      "size": 41216
    }
  ],
  "origin": "3fa9c17b2e5d0846",
  "parents": [
    "0c9d8e7f6a5b4c3d2e1f00112233445566778899aabbccddeeff001122334455"
  ],
  "recipes": [
    {
      "argv": ["npm", "run", "dev"],
      "cwd": "app",
      "env": { "NODE_ENV": "development", "PORT": "5173" },
      "ports": [5173],
      "started_at": 1756299500000
    },
    {
      "argv": ["cargo", "watch", "-x", "test"],
      "cwd": "engine",
      "env": {},
      "ports": []
    }
  ],
  "scope": "full",
  "summary": "flaky test fixed; dev server and watcher running",
  "title": "abra workspace"
}
```

Snapshot hash of the canonical form:

```
34d229d9f5ba4d0132b3f2ec0d54b0f77ba82b91b1eda85bcb5b30f0f5ea3f75
```

## 8. Worked example: a partial handoff

```json
{
  "abra_spec": 1,
  "created_at": 1756300500000,
  "extra": {
    "cursor": { "column": 12, "line": 240 },
    "open_files": ["engine/src/lease.rs", "docs/SPEC.md"],
    "selection": "fn acquire_lease("
  },
  "kind": "abra.handoff.v1",
  "link": "https://github.com/abra-p2p/abra/pull/12",
  "origin": "3fa9c17b2e5d0846",
  "provenance": {
    "capsule_id": "9f2c1d7a4b8e0355a6d1c4e7f0b93a26",
    "label": "turn 14: fix the flaky test",
    "snapshot_hash": "0c9d8e7f6a5b4c3d2e1f00112233445566778899aabbccddeeff001122334455"
  },
  "scope": "partial",
  "summary": "picking up on the lease expiry path",
  "thumbnail": "77889900aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff66",
  "title": "handoff: lease expiry"
}
```

Snapshot hash of the canonical form:

```
5b70e40e2c6b1e5d5cf5cb56a1ae3e2ab88f8d0dbdc6d9bd82f8f0e0c9a17d34
```

A device that has never heard of `abra.handoff.v1` still renders a card: title,
summary, origin, timestamp, a clickable link, a thumbnail. A device that knows
the kind reads `extra` and opens the file at the cursor. Same bytes, different
experience, and the sender authored neither.
