# Stage-1 review of `abra-core` (commit c0d562a) against SPEC v0.1

Reviewer: Claude Opus 5. Repo `/Users/vividh/Desktop/abra`, read-only.
Method: full read of `crates/abra-core/src/*` against SPEC.md; independent
re-derivation of `spec-vectors/vectors.json` in Python (BLAKE3 + a from-scratch
Abra-CJSON writer + a pure-Python RFC 8032 Ed25519); 16 + 5 executable probes
against the real crate from a scratch crate outside the repo (`/tmp/abra-probe`);
`cargo test --workspace` (30 pass) and `cargo clippy --all-targets` (clean).

---

## 0. Verification of the spec vectors (hand-traced, not trusting the tests)

I recomputed the vectors without touching the Rust code.

**`empty_tree_id`.** SPEC §3.2 says the zero-entry tree is `"abra.tree.v1\n"`
alone and `tree_id = hex(BLAKE3(tree_bytes))`.

```
preimage = b"abra.tree.v1\n"                      (13 bytes)
BLAKE3   = 9a23a560966dc2a95f70a61430ea1a2b4a402e91710c01721b02df16a15d2061
vectors  = 9a23a560966dc2a95f70a61430ea1a2b4a402e91710c01721b02df16a15d2061   MATCH
```

**`full.snapshot_id`.** I re-serialized the published `canonical` string with my
own CJSON writer and confirmed it is byte-identical (so the published bytes really
are canonical), removed `"signature"`, and hashed `"abra-snap-v1" || 0x00 || U`
(U = 419 bytes):

```
BLAKE3 = 1dcac42db0e9149a55259b7d843f5295c8c3fbf841088ec415253d6c54167f9e
vectors= 1dcac42db0e9149a55259b7d843f5295c8c3fbf841088ec415253d6c54167f9e     MATCH
```

`partial.snapshot_id` = `a7c28c5a…f8c722` also matches (U = 263 bytes, and its
`payload.delta:-7` exercises the negative-integer carve-out of §2).

**Signatures and lease chain.** With pure-Python Ed25519: the seed `0x07 × 32`
derives `ea4a6c63…46d22c`, which equals `origin.peer_id` in both manifests. Both
manifest signatures verify over `"abra-sig-v1"||0x00||"snapshot"||0x00||U`. The
genesis signature verifies over domain `genesis`. `BLAKE3(genesis_bytes)` =
`18447595…1bf0` equals lease-1's `prev_hash`, and each subsequent `prev_hash`
equals `BLAKE3` of the full previous record *including* `sig`, exactly as §5.4
requires. All three lease signatures verify under the signer implied by the §5.4
mode table (grant/refresh/transfer → previous holder).

**Verdict on vectors: correct and independently reproducible.** They are also
genuinely useful as a cross-implementation contract.

One gap: SPEC §2 requires vectors for "at least: one full and one partial
manifest…, the empty tree id, a signed lease chain". All present. But the chain
has no `takeover` and no equal-epoch race, which are the two hardest cases for a
second implementation to get right. See finding 22.

---

## 1. What is right (so the findings below are read in proportion)

These were checked by probe, not by inspection alone:

- **Ed25519 strictness (§0) is correct.** `identity.rs:27-35` uses
  `verify_strict`. A malleated signature `(R, S+L)` is rejected
  ("Cannot use scalar with high-bit set"); small-order and all-zero public keys
  fail verification. Domain separation holds: a `lease`-domain signature does not
  verify in the `label` domain.
- **Canonical-JSON byte rules (§2) are right** for every case I threw at it:
  unsorted keys, duplicate keys (even with identical values), insignificant
  whitespace, trailing newline, `1.0`, `1e2`, `-0`, `u64 > i64::MAX`,
  `2^53`, `\/`, unpaired surrogates, and >128 nesting all reject; raw non-ASCII,
  raw U+007F and the `\u00xx` lowercase form all behave per spec. The
  round-trip-and-compare design in `validate_canonical` is the right shape.
- **Tree encoding (§3.2) is exact**, including the re-sort-and-compare in
  `Tree::decode` (`cas.rs:186-192`) that refuses a canonically-decodable but
  non-canonically-ordered tree. Name rules reject `""`, `.`, `..`, `/`, NUL, and
  cap at 255 *bytes* (`name.len()`), which is what the spec says.
- **`materialize` cannot be made to write outside the destination.** I built a
  hostile tree with symlink entries targeting an absolute path and
  `../../../../../../tmp`. Both were created *as symlinks* (spec-correct: §3.2
  "symlinks are stored and materialized as links, never followed") and the file
  outside the destination was untouched. Traversal via entry *names* is blocked at
  `Tree::new`, and duplicate names are illegal, so the classic
  "symlink-then-write-through-it in one directory" sequence is unreachable.
  `remove_existing` correctly `lstat`s and unlinks a pre-existing symlink before
  writing. This is the part I most expected to be broken, and it is not.
- **The `.abra` carve-out is root-only** (`cas.rs:361`), which is right — a nested
  `sub/.abra` is user data and is captured. `.git` and `.env` are captured.
- **The signer-inference question Sol flagged is cryptographically sound.** I
  tried the obvious attack: take an attacker-signed `main` label-op and pass the
  *lease holder's* peer id as the `signer` argument. It fails with
  "Verification equation was not satisfied", because the key you name is the key
  the signature is checked against. You cannot promote a forgery by lying about
  the signer. See finding 7 for the part that *is* a problem.

---

## 2. Findings

### 2.1 Critical

---

**1. [CRITICAL] The snapshot id and the signature preimage are computed from a
re-serialized DOM, not from the received bytes — §2 byte authority is broken, and
one snapshot id has unboundedly many valid, verifying byte encodings.**

`manifest.rs:129-141` (`unsigned_value` / `unsigned_bytes` / `snapshot_id`),
`manifest.rs:290-300` (`RawManifest::parse`).

SPEC §2 is unusually explicit: *"Implementations MUST persist and forward the exact
bytes `M`; verification hashes stored bytes, never a re-serialized DOM."* And §6.4:
*"verify `BLAKE3("abra-snap-v1"||0x00||U) == snapshot_id` (recomputing `U` by
**removing `signature` from the received bytes**)"*.

The code does the opposite. `unsigned_bytes()` calls `serde_json::to_value(self)`
on the parsed `Manifest` struct and re-serializes. `RawManifest::parse` checks that
the input bytes are *canonical CJSON*, but never checks that they are the
*canonical encoding of this Manifest*. Those are different assertions, and the gap
is every field carrying `#[serde(skip_serializing_if = "Option::is_none")]`
(`manifest.rs:103-125`) or `skip_serializing_if = "…is_empty"`
(`manifest.rs:69-72`): an explicit `null`/`{}`/`[]` in the input deserializes to
`None`/empty and then vanishes on re-serialization.

Probe result — each mutation was accepted, produced different bytes, and yielded
the *same* snapshot id:

```
honest bytes len 361 id 3003787cef6172967070640304f8af5d5bbbdbd98487f54456cfc90d77798815
  ACCEPTED +summary:null      bytes_differ=true  same_id=true  (376 bytes)
  ACCEPTED +link:null         bytes_differ=true  same_id=true  (373 bytes)
  ACCEPTED +thumbnail:null    bytes_differ=true  same_id=true  (378 bytes)
  ACCEPTED +files:null        bytes_differ=true  same_id=true  (374 bytes)
  ACCEPTED +extensions:null   bytes_differ=true  same_id=true  (379 bytes)
  ACCEPTED +provenance:null   bytes_differ=true  same_id=true  (379 bytes)
  ACCEPTED recipe env:{}/ports:[]  bytes_differ=true  same_id=true
```

Consequences, all of which land squarely on stage 2:

- Any peer that relays a snapshot can rewrite its bytes while preserving both the
  id *and* a valid signature by the original author. §1.1's "Optional fields are
  omitted, never `null`" is a stated rule with no enforcement point.
- `store.rs:116` writes `<snapshot_id>.cjson`, so a later mutated copy silently
  **overwrites** the honest bytes of a snapshot the local device did not author.
- Two devices holding "the same" snapshot can hold different `M`. Every §6.5
  `have`/`plan` delta, every §8 relay envelope, and every §9.2 capability pack
  then disagrees byte-for-byte while agreeing on the id.
- An attacker can generate an unbounded family of distinct accepted encodings for
  one id (each optional field is an independent bit), which is a cheap cache/dedup
  poisoning primitive.

**Fix.** Two changes, both small:

1. In `RawManifest::parse`, after `serde_json::from_slice`, assert round-trip
   identity: `if canonical::to_vec(&m)? != bytes { return Err(Error::invalid("manifest bytes are not the canonical encoding of this manifest")) }`.
   This single check closes the whole class, including future fields.
2. Derive `U` from the accepted bytes rather than the DOM — parse `bytes` to a
   `serde_json::Value`, `remove("signature")`, and `canonical::to_vec` that; or
   (cheaper) keep the DOM path but only *after* (1) has proven the two are equal.
   Then have `RawManifest` be the only type that can produce a `snapshot_id`, and
   make `Manifest::snapshot_id()` `pub(crate)` or clearly documented as
   "author-side only, before the bytes exist".

Also add the explicit-null rejection to the §1.4 matrix implementation so the
error message is diagnostic rather than a generic byte mismatch.

---

### 2.2 Major

---

**2. [MAJOR] `Capsule::accept_lease` admits unauthenticated attacker-controlled
records into persistent state, without a signature check and without a bound.**

`capsule.rs:255-258`, and the `evidence` field at `capsule.rs:197`.

```rust
if r.prev_hash != prev || r.epoch != prev_epoch + 1 {
    self.evidence.push(r);      // <-- before r.verify_with(&signer) at line 274
    return Ok(false);
}
```

The signature is only verified at line 274, *after* the epoch/`prev_hash` gate. Any
record that fails the gate is stored as "evidence" with its signature never
examined. SPEC §5.4 says a distant-epoch record is "stored as evidence but never
wins" — but evidence that was never verified is not evidence of anything; it is
attacker-chosen bytes in your state.

Probe: a takeover record with epoch 9999 and a signature overwritten with
`0xAA × 64` returns `Ok(false)` and is retained. A second probe pushed 5000 such
records; all were admitted, no error, no cap:

```
5000 unverifiable lease records all admitted, no error, no cap; winning_lease still None
```

`self.leases` grows similarly (`capsule.rs:278-282` pushes race losers). Neither
vector is bounded. Once stage 2 accepts lease records off a connection, this is a
remote memory-exhaustion DoS reachable by anyone who can reach the daemon — and
after finding 6 is fixed and these are persisted, a remote disk-fill.

**Fix.** Move `r.verify_with(&signer)?` above the epoch/`prev_hash` gate. For the
gap-promotion path the signer is not yet known from the chain, so verify against
`r.holder` for `takeover` and against *both* `r.holder` and the current winner's
holder otherwise, rejecting if neither validates; discard anything unverifiable
rather than storing it. Then cap `evidence` (e.g. keep the highest-epoch verified
record per holder, ≤ 8 holders) and cap `leases` (keep the winning chain plus the
current epoch's race set).

---

**3. [MAJOR] Lease expiry is never enforced. An expired lease keeps full write
authority and can still move `main`.**

`capsule.rs:221-285` (`accept_lease` computes a TTL but never compares to now),
`capsule.rs:316` (fork determination), `capsule.rs:357-363` (`main` authorization).

`accept_lease` validates that `expires_at - acquired_at` lies in 60s..7d, then
never looks at `expires_at` again. `winning_lease()` returns the record regardless
of whether it expired. Probe:

```
accept 6-year-expired grant: Ok(true)
move `main` using that expired lease: Ok(true)
```

SPEC §5.4 makes the TTL load-bearing ("Holders refresh at least every 5 minutes
while actively writing"), and §5.3 gates `main` on "the holder of the *winning*
lease". A lease that expired in 2020 is not a winning lease. Concretely: a device
that goes offline mid-lease keeps `main`-move authority forever from the point of
view of every peer that has its record, and `insert_snapshot` will mark that
device's writes as non-forked indefinitely — which is exactly the "on lease loss,
the agent stops acting" contract inverted.

**Fix.** Give `Capsule` a clock (`now_ms: u64` argument, or a `&dyn Clock`; do not
call `SystemTime::now()` inside — it must be injectable for tests). Add
`LeaseRecord::is_live(now)`. Have `winning_lease()` keep returning the record (it
is still the chain head for `prev_hash` purposes) but add
`active_lease(now) -> Option<&LeaseRecord>` that returns `None` past `expires_at`,
and use *that* in `apply_label`'s `main` branch and in `insert_snapshot`'s fork
determination. Note in a doc comment that an expired head still anchors
`prev_hash`, otherwise the chain breaks.

---

**4. [MAJOR] `Capsule::insert_snapshot` takes the writer's identity as a caller
parameter instead of reading it from the verified manifest, so the fork-on-write
decision — the crate's only authorization output — rests on caller honesty.**

`capsule.rs:286-291`, `capsule.rs:316`.

```rust
pub fn insert_snapshot(&mut self, raw: RawManifest, received_at: String, writer: PeerId)
…
let lease_ok = self.winning_lease().is_some_and(|l| l.holder == writer);
```

`raw` is a verified `RawManifest`: `raw.manifest().origin.peer_id` is the
cryptographically established author. The `writer` parameter is a second,
unverified claim about the same fact. Probe:

```
snapshot authored by ATTACKER, writer param = lease holder -> forked = false (spec expects true)
```

`store.rs:102` happens to pass the right value today, so this is not currently
exploitable end-to-end — but it is the single authorization decision in the crate,
it is a `pub` API, and stage 2 will call it from the receive path where a
connection peer id and a manifest origin are two different things (relayed
snapshots, §8; forwarded offers). This is the kind of parameter that gets wired to
the wrong variable exactly once.

**Fix.** Delete the parameter and use `raw.manifest().origin.peer_id`. If a caller
ever needs "who handed me this", that is a separate `from: PeerId` field on
`SnapshotRecord`, not an input to the lease check.

---

**5. [MAJOR] Re-inserting an already-stored root snapshot is an error, so
redelivery/replay is not idempotent.**

`capsule.rs:297-304`.

```rust
if parents.is_empty() && self.snapshots.values().any(|r| … parents.is_empty()) {
    return Err(Error::invalid("capsule already has a root snapshot"));
}
```

The `any()` scan does not exclude the record being inserted. Probe:

```
first  insert: Ok("00a35a58…")
SECOND insert (identical bytes): Err("invalid: capsule already has a root snapshot")
```

SPEC §5.2 says "Out-of-order arrival is normal, not an error", and §6.4 requires a
receiver that already holds a snapshot to answer `offer-reject {reason:"duplicate"}`
or ack directly — not to fail. Retries and §6.9 resumes will re-present the same
root routinely; `store.rs:97` propagates the `Err` and *skips the disk write*, so a
duplicate delivery of the root can leave the capsule in an inconsistent state.

Second problem in the same check: it conflates "duplicate" with "rival root". A
peer who gets a bogus `parents: []` snapshot in first permanently blocks the real
root — with no way to distinguish, since the error is the same.

**Fix.** Make insertion idempotent first: `if let Some(existing) = self.snapshots.get(&id) { … return Ok(existing_result) }`
before any other check (bytes are content-addressed, so an id collision is a
byte-identical record — assert that and return early). Then apply the root check
only to *distinct* ids, and prefer storing a rival root as a fork rather than
rejecting it, per §5.5's "writing without the winning lease is fork-on-write,
never an error".

---

**6. [MAJOR] Nothing is loaded back. `AbraStore::open` always returns empty
capsules/inbox/outbox, and leases and label-ops are never persisted at all.**

`store.rs:37-52`, `store.rs:56-71`, `store.rs:97-118`.

```
capsules in memory after add_capsule: 1
capsules after REOPEN: 0  (genesis dirs on disk: 1)
```

`open()` constructs three empty `BTreeMap`s and never reads `capsules/`, `inbox/`
or `outbox/`. The `.cjson` files it writes are write-only. Worse, the *lease chain
and the label log are never written to disk in any form* — `Capsule::leases`,
`winner`, `labels`, `fork_counts` and `evidence` are pure in-memory state. A daemon
restart loses the winning lease, which means it loses `main` authority and its own
fork accounting.

SPEC §6.7 requires the ack to follow an "atomic durable commit… A crash after ack
must not lose the delivery", and §4 lists lease records and label-ops as capsule
store contents. Neither holds. This is the gap most likely to be mistaken for
"stage 2's problem" and it is not: stage 2's outbox correctness is defined in terms
of state this layer must already be able to reload.

**Fix.** Add `AbraStore::load()` that walks `capsules/*/genesis.cjson`,
`capsules/*/snapshots/*.cjson`, `capsules/*/leases/*.cjson`,
`capsules/*/labels/*.cjson` and `inbox/*.cjson`, re-parsing through
`RawManifest::parse` / `Genesis::verify` / `accept_lease` so nothing is trusted
just because it is on disk. Persist lease records and label-ops on acceptance.
Note that replaying leases through `accept_lease` in arbitrary directory order
will not reconstruct the winner — persist them under `<epoch>-<hash>.cjson` and
replay in epoch order.

---

**7. [MAJOR] Label-ops carry no signer, and unlike lease records their signer is
not derivable from any chain — so a label-op is only verifiable on the connection
that carried it, which blocks gossip and relay in stage 2.**

`capsule.rs:352-356`, SPEC §5.3.

This is the issue Sol's own report flagged, and my assessment is: **sound for
leases, structurally incomplete for label-ops.**

For *leases*, the signer is genuinely derivable — §5.4's mode table plus the
`prev_hash` chain determines it (takeover → `r.holder`, otherwise → previous
holder), and `capsule.rs:259-263` implements exactly that. No inference is
required from the caller. That part is fine.

For *label-ops*, `apply_label(op, signer)` requires the caller to supply the
signer out of band. It is not forgeable — I tried, and naming the wrong key just
fails verification (§1 above) — but it is *unresolvable* by any party that did not
receive the op directly from its author. §5.3 says `fork/*` ops "may be signed by
the forking writer", and there is no field naming that writer. So:

- a label-op relayed through §8 store-and-forward cannot be verified at all;
- a label-op gossiped between two full peers on behalf of a third cannot be
  verified;
- the §5.3 tie-break "equal `seq` ties break on lexicographically greater `sig`
  bytes" is computable, but *which* competing op is even admissible is not.

The `main` branch is saved by accident: it requires `signer == winning_lease.holder`,
so a receiver can just try the holder's key. `fork/*` and user labels have no such
anchor.

**Fix (code, now).** Change the signature to `apply_label(&mut self, op: LabelOp, author: PeerId)`
and document in the rustdoc — not just the module header — that `author` MUST be
the transport-authenticated identity of the peer that authored the op, never the
peer that forwarded it, and that this API is therefore not usable for relayed ops.
For the `main` case, derive the key internally from `winning_lease().holder` rather
than accepting it, so the caller cannot get that one wrong.

**Fix (spec erratum, recommend to the spec owner).** Add a `by: <peer id>` field to
the label-op CJSON, inside the signed bytes, exactly as `origin.peer_id` works for
manifests and `created_by` for genesis. It costs 78 bytes and makes label-ops
self-authenticating like every other signed object in §0's domain table. Without
it, §5.3's mutable-pointer log cannot cross a relay, which contradicts §8's premise
that relays "ship later without breaking correctness". Flag it now, while `0.x` may
still break.

---

**8. [MAJOR] `TreeEntry.size` is taken from `stat()` rather than from the bytes
actually hashed, so a file that changes size during the walk produces a
permanently unmaterializable tree.**

`cas.rs:359` (`symlink_metadata`), `cas.rs:379` (`(mode, store.put_file(&path)?, meta.len())`).

`walk` stats the file, then separately reads it via `put_file` → `fs::read`. The
hash comes from the bytes read; the `size` recorded in the tree comes from the
earlier `stat`. If the file is written between the two — which is the *normal* case
for `snapshot_dir` on a live workspace, and the entire point of the §10 `watch`
verb is that files change — the tree records a size that does not match its blob.

`materialize` then hard-fails on that tree forever:

```rust
if bytes.len() as u64 != entry.size {
    return Err(Error::corrupt("blob", "tree size mismatch"));   // cas.rs:437, 447
}
```

The snapshot is signed, distributed, and permanently broken. Note this is *not*
merely a torn read — the content hash is self-consistent, so nothing detects it
until materialization, possibly on another device days later.

**Fix.** Have `put_file` return `(Hash, u64)` (or read the bytes in `walk` and use
`bytes.len() as u64`), and use the hashed byte count as the entry size. Two lines.
Separately consider re-`stat`ing after the read and warning on mtime/size change,
since a torn read is still a torn read even when self-consistent.

---

**9. [MAJOR] Whole-object buffering makes multi-GB native blobs unusable and is a
memory-exhaustion vector.**

`cas.rs:287-291` (`put_file` → `fs::read`), `cas.rs:264-284` (`put(&[u8])`),
`cas.rs:294-310` (`get` → `fs::read` + rehash).

Every CAS path is `Vec<u8>`-shaped. SPEC §1.3's worked example is
`{"role":"memory", …, "bytes":2147483648}` — a 2 GiB Firecracker memory file — and
§3.1 justifies plain undomained BLAKE3 precisely so that "multi-GB native blobs can
be verified as they stream rather than after they land". The current API cannot
stream: `put_file` on a 2 GiB file allocates 2 GiB, and `get` allocates another
2 GiB and rehashes the whole thing on every read. On the receive side (stage 2), a
peer-supplied `total_size` would drive the same allocation.

**Fix.** Add streaming variants now, before stage 2 builds on the buffered ones:
`put_reader(&self, r: impl Read) -> Result<(Hash, u64)>` writing into the temp file
with a `blake3::Hasher` fed incrementally, and `get_reader(&self, h) -> Result<impl Read>`
(verify-on-read via a hashing wrapper, or accept verify-on-write and skip rehash for
large objects). Keep `put`/`get` as convenience wrappers with a documented size
ceiling. Since ids are plain BLAKE3, `blake3::Hasher::update_reader` / bao
verified streaming drops in cleanly later.

---

**10. [MAJOR] Persistence is neither atomic nor durable, mutates memory before
disk, and writes unverified data before rejecting it.**

`store.rs:56-71` (`add_capsule`), `store.rs:72-94` (`receive_partial`),
`store.rs:97-118` (`receive_full`).

Four distinct problems in ~60 lines:

- **Not atomic.** All three use bare `fs::write`, unlike `BlobStore::put`
  (`cas.rs:274-282`), which correctly does temp-file + `sync_all` + `rename`. A
  crash mid-write leaves a truncated `genesis.cjson` / `<id>.cjson`.
- **Not durable.** No `sync_all` on the file, no `sync_all` on the containing
  directory after rename. §6.7's "A crash after ack must not lose the delivery" is
  unmet even once the load path (finding 6) exists.
- **Memory before disk.** `receive_full` calls `capsule.insert_snapshot(...)`
  (line 109) and only then writes the file (line 116). If the write fails, the
  in-memory capsule contains a snapshot that does not exist on disk, and the error
  returned to the caller gives no way to distinguish "rejected" from "accepted then
  failed to persist".
- **Unverified data written before it is rejected.** `add_capsule` writes
  `genesis.cjson` at line 61 and only calls `Capsule::new(g)` — which is what runs
  `genesis.verify()` — at line 69. Probe: a genesis with a forged signature is
  rejected *and its bytes are on disk anyway*:

```
add_capsule(forged) -> Err("signature verification failed: … Cannot use scalar with high-bit set")
forged genesis.cjson on disk anyway: true
```

  Combined with finding 6's future load path, that forged file becomes an input to
  the next `open()`.

**Fix.** Verify first, mutate memory last: `Capsule::new(g)?` → atomic write
(temp + `sync_all` + `rename` + parent `sync_all`) → insert into the map. Factor
the atomic-write helper out of `BlobStore::put` and use it for every shelf. For
`receive_full`, write the manifest bytes *before* `insert_snapshot` and roll back
the file if insertion fails, or stage both and commit together.

---

### 2.3 Minor

---

**11. [MINOR] `Genesis::verify` checks the signature but validates none of the
signed content.** `capsule.rs:62-68` checks only `spec` and `type`. Probe: a
genesis with `created_at: "NOT-A-TIME-AT-ALL-XXXXXX"`, `kind: "!!!not reverse
dns!!!"` and a control character in `title` verifies `Ok`. §5.1 fixes the shape and
`kind`/`title`/`created_at` are the §1.1 floor fields.
*Fix:* reuse `manifest::time()`, the `reverse_dns` predicate and the `title` `text()`
check — export them as `pub(crate)` validators and call them from `Genesis::verify`.

**12. [MINOR] Lease timestamps use a laxer parser than manifest timestamps, so
signed lease records can carry impossible dates.** `capsule.rs:441` checks
`(1..=12).contains(&m) && d >= 1` with **no upper bound on the day**, whereas
`manifest.rs:383-391` does full leap-year-aware calendar validation. Probe:

```
grant with date 2026-02-31: Ok(true)
grant with date 2026-08-99: Ok(true)
grant with date 2026-13-01: Err("invalid: invalid lease time")
```

`2026-08-99` also silently produces a nonsense epoch through the civil-days
formula, so the TTL check is meaningless for it. Two implementations will disagree
about whether such a record is admissible — on *signed* bytes, which is the failure
mode §12 exists to prevent.
*Fix:* have `timestamp_ms` call the same `time()` validator first, then convert.
There should be exactly one canonical-time parser in the crate.

**13. [MINOR] `absolute_uri` is far too lax for a field the §9.3 viewer renders as
an anchor.** `manifest.rs:345-357` only checks "scheme chars, colon, non-empty
rest". Probe: `javascript:alert(1)`, `data:text/html,<script>x</script>`,
`http://a b` all validate. §1.1 says "Absolute URI (any scheme, incl. `http`), RFC
3986", and RFC 3986 forbids raw space and controls in a URI.
*Fix:* reject any byte outside RFC 3986's unreserved/reserved/`%` set (in
particular ` `, `<`, `>`, `"`, `\`, `^`, backtick, `{`, `|`, `}`, and all of
U+0000–U+001F and U+007F), and require a well-formed `%XX` wherever `%` appears.
Do *not* filter schemes here — that is the viewer's policy call — but do flag to
the spec owner that §9.3 needs an explicit "the viewer MUST NOT emit an anchor for
a non-`http(s)` scheme" sentence, or `javascript:` links are XSS-by-design in the
zero-install viewer.

**14. [MINOR] Negative integers are permitted under *any* key named `payload` or
`extensions` at any depth, not just the two top-level envelope fields.**
`canonical.rs:63`: `validate_at(x, negatives || k == "payload" || k == "extensions")`.
Probe: `{"o":{"payload":{"n":-5}}}` is accepted, and `to_vec` accepts
`{"origin":{"payload":{"n":-1}}}`. §2 scopes the carve-out to the envelope's
`payload`/`extensions`. Not exploitable through `Manifest` today (`deny_unknown_fields`
blocks a nested `payload` key from reaching validation), but `canonical::to_vec`
and `validate_canonical` are `pub` and stage 2 will hash other documents with them.
*Fix:* pass a depth/path down, or take an explicit `negatives_at: &[&str]` root-key
list, so the carve-out only applies at depth 1 of the top-level object.

**15. [MINOR] `materialize` is additive, not a sync, so it silently produces a
directory that does not hash to the tree it materialized.** `cas.rs:403-456`
creates and overwrites entries present in the tree but never removes entries absent
from it. Probe: materializing the *empty* tree into a directory containing
`stale.txt` leaves `stale.txt` in place, and re-snapshotting yields
`cd7445d0…` instead of `9a23a560…`. §3.3 promises "Round-trip preserves contents,
structure, exec bits, and symlink targets exactly", and §5.5's reconciliation flow
("a lease holder materializes both tips… resolves in the folder") depends on the
folder actually being the tip.
*Fix:* after writing a tree's entries, list the destination directory and remove
anything not named in the tree — skipping `.abra/` at the root, mirroring the
capture carve-out exactly. Document it as destructive, and consider a
`MaterializeMode::{Sync, Overlay}` so callers choose.

**16. [MINOR] `BlobStore::put` short-circuits on path existence without verifying,
so a corrupted object is never repaired and `has()` lies.** `cas.rs:267-269`:
`if dest.is_file() { return Ok(hash) }`. Probe:

```
put(b"good") again -> Ok("4ae75b23…")
bytes on disk now: "CORRUPTED"
has() reports present: true
```

`get()` does detect it (`cas.rs:303-308`), so this is not an integrity break — but
`has()` is what §6.5 says the receiver uses to compute `have`: *"The receiver MUST
recompute `have` against its own **verified** CAS."* A single corrupted object
therefore makes the receiver claim possession, decline the transfer, and fail at
materialize time instead — with no repair path, since `put` refuses to rewrite.
*Fix:* on the `dest.is_file()` path, either (a) verify size and rehash when the
file is small / when a `verify_on_put` flag is set, or (b) at minimum have `put`
overwrite via the temp+rename path when the existing file's length differs from
the input. Add a `BlobStore::verify(&Hash) -> Result<bool>` and an `fsck` that
`have`-computation can rely on, and note in `has()`'s rustdoc that it is a
*presence* check, not a *verified*-presence check.

**17. [MINOR] The `.abra` carve-out is bypassed when `.abra` is a symlink.**
`cas.rs:361`: `if root && name == ABRA_DIR && ty.is_dir()`. A symlink is not
`is_dir()` under `symlink_metadata`, so it falls through to the symlink branch.
Probe: root `.abra` symlinked at a real directory is captured as a `Link` entry.
Only the *target path string* leaks, not the key material — but §3.3's rationale is
explicit ("without this the daemon would capture and teleport its outbox, lease
records, and device key"), and leaking the absolute path of the daemon state
directory into a signed, teleported manifest is not what that rule intends.
*Fix:* drop the `ty.is_dir()` condition — skip root `.abra` whatever it is. If a
user genuinely has a file named `.abra`, refusing to capture it is the safer and
more predictable behaviour, and it makes the carve-out a pure name rule.

**18. [MINOR] `walk` and `materialize_inner` allow 513 tree levels, not 512.**
`cas.rs:342` / `cas.rs:414`: `if depth > 512` with the root at `depth = 0`. §3.2
says "max depth 512".
*Fix:* `>=`, or start the root at depth 1. Also note `path_len` at the root is 0,
so the 4096-byte limit is measured on the reconstructed *relative* path — which I
believe is the intent of §3.2, but it deserves a comment, since a receiver whose
destination prefix is long will still hit `ENAMETOOLONG` at materialize time. §3.2
covers this ("a tree that cannot materialize on some host is rejected at import on
that host"), so the current behaviour is right; it just is not obviously right.

---

### 2.4 Nits

**19.** `Manifest::verify()` (`manifest.rs:151-153`) is a bare alias for
`validate()`. Two names for one operation, one of which implies "signature only",
will eventually cause someone to call the wrong one. Delete `verify()` or make it
signature-only and have `validate()` call it.

**20.** `closure()` (`manifest.rs:10-23`) inserts the thumbnail and native hashes
without checking they exist in the store, and `validate()` does not enforce §1.1's
"Blob MUST be in the closure" for the thumbnail. Probe: a manifest whose thumbnail
blob is absent from CAS validates, and `closure()` returns it. Context-free
validation is the right call, but add a `Manifest::verify_closure(&store)` for the
receive path so stage 2 has an obvious thing to call before acking.

**21.** Unenforced §1.1 details, each individually harmless: reserved label names
(`agent-turn`, `fork`, `rollback`, `checkpoint`) are accepted as ordinary
in-manifest labels; `Fingerprint` fields may be empty strings though §1.3 calls
them "required strings"; `Recipe.argv` entries may contain NUL (§1.2 bans NUL in
`cwd` only, so this is arguably conformant — but an argv with a NUL cannot be
executed on any Unix, and §1.2 says recipes are lossy-but-honest).

**22.** Vector coverage: no `takeover` lease and no equal-epoch race in
`lease_chain`. Those are the two cases where the §5.4 signer table and the
"lexicographically greater `sig`" tie-break are load-bearing, and they are exactly
what a second implementation will get wrong. Add a fourth and fifth chain entry
(a takeover, and two epoch-N competitors with their expected winner recorded).
Also add a vector for a manifest with `labels`, `recipes`, `native`, `thumbnail`
and `extensions` populated — the current two exercise almost no optional fields, so
they would not have caught finding 1.

**23.** `Identity::load` (`identity.rs:86-93`) does not check the file's mode, and
`store.rs:39-41` creates `keys/` with default permissions. Measured: `keys/` is
0755, `keys/device.json` is 0600, store root is 0755. The key file itself is right
(§0: "stored with mode 0600"). Refuse to load a key file with group/other bits set
(git and rsync both love to widen modes), and create `keys/` 0700. Zeroization is
not required by the spec, but `Identity`/`DeviceKeys` hold raw secret bytes with a
derived-`Debug`-free but otherwise plain layout — a `zeroize::Zeroizing` wrapper on
`secret_bytes()`'s return and a `Drop` impl would be cheap insurance. Also note
`save_private` follows a pre-existing symlink at the key path.

**24.** `Capsule::evidence` (`capsule.rs:197`) is private with no accessor — state
that is written and never read. Either expose it (`pub fn evidence(&self) -> &[LeaseRecord]`,
which is what §5.4's "stored as evidence" implies a user should be able to inspect)
or drop it; see finding 2 first.

**25.** `identity.rs:48-50`: `domain_message` is a byte-identical duplicate of
`signature_preimage`. Delete one.

**26.** `canonical.rs:133`: a stray `use serde::Deserialize;` at the bottom of the
file, below all definitions. Move it to the top with the other imports.

---

## 3. Test adequacy

30 tests pass and clippy is clean, but the suite is *shallow where the risk is* —
none of findings 1–10 is caught by it. The tests mostly exercise the happy path and
the author-side round trip, which is precisely the direction that cannot detect a
DOM-vs-bytes divergence.

`store.rs` has **zero** tests. `Capsule::apply_label`, `insert_snapshot`,
`resolve_orphans` and `fork_counts` have **zero** tests. `materialize` has no
hostile-input test at all.

Specific missing tests, in the order I would write them:

1. **Byte authority** (would catch finding 1): for each optional manifest field,
   inject an explicit `null` into signed canonical bytes and assert
   `RawManifest::parse` rejects. Plus a general property test: for any parsed
   `RawManifest`, `canonical::to_vec(m.manifest())? == m.bytes()`.
2. **Idempotency** (finding 5): insert the same `RawManifest` twice, assert the
   second is `Ok` and does not duplicate state. Same for `receive_partial` and
   `receive_full`.
3. **Unverified-record rejection** (finding 2): a lease with a corrupted `sig` must
   be rejected from *every* path including the gap path; assert `evidence` stays
   empty. Plus a bound test: 10 000 junk records must not grow state without limit.
4. **Lease expiry** (finding 3): an expired winning lease must not authorize a
   `main` move and must make writes fork.
5. **Persistence round-trip** (finding 6): build a store with a capsule, a lease
   chain, a label log, an inbox entry and a snapshot; drop it; reopen; assert every
   piece of state matches, including `winning_lease().epoch` and `labels["main"]`.
6. **Hostile tree materialization** (currently absent): symlink targets `..`,
   absolute, and `/proc/self/…`; a `link` entry whose blob is longer than `size`; a
   tree entry named with a NUL byte injected post-encode; a tree whose child hash
   points at a *blob* rather than a tree; and a destination pre-populated with a
   symlink where a tree entry expects a directory. Assert nothing outside the
   destination is created, modified, or read.
7. **Filesystem edge cases in `snapshot_dir`/`materialize`** (currently absent):
   empty file (0 bytes), empty directory, directory containing only an empty
   directory, 255-byte name, 256-byte name (must reject), multi-byte UTF-8 and
   emoji names, a name that is 255 *bytes* but fewer chars, 512-deep nesting
   (accept) and 513 (reject), a file with mode 0700 vs 0600 (exec bit round trip),
   a FIFO or socket (must be a capture error per §3.2), and a non-UTF-8 name (must
   be a capture error).
8. **Signature strictness pinning** (currently only implicit): assert that
   `(R, S+L)` is rejected and that a small-order public key fails. This behaviour is
   correct today only because `verify_strict` is used; a refactor to `verify()`
   would pass every existing test. This is a one-line change away from a real
   vulnerability and deserves an explicit regression test.
9. **`size` fidelity** (finding 8): construct a tree whose entry size disagrees
   with its blob and assert `materialize` fails cleanly — then, once fixed, assert
   `snapshot_dir` cannot produce one.
10. **Round-trip fuzzing.** `cargo-fuzz` or `proptest` targets on
    `canonical::validate_canonical` (arbitrary bytes must never panic; accepted
    bytes must re-serialize identically), `Tree::decode` (arbitrary bytes must
    never panic; decoded trees must re-encode identically), and
    `RawManifest::parse`. All three are the parse-untrusted-input surface stage 2
    will feed straight from the wire, and all three are recursive.

---

## 4. Verdict

**Stage 1 is sound enough to build stage 2 on, but not to *ship*, and finding 1
must be fixed before any wire format work begins.**

The load-bearing cryptography is right, and that is the part that would have been
expensive to get wrong: `verify_strict` with malleability and small-order rejection
verified end-to-end, correct domain separation, an exact and independently
reproducible CJSON profile, exact tree encoding with decode-side re-canonicalization,
a correct lease `prev_hash` chain with a correctly derived signer table, and a
`materialize` that genuinely cannot be walked out of its destination. The spec
vectors are correct — I reproduced every id, hash and signature from the spec text
alone, in a different language, without reference to the Rust. That is a real
asset and the right thing to have built first.

What is missing is the layer between "the crypto is right" and "the system is
right": the implementation verifies a *reconstruction* of what it received rather
than what it received (finding 1), it does not persist or reload the state it is
responsible for (findings 6, 10), and it treats several authorization inputs as
caller-supplied facts rather than derived ones (findings 3, 4, 7). Those are
architectural rather than deep — the fixes are mostly tens of lines — but every one
of them gets harder after stage 2 has a receive path calling into it, and finding 1
in particular would silently corrupt the `have`/`plan` delta negotiation, relay
envelopes and capability packs that stage 2 is entirely built out of.

The test suite is the weakest artifact here and I would not treat "30 green" as
signal: it does not exercise `store.rs` at all, does not exercise `apply_label` or
`insert_snapshot` at all, and by construction cannot catch a DOM-vs-bytes
divergence.

### Top 3 must-fix, in order

1. **Finding 1 — hash and verify the received bytes, not a re-serialized DOM.**
   Add the round-trip identity assertion in `RawManifest::parse` and derive `U`
   from the accepted bytes. This is the spec's central invariant, it is currently
   violated, and everything in stage 2 rests on it. One assertion closes the class.
2. **Findings 2 + 3 — never admit an unverified record, and enforce lease expiry.**
   Move `verify_with` above the epoch gate, bound `evidence`/`leases`, inject a
   clock, and gate `main` moves and fork determination on a *live* lease. These are
   the difference between "the lease chain is cryptographically well-formed" and
   "the lease means something".
3. **Findings 6 + 10 — make the store durable and reloadable, verify-before-write.**
   Add the load path, persist leases and label-ops at all, and use the atomic
   temp+fsync+rename pattern that `BlobStore::put` already implements correctly
   everywhere else. Stage 2's outbox correctness (§6.7's "only a verified ack clears
   the duty to deliver") is defined over state this layer cannot currently survive a
   restart with.

I would also fix finding 8 (`size` from `stat`) in the same pass — it is two lines,
and it is the only finding here that silently produces permanently corrupt *signed*
artifacts that no peer can detect until materialization. And I would raise finding 7's
spec erratum (add `by` to label-ops) with the spec owner now, while `0.x` may still
break, rather than discovering it when relay support lands.
