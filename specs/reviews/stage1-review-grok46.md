# Stage 1 review: `abra-core` vs SPEC.md v0.1

Reviewer: Grok 4.6. Repo `/Users/vividh/Desktop/abra`, commit in scope is the stage-1 `crates/abra-core` implementation. Against SPEC.md only; not re-litigating product decisions.

**Method.** Read `SPEC.md` §§0–5, 12 and the crate (`canonical`, `identity`, `cas`, `manifest`, `capsule`, `store`). Independently recomputed `empty_tree_id` and both vector `snapshot_id`s from the stored canonical bytes (BLAKE3, not the in-crate tests). Checked ed25519-dalek 2.2.0 `verify` vs `verify_strict`. `cargo test -p abra-core`: 30 tests passed.

**What is sound.** Domain-separated snapshot ids (`abra-snap-v1 || 0x00 || U`) and signature preimages (`abra-sig-v1 || 0x00 || domain || 0x00 || payload`) match §0/§2. Tree encoding (`abra.tree.v1\n` + `mode SP name NUL hash[32] u64be(size)`), undomained blob/tree BLAKE3, empty-tree bytes, and `.abra/` root skip match §3. `PeerId::verify` calls `VerifyingKey::verify_strict` (not `Verifier::verify`). In dalek 2.2, *both* paths reject non-canonical `S` via `Scalar::from_canonical_bytes` (legacy_compatibility is off); `verify_strict` additionally rejects small-order `A` and `R`, which is what §0 requires. Device key files are mode `0600` on Unix. Lease `prev_hash` / epoch-gap / equal-epoch `sig`-byte tie-break logic is close to §5.4. Spec vectors’ bytes, ids, and lease `prev_hash` chain are correct (see appendix).

The holes below are why this is not yet a safe foundation for `abra-net`.

---

## Findings

1. **major** — `crates/abra-core/src/manifest.rs:129-140`, `crates/abra-core/src/manifest.rs:290-299`, `crates/abra-core/src/manifest.rs:69-72`

   **Byte authority is not implemented.** §2: persist and hash stored bytes `M`; `U` is that object with the `signature` member removed; receivers reject noncanonical bytes rather than silently reserializing. `RawManifest::parse` does check that the JSON *Value* reserializes to the input (good against whitespace/key-order/`1.0`). It then computes `snapshot_id` and verifies the signature over `serde_json::to_value(self)` with `skip_serializing_if` applied. That is a different `U` than “CJSON(M) minus `signature`”.

   Consequences:
   - Optional fields mapped as `Option<_>` (`summary`, `link`, `recipes`, `extensions`, `origin.name`, …) accept JSON `null` (serde → `None`) and then drop them from `U`. Empty `Recipe.env` / `Recipe.ports` are dropped the same way.
   - Distinct canonical documents therefore share a `snapshot_id` and a valid signature. Example: take a valid `M`, insert `"summary":null` or `"recipes":null` or a recipe `"env":{}`, re-sort keys, leave `signature` unchanged — this crate still verifies and reports the same id.
   - Stage 2’s `manifest_raw` is defined as the only wire form and is keyed by `snapshot_id`. Two peers can store different `M` under one id; a byte-faithful implementation that hashes strip(`M`) will reject snapshots this crate emits only if it includes skippable empties, and will disagree on ids if it is strict.

   **Fix:** After `Manifest` deserialize, require `canonical::to_vec(&manifest)? == bytes` (struct round-trip equals stored `M`). Compute `U` from the *Value* with only `signature` removed, never from a `skip_serializing_if` struct. Reject `null` for non-nullable optionals before serde maps them to `None`. Add a test that `"summary":null` and `"env":{}` are rejected and that `snapshot_id` equals `BLAKE3("abra-snap-v1" || 0x00 || strip_sig(bytes))`.

2. **major** — `crates/abra-core/src/store.rs:37-51`, `crates/abra-core/src/store.rs:56-118`

   **The capsule/inbox “store” is not a store.** `AbraStore::open` creates directories and loads keys, then starts with empty `capsules` / `inbox` / `outbox` maps. It never reads `capsules/<id>/genesis.cjson`, `snapshots/*.cjson`, or `inbox/*.cjson`. Leases and label-ops are not written at all. Restart → every genesis, snapshot, lease, label, and inbox row is gone from the API even though some files remain on disk. §4 shelves and §6.7 (“atomic durable commit”; crash after ack must not lose the delivery) cannot be built on this. `receive_full` / `receive_partial` `fs::write` also does not `sync_all` the file or parent directory.

   **Fix:** On `open`, scan shelves, `RawManifest::parse` each snapshot, `validate_canonical` + verify genesis/lease/label records, and restore maps. Persist lease and label logs next to genesis (exact CJSON bytes). `fsync` file then directory before returning success from receive/add. Treat that as the stage-2 ack durability primitive.

3. **major** — `crates/abra-core/src/capsule.rs:200-210`, `crates/abra-core/src/store.rs:56-70`

   **Grant is not issued with genesis.** §5.4 mode table: `grant` is signed by the capsule creator, epoch 1, holder = creator, **issued with genesis**. `Capsule::new` / `add_capsule` only store the genesis record. `winning_lease()` stays `None` until a caller remembers to `accept_lease` a grant. `insert_snapshot` then treats every write as fork-on-write (`lease_ok` is false when there is no winner), including the capsule root.

   **Fix:** `Capsule::new` should take the epoch-1 grant (or build it from the creator) and `accept_lease` it atomically with genesis. `add_capsule` must persist both files. Reject genesis without a valid grant.

4. **major** — `crates/abra-core/src/capsule.rs:316-327`, `crates/abra-core/src/store.rs:97-117`

   **Fork-on-write does not create the `fork/<8hex>` label-op.** §5.5: a full snapshot authored without the winning lease is stored, `main` is untouched, a `fork/<first 8 hex of tip id>` label-op is created, and the writer is told `forked: true`. The code only returns `fork_label: Some(...)`. Nothing calls `apply_label`. After `receive_full`, the capsule label log is unchanged.

   **Fix:** When `forked` is true because of lease mismatch, sign/apply/persist a `label-op` `set` of `fork/<id[0..8]>` with the writer’s key and current lease epoch (or 0 if none — spec this if needed). Do not mark *orphans* as forks just because parents are missing; §5.2 already makes them ineligible for `main`.

5. **major** — `crates/abra-core/src/capsule.rs:221-274`, `crates/abra-core/src/capsule.rs:352-356`

   **Signer inference is sound for leases, a hole for labels, and unenforced for takeover.** Lease records have no `signer` field (as spec’d). Inference from mode + chain is the right table:

   | mode | inferred signer in code | spec |
   |---|---|---|
   | `grant` | genesis `created_by` | creator |
   | `refresh` / `transfer` | previous winning holder | current holder |
   | `takeover` | `r.holder` (the new holder) | new holder |

   That inference is correct. Gaps:
   - `accept_lease` never checks that the inferred signer is a **full peer**, or that a guest has `lease_takeover` (§5.4, §7.4). Any Ed25519 key can currently win a live takeover. Fine only while this API is local; fatal once stage 2 feeds network records into it.
   - `transfer` does not check the new holder is trusted.
   - `apply_label(op, signer)` takes the signer from the *caller*. The op itself cannot be verified later: Ed25519 verify needs the public key, and it is not in the record. `fork/*` authorization (“forking writer”) and the 32-forks-per-peer cap are unenforceable after restart or over the wire unless the transport `peer_id` is bound and persisted.
   - Gap-epoch records are pushed to `evidence` **before** signature verification (`capsule.rs:255-257`). Garbage and forgeries accumulate as “evidence”.

   **Fix:** Thread a trusted-peer + guest-scope callback into `accept_lease`. Persist `signer: PeerId` beside every label-op (or require the op schema to grow a field — if the spec stays signer-less, the shelf metadata must hold it). Verify evidence before storing. Stage 2 MUST pass the transport-authenticated `peer_id` as `signer` and refuse mismatches with `origin.peer_id` / inferred lease signer.

6. **major** — `crates/abra-core/src/cas.rs:258-268`, `crates/abra-core/src/cas.rs:264-283`

   **CAS `has` / `put` trust a path that exists without hashing it.** `put` returns success if `dest.is_file()` without reading. `has` is `path.is_file()`. `get` does re-hash (good). A truncated or bit-flipped object therefore looks present. §3.1: a path either does not exist or holds complete verified content. Stage 2 `have` is required to be recomputed against verified CAS (§6.5); this implementation of `has` will skip transfer of corrupt objects. Rename is atomic and the temp file is `sync_all`’d, but the parent directory is never fsynced, so a crash can drop a just-committed blob from the directory.

   **Fix:** `has`/`put` must `get`-verify (or compare length+hash) before treating an object as present; on mismatch delete and rewrite. `fsync` the shard directory after `rename`. Do not advertise `has == true` for unverified bytes.

7. **major** — `crates/abra-core/src/cas.rs:403-455`, `crates/abra-core/src/cas.rs:202-217`

   **`materialize` is an overlay, and names are not fully constrained.** Round-trip from a clean dest is fine (contents, exec bits, symlink *targets*). Issues:
   - Unmentioned files/dirs/symlinks in `dest` are left in place. Re-materializing a new tree into an existing sandbox therefore leaves stale secrets and leftover symlinks. §3.3’s round-trip claim assumes the dest *is* the tree; overlay semantics will surprise stage-2 capsule updates.
   - Same-directory unique names plus `remove_existing` before write/link, and removing a leftover symlink before descending into a `tree` entry, do prevent *following a stored symlink* while writing (the §3.3 rule) on Unix.
   - `check_name` bans `/`, `.`, `..`, NUL, and length > 255, but not `\`. On Windows `dest.join("foo\\..\\..\\bar")` can escape the destination. Spec is silent on `\`; the implementation still must not escape `dest`.

   **Fix:** Either require empty dest or delete entries not in the tree (after materializing to a sibling temp dir and renaming). Reject `\` and (on Windows) reserved names at `check_name` / `materialize`. Refuse to `create_dir_all` / `fs::write` through a dest that is a symlink (`O_NOFOLLOW` / `symlink_metadata` on dest). Add an explicit test: tree with a `link` named `s` → `..` and a sibling file must not write outside `dest`.

8. **minor** — `crates/abra-core/src/capsule.rs:62-68`, `crates/abra-core/src/capsule.rs:127-129`, `crates/abra-core/src/capsule.rs:172-174`

   **Genesis / lease / label-op verify only a subset of the schema.** `Genesis::verify` checks `spec`, `type`, and the signature — not canonical time, title (non-empty, ≤512 scalars, no C0), or reverse-DNS `kind`. `LeaseRecord::verify_with` is signature-only; TTL/mode/epoch checks live in `accept_lease` and are skipped for `evidence`. Label-ops do not check `spec`/`type` beyond `op == "set"`. §2 CJSON + §12 unknown-field rejection apply to every signed document; these paths also never `validate_canonical` on stored bytes (they re-serialize a DOM for `hash()` / `unsigned()`).

   **Fix:** Share the manifest `time` / `text` / `kind` helpers. `validate_canonical` on the exact bytes before accept, and persist those bytes. Put TTL/mode checks before the evidence branch so forgeries are `Err`, not stored.

9. **minor** — `crates/abra-core/src/manifest.rs:244-278`, `crates/abra-core/src/manifest.rs:312-317`

   **Validation matrix gaps vs §1.4 / §1.2 / §11.** Covered well: `spec`, scope, full/partial field presence, title, unknown top-level fields (`deny_unknown_fields`), signature, parent dup/cap, label sort. Missing or weak:
   - Recipe `cwd` allows `foo/./bar` and `foo//bar` (`relative` only strips a leading `/`, NUL, and `..` components).
   - `thumbnail.bytes` / `native[].bytes` are not checked against the blob in CAS; thumbnail-in-closure is unioned in `closure()` but never required to exist.
   - Kind-specific §11 is unimplemented: `dev.abra.handoff.v1` does not require `manifest.link == payload.url`; workspace `default_cwd` is not checked.
   - `title` control-char check is `<= 31` (correct for U+0000–U+001F). Empty `origin.name` (`text(..., min: 0)`) is allowed; spec says optional, not empty-if-present — omit vs `""` should be decided and tested.

   **Fix:** Tighten `relative` to reject `.` and empty components except cwd `"`.`"`. At receive time, require referenced blobs exist and `bytes` match. Add kind validators behind the known-kind table; unknown kinds stay opaque.

10. **minor** — `crates/abra-core/src/cas.rs:361-379`, `crates/abra-core/src/cas.rs:341-344`

    **Capture edge cases.** `.abra` is skipped only at the walk root and only if it is a directory. A root *file* or *symlink* named `.abra` is captured (symlink-to-dir is stored as `link`, not skipped). Concurrent size-vs-read on a file uses `meta.len()` for the tree `size` and `put_file` for bytes — a mutating file can be snapshotted with `size != blob.len()`, and `materialize` then fails. Depth test is `> 512`, so 512 nested directories under the root are allowed; off-by-one vs “max depth 512” depending on whether root counts. Special files error (good). Symlink-to-directory is not walked (good).

    **Fix:** Skip any root entry named `.abra` regardless of type. Use the put blob’s length as `size`. Clarify depth as “512 hops from the root tree” and test the boundary.

11. **nit** — `crates/abra-core/src/identity.rs:71-73`, `crates/abra-core/src/identity.rs:179-201`

    Secrets are not zeroized (spec does not require it; note for later). `Identity::save` writes raw 32 bytes while `DeviceKeys::save` writes CJSON — two on-disk formats. `save_private` follows a symlink at the destination. `keys/` is created with the process umask (often `0755`); only the file is `0600`. CAS objects holding workspace secrets inherit the umask as well.

    **Fix:** One key file format. `O_NOFOLLOW`. `0o700` on `keys/` and optionally the store root. `zeroize` on drop is optional.

12. **nit** — `crates/abra-core/src/canonical.rs:46-64`

    Negative integers are enabled for *any* object key named `payload` or `extensions`, at any depth, not only the envelope slots in §2. Harmless for current structs; a future signed record with a differently shaped `payload` field would inherit the looser range. Duplicate keys are effectively rejected because reserialize ≠ input (tested). U+2028 is emitted as raw UTF-8 (correct).

    **Fix:** Pass a path/context instead of a key-name boolean.

---

## Spec-vector check (independent of `cargo test`)

Empty tree = bytes `abra.tree.v1\n` (no entries).

```
empty_tree_id = BLAKE3("abra.tree.v1\n")
             = 9a23a560966dc2a95f70a61430ea1a2b4a402e91710c01721b02df16a15d2061
```

Matches `spec-vectors/vectors.json` and `Tree::default().hash()`. Full vector `files` is that id (empty tree as required for a file-less full snapshot).

Full `snapshot_id`: take `full.canonical`, delete the `,` + `"signature":"<128 hex>"` member (keys are already CJSON-sorted, so `signature` sits between `scope` and `spec`), then

```
BLAKE3("abra-snap-v1" || 0x00 || U)
  = 1dcac42db0e9149a55259b7d843f5295c8c3fbf841088ec415253d6c54167f9e
```

Partial (payload `delta: -7`, allowed only inside `payload`) similarly hashes to `a7c28c5ad632cebaabea819cf0ab8f5e8ae390f321cb2c7f8131ba8cf3f8c722`.

Lease chain: `prev_hash` of grant = BLAKE3(genesis CJSON including `sig`) = `184475951d1dfba1…`; each subsequent `prev_hash` is BLAKE3 of the previous record’s full CJSON. Transfer at epoch 3 is signed by the *previous* holder (seed `0x07`), not the new holder — correct for `mode=transfer`.

Vectors are authoritative and internally consistent. They do **not** cover the byte-authority mismatch in finding 1 (they were emitted by the same struct serializer).

---

## Test adequacy

Covered: CJSON sort/escapes/duplicate keys/floats/core negatives; snapshot id ignores signature bytes; validation matrix smoke; empty tree; `.git`/`.env` captured and `.abra/` skipped; exec bit + symlink round-trip; lease gap + equal-epoch takeover race; vector parse.

**Missing tests that could plausibly be wrong today:**

- `RawManifest::parse` of otherwise-valid `M` plus `"summary":null` / recipe `"env":{}` (finding 1).
- `snapshot_id` computed by stripping `signature` from stored bytes vs `Manifest::snapshot_id`.
- `AbraStore::open` after `add_capsule` + `receive_full` in a new process (finding 2).
- Genesis without grant; first snapshot `forked` bit (finding 3).
- `insert_snapshot` without winning lease actually produces a stored `fork/*` label-op (finding 4).
- `apply_label` `main` rejected for non-holder / wrong epoch / orphan target; `fork/` 32-per-peer and 128-label caps; seq/`sig` tie-break.
- Takeover from an unknown key rejected (once trust is plumbed).
- Malleable Ed25519: `S += L`, small-order `A`/`R` — `verify_strict` vs `verify`.
- `BlobStore::has` after truncating the shard file; `put` of the same hash over corrupt bytes.
- `materialize` into a dest that already contains extra files or a leftover symlink; Windows/`\` names; symlink target `..` / absolute path must not cause writes outside dest.
- `snapshot_dir` of an empty directory; empty file; unicode names; 512-deep tree; 4097-byte reconstructed path; root `.abra` *file*.
- Recipe `cwd` `../x`; parent list >16; unknown enum `scope`; handoff `link != payload.url`.
- Device file mode `0600`; lease TTL 59s and 7d+1s.

---

## Verdict

**Not yet.** Crypto, CJSON, tree bytes, snapshot-id domain, `verify_strict`, and the published vectors are good enough to keep. Do not start `abra-net` on this crate until the local shelves actually survive a restart and the manifest id is a function of the stored bytes. Otherwise offer/ack, `have`/`want`, and lease gossip will inherit split-brain ids and a store that cannot honor “crash after ack must not lose the delivery”.

**Top 3 must-fix**

1. Bind `snapshot_id` and snapshot signatures to exact canonical bytes (`U` = CJSON(M) minus `signature`; struct round-trip must equal `M`). Finding 1.
2. Make `AbraStore` durable: load on `open`, persist leases/labels as CJSON, fsync; issue the epoch-1 grant with genesis. Findings 2–3.
3. Implement §5.5 fork label-ops and close lease/label authorization (trusted-peer gate on takeover/transfer; persist label signer; don’t stash unverified evidence). Findings 4–5.

Finding 6 (verified `has`/`put`) should land in the same pass — stage 2 delta negotiation is unsafe without it.
