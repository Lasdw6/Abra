# Cross-review of Abra spec drafts (by Grok 4.6)

Reviewer: Grok 4.6, author of `draft-grok46.md`.
Subjects: `draft-opus5.md` (Claude Opus 5), `draft-gpt56-sol.md` (GPT-5.6 Sol).
Authoritative constraints: `/tmp/abra-prompts` design context, plus `/Users/vividh/Desktop/abra/DESIGN.md`.
A draft that contradicts the design context is wrong. DESIGN.md is additional recorded decisions, not a license to drop delivery/pairing/adapters.

---

## draft-opus5.md (Claude Opus 5)

This is a strong **phase-1 wire-format** note (CAS, trees, one envelope, capability seal) and an incomplete **protocol spec**. An implementer can hash a tree and a manifest. They cannot pair a device, enroll a cloud agent, run the outbox, ack a teleport, speak an adapter, or use a relay. Those are not later-phase niceties in the design context; they are settled decisions 6–10 and 14.

### Defects

**1. The document is not the spec it claims to be.**
Header: "normative for `abra-core` 0.1" / "on-disk and on-the-wire encoding." Design context requires OUTBOX → HEALTH-CHECK → TRANSFER → ACK, pairing tickets, scoped expiring tokens, optional blind relays, capability TTL/revocation, adapter stdio verbs, and built-in kinds `dev.abra.workspace` / `dev.abra.handoff.v1`. None of those surfaces exist here (no §delivery, §pairing, §enrollment, §relay, §adapter, §kinds). §1.4 even names enrollment certificates (`abra.enroll.v1`) and then never defines one. That is an internal dangling reference, not a forward pointer.

**2. Built-in kind names contradict the design context.**
§4.1 / §7 / §8 use `abra.workspace` and `abra.handoff.v1`. Design context §14 is explicit: `dev.abra.workspace` and `dev.abra.handoff.v1`. DESIGN.md's `abra.*` examples do not override the context. Wrong names in the only worked examples will fork the ecosystem on day one.

**3. `dev.abra.handoff.v1` payload is unspecified.**
Design context: partial handoff is `{url, title, note?}`. §8 dumps cursor/open_files/selection into `extra` and uses top-level `link` as the URL. No required `url`/`note`, no rule that floor `title` relates to the kind. A second implementation cannot interoperate on the one built-in partial kind.

**4. Lease is both in the hashed manifest and "not part of the wire format."**
§4.1/§4.5 put `lease` `{holder, acquired_at, expires_at}` on full snapshots. §5 then says capsule metadata including "lease holder" is "local bookkeeping. It is not part of the wire format and is not hashed." Those cannot both be true. There is no signed lease record, no epoch/seq, no takeover, no "write without lease = fork", no integrator stop-on-loss contract, no control payloads on the pipe. The field is a dead annotation, and unsigned, so anyone can mint `holder: <victim>`.

**5. Origin is an unverifiable truncated id.**
§1.2: peer id = first 8 bytes of `blake3(pubkey)` (matches DESIGN.md's display id). §4.1 stores only that in `origin`. §1.2 says verification is always against the full public key "stored alongside" — alongside what? Not the manifest. A snapshot does not commit to a public key, is not signed, and `origin` can be set to any 16 hex chars. Combined with no snapshot signatures anywhere, identity primitives from design context §15 are decorative.

**6. Worked-example snapshot hashes are not hashes of the examples.**
§7 claims
`34d229d9f5ba4d0132b3f2ec0d54b0f77ba82b91b1eda85bcb5b30f0f5ea3f75`
and §8 claims
`5b70e40e2c6b1e5d5cf5cb56a1ae3e2ab88f8d0dbdc6d9bd82f8f0e0c9a17d34`.
BLAKE3-256 of the obvious canonicalizations (sorted keys, no whitespace, omit empty collections vs keep them, `json.dumps` separators, even the pretty-printed block as written) does **not** produce either digest. The only test vectors in the spec are wrong. That will waste implementer time and destroy trust in the rest of the numeric examples (native blob hashes are also repeating `aa11bb22…` placeholders, which is fine if labeled; the snapshot ids are labeled as real).

**7. Canonical JSON is not implementable to bit-identity.**
§1.5 lists UTF-8, no whitespace, sorted keys, omit null/empty collections, integers without exponent. Missing: string escape table (when `\u00xx` vs raw UTF-8, solidus, unpaired surrogates, NFC or not). Two legal JSON encoders will disagree on `title` containing U+2028 or a backslash, therefore disagree on snapshot id. DESIGN.md's "fetch it, hash it, compare" fails across languages. Empty-collection omission also fights DESIGN.md §3 ("always carries `capsule_id` and `parents`"): a root full snapshot omits `parents` instead of sending `[]`. §4.6's "`parents` empty" vs "absent" wording is itself ambiguous.

**8. Capability links miss TTL, deliberate minting, and the viewer.**
§6 matches DESIGN.md's `abra://s/<hash>#<base64url-nopad key>` and uses XChaCha20-Poly1305 with AAD `abra.link.v1` — good. Design context §10 also requires: deliberately minted, TTL'd, revocable, static-JS viewer rendering the floor. No expiry field, no mint record, no viewer MUST-render list, no `floor` vs `full` packing. §6.1 inlines every referenced blob as base64 in one JSON object, so a Firecracker memory blob (~GiB) cannot be linked. Revocation-by-deleting-ciphertext is stated; TTL is not.

**9. `files` is optional on `scope: full`.**
Design context: the file tree is the portable source of truth; native blobs are never truth. Nothing in §4.6 rejects a full snapshot that is only `native` / only `recipes`. A receiver can be handed a capsule version with no folder to materialize.

**10. Relays, delivery, pairing — absent, not stubbed.**
You cannot "hybrid configurable" what is not specified. No HMAC(recipient-key, epoch-day), no outbox states, no cryptographic ack. This is not a small omission; it is the verb "teleport."

**11. Minor spec bugs that would still block a parser.**
- §4.6: `scope == "partial" ⇒ … (`parents` empty)` after saying parents must be absent.
- Recipe `env: {}` in the §7 example is an empty map; §1.5 says omit empty maps, so the pretty example is not in canonical form (and the second recipe has empty `ports` too).
- No domain separation on blob hashes (raw BLAKE3 of bytes). Trees have `abra.tree.v1\n`, manifests do not. Acceptable if kinds are only known from the parent pointer, but a confused-deputy CAS get-by-hash has no type tag.
- Timestamps as JSON integers: fine for canonicalization, unspecified timezone (Unix ms is UTC-by-convention; say so).

**Over-engineering:** almost none. The problem is under-specification. The binary tree format is proportionate.

### Best ideas worth adopting

These beat both GPT-5.6 Sol and my draft in their niches. Adopt them.

1. **On-disk blob layout `blobs/<hex[0..2]>/<hex[2..64]>` plus atomic rename (§2).** DESIGN.md §9 verbatim. Neither of the other drafts specifies sharding. Do this.

2. **Tree encoding as a git-like typed object with a magic prefix (§3).** `abra.tree.v1\n` + `(mode, name, NUL, raw 32-byte hash)`, modes `file|exec|link|tree`, sorted unique names. Closer to DESIGN.md's `(name, mode, hash)` than GPT's JSON trees or my length-prefixed binary. Keep the prefix for type separation; consider my domain-separated digest as well.

3. **Snapshot id = `blake3(canonical_json(manifest))` with no signature inside the hashed bytes (§1.6).** This is exactly design context §15. GPT hashes the signed document (author-addresses the id). I prefixed a domain tag (`abra-snap-v1`). Opus is the letter of the law; keep signatures as a sidecar record (my §5.2), not as inputs to the id.

4. **Recipe schema matches DESIGN.md exactly (§4.3):** `{argv, cwd, env, ports, started_at}` with **cwd relative, no `..`, no absolute paths**, core never executes. **Better than my draft**, which allowed absolute host cwd and thereby leaked host layout and contradicted DESIGN.md §5. GPT's `listen[]` is richer than needed; Opus's `ports: [5173]` is the settled shape.

5. **Capability URL shape `abra://s/<hash>#key` and `https://<host>/s/<hash>#key` with nopad base64url (§6).** DESIGN.md §10. My fragment-encoded `u=` + `k=` is more "hosted anywhere"; the synthesis should support **both** this DESIGN.md URL and a viewer-app URL. Opus's AAD `abra.link.v1` is the right idea (GPT used empty AAD).

6. **`.abra` is the only walk skip (§3.1).** Byte-for-byte otherwise, including `.git`. GPT never says this; without it, materializing a capsule and re-exporting ingests lease/metadata. **Better than GPT; equal to mine.**

7. **Native `role` + `size` + string fingerprint, evictable, MUST NOT restore on mismatch (§4.4).** Clean. Prefer GPT/Grok structured fingerprint fields at the wire, but Opus's "never source of truth" language is the one to copy.

8. **Integer `abra_spec` with reject-unknown (§0, §4.6).** Simpler than three parallel version strings. Not sufficient alone (see versioning verdict) but a good manifest field.

9. **Floor-first prose in §4.1 and §8** ("same bytes, different experience, and the sender authored neither"). Best statement of decision 4–5 in any draft.

10. **Provenance as reference, not membership (§4.2).** Correct and short. Field name `snapshot_hash` is clearer than my `snapshot_id` in a document that also has capsule ids.

---

## draft-gpt56-sol.md (GPT-5.6 Sol)

This is a real protocol spec: one envelope, CAS, signed everything, outbox state machine, pairing, enrollment, adapters, kinds, versioning. It is the only other draft that an engineer could implement a daemon from. It also fights the design context in a few load-bearing places, leaves relay crypto unpinned, and wraps large binary in JSON.

### Defects

**1. Snapshot id commits to the signature, so ids are not content addresses.**
§2: strip `signature`, sign, reinsert, `snapshot_id = base32(BLAKE3(canonical_complete_manifest_bytes))`. Same tree + same parents from two devices (or a re-sign) are different snapshots. Design context §15: snapshot id = BLAKE3 of canonical manifest bytes, in a list of primitives next to (not mixed with) Ed25519. DESIGN.md: id is self-verifying content. Attestation belongs in a sidecar (my snapshot record) or a parallel field that is **not** hashed into the id. This also makes the id uncomputable until you have the private key, which breaks "hash then gossip then sign" pipelines.

**2. Peer / object id encoding contradicts DESIGN.md and adds a second identifier dialect.**
§1: IDs are unpadded base32 of 32-byte BLAKE3 digests. Then §4: peer id is `p_` + base32(**public key**, not a digest). §5: capsule id is `c_` + base32(**16 random bytes**, not 32). Internal inconsistency in the first page. DESIGN.md: hex, blobs `blobs/ab/cdef…`, peer display id = 8-byte BLAKE3 prefix. Base32 + prefixes are not wrong as engineering, but they are a needless fork from recorded decisions and from Opus/me (hex).

**3. Control payloads as typed partial snapshots (§5 last sentence).**
Design context §9: pause/stop/instruct flow user→agent **on the same pipe**. Partials **land in an inbox** (decision 2). If control is a partial, "pause" becomes an inbox card with a floor title, DAG-less, and is subject to inbox GC rather than an RPC. No control `kind` is defined in §11. This is the wrong noun. Use control messages on the delivery connection (my §6.8).

**4. Relay is specified just enough to be non-interoperable (§8).**
Design context §6: optional blind relays, E2E + `HMAC(recipient-key, epoch-day)`. GPT correctly uses a **separately provisioned** 32-byte recipient relay key (see "best ideas"). Then: "precise HPKE suite remains v-next and therefore relay interoperability is not required by v0.1" and Ed25519-to-X25519 is "fixed by the negotiated extension" without fixing it. A relay that cannot be implemented is not a specified option; it is an open question wearing a section number.

**5. Capability AEAD uses empty AAD (§9).**
XChaCha20-Poly1305 with empty associated data. Key is unique per link, so this is not immediately exploitable, but the ciphertext is not bound to "this is an Abra capability bundle" or to TTL. Opus AAD `abra.link.v1` and my AAD-over-magic/alg/nonce/expiry are safer. Also: no `abra://` form (DESIGN.md §10); only `https://<host>/v/0.1/<object-id>#k=…&id=…`. Path leaks the ciphertext hash to the host (acceptable and DESIGN.md-like); empty AAD is the real crypto sloppiness.

**6. Handoff/link URIs MUST be `https` (§1 `link`, §11.2).**
`dev.abra.handoff.v1` `url` is "absolute `https` URI". Agent handoff of `http://127.0.0.1:5173` or `http://localhost:3000` is the common case. This rejects the product. Design context does not restrict the scheme. Registered-application URIs on the floor `link` field do not save `url`.

**7. No `.abra` exclusion; re-export can ingest daemon metadata.**
§3 capture: names, no follow-symlinks, special files are errors. Never "skip `.abra`". Opus §3.1 and my §3.4 make this the sole exception to byte-for-byte. Without it, a materialized capsule's lease/head/native cache becomes user files in the next snapshot (and can leak). This is a correctness bug, not a nit.

**8. Canonical JSON forbids all negative numbers in every protocol document (§2).**
`Numbers MUST be integers in 0..=9007199254740991; negative values … are forbidden throughout protocol JSON.` Lease epochs are fine; payload kinds and `extra`/`extensions` are not. A workspace adapter that wants `line: -1` (or any signed offset) must invent decimal strings. Over-constraint. Cap **id-hashed envelopes** to integers in the 2^53 range; do not ban minus in kind payloads.

**9. `parents` max 2, sorted lexicographically (§1, §5).**
DAG + deliberate merge is right. Sorting parents removes any ours/theirs order (probably OK). Max 2 means three concurrent forks need two serial reconciliations — acceptable, but say so as a UI limit, not a hash-invalid state. Empty parents as `[]` required on full: **better than Opus**. Every parent MUST already be a known full snapshot in the same capsule: rejects dangling parents at receive (good) but also rejects offering a snapshot whose parent has not arrived yet (order-dependent ingest; my orphan state is more operationally true).

**10. Enrollment `audience` must be known at mint time (§7).**
Token contains `audience: "p_..."`. Infra must possess the guest keypair before minting. Design context: infra adds the binary **and** the token; tokenless guest is inert. That still works if infra generates the key, not if the sandbox generates the key on first start (my bind-on-first-use). Stolen-token story is better with audience (see best ideas); operational story is worse. Spec should pick one flow and describe the infra injection, not leave both implied.

**11. Provenance-free partials require capsule `*` (§7).**
A token scoped to `[c1]` + kind `dev.abra.handoff.v1` cannot send a handoff without attaching provenance to c1. That is a silent extra authz rule, not in the design context. Either force provenance (then fake provenance on c1 is a cheap lie — provenance is not membership) or allow kind-only partials. Current rule is both bypassable (lie in provenance) and blocking (no provenance, no send).

**12. Adapter `exec` is an absolute path (§10).**
Registration `{"exec":["/absolute/adapter"],…}` is not relocatable, not Nix/Homebrew-friendly, and is a local-privilege footgun. My "binary beside `abra-adapter.json`" is the better default.

**13. Delivery frames large objects as JSON base64 (§6).**
16 MiB frames, 8 MiB decoded chunks, `blob_chunk.data` base64url. QUIC already frames bytes. This taxes CPU, expands size ~4/3, and makes Firecracker memory blobs millions of JSON messages. Have/want and signed acks are good; the chunk representation is not. `object_ack` says `hash` equals `object_id` (redundant) and never defines the **signed payload bytes** (only the domain `abra-object-ack-v1`). Same underspecification on `snapshot_ack`. Implementers will guess preimages; they will guess differently.

**14. Signed-record unknown-field rejection vs `extensions` (§12).**
Rejecting unknown top-level fields on signed records is the right anti-split rule. Combined with required `payload`, `labels`, `recipes`, `native_blobs`, `signer`, `signature`, `origin` object, `spec_version` string, it is a lot of surface that all implementations must emit identically. `thumbnail` as `{blob, media_type, width, height}` with four image types including AVIF is over-specified for a floor preview (DESIGN.md: thumbnail is a blob hash). Native blobs carry `media_type` they should not interpret.

**15. Scope-bypass / downgrade nits.**
- `hello.grants: [<token-id>…]` leaks which enrollment tokens a guest holds to every peer it dials.
- Revocation is fail-open until the record happens to arrive (admitted in Open Questions). Intermittent agents keep working on a stolen token until expiry. Design context says revocable; v0.1 should at least require refresh/re-fetch of revocation from a full device on enroll and on lease acquire.
- `features` and `versions` negotiation is fine; unspecified HPKE "negotiated extension" is a crypto downgrade hatch — pin or omit.
- `object_id` in capability path is the hash of ciphertext (good); fragment also carries `id=<snapshot-id>` which is not secret but is an integrity check the viewer can use — OK.

**16. Recipe env drops non-UTF-8 (§1).**
"non-UTF-8 entries are omitted." Files are byte-for-byte; recipes silently lose env. Document as lossy or store env as bytes/base64. Do not pretend byte-for-byte.

**Over-engineering (surface without v1 value):** JSON tree objects with decimal modes 420/493; required empty `labels`/`recipes`/`native_blobs` arrays; `hello` + `hello_auth` when the Transport already authenticates Ed25519 (keep `hello_auth` only if Transport is allowed to be unauthenticated, which iroh is not); per-object signed acks in addition to snapshot acks; thumbnail pixel dimensions; reverse-DNS `extensions` plus `payload` plus `extra`-equivalent.

### Best ideas worth adopting

Several of these are **better than my draft**. Use them.

1. **Adapter staging directory owned by core (§10).** Core creates `staging_dir`, adapter writes into it, core hashes, adapters never choose ids/origin. **Strictly better than my `result.dir` (adapter-chosen path),** which can point at `/etc`. Also: cancel + 5s kill, watch cursors, standard error codes, "MUST NOT run recipes implicitly." This is the adapter contract to merge.

2. **Relay tag key is a secret 32-byte discovery key, not the Ed25519 public key (§8).** Design context HMAC(recipient-key, epoch-day) only blinds the relay if `recipient-key` is not public. **My draft HMAC'd the Ed25519 public key; anyone who knows the peer can compute daily tags and poll.** GPT is correct; I was wrong. Keep GPT's keying, my envelope bytes, and pin XChaCha20-Poly1305/X25519 (libsodium maps) instead of "HPKE later."

3. **Receiver-computed have/want; sender lists never trusted (§6).** "The receiver MUST recompute `have`." Duplicate/idempotent offers, overlapping chunk = `hash_mismatch`, snapshot ack proves receipt not import. **Clearer safety than my plan−have default.** Adopt this rule even if we use binary object streams.

4. **Outbox state machine (§6 last paragraph).** `queued → health_check → negotiating → transferring → awaiting_ack → delivered` with `retry_wait`, jittered exponential backoff, clear **only** on verified `snapshot_ack`. This is the same loop I drew; GPT's state names and "delivery receipt SHOULD remain" are cleaner. Use GPT's SM + my ack preimage `offer_id || snapshot_id` (GPT's ack signed payload is unspecified).

5. **Built-in kinds match the design context (§11).** `dev.abra.workspace` (full, files required) and `dev.abra.handoff.v1` `{url, title, note?}`. My handoff omitted payload `title`; context includes it. Keep floor `title`/`link` equal to payload `title`/`url` (GPT rule) but **allow any absolute URI**, not https-only. Workspace `files` required (empty tree OK) is **better than my kind-conditional `tree` and than Opus's optional `files`.** Native-never-truth then follows: files always present.

6. **Structured native fingerprint (§1) uses the exact context keys:** `os`, `arch`, `hypervisor`, `fc_snapshot_format_major`, `cpu_template`, match-all-or-skip. Better naming than my `snapshot_format_major`. Keep my/Opus `role` + size. Drop `media_type` on native blobs.

7. **Canonical JSON specified to the escape (§2) + reject noncanonical bytes + persist original bytes (§12).** This is the interoperability package Opus lacks and that I only half-stated (I allowed re-canonicalizing with a correct writer). **GPT is strongest here. Adopt as-is**, except allow negatives in unsigned payload JSON or restrict the ban to hashed envelopes.

8. **Pairing = short-lived signed ticket + live confirm, ticket possession is not enrollment (§7).** Nonce hashed until expiry, display short ids, local user confirmation, 10-minute TTL. Matches decision 7. Equal to mine; GPT's `abra-pair:` encoding and "addresses as hints" are worth taking.

9. **Enrollment enforced at receipt, not trusted to the sender (§7).** Kind, capsule, direction, audience, expiry, revocation. Token cannot mint/pair/revoke. "Local policy may further restrict agent-initiated sends and can never be widened by a token." **Equals my `abra.allow_agent_send`;** keep both the token `send` bit and the local default-deny flag (decision 8). Token_id = hash of unsigned token (no self-reference) is nicer than my random id.

10. **Labels as immutable snapshot annotations with reserved names `agent-turn`, `fork`, `rollback`, `checkpoint` (§1, §5).** Design context §13: "parents, labels e.g. agent-turn boundaries, forks, rollback." I put `main`/`head` outside the hash (good for rollback-without-rewrite) and turn labels as `tags[]`. GPT's in-manifest labels are the right place for **turn boundaries**. Synthesis: GPT labels inside the manifest; my `main` pointer outside.

11. **Full snapshots always carry files/recipes/native arrays (empty allowed) so the portable representation is invariant (§1).** Decision 3. Better than optional-omit.

12. **Zero-install viewer crypto budget stated (§9):** canonical JSON, BLAKE3, Ed25519, XChaCha20-Poly1305, floor fields only, no recipe/native execution. Copy this MUST-list. Floor-only default packing is in my draft; GPT always packs the full closure — use **my floor vs full mint**, GPT's viewer constraints.

13. **hello version negotiation + `unsupported_version` (§6).** My `wire: 1` integer is cruder. Keep integer ALPN/`wire` plus this explicit error.

---

## Verdict per major area

Which draft is strongest (all three, including `draft-grok46.md`). One line each.

| Area | Strongest | Why |
|---|---|---|
| **Manifest schema** | **GPT-5.6 Sol** | Correct `dev.abra.*` kinds, required `files` on full, provenance shape, payload as kind JSON, scope conditionals that an implementer can code. Trim https-only and signature-inside-id. Grok is close (native-never-truth, validation matrix). Opus is the DESIGN.md field list but wrong kind names and unsigned/unverified origin. |
| **Canonical serialization / ids** | **GPT-5.6 Sol** | Only complete escape table, integer range, reject-noncanonical, persist original bytes. Do **not** take its "id hashes the signature" or base32/`p_`/`c_` prefixes — ids should stay hex BLAKE3 of unsigned canonical bytes (Opus/context §15) with Grok's optional domain tags if the synthesis wants type separation. |
| **Content addressing** | **Opus 5** | DESIGN.md git-style blob sharding, git-like trees, `.abra`-only skip, symlink-not-followed, exec bit only. Grok adds domain-separated blob/tree digests (worth merging). GPT JSON trees + decimal modes + no on-disk layout is the weakest CAS. |
| **Identity / signatures** | **Grok 4.6** | Domain table for every signed object, explicit preimage bytes, snapshot sig as sidecar, enroll-bind, trust-store roles. GPT is a close second (hello_auth, key-in-peer-id, every object signed) but folds the sig into the snapshot id and leaves ack preimages implicit. Opus has peer-id truncation and no signed snapshots. |
| **Capsule / DAG / lease** | **Grok 4.6** | Genesis, signed lease with grant/refresh/transfer/takeover, write-without-lease = fork label, explicit multi-parent merge, `main` outside the hash, two shelves. GPT's epoch+`previous` chain and in-manifest turn labels should be merged in. Opus lease is an unsigned, self-contradictory comment. |
| **Delivery protocol** | **Grok 4.6** | Binary object streams, offer/plan/have/want, ack over `offer_id\|\|snapshot_id`, outbox diagram, resume, control on the same pipe. GPT's outbox names, receiver-computed have, error codes, and idempotency rules should replace the fuzzy bits of Grok; GPT's JSON-base64 chunks should not. Opus: missing. |
| **Pairing / enrollment** | **Grok 4.6** | Bind dance, inert guest, scope flags including `lease_takeover`/`pair`/`control` denied, vendor send flag, revocation flood. GPT pairing confirmation + audience-bound tokens + receipt-time enforcement text should be copied. Opus: domain tag only. |
| **Relay** | **GPT-5.6 Sol** (addressing) / **Grok 4.6** (envelope) — call **GPT** if one name is required | GPT is the only draft that keeps HMAC(recipient-key) **secret**, which is the whole point of "relay can't correlate." Grok's envelopes (`ABRAREL1`/`ABRABL1`, sealed box, relay-ack, pending-ack-on-dial) are the only complete bytes. Opus: missing. **Do not ship Grok's HMAC(pubkey).** |
| **Capability links** | **Grok 4.6** | Key only in fragment, blob hosted anywhere (`u`+`k`), AEAD AAD binds header/expiry, floor vs full mint, mint record without the key, viewer card. Opus wins DESIGN.md URL shape and AAD string — merge those in. GPT viewer MUST-list and 30-day mint cap — merge those in. GPT empty AAD: reject. |
| **Adapter contract** | **GPT-5.6 Sol** | Staging dir, core authors the envelope, verbs export/import/watch, cancel, errors, watch as hints. **Better than Grok.** Opus: missing. |
| **Payload kinds** | **GPT-5.6 Sol** | Literal design-context kinds and handoff `{url,title,note?}`. Fix https-only. Grok workspace stats payload is extra; handoff dropped payload title. Opus: examples only, wrong names. |
| **Versioning** | **GPT-5.6 Sol** | Per-schema version strings, hello negotiation, unknown-field policy that does not split signatures, `extensions` bag, retain original canonical bytes. Grok's `0.x` may-break table is the right honesty for 0.1. Opus `abra_spec: 1` reject-else is a floor, not a story. |

---

## Synthesis guidance

Ranked recommendations for the final spec. Each is a concrete merge, not a vibe.

1. **Take Opus/DESIGN.md CAS as the object store:** hex BLAKE3 ids, `blobs/ab/cdef…` atomic rename, git-like trees with a magic prefix (Opus §3) **plus** Grok domain tags `abra-blob-v1` / `abra-tree-v1` so blob bytes cannot be confused with tree bytes. Skip only `.abra`. No ignore, no secret scan. GPT JSON trees and base32 ids: drop.

2. **Take GPT canonical JSON (escape table, no insignificant whitespace, sorted keys, omit nulls, persist original bytes, reject noncanonical on the wire).** Hash **unsigned** canonical manifest bytes for `snapshot_id` (Opus / design context §15). Put Ed25519 on a sidecar snapshot record (Grok §5.2) so the id stays a content address. Optional Grok domain prefix `abra-snap-v1` if the synthesis wants one hash function and many types — not required by the context.

3. **Manifest = Opus field list + GPT conditionals + Grok native-never-truth.** Required floor: `kind`, `title`, `origin`, `created_at`. `scope` full|partial. Full: `capsule_id`, `parents` (required, `[]` ok), `files` required (empty tree ok), `recipes`/`native` present or omitted-empty but **invalid if native without files**. Partial: no capsule/parents/lease; optional provenance `{capsule_id, snapshot_id, turn}`. `kind` names: `dev.abra.workspace`, `dev.abra.handoff.v1`. `origin` MUST be the full public key (or a `{peer_id, pubkey}` object); never Opus's 8-byte truncated id alone. `payload` object as GPT (kind JSON); unknown kinds still floor-render.

4. **Use GPT's adapter contract unchanged except:** registration by manifest-beside-binary (Grok) rather than absolute `exec`; core-provided `staging_dir` (GPT) kept. Adapters never hash, never sign, never pick snapshot ids.

5. **Delivery: Grok binary object streams on the Transport trait (iroh/QUIC, ALPN `abra/1`) + GPT outbox state machine + receiver-computed have/want + Grok ack preimage `offer_id || snapshot_id`.** Do not put blob bytes in JSON. Specify every signature preimage as `domain || 0x00 || payload` (both GPT and Grok; Grok's table is complete — copy it). Control is a signed `control` message on the same connection (Grok), **not** a partial snapshot (GPT).

6. **Lease/history: Grok genesis + fork-on-write + `main` label outside the hash + explicit multi-parent reconciliation, with GPT's signed lease epoch/`previous` chain and in-manifest turn labels (`agent-turn`, `rollback`).** Highest epoch wins; do not use Grok's equal-seq wall-clock tie-break as the only rule (clock skew). GPT's "same-epoch conflict stalls until a higher epoch" is safer; add Grok's `lease-update` push so the loser stops acting (integrator contract).

7. **Pairing from GPT (ticket + confirm + single-use nonce); enrollment from Grok scopes (`capsules`, `kinds`, `send`/`receive`/`lease_acquire`/`lease_takeover`, `pair`/`control` false for guests) plus GPT receipt-time checks and "token cannot widen local send policy."** Pick one bind story and write the infra sequence: **prefer Grok bind-on-first-use** so "binary AND token" is one injection, and **add GPT's audience field as optional** (set when infra generated the key). Revoke via signed record flooded on the delivery channel; guests re-validate with a full device before lease acquire (closes GPT's fail-open gap without pretending to be online-always).

8. **Relay: GPT HMAC keying (separate 32-byte recipient relay key, epoch-day, query D-1/D/D+1) + Grok binary envelopes and pending-ack-on-next-dial.** Pin the sealed box: libsodium `crypto_sign_ed25519_*_to_curve25519` + X25519-XChaCha20-Poly1305 (Grok §4.2). Do not ship "HPKE TBD." Direct p2p remains sufficient. Admit same-day tag correlation.

9. **Capability links: DESIGN.md/Opus URL `https://<host>/s/<ciphertext-hash>#<key>` and `abra://s/…`, plus Grok's viewer-origin form with `u` and `k` both in the fragment for "hosted anywhere."** AEAD = XChaCha20-Poly1305 with **non-empty AAD** (Opus domain or Grok header bind). TTL in mint policy (GPT 30 days) and optionally in plaintext header for the viewer (Grok). Default pack **floor only** (Grok); full closure is an explicit mint mode. Viewer MUST (GPT §9): floor fields, no recipe/native execution. Revocation = delete ciphertext.

10. **Recipes and native: Opus recipe object (relative `cwd`, `ports[]`, derived, never executed by core) + GPT native fingerprint field names + Grok match-string and skip-on-mismatch materialization.** Display recipes; run only on explicit user action. Handoff payload = GPT `{url, title, note?}` with **schemes other than https allowed**. Workspace kind requires `files`. Versioning = GPT unknown-field/`extensions` rules + Grok `0.x` may-break + Opus integer `abra_spec` or a single `spec: "abra/0.1"` string, not three dialects.

If the synthesis author needs a bias: **GPT for schema completeness and adapters; Grok for mesh/runtime (delivery, lease, enroll, capabilities, binary CAS movement); Opus for local object format and for catching where the other two drifted from DESIGN.md.** None of the three is shippable alone.
