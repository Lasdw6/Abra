# Cross-review by GPT-5.6 Sol

This review treats `DESIGN.md` and the supplied settled context as normative. “GPT-5.6” below means `draft-gpt56-sol.md`, my own draft.

## Review of `draft-opus5.md`

### Defects

1. **It is not an end-to-end technical spec.** Despite calling itself normative “on-disk and on-the-wire,” it specifies no delivery protocol, durable outbox, health-check, have/want exchange, cryptographic acknowledgement, pairing flow, enrollment-token format or enforcement, relay, adapter contract, built-in payload schemas, control messages, or transport abstraction. These are required settled surfaces, not optional elaborations. Sections 1–6 are a good snapshot-format note, but an implementer cannot build Abra from it.

2. **Snapshots have no author signature or usable identity binding** (§1.2, §4). `origin` is only the 8-byte display/index peer id. The draft says the full public key is “stored alongside” but defines no field or signed snapshot record in which it is stored. A malicious or corrupt store can substitute `origin`, capsule membership, parents, cargo, or lease metadata while recomputing the snapshot hash. Content integrity is not author authenticity, and the short-id collision rule is not implementable without a defined full-key binding.

3. **The canonical-JSON algorithm is incomplete and schema-dependent** (§1.5). It does not define string escaping, duplicate-key rejection, Unicode/surrogate handling, accepted number range, booleans/null, or whether input Unicode is normalized. “Empty optional collections omitted” is not a generic canonicalization rule: it requires knowing the schema and makes `{}`/`[]` and absence hash-identical only after an unstated value transformation. Different JSON libraries can produce different bytes.

4. **`parents` contradicts the full-envelope invariant** (§4.1, §4.6). The design says a full snapshot always carries `parents`; Opus says it is omitted when empty and validates only `capsule_id` for full snapshots. A root full snapshot therefore lacks a field the settled model requires, and a non-root full snapshot with no parents is also accepted.

5. **The lease is unauthenticated, embedded, and operationally undefined** (§4.5, §5). `{holder, acquired_at, expires_at}` has no capsule binding, sequence/epoch, predecessor, signer, or signature. Anyone able to author a manifest can claim any holder. There is no acquire/refresh/transfer/takeover protocol, no winning-record rule, no lease-loss notification, no integrator stop contract, no canonical-head rule, and no concrete branch labelling or deliberate reconciliation operation.

6. **DAG/head behavior is reduced to local bookkeeping** (§5). The “history reachable from its head” is underspecified when forks produce multiple tips; `head` is local and unsigned, and there is no replicated rule for advancing or rolling it back. Sorting a log by attacker-controlled `created_at` is deterministic but not causal and does not solve head selection.

7. **The CAS conflates object types without domain separation or reference metadata** (§2–3). Storing manifests, trees, and blobs in one namespace can work, but “what an object is comes from how it was referenced” leaves transfer plans and validation responsible for type. No descriptor/closure protocol is defined, and a tree and a file with identical bytes deliberately share an id. This is not necessarily cryptographically unsafe, but it makes parsers context-sensitive and weakens type-confusion defenses compared with Grok’s typed hashes.

8. **Tree fidelity and portability rules are incomplete** (§3). Symlink targets are raw bytes, but names must be UTF-8; behavior for non-UTF-8 host names, Windows reserved names, special files, case collisions, invalid symlinks, maximum depth/size, and path-length limits is absent. Materialization also follows a stored symlink target without explicitly requiring safe creation that cannot escape the destination during later writes.

9. **Capability links violate the settled TTL requirement** (§6). They have fresh-key encryption and deletion-based revocation, but no expiry in the URL, ciphertext, signed mint record, or hosting contract. A deliberately minted link is therefore not TTL’d. Requiring the entire transitive closure in every link also makes a card-only link for a multi-gigabyte workspace impractical.

10. **The manifest extension model is too loose** (§4.1). A single unnamespaced `extra` object gives no collision rules, payload schema/version convention, retention requirements, or unknown-field evolution behavior. It also uses example kinds `abra.workspace` and `abra.handoff.v1`, conflicting with the settled built-ins `dev.abra.workspace` and `dev.abra.handoff.v1`.

11. **Native and portable-source validation is too weak** (§4.4, §4.6). The prose says native blobs are never source of truth, but validation permits a full snapshot containing only `native` and no `files`/portable representation. The `fingerprint` is an opaque string rather than a validated tuple, so equivalent or incomplete fingerprints will not interoperate.

12. **The worked examples publish unverifiable claimed hashes** (§7–8). No test-vector canonical bytes are supplied, only pretty JSON and an asserted digest. Given the incomplete string canonicalization, these do not serve as cross-implementation vectors.

### Best ideas worth adopting

- **The binary tree encoding is the best compact tree format of the three** (§3). The prefix, raw 32-byte child hashes, sorted entries, and simple mode vocabulary are substantially smaller and easier to stream than my canonical-JSON tree. I would adopt it, adding explicit lengths/type-separated object ids, portability limits, and vectors.
- **The concise manifest table and validation list are excellent editorial structure** (§4.1, §4.6). They keep the one-envelope/full-vs-partial distinction immediately legible.
- **`cwd` is correctly required to be relative and free of `..`** (§4.3). This is better than Grok’s permission for absolute observed paths and matches the settled recipe shape.
- **Native blobs use the settled opaque host-fingerprint string directly** (§4.4), rather than prematurely freezing a platform enum. This is more extensible than both my structured fingerprint and Grok’s closed OS/arch values, though the final spec should define its component grammar.
- **The capability bundle and encryption recipe are admirably small** (§6). Fresh random key, XChaCha20-Poly1305, fragment key, ciphertext hash, and deletion-based revocation are the right core. Add authenticated expiry and an optional floor-only closure.
- **The explicit statement of fidelity limits** (§3.2)—contents, structure, targets, and executable bit, but not ownership/mtime/other permissions—is clearer than pretending “byte-for-byte” covers filesystem metadata.

## Review of `draft-grok46.md`

### Defects

1. **It contradicts settled identity and hash primitives** (§0.3, §2.2, §3, §4.1). The authoritative design fixes peer id as the first 8 bytes of `blake3(pubkey)` with the full public key alongside, blob ids as BLAKE3 of bytes, and snapshot id as BLAKE3 of canonical manifest bytes. Grok instead makes peer id the public key and adds domain and length prefixes to blob ids, domain prefixes to tree ids, and `abra-snap-v1\0` to snapshot ids. Those may be defensible greenfield choices, but they are wrong for this task and incompatible with the other settled implementation work.

2. **The offer has a parsed/raw split that enables scope bypass and spoofed previews** (§6.4). It transmits both `manifest` and `manifest_raw`, but validation never requires `manifest == parse(manifest_raw)`. Scope checks and immediate floor rendering are described against `manifest`, while the snapshot id commits only to `manifest_raw`. A guest can present an allowed kind/capsule in the parsed object and a forbidden kind/capsule in the signed raw bytes, or spoof the title shown before receipt. The wire must carry one authoritative byte string; parse, validate, render, and authorize only that value.

3. **Mutable `main` can be moved by a non-holder** (§5.3). A label update merely needs a signature, and the holder being the only writer of `main` is only a SHOULD. The winner is highest per-label sequence, with a signature tie-break. Any trusted full peer—or scoped guest if not separately blocked—can sign a higher-sequence `main` update and replace the canonical tip without the lease, defeating “writing without the lease = branch.” Receiver validation MUST require the winning lease holder and matching lease epoch for `main` mutations.

4. **The ACK is not explicitly conditioned on durable shelf commit** (§6.6–6.7). Grok says to ACK after wanted objects are verified, but does not require the canonical manifest, snapshot record/inbox entry, CAS refs, and pending receipt to be atomically durable first. A crash after ACK can lose the delivery after the sender clears its outbox. My draft’s “sent only after all objects and manifest are durable and referential checks pass” is stronger and should be adopted.

5. **Relay addressing is not blind to a relay that learns public keys** (§8.1). The HMAC key is `recipient_ed25519_pk`, which is public; the claim that the relay “cannot compute” a tag without it is not a security property. A relay observing any peer id elsewhere, colluding with a sender, or receiving a public directory can compute every day’s tags and correlate the recipient. My draft is explicitly better here: use a separately provisioned secret relay-discovery key.

6. **The relay sealed-box construction is not actually specified and appears cryptographically confused** (§4.2, §8.3). “key = HChaCha20(X25519(...))” is not a complete KDF/nonce/key-confirmation construction, and naming a libsodium primitive does not define the ephemeral public-key placement or packet bytes. The draft later lists this as needing test vectors, despite claiming an implementable contract. Keep relay v-next until an audited HPKE/sealed-box suite and exact encoding are fixed.

7. **Recipe paths contradict the settled portable recipe schema** (§1.6). Absolute `cwd` is allowed when outside the tree. The authoritative shape requires `cwd` relative to workspace root; an absolute sender-host path cannot recreate portably and can induce unsafe receiver behavior. Reject or omit processes whose working directory cannot be represented relative to the captured root.

8. **Recipe execution language blurs the core boundary** (§1.6). “The core … does not start processes unless the user explicitly runs a recipe” implies core may execute after confirmation. `DESIGN.md` is stricter: core executes nothing; a receiver/integrator may choose to run a displayed recipe. State that boundary normatively.

9. **Control replay defense is incomplete** (§6.8). A random nonce is called “anti-replay,” but no receiver nonce store, uniqueness scope, expiry window, sequence, or durable consumption rule is specified. A captured signed `stop`/`instruct` can be replayed indefinitely. Bind controls to recipient and capsule, give them an expiry or monotonic sequence, and atomically persist replay state before acting.

10. **Lease conflict resolution relies on clocks and permits chain skipping** (§5.4). Equal-sequence races are resolved by later `acquired_at`, which lets clock skew decide who is driving. Worse, a greater sequence is accepted despite `prev_hash` mismatch, so the predecessor chain is not an integrity condition. The draft itself admits the race is unresolved. My draft’s fail-closed same-epoch conflict is safer; the final spec needs an explicit signed conflict-resolution/takeover record.

11. **Label sequence is not well-defined** (§5.3). The record says `seq` is “per-capsule label log,” while winner selection is per `(capsule_id,name)`. Concurrent writers cannot allocate a single monotonic capsule sequence without consensus, and accepting the highest value lets any writer jump arbitrarily far. Use signed operations tied to a lease epoch/predecessor, or treat human labels as immutable snapshot metadata and keep only a narrowly authorized head pointer mutable.

12. **Pairing completion is not crash-safe or mutually confirmed** (§7.1). A sends unsigned `pair-accept` (transport authentication helps) and “both insert” trust, but there is no final confirmation/commit and no prescribed atomic ticket consumption with trust insertion. A crash can leave one side full-trusting the other while the other remains unpaired. Use a signed join request, local confirmation, atomic nonce consumption, signed acceptance, and an idempotent final confirmation.

13. **Enrollment bind propagation lacks a signed issuer-side binding record** (§7.2). Other full peers are told to “gossip the bind,” but the bind record format and signer are undefined. A guest signature proves possession of the guest key, not that the issuer accepted this first binding. Define an issuer-signed token-id→guest-key certificate so every peer can verify the same one-time bind and reject competing binds deterministically.

14. **Revocation freshness is overstated** (§7.3). Flooding signed records works only after peers receive them; an offline guest can continue using an unexpired certificate against a stale peer. The spec needs an explicit fail-open/fail-closed freshness policy, bounded token lifetime, and last-revocation-sync behavior rather than implying immediate mesh revocation.

15. **Capability expiry/revocation is client-enforced and hosting deletion is only SHOULD** (§9.2). A modified viewer can ignore plaintext expiry and keep decrypting indefinitely if ciphertext remains. For a bearer link, effective TTL/revocation requires the host/minter to make ciphertext unavailable; the minter SHOULD/MUST schedule deletion and record whether the host supports revocation. The floor/full mode is useful, but a floor pack containing a manifest whose referenced closure is absent must be identified as a projection, not a complete snapshot bundle.

16. **The adapter registry has unsafe ambiguity** (§10.1). “First registered wins” for two executables claiming the same kind is machine/order dependent and enables path-order hijacking. Conflicts should be a hard configuration error or require an explicit user-selected binding. The `register` argv alternative also creates two discovery contracts without much value.

17. **The workspace payload adds derived declarations with little value** (§11.1). `has_recipes` and `has_native` duplicate top-level arrays and can disagree with them. `file_count` and `total_bytes` require a full traversal and are not settled floor fields. Receivers can derive these; requiring them violates the general “rendering is derived” direction and adds validation surface.

18. **Versioning is internally contradictory** (§1.2, §12.2). The validation matrix says a `spec` mismatch may be “unknown major” or “ignore-extra,” while the compatibility table says every unknown 0.x minor is rejected. “Unknown required-looking field is optional by definition” makes it impossible to introduce a security-critical required field safely. Define a major compatibility rule plus explicit critical-feature negotiation; do not infer optionality from ignorance.

19. **The draft over-specifies unstable v-next and local policy while leaving security-critical edges open.** Relay HTTP, GC grace, exact retry timings, Windows reserved names, label names, concurrency caps, and redundant workspace counters consume substantial normative surface, yet durable ACK ordering, offer single-source-of-truth, control replay, bind gossip, and lease conflict recovery are incomplete. Move operational defaults and relay HTTP to informative appendices until the core invariants are closed.

### Best ideas worth adopting

- **The outbox state machine is the strongest of the three** (§6.10). It makes retry, resume, awaiting-ACK, cancellation, expiry, and the “only a valid ACK clears duty” invariant concrete. Adopt it with my durable-commit ACK condition and keep a stable delivery id across retries.
- **The signed ACK binds attempt and snapshot** (§6.7). `offer_id || snapshot_id`, verified specifically against the intended recipient, prevents cross-attempt replay. This is better than an ACK that signs only a snapshot id.
- **The delivery plan and object streams are much more practical than my JSON/base64 baseline** (§6.1, §6.5–6.9). Typed binary streams, receiver-verified CAS, bounded concurrency, and resumable offsets are the right wire design. Fix offer authority and durable completion.
- **The capsule genesis/snapshot/lease record separation is valuable** (§5.1–5.4). A signed random-id genesis and signed snapshot record give capsule identity and authorship a clean home outside the hashed manifest. This is better organized than my signature-inside-manifest approach, provided head updates and leases are tightened.
- **The explicit two-shelf and GC-root model is excellent** (§5.7). It operationalizes capsule store versus inbox and prevents outbox/in-flight/capability objects from being collected prematurely.
- **Enrollment scope enforcement is the most complete treatment** (§7.2–7.4). Direction, kind, capsule, lease operations, guest-to-guest denial, inert tokenless binary, and the local vendor send gate are all concrete. My audience-bound token is better than first-use bearer binding for provisioning simplicity/security, but Grok’s enforcement matrix should be retained.
- **The capability viewer contract is the best of the three** (§9.1–9.3): the ciphertext URL and key both remain in the fragment, the format authenticates expiry as AAD, and the zero-backend floor rendering requirements are explicit. Combine it with stronger server-side TTL/revocation.
- **The adapter request/response lifecycle is the strongest overall** (§10): NDJSON ids, structured errors, cancellation, timeouts, watch streaming, stderr isolation, and daemon-owned hashing provide implementers a real contract. Resolve registry collisions and avoid adapter-authored recipes.
- **The manifest validation matrix and object-closure definition are useful** (§1.2, §3.3). These should become normative checklists in the synthesis.
- **The “native requires tree” invariant is exactly right** (§1.1). It turns “native is never source of truth” from prose into validation.

## Verdict per major area

- **Manifest schema — Grok 4.6**, for the most complete field constraints, floor validation, single envelope, and native-requires-tree invariant; replace its identity/hash choices and absolute recipe path.
- **Canonical serialization / ids — GPT-5.6**, because it most precisely defines escaping, number space, noncanonical-byte rejection, and original-byte retention while keeping the settled plain BLAKE3 snapshot rule; adjust its peer-id encoding to the authoritative short-id rule.
- **Content addressing — Opus 5**, narrowly, for the simplest compact tree bytes and unchanged blob hashing that best match the settled primitives; add type framing/lengths and portability limits from Grok.
- **Identity / signatures — GPT-5.6**, for explicit signed manifests, domain separation, peer-key-derived verification, and identity/authz separation; Grok’s separate signed snapshot record is worth adopting structurally.
- **Capsule / DAG / lease — Grok 4.6**, for genesis, fork labels, explicit merge, rollback, store layout, and lease operations, despite its unsafe `main` authorization and clock-based conflict rule; repair those with fail-closed conflicts.
- **Delivery protocol — Grok 4.6**, decisively, for binary object streams, have/want, resume, signed per-attempt ACK, and the persisted outbox state machine; use GPT-5.6’s durable-commit ACK precondition.
- **Pairing / enrollment — GPT-5.6**, for audience-bound enrollment, signed channel-bound handshake, atomic single-use nonce intent, and simpler non-transitive grants; import Grok’s detailed receiver enforcement matrix.
- **Relay — GPT-5.6**, because it correctly uses a separate secret discovery key and refuses to pretend an unspecified crypto suite is baseline; Grok’s public-key HMAC is not blind.
- **Capability links — Grok 4.6**, for the strongest browser/viewer, encrypted format, floor/full, and mint-record treatment; require effective host deletion for TTL/revocation and call floor mode a projection.
- **Adapter contract — Grok 4.6**, for the most implementable NDJSON lifecycle, errors, cancellation, and watch behavior; GPT-5.6’s per-operation process/staging boundary is safer and should replace first-wins registration.
- **Payload kinds — GPT-5.6**, for explicit schemas and consistency constraints without Grok’s redundant required counters; simplify the workspace VCS extras if not needed in v1.
- **Versioning — GPT-5.6**, for explicit preservation/rejection boundaries, exact-byte forwarding, and negotiated feature gating; it still needs a critical-extension mechanism, but Opus has almost none and Grok contradicts itself.

## Synthesis guidance

1. **Make one canonical manifest byte string the sole authority.** Parse, hash, sign/verify, authorize, render, and store those exact bytes. Never transmit a second parsed manifest alongside raw bytes. This closes Grok’s most serious scope-bypass bug.
2. **Keep the settled primitives exactly:** Ed25519; full public key alongside the display-only `first8(blake3(pubkey))` peer id; raw `blake3(blob_bytes)`; and `blake3(canonical_manifest_bytes)` snapshot id. Add signature-domain separation without changing these settled content ids.
3. **Use Grok’s outbox/state/resume design, but ACK only after an atomic durable commit** of manifest/snapshot record or inbox entry, all verified objects, CAS references, and pending receipt. Sign `(delivery_id, snapshot_id, recipient, protocol version)` and verify against the intended recipient before clearing.
4. **Use Opus’s compact sorted binary tree as the base**, adding explicit entry/name lengths, type-safe parsing, size fields or verified lengths, empty-directory representation, special-file policy, path/depth limits, and cross-platform rejection rules. Publish byte-level test vectors for empty tree, Unicode, symlink, executable, and nested cases.
5. **Separate immutable history from narrowly mutable coordination.** Full manifests commit to capsule id, ordered parents, and immutable turn labels. Use signed genesis and snapshot-author records. A mutable canonical-head operation MUST be signed by the current lease holder and bind the lease epoch/predecessor; an unauthorized write creates only a fork pointer. Never silently merge.
6. **Make lease races fail closed.** Signed epoch/predecessor records support grant, refresh, transfer, takeover, and explicit conflict resolution. Equal-epoch branches authorize neither canonical-head writes until a signed higher-epoch resolution selects a predecessor. Do not use wall-clock ordering or accept predecessor mismatch merely because a sequence is higher.
7. **Adopt audience-bound, expiring enrollment certificates plus Grok’s enforcement matrix.** Bind the sandbox public key at mint time where possible; if first-use binding is retained, emit an issuer-signed binding certificate. Enforce direction, kind, capsule, lease, pairing/control denial, expiry, known revocation, and the independent local agent-send gate on every relevant operation.
8. **Specify direct p2p first and quarantine relay as a negotiated v-next extension.** Use iroh behind `Transport`, typed binary object streams, and authenticated QUIC. Relay discovery tags require a separate secret recipient key—not a public key—and relay ciphertext must use a fully pinned audited HPKE/sealed-box suite with vectors before interoperability is claimed.
9. **Combine Grok’s capability viewer with a truthful lifecycle contract.** Put only retrieval URL and random key in the fragment; authenticate format/expiry; distinguish a floor projection from a complete bundle; verify manifest/signature/object hashes; and require the minter/host to enforce scheduled deletion and revocation. Client-clock expiry alone is advisory.
10. **Use Grok’s adapter lifecycle with GPT-5.6’s staging isolation.** Separate executable, one-operation process, NDJSON ids, bounded messages, structured errors, cancellation, and watch events; daemon owns hashing/origin/signature. Registration conflicts are fatal or explicitly selected, recipes come only from the ambient observer, and core never executes recipes or payload actions.
