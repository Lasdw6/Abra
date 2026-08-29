# Stage 5 review: capsule round-trip / main-pointer propagation (commit 5262dfe)

Reviewer: Grok 4.6 (security-focused)
Repo: `/Users/vividh/Desktop/abra` @ `5262dfe56ca7a871756d29f97cca831f10ccbe26`
Authoritative: `SPEC.md` (delivery, capsules/leases/labels + errata), `DESIGN.md` §3
Method: read-only review of `crates/abra-core` (lease/label/descend), `crates/abra-net` (offer carry + `adopt_offer_capsule_state`), `crates/cadabra` (`accept` restores `.abra/capsule_id`), and the two new tests. No repo modifications.

The happy-path design is the right one: commit the immutable snapshot first, then feed the sender’s signed lease ancestry and `main` label-op through the ordinary `accept_lease` / `apply_label` rules, and refuse a winning `main` move that does not descend from the current head. Locally-authored snapshots still parent from `main`, so honest turn-taking is a linear DAG. Signature, epoch, `prev_hash`, and “signer == winning-lease holder” checks are the same functions as local writes. That is not a new trust primitive.

What is new is a **wire composition** of those primitives: every full offer is now an implicit lease-and-pointer update, applied with `let _ =`, against `offer.capsule_id` / `op.capsule_id` that are not bound to the snapshot just committed. That is where the authorization-adjacent defects live.

---

## Findings

1. **major** — `crates/abra-net/src/delivery.rs:934–937`, `1074–1096`; `crates/abra-core/src/store.rs:136–151`
   **Defect:** Capsule-state adoption is neither atomic nor fail-closed. After `commit_manifest`, the receiver runs `let _ = self.adopt_offer_capsule_state(&offer, now)` and still signs/sends `ack`. Inside adopt, each unknown `lease_chain` record is `accept_lease`d (and **persisted**) before `main_label` is attempted. `store.accept_lease` writes the record to `leases/` even when `Capsule::accept_lease` returns `Ok(false)` (gap → evidence). A later `Err` (bad sig, unauthorized holder, non-descendant `main`, expired lease, missing target) aborts the rest of the function via `?` and is discarded by `let _`.
   SPEC §6.4: adopt `main` only if the **complete** applicable chain and label-op validate; “Failure leaves the snapshot stored as a fork.” The implementation can change the winning lease and still ack a successful transfer with `main` unchanged.
   **Failure scenario:** Paired full peer B (takeover is allowed for `Role::Full` with no extra scope — `authorize_lease` at `auth.rs:594–596`) sends a full snapshot of a **sibling** of A’s `main`, with `lease_chain = [B’s signed takeover]` and `main_label` pointing at that sibling. Receiver: stores the snapshot; takeover **wins**; `apply_label` returns `main move does not descend from current head`; error swallowed; ack sent. A has lost the lease (integrator contract: stop acting) while `main` still names A’s tip. B cannot subsequently move `main` to B’s fork either. Concurrent authoring, a hostile “decoy” snapshot, or a truncated chain that applies epoch 2 then fails epoch 4 all produce the same split brain: lease moved, pointer not, sender believes the hop landed.
   **Fix:** Stage leases+label against a cloned `Capsule`. Commit to disk only if every applicable record is accepted **and** (if present) `main_label` applies, **or** roll back leases if the pointer fails. Bind the whole bundle to one `capsule_id` (finding 2). On adopt failure, leave winner+`main` untouched, keep the snapshot, and surface a distinct outcome (do not `let _ =`; do not ack as if the pointer moved). Cap `lease_chain` and do not persist `Ok(false)` evidence via the same `leases/` path the winner uses.

2. **major** — `crates/abra-net/src/delivery.rs:1075–1095`, `912–927`; `crates/abra-core/src/store.rs:153–164`
   **Defect:** The offered snapshot’s capsule and the authz bundle are different objects. `add_capsule` / `commit_manifest` key off `raw.manifest().capsule_id`. `adopt_offer_capsule_state` keys leases off `offer.capsule_id` with `self.store.capsules[&capsule_id]` (BTreeMap `Index`: **panic** if absent). `apply_label` then keys off `op.capsule_id`, and is called as `apply_label(op.clone(), op.by, now)` so the “caller == signer” check is tautological — any trusted session can submit another capsule’s signed op.
   `validate_incoming_offer` never requires `offer.capsule_id == manifest.capsule_id == genesis.capsule_id == lease.capsule_id == main_label.capsule_id`.
   **Failure scenario:** (a) B sends a legitimate snapshot of capsule A with `offer.capsule_id` set to existing capsule C. After the A snapshot commits, adopt applies `lease_chain` to **C**. A valid takeover in that vector steals C’s lease as a side effect of receiving A. (b) `main_label.capsule_id = C` moves C’s `main` (if B already holds C’s lease on the receiver) while the user thought they were receiving A. (c) `offer.capsule_id` is a random id: `capsules[&id]` panics in the inbound `tokio::spawn` (`cadabra/src/lib.rs:287–298`). That session dies; with a poisoned path or a panic-abort profile it is worse. Honest Sol senders set both ids from the same manifest — a malicious paired peer or a buggy client need not.
   **Fix:** Reject the offer unless every id in `{offer, manifest, genesis, genesis_grant, lease_chain[], main_label}` matches. Use `get`/`ok_or`, never `[]`. Pass `connection.peer_id()` into adopt only as the transport principal; authorization remains the signed `by`/`holder` plus lease rules.

3. **major** — `crates/abra-net/src/delivery.rs:1078–1091`, `1100–1118`; `crates/abra-net/src/framing.rs:5–25`; `crates/abra-core/src/store.rs:148–150`, `323–341`
   **Defect:** `lease_chain` is attacker-sized up to `MAX_CONTROL_FRAME` (16 MiB) with no record cap. Each element is signature-verified. `Takeover` is self-signed by `r.holder`; a full peer therefore satisfies `verify_with` + `authorize_lease` even when `prev_hash`/`epoch` do not match the winner (those records go to evidence and `Ok(false)`). They are still written under `leases/{epoch}-{hash}.cjson`. In-memory `evidence` is capped at 64; **disk is not**. Reload reapplies every file with `authorize = |_| true` (`store.rs:335`).
   `winning_lease_chain` on the honest send path emits the full epoch-2..=winner walk with no compaction; a long-lived capsule can also fail to *send* when the chain exceeds 16 MiB.
   **Failure scenario:** B, already paired, offers a tiny full snapshot whose `lease_chain` is tens of thousands of unique, validly signed takeovers with junk `prev_hash`. Receive walks/verifies them, fills `capsules/<id>/leases/`, acks. Daemon restart replays the directory. Repeat per offer. Same budget also burns CPU on Ed25519 at offer-parse time (the 16 MiB frame was previously mostly inert JSON; it is now a signature mill).
   **Fix:** Hard cap the vector (e.g. 256 or “epoch delta from local winner”). Require strictly increasing epochs, `prev_hash` linking to the last accepted record or the local winner, and `capsule_id` match *before* `accept_lease`. Persist only records that extend the winner (or a dedicated evidence shelf with a 64-file cap). Consider a skip-proof later; for v1, refuse to offer if the ancestry will not fit.

4. **minor** — `crates/abra-core/src/capsule.rs:431–449`, `484–502`; `crates/abra-net/src/delivery.rs:421`, `912–933`
   **Defect:** The new descend check is **sound** against parent-pointer forgery: parents are inside the hashed manifest, capped at 16 distinct hashes (`manifest.rs:222–225`); missing nodes are not treated as ancestors; `seen` stops cycles; targeting an orphan is already rejected. A non-descendant cannot be made to look like a descendant without inserting a real connecting snapshot, which *is* a descendant. `descends_from(X, X)` is true, so idempotent re-points work. Moving `main` to an **ancestor** is correctly rejected (SPEC §5.3 rollback is a *new* one-parent snapshot, not a pointer rewind).
   Remaining gaps: (1) no iteration/snapshot cap on the walk — hostile history is bounded by how many snapshots the victim already stored, each requiring a prior transfer, so this is a slow leak not a one-frame bomb; (2) “orphan” means “parent missing,” not “parent is orphan,” so a non-orphan child of an orphan is eligible as `main` if it otherwise descends — still cannot jump to a disjoint head; (3) wire receive still calls `receive_full(..., fork_signer: None)`, so SPEC §5.5’s `fork/<8hex>` label is **not** created on the receive path. “Stored as a fork” is only “`main` unchanged + snapshot in the DAG.” Equal-`seq` races: the sig-winner must now descend from whoever was applied first, so a sibling pair at the same seq can reject the spec-winning sig.
   **Failure scenario:** Two devices both move `main` at `seq=n` to sibling descendants; depending on apply order, the lexicographically greater `sig` is rejected for ancestry against the lesser. Not forgery; it is a new disagreement with §5.3’s tie-break. Walk DoS requires an already-huge local DAG.
   **Fix:** Optionally require the new target to descend from the *pre-op* head (already the case when a single winner exists). Document equal-seq + sibling as reject-both / keep incumbent. Create `fork/*` on receive when `insert_snapshot` reports `forked` (needs a local signer or a signed fork-op on the offer). Bound `descends_from` iterations to `snapshots.len()`.

5. **minor** — `crates/cadabra/src/lib.rs:763–787`, `652–715`
   **Defect:** Restoring `.abra/capsule_id` from `raw.manifest().capsule_id` after materialize is the right bit for “received capsule is a real workspace.” The id is inside the hashed manifest (byte authority holds). Gaps: inbox/`partial` accept still skips it (correct — partials have no capsule id). Full accept overwrites `.abra/capsule_id` in a destination that may already belong to another capsule (`validate_destination` only checks absolute + not a symlink). Local `snapshot` always parents from current `main` then `apply_label`s; if that apply fails (no lease), `receive_full` has already persisted the snapshot and the user gets an error — pre-existing, now easier to hit when adopt left the lease with the peer (finding 1).
   **Failure scenario:** User `abra accept`s a second capsule into a directory that still has another capsule’s `.abra`. Subsequent `snapshot` writes into the **incoming** id with a tree that is the other project’s files. No signature forgery; it is a workspace-identity mix-up the new write makes silent.
   **Fix:** Refuse accept if `destination/.abra/capsule_id` exists and differs. If `apply_label` fails after `receive_full`, do not pretend the snapshot is the new head; return `forked: true` instead of a hard error once the wire path is transactional.

6. **minor** — tests: `crates/cadabra/tests/e2e.rs:29–154`, `crates/abra-core/tests/core_spec.rs:61–128`, `crates/abra-net/tests/net_spec.rs:648–649`
   **Defect:** Coverage is the cooperative three-hop line plus a local sibling reject. The e2e still `lease-take`s on each authoring side rather than proving the receiver can author from **offer-adopted** lease state alone; A never rematerializes B’s tree before hop 3 (parent pointer is linear; folder bytes need not be). `net_spec` only adds empty `lease_chain` / `main_label: None` so `Offer` still deserializes. No wire test of the reject/ack matrix.
   **Failure scenario:** A daemon that acks after a swallowed adopt failure, applies a cross-capsule `lease_chain`, accepts a non-holder `main_label`, promotes a gapped chain, or panics on a mismatched `offer.capsule_id` still ships green on “69 tests.” Concurrent both-move (the case DESIGN §3 / SPEC §5.5 exist for) is untested.
   **Fix:** Named tests below (checklist §6). Keep the linear e2e; it is necessary, not sufficient.

7. **nit** — `crates/abra-net/src/delivery.rs:637`, `632`; `SPEC.md:308–333` vs `452–463`
   **Defect:** Honest `genesis_grant` is `leases().first()`, which is insertion order, not “winning epoch-1 grant” (harmless while only the creator’s grant exists). `fork: false` is hardcoded on every offer and never read on receive. SPEC §5.3 still does not mention the ancestry rule that `apply_label` now enforces for local *and* remote `main` moves; only §6.4 / the stage-5 erratum do.
   **Failure scenario:** None today for honest capsules. Docs and the `fork` field will mislead the next implementer.
   **Fix:** Select the epoch-1 `Grant`. Set `offer.fork` from `insert_snapshot`’s `forked`. Copy the descend rule into §5.3.

---

## Priority checklist (task items)

**1. No new trust / no forgery.** Manifest origin still has to be a trusted peer; snapshot id is still `BLAKE3` of received `manifest_raw`. Lease records still `verify_with` the takeover holder or the previous winner; `main` still requires `op.by == winning holder && op.lease_epoch == winning epoch` and a non-orphan target. A sender **cannot** forge a `main` move for a lease they do not hold, and **cannot** install a takeover the receiver’s `authorize_lease` rejects (guests without `lease_takeover` still `Err` before persist). Lower-epoch / wrong-`prev_hash` records do not become winner (`Ok(false)` → evidence). Those core checks are intact.

   What *is* new trust-adjacent: any full offer from a **full** peer is now a live takeover channel (stage 4 never shipped `lease-update`), applied even when the pointer is invalid (finding 1), and may target a **different** capsule than the snapshot (finding 2). Replay of an old **lower-seq** label does not win. Replay of an old lower-epoch lease does not win. A holder **can** no longer rewind `main` onto an ancestor (descend check) — that matches §5.3’s “rollback = new snapshot” rule. Descend-check forgery via crafted parents: no (finding 4).

**2. No silent merge / fork integrity.** Receipt does not infer a head from `parents` or from being the latest snapshot. `insert_snapshot` never moves `main`. A sideways target fails `apply_label` and, on the happy error path, leaves `main` in place. **Both directions** use the same `apply_label`. There is no merge of folder trees on receive. Caveat: if leases applied and label failed, the object is not a clean fork — the writer set changed (finding 1). Wire path still does not mint `fork/*` (finding 4). Concurrent both-move: deterministic *pointer* fork if the second tip does not descend; lease may still flip.

**3. Round-trip correctness under adversity.** Cooperative A→B→A→B with explicit `lease-take` and linear parents works (e2e). Out-of-order `N+2` before `N+1`: target is orphan → label `Err` → snapshot stored, `main` unchanged; later `N+1` un-orphans via `resolve_orphans` but does **not** retroactively move `main` (fail-closed; another offer is required). Missing intermediate lease: gap → `Ok(false)` for that record; if an earlier chain element already won, partial apply (finding 1); if the whole chain gaps, `main_label` is unauthorized → fork. Takeover the receiver never saw: that is the intended return-path (B’s takeover must land on A for B’s `main_label` to verify). Empty `winning_lease_chain` (broken local `prev_hash` walk) sends `main_label` without ancestry → receiver fail-closes the pointer. Concurrent both-take/both-move: see findings 1 and 4 — not corruption of CAS bytes, but lease/pointer split is possible.

**4. Byte authority intact.** `validate_incoming_offer` still decodes `manifest_raw` and requires `raw.snapshot_id() == offer.snapshot_id`; `commit_manifest` stores those exact bytes (`store.rs:234`). Lease/label verification is the same path as local: serde → struct → canonical unsigned bytes → Ed25519 (`unsigned` + `verify` / `verify_with`). Persisted form is `record.bytes()` / `op.bytes()` (canonical), with reload `read_canonical` exact round-trip. They are not hashing a second hand-built DOM. They are also **not** hashing the offer-frame bytes verbatim; that matches SPEC’s CJSON-of-the-record rule, not the snapshot’s “`manifest_raw` is the only representation” rule. Do not treat lease JSON on the offer as byte-authoritative beyond “deserializes to the signed struct.”

**5. DoS/resource.** New cost is `lease_chain` inside the existing 16 MiB control frame plus per-record verify + disk write (finding 3). `descends_from` is O(ancestor subgraph) with `seen`; parents ≤ 16 (finding 4). No dedicated bound on how many lease records an offer may carry or a receiver will walk. Honest chain length grows with every refresh (~5 min) and will eventually fail `write_frame` for a hot capsule.

**6. Test adequacy — missing adversarial cases.**
   - Wire: forged `main_label` whose `by` is not the receiver’s winning holder → snapshot stored, `main` unchanged, **no** lease change.
   - Wire: replay of a lower-epoch / wrong-`prev` lease as if it were the winner.
   - Wire: `main` to an **ancestor** (backward roll), not only a sibling (unit test covers sibling only).
   - Wire: concurrent both-move from the same parent → two tips, one `main`, no merge; assert lease/pointer invariant you choose after fixing finding 1.
   - Wire: `N+2` before `N+1` → orphan, `main` stays; after `N+1`, `main` still not silently at `N+2`.
   - Wire: `lease_chain` with a hole (2 then 4) → no partial winner (after the atomicity fix).
   - Wire: `offer.capsule_id != manifest.capsule_id` → protocol error, no panic, other capsules untouched.
   - Wire: 1 + cap+1 lease records → reject.
   - E2e: B authors hop 2 **without** local `lease-take` if that is the intended handoff (or document that takeover remains a local verb and the chain only *explains* `main`).
   - E2e: original author rematerializes the peer’s tree before the next hop (folder bytes, not just parent ids).

---

## SPEC-critical invariants (spot check)

**Signed lease/label, not inferred head.** Preserved on the success path. Violated as a *bundle* when leases persist and `main` does not (finding 1).

**Signer == winning-lease holder + epoch.** `apply_label` still enforces this before the new descend check. Intact.

**Genesis-rooted `prev_hash` chain.** Intact for records that `Ok(true)`. Gaps do not promote (good) but now persist from the wire (finding 3).

**Descend-from-current-head for winning `main`.** New, enforced, sound (finding 4). Missing from SPEC §5.3 body.

**Receipt never silently merges.** DAG-level: yes. Workspace-folder: accept materializes a tree; it does not merge with an existing dest beyond whatever `materialize` already did.

---

## Overall verdict

**Not safe to keep/ship as the turn-based handoff mechanism without fixing findings 1–3.** The round-trip *idea* should stay: restoring `.abra/capsule_id`, carrying signed `main` + lease ancestry, committing the snapshot first, and rejecting non-descendant `main` moves are the correct SPEC/DESIGN shape, and the linear e2e is real. A malicious or merely concurrent paired peer can today steal or split the lease while the protocol acks, retarget a different capsule’s pointer, or fill `leases/` with self-signed takeovers — and none of that is tested.

It is acceptable as an **in-tree prototype** of A→B→A→B on the happy path (two cooperative full devices, explicit `lease-take`, no concurrent writes). It is not yet the authorization boundary for Blink Chess-style handoff over the wire.

### Top-3 must-fix

1. **Transactional adopt (finding 1):** apply lease ancestry + `main_label` to a clone; persist both or neither (except the already-committed snapshot). Stop swallowing the result. Ack must not mean “pointer moved” if it did not.
2. **Bind and bound the bundle (findings 2–3):** one `capsule_id` for offer/manifest/genesis/leases/label; no `[]` panic; cap `lease_chain`; persist only chain-extending records.
3. **Adversarial tests (finding 6):** non-holder `main`, ancestor rewind, gapped chain, cross-capsule ids, concurrent both-move, out-of-order orphan. Until those exist, do not treat stage 5 as closing the Blink Chess continuation gap under adversity.
