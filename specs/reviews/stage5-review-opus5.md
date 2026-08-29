# Stage 5 security review — capsule round-trip / signed main-pointer propagation (commit 5262dfe)

Reviewer: Claude Opus 5, security-focused. Repo: /Users/vividh/Desktop/abra. Read-only; no repo mutation.
Sanity: `cargo test -p abra-core signed_main_move_to_non_descendant_is_rejected` → pass; the round-trip test lives in `crates/cadabra/tests/e2e.rs` and the tree compiles clean. Both stage-5 tests present and green.

## Bottom line up front

I found **no forgery, no silent-merge, and no backward-roll bypass** in the adopt path. Transmitted lease records and the `main` label-op are validated through the *same* `accept_lease` / `apply_label` code that governs locally-authored records — signer, epoch monotonicity (`prev_epoch + 1`), `prev_hash` chaining, genesis rooting, lease-holder authorization, and the new descend check all apply. The path is fail-closed: any gap leaves the object as a fork and never infers a head. The real defects are **(a) an unbounded-work / disk-write DoS on the new `lease_chain`**, **(b) a round-trip robustness gap** (missing-hop / out-of-order adoption permanently forks and never self-heals), and **(c) a missing `offer.capsule_id` ↔ committed-manifest cross-check** (defense-in-depth). Details below.

---

## Findings

### 1. [MEDIUM] Unbounded lease-chain verification + disk-write amplification
`crates/abra-net/src/delivery.rs:~1073-1094` (`adopt_offer_capsule_state`), `crates/abra-core/src/store.rs:148-149` (`AbraStore::accept_lease`).

**Defect.** `offer.lease_chain: Vec<LeaseRecord>` is attacker-sized, capped only by `MAX_CONTROL_FRAME = 16 MiB` (`framing.rs:5`). `adopt_offer_capsule_state` iterates the whole vector and calls `store.accept_lease` on every not-already-known record. Each call runs an Ed25519 verify (`Capsule::accept_lease` → `r.verify_with`) and, for every record that verifies, an fsync'd `atomic_write` to `leases/…` — *including records that only reach the evidence buffer* (`store.rs:148` writes before checking the `Ok(false)` from `capsule.rs:308-313`). A 16 MiB frame holds ~50k lease records.

**Failure scenario.** (a) Any *trusted* sender (including a scoped guest allowed to Send) can ship a 16 MiB offer of well-formed-but-non-chaining leases; the receiver burns ~50k signature verifies (~seconds of CPU) per offer, repeatable per connection. (b) A Full peer (or guest with `lease_takeover` scope) can make each junk record a self-signed `Takeover` with a garbage `prev_hash`: it passes `verify_with(r.holder)` and `authorize`, then fails the `prev_hash != prev` check → lands in evidence **and gets fsync'd to disk**. Result: one frame → tens of thousands of distinct fsync'd files (evidence is capped at 64 in memory, but the on-disk `lease_path` files are hash-keyed and unbounded).

**Fix.** Cap `lease_chain.len()` on receipt (a chain only needs `winning.epoch - 1` records; reject anything larger, e.g. `> 64` or `> current_epoch_gap`). Persist a lease only after it *wins or is chain-valid*, not for evidence-only records (move the `atomic_write` in `store.rs` behind the win/append decision, or persist evidence to a bounded ring). Consider verifying the full chain in-memory (`Capsule::clone` staging is already used) and committing to disk once.

### 2. [MEDIUM] Missing intermediate hop / out-of-order arrival forks permanently and never self-heals
`crates/abra-core/src/capsule.rs:441-450` (descend check) + `delivery.rs:~1095` (main_label applied once, error swallowed).

**Defect.** `apply_label` rejects a winning `main` move whose target does not `descends_from` the current head. `descends_from` walks only *present* snapshots; a parent not yet in the store simply terminates that branch → returns `false` → `Err`. The offer applies `main_label` exactly once and the caller discards the error (`let _ = self.adopt_offer_capsule_state(...)`). There is no retry/re-evaluation when the missing ancestor later arrives.

**Failure scenario.** Receiver is at head N-1 and never received snapshot N (dropped/re-ordered). An honest offer for snapshot N+1 (parent = N) arrives: `descends_from(N+1, N-1)` fails because N is absent → main move rejected → N+1 stored as a fork. When N later arrives, the N+1 label-op is gone; `main` stays at N-1 and the capsule is permanently split until the sender manually re-sends. Same effect for `snapshot N+2 before N+1`. It is fail-closed (no corruption, no silent merge — good), but the round-trip does **not converge** under any reordering; it only works for strictly in-order, no-loss delivery.

**Fix.** For the turn-based pattern, document the in-order/no-loss assumption explicitly and have the sender re-offer the current `main` label-op on the next hop (idempotent) so a lagging peer catches up. Better: buffer a rejected-for-missing-ancestor `main` label-op and re-run `apply_label` after `resolve_orphans`/new-snapshot events. Distinguish "rejected: non-descendant (sideways — real fork)" from "rejected: ancestor absent (retryable)".

### 3. [LOW/MEDIUM] `offer.capsule_id` is not cross-checked against the committed manifest's capsule id
`crates/abra-net/src/delivery.rs:~1075-1076` (`adopt` reads `offer.capsule_id`) vs `delivery.rs:417,913` (commit uses `raw.manifest().capsule_id`).

**Defect.** The snapshot is committed to `manifest.capsule_id`, but `adopt_offer_capsule_state` operates on the separate, sender-controlled `offer.capsule_id` field with no assertion they are equal. Forgery is still blocked downstream (each `LeaseRecord`/`LabelOp` re-checks `capsule_id == genesis.capsule_id`, and the `main` target must be a present non-orphan snapshot in *that* capsule), so a mismatch cannot advance a capsule the attacker doesn't already hold the lease for. But it decouples "the snapshot I just committed" from "the capsule whose `main` I move," which is a latent correctness hazard and removes a cheap integrity invariant.

**Fix.** Assert `offer.capsule_id == Some(raw.manifest().capsule_id)` before adopting (fail-closed otherwise).

### 4. [LOW] Losing / evidence records are written to disk
`crates/abra-core/src/store.rs:148-149` and `store.rs:161-162`.

**Defect.** Both `store.accept_lease` and `store.apply_label` persist the record whenever the in-memory apply returns `Ok(_)`, i.e. also for `Ok(false)` (lost the race / went to evidence / lost on seq). Combines with #1 as write amplification and leaves losing label-ops/leases on disk. Not a bypass, but junk accumulation and unnecessary fsyncs.

**Fix.** Persist only when the record won or is otherwise authoritative; keep evidence in a bounded structure.

### 5. [NIT] Dedup via `hash().ok() == hash().ok()` matches on double-`None`
`crates/abra-net/src/delivery.rs:~1079-1083`.

`already_known` compares `known.hash().ok() == lease.hash().ok()`. If canonicalization ever errored for both sides, `None == None` would falsely treat an incoming lease as already-known and silently skip it. Not exploitable for well-formed structs, but the `Option`-equality pattern is a latent bug; compare on `Result`/`Hash` values, treating hash failure as "not equal".

---

## Priority-by-priority answers to the review brief

1. **No new trust / forgery.** Confirmed same rigor. Leases: `verify_with(signer)` where `signer` is `old_holder` (grant/refresh/transfer) or `r.holder` (takeover), plus `epoch == prev_epoch+1`, `prev_hash == prev`, genesis-rooted at epoch 1, and `authorize()` (mapped to `trust.authorize_lease`) for Transfer/Takeover — identical to local acceptance. Label: `op.verify()` (signature by `op.by`), `op.by == active_lease.holder`, `op.lease_epoch == w.epoch`, target present & non-orphan. A malicious sender cannot advance `main` unless it *is* the authorized current lease holder (Full peer, or scoped guest via `authorize_lease`), which is the intended trust model, not a bypass. Replay of a lower-epoch lease → `evidence`, `Ok(false)`, not winning. Replay of a lower-seq label → `wins=false`, ignored. A higher-seq backward/sideways `main` is caught by the descend check. The descend walk is DAG-sound (BTreeSet `seen` guards cycles; a crafted parent chain cannot make a non-descendant look like a descendant because it only follows real, present parent hashes).

2. **No silent merge / fork integrity.** Confirmed in both directions. Non-descendant `main` target → `Err` → head unchanged, snapshot is a fork. Label-op whose signer isn't the current holder → `Err("unauthorized main move")` → head unchanged. First-ever `main` (no prior label) has no descend constraint by design (establishing initial head), still gated by lease-holder auth. No path infers or merges a head.

3. **Round-trip under adversity.** Concurrent-both-take-lease converges deterministically via the epoch-race sig comparison in `accept_lease` (`capsule.rs:325-331`); the loser's snapshot forks because its `main` label-op fails `op.by == w.holder`. **But** missing intermediate hop / out-of-order arrival forks permanently with no self-heal (Finding 2). If the offer's `winning_lease_chain` can't reconstruct a link it returns an *empty* chain (`delivery.rs` `winning_lease_chain`), so main adoption fails-closed as a fork — safe, but the offer carries no partial history and the receiver cannot recover without a re-send.

4. **Byte authority intact.** Confirmed. Snapshot id remains hash-of-signed-manifest (`raw.snapshot_id()`, cross-checked at `delivery.rs:437`). `LeaseRecord` and `LabelOp` are verified from their own canonical signed bytes (`verify_with`/`verify` over `unsigned(self,"sig")`), never a re-serialized DOM.

5. **DoS / resource.** The new `lease_chain` is the weak point — see Finding 1 (no length cap; per-record verify + fsync, evidence still persisted). `descends_from` itself is bounded (O(present snapshots), parents ≤16 per manifest, cycle-guarded).

6. **Test adequacy — missing adversarial cases.** Present tests cover the linear happy path and one sideways rejection. Missing (recommend adding):
   - `main_move_to_ancestor_is_rejected_backward_roll` — higher-seq `main` op pointing at an ancestor of the current head (backward roll) is rejected and head unchanged.
   - `forged_non_holder_main_move_over_wire_is_forked` — offer whose `main_label` is signed by a non-holder (or `lease_epoch` mismatched) leaves head unchanged, snapshot a fork.
   - `adopt_with_missing_intermediate_snapshot_forks` and `adopt_out_of_order_N+2_before_N+1` — asserts current behavior AND (after Finding 2 fix) self-heal on late arrival.
   - `adopt_lease_chain_with_missing_link_carries_empty_chain_and_forks`.
   - `concurrent_both_move_main_converges_to_single_head_no_corruption` (both sides take epoch-N lease, both move main, exchange).
   - `oversized_lease_chain_is_rejected` / `evidence_only_leases_are_not_persisted_en_masse` — Finding 1 regression guard.
   - `offer_capsule_id_mismatch_with_manifest_is_rejected` — Finding 3.

---

## Verdict

**Safe to keep/ship for the turn-based handoff pattern it targets** — the authorization core is sound, the adopt path adds no new trust, and it is fail-closed against forgery, backward-roll, and silent merge. It is **not** robust to packet loss/reordering or to a hostile-but-trusted peer's oversized lease chain, so it should not be relied on as a general multi-writer sync until Findings 1 and 2 are addressed.

**Top 3 must-fix:**
1. **Bound `lease_chain` and stop persisting evidence-only/losing records** (Finding 1) — the one exploitable-for-DoS defect.
2. **Handle missing-ancestor `main` adoption as retryable, and re-offer the current main label each hop** (Finding 2) — otherwise any loss/reorder permanently forks the round-trip.
3. **Cross-check `offer.capsule_id` against the committed manifest's capsule id before adopting** (Finding 3) — cheap integrity invariant.
