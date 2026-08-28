//! Capsule history, labels, leases, orphans, and fork-on-write (SPEC §5).
use crate::{
    canonical,
    cas::Hash,
    identity::{Identity, PeerId, Signature},
    manifest::{RawManifest, Scope},
    Error, Result,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub type CapsuleId = Hash;
pub const LEASE_TTL_MIN_MS: u64 = 60_000;
pub const LEASE_TTL_DEFAULT_MS: u64 = 86_400_000;
pub const LEASE_TTL_MAX_MS: u64 = 604_800_000;
pub fn random_capsule_id() -> CapsuleId {
    let mut b = [0; 32];
    OsRng.fill_bytes(&mut b);
    Hash::from_bytes(b)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub spec: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub capsule_id: CapsuleId,
    pub created_at: String,
    pub created_by: PeerId,
    pub kind: String,
    pub title: String,
    pub sig: Signature,
}
impl Genesis {
    pub fn new(
        id: CapsuleId,
        at: String,
        kind: String,
        title: String,
        creator: &Identity,
    ) -> Result<Self> {
        let mut x = Self {
            spec: crate::SPEC.into(),
            record_type: "capsule-genesis".into(),
            capsule_id: id,
            created_at: at,
            created_by: creator.peer_id(),
            kind,
            title,
            sig: Signature::from_bytes([0; 64]),
        };
        x.sig = creator.sign("genesis", &unsigned(&x, "sig")?);
        Ok(x)
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        canonical::to_vec(self)
    }
    pub fn hash(&self) -> Result<Hash> {
        Ok(Hash::of(&self.bytes()?))
    }
    pub fn verify(&self) -> Result<()> {
        if self.spec != crate::SPEC || self.record_type != "capsule-genesis" {
            return Err(Error::invalid("invalid genesis schema"));
        }
        self.created_by
            .verify("genesis", &unsigned(self, "sig")?, &self.sig)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseMode {
    Grant,
    Refresh,
    Transfer,
    Takeover,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    pub spec: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub capsule_id: CapsuleId,
    pub holder: PeerId,
    pub epoch: u64,
    pub mode: LeaseMode,
    pub acquired_at: String,
    pub expires_at: String,
    pub prev_hash: Hash,
    pub sig: Signature,
}
impl LeaseRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capsule_id: CapsuleId,
        holder: PeerId,
        epoch: u64,
        mode: LeaseMode,
        acquired_at: String,
        expires_at: String,
        prev_hash: Hash,
        signer: &Identity,
    ) -> Result<Self> {
        let mut x = Self {
            spec: crate::SPEC.into(),
            record_type: "lease".into(),
            capsule_id,
            holder,
            epoch,
            mode,
            acquired_at,
            expires_at,
            prev_hash,
            sig: Signature::from_bytes([0; 64]),
        };
        x.sig = signer.sign("lease", &unsigned(&x, "sig")?);
        Ok(x)
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        canonical::to_vec(self)
    }
    pub fn hash(&self) -> Result<Hash> {
        Ok(Hash::of(&self.bytes()?))
    }
    pub fn verify_with(&self, p: &PeerId) -> Result<()> {
        p.verify("lease", &unsigned(self, "sig")?, &self.sig)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelOp {
    pub spec: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub capsule_id: CapsuleId,
    pub seq: u64,
    pub op: String,
    pub name: String,
    pub snapshot_id: Hash,
    pub lease_epoch: u64,
    pub at: String,
    pub sig: Signature,
}
impl LabelOp {
    pub fn new(
        capsule_id: CapsuleId,
        seq: u64,
        name: String,
        snapshot_id: Hash,
        lease_epoch: u64,
        at: String,
        signer: &Identity,
    ) -> Result<Self> {
        let mut x = Self {
            spec: crate::SPEC.into(),
            record_type: "label-op".into(),
            capsule_id,
            seq,
            op: "set".into(),
            name,
            snapshot_id,
            lease_epoch,
            at,
            sig: Signature::from_bytes([0; 64]),
        };
        x.sig = signer.sign("label", &unsigned(&x, "sig")?);
        Ok(x)
    }
    pub fn verify_with(&self, p: &PeerId) -> Result<()> {
        p.verify("label", &unsigned(self, "sig")?, &self.sig)
    }
}

#[derive(Clone, Debug)]
pub struct SnapshotRecord {
    pub raw: RawManifest,
    pub received_at: String,
    pub orphan: bool,
}
#[derive(Clone, Debug)]
pub struct WriteResult {
    pub snapshot_id: Hash,
    pub forked: bool,
    pub fork_label: Option<String>,
}
#[derive(Debug)]
pub struct Capsule {
    pub genesis: Genesis,
    snapshots: BTreeMap<Hash, SnapshotRecord>,
    leases: Vec<LeaseRecord>,
    winner: Option<usize>,
    labels: BTreeMap<String, LabelOp>,
    fork_counts: BTreeMap<PeerId, u32>,
    evidence: Vec<LeaseRecord>,
}
impl Capsule {
    pub fn new(genesis: Genesis) -> Result<Self> {
        genesis.verify()?;
        Ok(Self {
            genesis,
            snapshots: BTreeMap::new(),
            leases: vec![],
            winner: None,
            labels: BTreeMap::new(),
            fork_counts: BTreeMap::new(),
            evidence: vec![],
        })
    }
    pub fn winning_lease(&self) -> Option<&LeaseRecord> {
        self.winner.map(|i| &self.leases[i])
    }
    pub fn snapshot(&self, id: &Hash) -> Option<&SnapshotRecord> {
        self.snapshots.get(id)
    }
    pub fn label(&self, n: &str) -> Option<&LabelOp> {
        self.labels.get(n)
    }
    pub fn accept_lease(&mut self, r: LeaseRecord) -> Result<bool> {
        if r.spec != crate::SPEC
            || r.record_type != "lease"
            || r.capsule_id != self.genesis.capsule_id
            || r.epoch == 0
        {
            return Err(Error::invalid("invalid lease record"));
        }
        let ttl = timestamp_ms(&r.expires_at)?
            .checked_sub(timestamp_ms(&r.acquired_at)?)
            .ok_or_else(|| Error::invalid("lease expires before acquisition"))?;
        if !((LEASE_TTL_MIN_MS as i64)..=(LEASE_TTL_MAX_MS as i64)).contains(&ttl) {
            return Err(Error::invalid("lease TTL outside 60s..=7d"));
        }
        let race = self
            .winning_lease()
            .is_some_and(|w| r.epoch == w.epoch && r.prev_hash == w.prev_hash);
        let (prev, prev_epoch, old_holder) = if race {
            if r.epoch == 1 {
                (self.genesis.hash()?, 0, self.genesis.created_by)
            } else {
                let p = self
                    .leases
                    .iter()
                    .find(|x| x.hash().ok() == Some(r.prev_hash))
                    .ok_or_else(|| Error::invalid("lease race predecessor unavailable"))?;
                (r.prev_hash, p.epoch, p.holder)
            }
        } else {
            match self.winning_lease() {
                None => (self.genesis.hash()?, 0, self.genesis.created_by),
                Some(w) => (w.hash()?, w.epoch, w.holder),
            }
        };
        if r.prev_hash != prev || r.epoch != prev_epoch + 1 {
            self.evidence.push(r);
            return Ok(false);
        }
        let signer = if r.mode == LeaseMode::Takeover {
            r.holder
        } else {
            old_holder
        };
        if r.epoch == 1 && r.mode != LeaseMode::Grant {
            return Err(Error::invalid("epoch 1 must be a grant"));
        }
        if r.mode == LeaseMode::Grant {
            if r.epoch != 1 || r.holder != self.genesis.created_by {
                return Err(Error::invalid("invalid grant"));
            }
        } else if r.mode == LeaseMode::Refresh && r.holder != old_holder {
            return Err(Error::invalid("refresh changes holder"));
        }
        r.verify_with(&signer)?;
        if race {
            let w = self.winning_lease().unwrap();
            if r.sig.to_bytes() <= w.sig.to_bytes() {
                self.leases.push(r);
                return Ok(false);
            }
        }
        self.leases.push(r);
        self.winner = Some(self.leases.len() - 1);
        Ok(true)
    }
    pub fn insert_snapshot(
        &mut self,
        raw: RawManifest,
        received_at: String,
        writer: PeerId,
    ) -> Result<WriteResult> {
        let m = raw.manifest();
        if m.scope != Scope::Full || m.capsule_id != Some(self.genesis.capsule_id) {
            return Err(Error::invalid("snapshot is not in capsule"));
        }
        let parents = m.parents.as_ref().unwrap();
        if parents.is_empty()
            && self
                .snapshots
                .values()
                .any(|r| r.raw.manifest().parents.as_ref().is_some_and(Vec::is_empty))
        {
            return Err(Error::invalid("capsule already has a root snapshot"));
        }
        let orphan = parents.iter().any(|p| !self.snapshots.contains_key(p));
        let id = raw.snapshot_id();
        self.snapshots.insert(
            id,
            SnapshotRecord {
                raw,
                received_at,
                orphan,
            },
        );
        self.resolve_orphans();
        let lease_ok = self.winning_lease().is_some_and(|l| l.holder == writer);
        let forked = !lease_ok || orphan;
        let fork_label = if forked {
            Some(format!("fork/{}", &id.to_hex()[..8]))
        } else {
            None
        };
        Ok(WriteResult {
            snapshot_id: id,
            forked,
            fork_label,
        })
    }
    fn resolve_orphans(&mut self) {
        loop {
            let known: BTreeSet<_> = self.snapshots.keys().copied().collect();
            let mut changed = false;
            for r in self.snapshots.values_mut() {
                if r.orphan
                    && r.raw
                        .manifest()
                        .parents
                        .as_ref()
                        .unwrap()
                        .iter()
                        .all(|p| known.contains(p))
                {
                    r.orphan = false;
                    changed = true
                }
            }
            if !changed {
                break;
            }
        }
    }
    pub fn apply_label(&mut self, op: LabelOp, signer: PeerId) -> Result<bool> {
        if op.capsule_id != self.genesis.capsule_id || op.op != "set" {
            return Err(Error::invalid("invalid label op"));
        }
        op.verify_with(&signer)?;
        if op.name == "main" {
            let w = self
                .winning_lease()
                .ok_or_else(|| Error::invalid("main requires lease"))?;
            if signer != w.holder || op.lease_epoch != w.epoch {
                return Err(Error::invalid("unauthorized main move"));
            }
            if !self
                .snapshots
                .get(&op.snapshot_id)
                .is_some_and(|r| !r.orphan)
            {
                return Err(Error::invalid("main target missing or orphan"));
            }
        } else if op.name.starts_with("fork/") {
            if op.name.len() != 13
                || !op.name[5..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && (!b.is_ascii_uppercase()))
            {
                return Err(Error::invalid("invalid fork label"));
            }
        } else if op.name.len() > 64
            || op.name.is_empty()
            || op
                .name
                .bytes()
                .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:-".contains(&b)))
        {
            return Err(Error::invalid("invalid user label"));
        }
        if !self.labels.contains_key(&op.name) && self.labels.len() >= 128 {
            return Err(Error::invalid("capsule label limit exceeded"));
        }
        let wins = !self.labels.get(&op.name).is_some_and(|old| {
            op.seq < old.seq || (op.seq == old.seq && op.sig.to_bytes() <= old.sig.to_bytes())
        });
        if wins {
            if op.name.starts_with("fork/") && !self.labels.contains_key(&op.name) {
                let count = self.fork_counts.entry(signer).or_default();
                if *count >= 32 {
                    return Err(Error::invalid("fork label limit exceeded"));
                }
                *count += 1;
            }
            self.labels.insert(op.name.clone(), op);
        }
        Ok(wins)
    }
}
fn unsigned<T: Serialize>(v: &T, field: &str) -> Result<Vec<u8>> {
    let mut x = serde_json::to_value(v)?;
    x.as_object_mut()
        .ok_or_else(|| Error::invalid("signed record not object"))?
        .remove(field);
    canonical::to_vec(&x)
}

fn timestamp_ms(s: &str) -> Result<i64> {
    if s.len() != 24
        || &s[4..5] != "-"
        || &s[7..8] != "-"
        || &s[10..11] != "T"
        || &s[13..14] != ":"
        || &s[16..17] != ":"
        || &s[19..20] != "."
        || &s[23..] != "Z"
    {
        return Err(Error::invalid("noncanonical lease time"));
    }
    let n = |a: usize, b: usize| {
        s[a..b]
            .parse::<i64>()
            .map_err(|_| Error::invalid("noncanonical lease time"))
    };
    let (y, m, d, hh, mm, ss, ms) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
        n(20, 23)?,
    );
    if !(1..=12).contains(&m) || d < 1 || hh > 23 || mm > 59 || ss > 59 {
        return Err(Error::invalid("invalid lease time"));
    }
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok((((days * 24 + hh) * 60 + mm) * 60 + ss) * 1000 + ms)
}
