use crate::{
    auth::{format_time, Direction, TrustStore},
    Error, Outbox, OutboxState, Result,
};
use abra_core::{
    capsule::{Genesis, LeaseRecord},
    cas::{Hash, Tree},
    identity::{Identity, PeerId, Signature},
    manifest::{closure, RawManifest, Scope},
    store::AbraStore,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

pub const HEALTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const MAX_OBJECT_STREAMS: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    #[serde(rename = "type")]
    pub message_type: String,
    pub offer_id: String,
    pub snapshot_id: Hash,
    pub scope: Scope,
    pub kind: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capsule_id: Option<Hash>,
    pub fork: bool,
    pub bytes_hint: u64,
    pub object_count: u64,
    pub manifest_raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis: Option<Genesis>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferAccept {
    #[serde(rename = "type")]
    pub message_type: String,
    pub offer_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferReject {
    #[serde(rename = "type")]
    pub message_type: String,
    pub offer_id: String,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanObject {
    pub digest: Hash,
    pub kind: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    #[serde(rename = "type")]
    pub message_type: String,
    pub offer_id: String,
    pub seq: u64,
    pub eof: bool,
    pub objects: Vec<PlanObject>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Have {
    #[serde(rename = "type", default = "have_type")]
    pub message_type: String,
    pub offer_id: String,
    pub have: Vec<Hash>,
    pub resume: BTreeMap<Hash, u64>,
    pub eof: bool,
}
fn have_type() -> String {
    "have".into()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resume {
    #[serde(rename = "type")]
    pub message_type: String,
    pub offer_id: String,
    pub complete: Vec<Hash>,
    pub partial: BTreeMap<Hash, u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferError {
    #[serde(rename = "type")]
    pub message_type: String,
    pub offer_id: String,
    pub digest: Hash,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    #[serde(rename = "type")]
    pub message_type: String,
    pub offer_id: String,
    pub snapshot_id: Hash,
    pub received_at: String,
    pub shelf: String,
    pub sig: Signature,
}

fn ack_payload(
    offer_id: &str,
    snapshot_id: Hash,
    sender: PeerId,
    receiver: PeerId,
) -> Result<Vec<u8>> {
    let offer = hex::decode(offer_id).map_err(|_| Error::protocol("bad offer id"))?;
    if offer.len() != 16 {
        return Err(Error::protocol("bad offer id"));
    }
    let mut p = offer;
    p.extend_from_slice(snapshot_id.as_bytes());
    p.extend_from_slice(sender.as_bytes());
    p.extend_from_slice(receiver.as_bytes());
    Ok(p)
}
impl Ack {
    pub fn sign(
        offer_id: String,
        snapshot_id: Hash,
        shelf: String,
        now: u64,
        sender: PeerId,
        receiver: &Identity,
    ) -> Result<Self> {
        let mut x = Self {
            message_type: "ack".into(),
            offer_id,
            snapshot_id,
            received_at: format_time(now),
            shelf,
            sig: Signature::from_bytes([0; 64]),
        };
        x.sig = receiver.sign(
            "ack",
            &ack_payload(&x.offer_id, snapshot_id, sender, receiver.peer_id())?,
        );
        Ok(x)
    }
    pub fn verify(&self, sender: PeerId, intended_receiver: PeerId) -> Result<()> {
        intended_receiver.verify(
            "ack",
            &ack_payload(&self.offer_id, self.snapshot_id, sender, intended_receiver)?,
            &self.sig,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransferStats {
    pub objects_transferred: u64,
    pub bytes_transferred: u64,
    pub objects_reused: u64,
    pub resumed_bytes: u64,
}
#[derive(Clone, Debug)]
pub enum DeliveryOutcome {
    Complete { ack: Ack, stats: TransferStats },
    Interrupted { stats: TransferStats },
}

pub struct DeliveryNode {
    pub store: AbraStore,
    pub trust: TrustStore,
    pub outbox: Outbox,
    pub allow_agent_send: bool,
    partial_dir: PathBuf,
    pending_ack_dir: PathBuf,
}
impl DeliveryNode {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        Ok(Self {
            store: AbraStore::open(root)?,
            trust: TrustStore::open(root)?,
            outbox: Outbox::open(root)?,
            allow_agent_send: false,
            partial_dir: root.join("net/partials"),
            pending_ack_dir: root.join("net/pending-acks"),
        })
    }
    pub fn peer_id(&self) -> PeerId {
        self.store.keys.identity.peer_id()
    }
    pub fn enqueue(&mut self, peer: PeerId, raw: &RawManifest, now: u64) -> Result<String> {
        if self
            .trust
            .get(&self.peer_id())
            .is_some_and(|p| p.role == crate::Role::Guest)
        {
            let scopes = self
                .trust
                .get(&self.peer_id())
                .and_then(|p| p.scopes.as_ref());
            if !self.allow_agent_send || !scopes.is_some_and(|s| s.send) {
                return Err(Error::authz("local agent sending disabled"));
            }
        }
        self.outbox
            .enqueue(peer, raw.snapshot_id(), raw.bytes().to_vec(), now)
    }
    pub fn deliver(&mut self, id: &str, receiver: &mut Self, now: u64) -> Result<DeliveryOutcome> {
        self.deliver_limited(id, receiver, now, None)
    }
    pub fn deliver_limited(
        &mut self,
        id: &str,
        receiver: &mut Self,
        now: u64,
        disconnect_after: Option<u64>,
    ) -> Result<DeliveryOutcome> {
        let entry = self
            .outbox
            .get(id)
            .cloned()
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        if entry.peer_id != receiver.peer_id() {
            return Err(Error::Authentication(
                "connected recipient differs from outbox".into(),
            ));
        }
        self.outbox.transition(id, OutboxState::Healthcheck, now)?;
        let raw = RawManifest::parse(entry.manifest_raw.clone())?;
        let manifest = raw.manifest();
        receiver.trust.authorize_offer(
            self.peer_id(),
            receiver.peer_id(),
            manifest.capsule_id,
            &manifest.kind,
            Direction::Send,
            now,
        )?;
        if self
            .trust
            .get(&receiver.peer_id())
            .is_some_and(|p| p.role == crate::Role::Guest)
        {
            self.trust.authorize_offer(
                receiver.peer_id(),
                self.peer_id(),
                manifest.capsule_id,
                &manifest.kind,
                Direction::Receive,
                now,
            )?;
        }
        let closure = closure(&self.store.cas, manifest)?;
        let bytes_hint = closure
            .iter()
            .map(|h| self.store.cas.get(h).map(|b| b.len() as u64))
            .collect::<abra_core::Result<Vec<_>>>()?
            .into_iter()
            .sum();
        let _offer = Offer {
            message_type: "offer".into(),
            offer_id: entry.offer_id.clone(),
            snapshot_id: raw.snapshot_id(),
            scope: manifest.scope,
            kind: manifest.kind.clone(),
            title: manifest.title.clone(),
            capsule_id: manifest.capsule_id,
            fork: false,
            bytes_hint,
            object_count: closure.len() as u64,
            manifest_raw: data_encoding::BASE64URL_NOPAD.encode(raw.bytes()),
            genesis: manifest
                .capsule_id
                .and_then(|c| self.store.capsules.get(&c).map(|x| x.genesis.clone())),
        };
        self.outbox.transition(id, OutboxState::Offered, now)?;
        let have = receiver.compute_have(&entry.offer_id, &closure)?;
        self.outbox.transition(id, OutboxState::Transferring, now)?;
        let mut stats = TransferStats::default();
        let have_set: BTreeSet<_> = have.have.into_iter().collect();
        stats.objects_reused = have_set.len() as u64;
        let mut budget = disconnect_after.unwrap_or(u64::MAX);
        for digest in closure.iter().filter(|h| !have_set.contains(h)) {
            let bytes = self.store.cas.get(digest)?;
            let offset = have
                .resume
                .get(digest)
                .copied()
                .unwrap_or(0)
                .min(bytes.len() as u64);
            stats.resumed_bytes += offset;
            let left = bytes.len() as u64 - offset;
            let take = left.min(budget);
            receiver.append_partial(
                &entry.offer_id,
                *digest,
                bytes.len() as u64,
                offset,
                &bytes[offset as usize..(offset + take) as usize],
            )?;
            stats.bytes_transferred += take;
            budget -= take;
            if take < left {
                return Ok(DeliveryOutcome::Interrupted { stats });
            }
            receiver.commit_partial(&entry.offer_id, *digest)?;
            stats.objects_transferred += 1;
            if budget == 0 && closure.iter().any(|h| !receiver.store.cas.has(h)) {
                return Ok(DeliveryOutcome::Interrupted { stats });
            }
        }
        self.outbox.transition(id, OutboxState::AwaitingAck, now)?;
        let shelf = receiver.commit_manifest(raw.clone(), self.peer_id(), now)?;
        let ack = Ack::sign(
            entry.offer_id.clone(),
            entry.snapshot_id,
            shelf,
            now,
            self.peer_id(),
            &receiver.store.keys.identity,
        )?;
        receiver.persist_pending_ack(&ack)?;
        ack.verify(self.peer_id(), entry.peer_id)?;
        if !self
            .outbox
            .mark_acked(id, &ack.offer_id, ack.snapshot_id, ack.sig, now)?
        {
            return Err(Error::Authentication(
                "ack offer or snapshot mismatch".into(),
            ));
        }
        receiver.clear_partials(&entry.offer_id)?;
        receiver.clear_pending_ack(&entry.offer_id)?;
        Ok(DeliveryOutcome::Complete { ack, stats })
    }
    fn compute_have(&self, offer: &str, closure: &BTreeSet<Hash>) -> Result<Have> {
        let mut have = Vec::new();
        let mut resume = BTreeMap::new();
        for h in closure {
            if self.store.cas.has(h) {
                have.push(*h)
            } else if let Some(n) = self.partial_len(offer, *h)? {
                resume.insert(*h, n);
            }
        }
        Ok(Have {
            message_type: "have".into(),
            offer_id: offer.into(),
            have,
            resume,
            eof: true,
        })
    }
    fn partial_path(&self, offer: &str, h: Hash) -> PathBuf {
        self.partial_dir.join(offer).join(h.to_hex())
    }
    fn partial_len(&self, offer: &str, h: Hash) -> Result<Option<u64>> {
        match fs::metadata(self.partial_path(offer, h)) {
            Ok(m) => Ok(Some(m.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn append_partial(
        &self,
        offer: &str,
        h: Hash,
        total: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        use std::io::Write;
        let p = self.partial_path(offer, h);
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?
        }
        let current = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        if current != offset {
            return Err(Error::protocol("non-contiguous resume offset"));
        }
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&p)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        if f.metadata()?.len() > total {
            return Err(Error::protocol("partial exceeds total size"));
        }
        Ok(())
    }
    fn commit_partial(&self, offer: &str, h: Hash) -> Result<()> {
        let p = self.partial_path(offer, h);
        let b = fs::read(&p)?;
        if Hash::of(&b) != h {
            let _ = fs::remove_file(p);
            return Err(Error::protocol("object hash mismatch"));
        }
        self.store.cas.put(&b)?;
        fs::remove_file(p)?;
        Ok(())
    }
    fn clear_partials(&self, offer: &str) -> Result<()> {
        let p = self.partial_dir.join(offer);
        match fs::remove_dir_all(p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    fn pending_ack_path(&self, offer: &str) -> PathBuf {
        self.pending_ack_dir.join(format!("{offer}.cjson"))
    }
    fn persist_pending_ack(&self, ack: &Ack) -> Result<()> {
        let path = self.pending_ack_path(&ack.offer_id);
        fs::create_dir_all(&self.pending_ack_dir)?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, abra_core::canonical::to_vec(ack)?)?;
        fs::OpenOptions::new().read(true).open(&tmp)?.sync_all()?;
        fs::rename(tmp, path)?;
        Ok(())
    }
    fn clear_pending_ack(&self, offer: &str) -> Result<()> {
        match fs::remove_file(self.pending_ack_path(offer)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn pending_acks(&self) -> Result<Vec<Ack>> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(&self.pending_ack_dir) else {
            return Ok(out);
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|x| x.to_str()) == Some("cjson") {
                let bytes = fs::read(path)?;
                abra_core::canonical::validate_canonical(&bytes)?;
                out.push(serde_json::from_slice(&bytes)?);
            }
        }
        Ok(out)
    }
    fn commit_manifest(&mut self, raw: RawManifest, from: PeerId, now: u64) -> Result<String> {
        let at = format_time(now);
        match raw.manifest().scope {
            Scope::Partial => {
                self.store.receive_partial(raw, from.to_hex(), at)?;
                Ok("inbox".into())
            }
            Scope::Full => {
                let capsule = raw.manifest().capsule_id.expect("validated");
                if !self.store.capsules.contains_key(&capsule) {
                    return Err(Error::protocol("receiver lacks capsule genesis"));
                }
                self.store.receive_full(raw, at, now, None)?;
                Ok("capsule".into())
            }
        }
    }
}

pub fn add_capsule_from_peer(
    receiver: &mut DeliveryNode,
    genesis: Genesis,
    grant: LeaseRecord,
) -> Result<()> {
    receiver.store.add_capsule(genesis, grant)?;
    Ok(())
}

pub fn object_kind(bytes: &[u8]) -> crate::framing::ObjectKind {
    if Tree::decode(bytes).is_ok() {
        crate::framing::ObjectKind::Tree
    } else {
        crate::framing::ObjectKind::Blob
    }
}
