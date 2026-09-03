use crate::{
    auth::{
        accept_handshake, bootstrap_allowed, dial_handshake_with_trust, format_time, has_feature,
        BindCertificate, Direction, LocalRole, MeshProfile, Ping, Pong, ProtocolError, Revocation,
        TrustStore, FEATURE_BIND_CERT, FEATURE_REVOCATION, FEATURE_SKIP_NATIVE,
        MAX_REVOCATIONS_PER_MESSAGE,
    },
    framing::{ObjectHeader, ObjectKind},
    read_frame, write_frame, Connection, Error, Outbox, OutboxState, Result,
};
use abra_core::{
    capsule::{Genesis, LabelOp, LeaseMode, LeaseRecord},
    cas::{Hash, Tree},
    identity::{Identity, PeerId, Signature},
    manifest::{closure, RawManifest, Scope},
    store::AbraStore,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub const HEALTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const MAX_OBJECT_SIZE: u64 = 256 * 1024 * 1024;
pub const MAX_NATIVE_OBJECT_SIZE: u64 = 8 * 1024 * 1024 * 1024;
pub const DEFAULT_OFFER_BUDGET: u64 = 16 * 1024 * 1024 * 1024;
pub const OBJECT_STREAM_CHUNK: u64 = 1024 * 1024;
pub const STREAMING_THRESHOLD: u64 = 8 * 1024 * 1024;
const MAX_INBOX_ENTRIES: usize = 10_000;
const MAX_PENDING_PAIRS: usize = 128;
const MAX_EVENT_LOG_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_LEASE_CHAIN_LEN: usize = 256;
const MAX_REJECTION_REASON_CHARS: usize = 256;

struct DirectoryCleanup(PathBuf);

impl Drop for DirectoryCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn rejection_reason(error: &Error) -> String {
    let reason = match error {
        Error::Authorization(message)
        | Error::Authentication(message)
        | Error::Protocol(message) => message.as_str(),
        Error::Core(_) => "invalid manifest",
        Error::Json(_) => "invalid offer",
        Error::Io(_) | Error::Transport(_) | Error::Timeout => "delivery validation failed",
    };
    sanitize_rejection_reason(reason)
}

fn sanitize_rejection_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_REJECTION_REASON_CHARS)
        .collect()
}

fn update_object_hasher(
    hashers: &mut BTreeMap<Hash, blake3::Hasher>,
    digest: Hash,
    bytes: &[u8],
) -> Result<()> {
    hashers
        .get_mut(&digest)
        .ok_or_else(|| Error::protocol("object stream for completed object"))?
        .update(bytes);
    Ok(())
}

fn add_relay_object_bytes(total: u64, bytes: u64) -> Result<u64> {
    let total = total
        .checked_add(bytes)
        .ok_or_else(|| Error::protocol("relay byte count overflow"))?;
    if total > MAX_OBJECT_SIZE {
        return Err(Error::protocol(
            "snapshot too large for relay transit; use direct delivery",
        ));
    }
    Ok(total)
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_grant: Option<LeaseRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lease_chain: Vec<LeaseRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_label: Option<LabelOp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_certificate_issuer: Option<PeerId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_certificate: Option<BindCertificate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocations: Vec<Revocation>,
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
    #[serde(default, skip_serializing_if = "is_false")]
    pub skip_native: bool,
}
fn have_type() -> String {
    "have".into()
}
fn is_false(value: &bool) -> bool {
    !*value
}

fn exceeds_storage_quota(required: u64, budget: u64, available: std::io::Result<u64>) -> bool {
    required > budget || available.map_or(true, |free| free < required)
}

fn wanted_plan_object<'a>(
    allowed: &'a BTreeMap<Hash, &PlanObject>,
    have: &BTreeSet<Hash>,
    digest: &Hash,
) -> Result<&'a PlanObject> {
    if have.contains(digest) {
        return Err(Error::protocol("object not wanted"));
    }
    allowed
        .get(digest)
        .copied()
        .ok_or_else(|| Error::protocol("object not wanted"))
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayObject {
    pub digest: Hash,
    pub kind: String,
    pub data: String,
}

/// Recipient-sealed relay payload. It deliberately embeds the exact direct
/// `Offer` and a byte-authoritative object pack, so relay receipt uses the same
/// authorization and manifest validation as a live session.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RelayPayload {
    Delivery {
        sender: PeerId,
        offer: Box<Offer>,
        objects: Vec<RelayObject>,
    },
    Ack {
        sender: PeerId,
        ack: Ack,
    },
}

fn ack_payload(
    offer_id: &str,
    snapshot_id: Hash,
    sender: PeerId,
    receiver: PeerId,
    shelf: &str,
) -> Result<Vec<u8>> {
    let offer = hex::decode(offer_id).map_err(|_| Error::protocol("bad offer id"))?;
    if offer.len() != 16 {
        return Err(Error::protocol("bad offer id"));
    }
    let mut p = offer;
    p.extend_from_slice(snapshot_id.as_bytes());
    p.extend_from_slice(sender.as_bytes());
    p.extend_from_slice(receiver.as_bytes());
    p.extend_from_slice(shelf.as_bytes());
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
            &ack_payload(
                &x.offer_id,
                snapshot_id,
                sender,
                receiver.peer_id(),
                &x.shelf,
            )?,
        );
        Ok(x)
    }
    pub fn verify(&self, sender: PeerId, intended_receiver: PeerId) -> Result<()> {
        intended_receiver.verify(
            "ack",
            &ack_payload(
                &self.offer_id,
                self.snapshot_id,
                sender,
                intended_receiver,
                &self.shelf,
            )?,
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
    /// Daemon policy for non-interactive pairing. Interactive daemons leave
    /// this false and approve requests before retrying; test/automation
    /// daemons opt in explicitly.
    pub auto_confirm_pairs: bool,
    /// Maximum bytes this receiver accepts for one direct offer.
    pub offer_budget: u64,
    /// Decline optional native cache blobs while accepting portable content.
    pub skip_native: bool,
    streaming_threshold: u64,
    /// Pair requests observed by an interactive daemon and approvals granted
    /// through its local control API. They are intentionally process-local;
    /// tickets remain the durable, bounded authorization.
    pub pending_pair_requests: BTreeMap<PeerId, crate::PairRequest>,
    pub approved_pair_requests: BTreeSet<PeerId>,
    pending_main_labels: BTreeMap<Hash, Vec<LabelOp>>,
    partial_dir: PathBuf,
    pending_ack_dir: PathBuf,
    pending_pair_dir: PathBuf,
    approved_pair_dir: PathBuf,
    event_log: PathBuf,
}
impl DeliveryNode {
    fn offer_bind_certificate(&self, origin: PeerId) -> (Option<PeerId>, Option<BindCertificate>) {
        if !matches!(self.trust.local_role(), LocalRole::Full)
            || self
                .trust
                .get(&origin)
                .is_none_or(|peer| peer.role != crate::Role::Guest)
        {
            return (None, None);
        }
        self.trust
            .bind_certificate(&origin)
            .map_or((None, None), |stored| {
                (Some(stored.issuer), Some(stored.certificate.clone()))
            })
    }
    /// Removes every partial-transfer directory under the root. Only the
    /// daemon calls this, once, before it accepts sessions: `open` runs on
    /// every control request and must never touch in-flight transfers.
    pub fn sweep_abandoned_partials(root: impl AsRef<Path>) -> Result<()> {
        let partial_dir = root.as_ref().join("net/partials");
        if partial_dir.is_dir() {
            for entry in fs::read_dir(&partial_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    fs::remove_dir_all(entry.path())?;
                }
            }
        }
        Ok(())
    }
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let partial_dir = root.join("net/partials");
        Ok(Self {
            store: AbraStore::open(root)?,
            trust: TrustStore::open(root)?,
            outbox: Outbox::open(root)?,
            allow_agent_send: false,
            auto_confirm_pairs: false,
            offer_budget: DEFAULT_OFFER_BUDGET,
            skip_native: false,
            streaming_threshold: STREAMING_THRESHOLD,
            pending_pair_requests: BTreeMap::new(),
            approved_pair_requests: BTreeSet::new(),
            pending_main_labels: BTreeMap::new(),
            partial_dir,
            pending_ack_dir: root.join("net/pending-acks"),
            pending_pair_dir: root.join("net/pending-pairs"),
            approved_pair_dir: root.join("net/approved-pairs"),
            event_log: root.join("net/events.ndjson"),
        })
    }
    pub fn peer_id(&self) -> PeerId {
        self.store.keys.identity.peer_id()
    }
    /// Snapshot the immutable delivery inputs and a detached copy of outbox
    /// state so a daemon can perform network I/O without holding its node lock.
    pub fn outgoing_session(&self) -> Self {
        Self {
            store: self.store.clone(),
            trust: self.trust.clone(),
            outbox: self.outbox.detached(),
            allow_agent_send: self.allow_agent_send,
            auto_confirm_pairs: self.auto_confirm_pairs,
            offer_budget: self.offer_budget,
            skip_native: self.skip_native,
            streaming_threshold: self.streaming_threshold,
            pending_pair_requests: self.pending_pair_requests.clone(),
            approved_pair_requests: self.approved_pair_requests.clone(),
            pending_main_labels: self.pending_main_labels.clone(),
            partial_dir: self.partial_dir.clone(),
            pending_ack_dir: self.pending_ack_dir.clone(),
            pending_pair_dir: self.pending_pair_dir.clone(),
            approved_pair_dir: self.approved_pair_dir.clone(),
            event_log: self.event_log.clone(),
        }
    }

    /// Override the sender cutoff in tests so small fixtures exercise chunking.
    #[doc(hidden)]
    pub fn set_streaming_threshold_for_tests(&mut self, bytes: u64) {
        debug_assert!(bytes <= STREAMING_THRESHOLD);
        self.streaming_threshold = bytes.min(STREAMING_THRESHOLD);
    }
    pub fn approve_pair(&self, peer: PeerId) -> Result<()> {
        fs::create_dir_all(&self.approved_pair_dir)?;
        fs::write(self.approved_pair_dir.join(peer.to_hex()), b"approved")?;
        Ok(())
    }
    pub fn durable_pending_pairs(&self) -> Result<Vec<crate::PairRequest>> {
        let mut requests = Vec::new();
        let Ok(entries) = fs::read_dir(&self.pending_pair_dir) else {
            return Ok(requests);
        };
        for entry in entries {
            let bytes = fs::read(entry?.path())?;
            requests.push(serde_json::from_slice(&bytes)?);
        }
        Ok(requests)
    }
    pub fn enqueue(&mut self, peer: PeerId, raw: &RawManifest, now: u64) -> Result<String> {
        let recipient = self
            .trust
            .get(&peer)
            .ok_or_else(|| Error::authz("unknown or untrusted recipient"))?;
        if let LocalRole::Guest { token } = self.trust.local_role() {
            if !self.allow_agent_send || !token.scopes.send || token.verify(now).is_err() {
                return Err(Error::authz("local agent sending disabled"));
            }
            if recipient.role == crate::Role::Guest
                && (self.trust.mesh_profile() == MeshProfile::Personal
                    || !recipient.scopes.as_ref().is_some_and(|scopes| {
                        scopes.allows(
                            raw.manifest().capsule_id,
                            &raw.manifest().kind,
                            Direction::Receive,
                        )
                    }))
            {
                return Err(Error::authz(
                    "guest-to-guest delivery forbidden or out of scope",
                ));
            }
        }
        self.outbox
            .enqueue(peer, raw.snapshot_id(), raw.bytes().to_vec(), now)
    }

    pub fn relay_delivery(&self, id: &str, now: u64) -> Result<RelayPayload> {
        let entry = self
            .outbox
            .get(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        let raw = RawManifest::parse(entry.manifest_raw.clone())?;
        let closure_set = closure(&self.store.cas, raw.manifest())?;
        let mut objects = Vec::with_capacity(closure_set.len());
        let mut bytes_hint = 0u64;
        for digest in closure_set {
            let bytes = self.store.cas.get(&digest)?;
            bytes_hint = add_relay_object_bytes(bytes_hint, bytes.len() as u64)?;
            objects.push(RelayObject {
                digest,
                kind: if Tree::decode(&bytes).is_ok() {
                    "tree"
                } else {
                    "blob"
                }
                .into(),
                data: data_encoding::BASE64URL_NOPAD.encode(&bytes),
            });
        }
        let capsule = raw
            .manifest()
            .capsule_id
            .and_then(|c| self.store.capsules.get(&c));
        let offer = Offer {
            message_type: "offer".into(),
            offer_id: entry.offer_id.clone(),
            snapshot_id: entry.snapshot_id,
            scope: raw.manifest().scope,
            kind: raw.manifest().kind.clone(),
            title: raw.manifest().title.clone(),
            capsule_id: raw.manifest().capsule_id,
            fork: capsule.is_some_and(|c| {
                c.active_lease(now)
                    .is_none_or(|l| l.holder != raw.manifest().origin.peer_id)
            }),
            bytes_hint,
            object_count: objects.len() as u64,
            manifest_raw: data_encoding::BASE64URL_NOPAD.encode(raw.bytes()),
            genesis: capsule.map(|c| c.genesis.clone()),
            genesis_grant: capsule.and_then(|c| {
                c.leases()
                    .iter()
                    .find(|l| l.epoch == 1 && l.mode == LeaseMode::Grant)
                    .cloned()
            }),
            lease_chain: capsule.map(winning_lease_chain).unwrap_or_default(),
            main_label: capsule.and_then(|c| c.label("main").cloned()),
            // Relay envelopes have no preceding feature handshake.
            bind_certificate_issuer: None,
            bind_certificate: None,
            revocations: Vec::new(),
        };
        Ok(RelayPayload::Delivery {
            sender: self.peer_id(),
            offer: Box::new(offer),
            objects,
        })
    }

    pub fn receive_relay_delivery(
        &mut self,
        payload: RelayPayload,
        now: u64,
    ) -> Result<(PeerId, Ack)> {
        let RelayPayload::Delivery {
            sender,
            offer,
            objects,
        } = payload
        else {
            return Err(Error::protocol("relay payload is not a delivery"));
        };
        let raw = self.validate_incoming_offer(&offer, sender, now)?;
        if objects.len() as u64 != offer.object_count {
            return Err(Error::protocol("relay object count mismatch"));
        }
        let mut supplied = BTreeSet::new();
        let mut total = 0u64;
        let mut decoded = Vec::with_capacity(objects.len());
        for object in objects {
            let bytes = data_encoding::BASE64URL_NOPAD
                .decode(object.data.as_bytes())
                .map_err(|_| Error::protocol("bad relay object base64"))?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| Error::protocol("relay byte count overflow"))?;
            if Hash::of(&bytes) != object.digest
                || !matches!(object.kind.as_str(), "blob" | "tree")
                || (object.kind == "tree") != Tree::decode(&bytes).is_ok()
            {
                return Err(Error::protocol("invalid relay object"));
            }
            if !supplied.insert(object.digest) {
                return Err(Error::protocol("duplicate relay object"));
            }
            decoded.push((object.digest, bytes));
        }
        if total != offer.bytes_hint || total > MAX_OBJECT_SIZE {
            return Err(Error::protocol("relay object pack exceeds delivery limit"));
        }
        let staged = abra_core::cas::BlobStore::open(
            self.partial_dir.join(&offer.offer_id).join("relay-staged"),
        )?;
        let _staged_cleanup = DirectoryCleanup(staged.root().to_path_buf());
        for (_, bytes) in &decoded {
            staged.put(bytes)?;
        }
        if closure(&staged, raw.manifest())? != supplied {
            return Err(Error::protocol(
                "relay pack differs from verified manifest closure",
            ));
        }
        for (_, bytes) in decoded {
            self.store.cas.put(&bytes)?;
        }
        if raw.manifest().scope == Scope::Full {
            let capsule_id = raw.manifest().capsule_id.expect("validated");
            if !self.store.capsules.contains_key(&capsule_id) {
                self.store.add_capsule(
                    offer
                        .genesis
                        .clone()
                        .ok_or_else(|| Error::protocol("missing genesis"))?,
                    offer
                        .genesis_grant
                        .clone()
                        .ok_or_else(|| Error::protocol("missing genesis grant"))?,
                )?;
            }
        } else if self.store.inbox.len() >= MAX_INBOX_ENTRIES {
            return Err(Error::authz("inbox quota exceeded"));
        }
        let mut shelf = self.commit_manifest(raw, sender, now)?;
        if shelf == "capsule" {
            shelf = if self.adopt_offer_capsule_state(&offer, now).unwrap_or(false) {
                "capsule-head"
            } else {
                "capsule-fork"
            }
            .into();
        }
        let ack = Ack::sign(
            offer.offer_id.clone(),
            offer.snapshot_id,
            shelf,
            now,
            sender,
            &self.store.keys.identity,
        )?;
        self.persist_pending_ack(&ack)?;
        self.record_event(&serde_json::json!({"event":if offer.scope == Scope::Full {"capsule-sync"} else {"inbox-arrival"},"snapshot_id":ack.snapshot_id,"from":sender,"at":ack.received_at,"via":"relay"}))?;
        self.clear_partials(&offer.offer_id)?;
        Ok((sender, ack))
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
            skip_native: self.skip_native,
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
        if offset.saturating_add(bytes.len() as u64) > total {
            return Err(Error::protocol("partial exceeds total size"));
        }
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&p)?;
        f.write_all(bytes)?;
        if offset + bytes.len() as u64 == total {
            f.sync_all()?;
        }
        if f.metadata()?.len() > total {
            return Err(Error::protocol("partial exceeds total size"));
        }
        Ok(())
    }
    #[cfg(test)]
    fn commit_partial(&self, offer: &str, h: Hash) -> Result<()> {
        let p = self.partial_path(offer, h);
        let staged = abra_core::cas::BlobStore::open(self.partial_dir.join(offer).join("staged"))?;
        staged
            .commit_file(&p, &h)
            .map(|_| ())
            .map_err(|_| Error::protocol("object hash mismatch"))
    }

    fn commit_verified_partial(&self, offer: &str, h: Hash) -> Result<()> {
        let source = self.partial_path(offer, h);
        let staged = abra_core::cas::BlobStore::open(self.partial_dir.join(offer).join("staged"))?;
        staged.commit_verified_file(source, &h)?;
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
        fs::File::open(&self.pending_ack_dir)?.sync_all()?;
        Ok(())
    }
    fn clear_pending_ack(&self, offer: &str) -> Result<()> {
        match fs::remove_file(self.pending_ack_path(offer)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    fn record_event(&self, value: &serde_json::Value) -> Result<()> {
        use std::io::Write;
        if let Some(parent) = self.event_log.parent() {
            fs::create_dir_all(parent)?;
        }
        if fs::metadata(&self.event_log).is_ok_and(|metadata| metadata.len() >= MAX_EVENT_LOG_BYTES)
        {
            fs::write(&self.event_log, [])?;
        }
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.event_log)?;
        file.write_all(&bytes)?;
        file.sync_data()?;
        Ok(())
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

    pub fn validate_incoming_offer(
        &mut self,
        offer: &Offer,
        from: PeerId,
        now: u64,
    ) -> Result<RawManifest> {
        if offer.revocations.len() > MAX_REVOCATIONS_PER_MESSAGE {
            return Err(Error::protocol("revocation list exceeds 128 records"));
        }
        self.trust.apply_revocations(&offer.revocations, now)?;
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(offer.manifest_raw.as_bytes())
            .map_err(|_| Error::protocol("bad manifest base64"))?;
        let raw = RawManifest::parse(bytes)?;
        if raw.snapshot_id() != offer.snapshot_id {
            return Err(Error::protocol("offer snapshot id mismatch"));
        }
        let manifest = raw.manifest();
        if offer.lease_chain.len() > MAX_LEASE_CHAIN_LEN {
            return Err(Error::protocol("lease chain exceeds 256 records"));
        }
        for pair in offer.lease_chain.windows(2) {
            if pair[1].epoch != pair[0].epoch + 1 || pair[1].prev_hash != pair[0].hash()? {
                return Err(Error::protocol("lease chain is not strictly contiguous"));
            }
        }
        if offer.capsule_id != manifest.capsule_id {
            return Err(Error::protocol("offer capsule differs from manifest"));
        }
        if let Some(capsule_id) = manifest.capsule_id {
            if offer
                .genesis
                .as_ref()
                .is_some_and(|genesis| genesis.capsule_id != capsule_id)
                || offer
                    .genesis_grant
                    .as_ref()
                    .is_some_and(|grant| grant.capsule_id != capsule_id)
                || offer
                    .lease_chain
                    .iter()
                    .any(|lease| lease.capsule_id != capsule_id)
                || offer
                    .main_label
                    .as_ref()
                    .is_some_and(|op| op.capsule_id != capsule_id)
            {
                return Err(Error::protocol("offer capsule-state bundle mismatch"));
            }
        } else if offer.genesis.is_some()
            || offer.genesis_grant.is_some()
            || !offer.lease_chain.is_empty()
            || offer.main_label.is_some()
        {
            return Err(Error::protocol("partial offer carries capsule state"));
        }
        let origin = manifest.origin.peer_id;
        let sender = self
            .trust
            .get(&from)
            .ok_or_else(|| Error::authz("untrusted peer"))?
            .clone();
        if self.trust.get(&origin).is_none() {
            match (&offer.bind_certificate_issuer, &offer.bind_certificate) {
                (Some(issuer), Some(certificate))
                    if certificate.guest_peer_id == origin
                        && from == *issuer
                        && sender.role == crate::Role::Full =>
                {
                    self.trust
                        .install_bind_certificate(*issuer, certificate.clone(), now)
                        .map_err(|_| Error::authz("untrusted manifest origin"))?;
                }
                _ => return Err(Error::authz("untrusted manifest origin")),
            }
        }
        let origin_peer = self
            .trust
            .get(&origin)
            .ok_or_else(|| Error::authz("untrusted manifest origin"))?;
        if origin_peer.role == crate::Role::Guest
            && origin_peer
                .expires_at
                .as_deref()
                .map(crate::auth::parse_time)
                .transpose()?
                .is_none_or(|end| now > end)
        {
            return Err(Error::authz("manifest origin expired"));
        }
        if sender.role == crate::Role::Guest {
            if !matches!(self.trust.local_role(), LocalRole::Full)
                && self.trust.mesh_profile() == MeshProfile::Personal
            {
                return Err(Error::authz("guest-to-guest forbidden"));
            }
            let token_id = sender
                .token_id
                .as_deref()
                .ok_or_else(|| Error::authz("guest lacks token"))?;
            if self.trust.is_revoked(token_id)
                || sender
                    .expires_at
                    .as_deref()
                    .map(crate::auth::parse_time)
                    .transpose()?
                    .is_none_or(|end| now > end)
                || !sender
                    .scopes
                    .as_ref()
                    .is_some_and(|s| s.allows(manifest.capsule_id, &manifest.kind, Direction::Send))
            {
                return Err(Error::authz("guest sender out of scope"));
            }
        }
        if let LocalRole::Guest { token } = self.trust.local_role() {
            if self.trust.get(&from).is_none_or(|p| {
                p.role != crate::Role::Full && self.trust.mesh_profile() == MeshProfile::Personal
            }) {
                return Err(Error::authz(
                    "guest-to-guest or unknown counterparty forbidden",
                ));
            }
            token.verify(now)?;
            if !token
                .scopes
                .allows(manifest.capsule_id, &manifest.kind, Direction::Receive)
            {
                return Err(Error::authz("local guest receive out of scope"));
            }
            if self
                .trust
                .get(&from)
                .is_some_and(|p| p.role == crate::Role::Guest)
                && !sender.scopes.as_ref().is_some_and(|scopes| {
                    scopes.allows(manifest.capsule_id, &manifest.kind, Direction::Send)
                })
            {
                return Err(Error::authz("guest sender out of scope"));
            }
        }
        Ok(raw)
    }

    pub async fn send_offer(
        &mut self,
        id: &str,
        connection: &mut Connection,
        now: u64,
    ) -> Result<DeliveryOutcome> {
        if self.outbox.get(id).is_some_and(|entry| {
            crate::auth::parse_time(&entry.next_attempt_at).is_ok_and(|at| at > now)
        }) {
            return Err(Error::protocol("outbox backoff active"));
        }
        let result = self.send_offer_inner(id, connection, now, None).await;
        if let Err(error) = &result {
            let _ = self.outbox.fail_attempt(id, error.to_string(), now);
        }
        result
    }

    pub async fn send_offer_limited(
        &mut self,
        id: &str,
        connection: &mut Connection,
        now: u64,
        byte_limit: u64,
    ) -> Result<DeliveryOutcome> {
        self.send_offer_inner(id, connection, now, Some(byte_limit))
            .await
    }

    async fn send_offer_inner(
        &mut self,
        id: &str,
        connection: &mut Connection,
        now: u64,
        byte_limit: Option<u64>,
    ) -> Result<DeliveryOutcome> {
        let entry = self
            .outbox
            .get(id)
            .cloned()
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        if entry.peer_id != connection.peer_id() {
            return Err(Error::Authentication(
                "connected recipient differs from outbox".into(),
            ));
        }
        self.outbox.expire(now)?;
        if self
            .outbox
            .get(id)
            .is_some_and(|e| e.state == OutboxState::Expired)
        {
            return Err(Error::protocol("outbox entry expired"));
        }
        if crate::auth::parse_time(&entry.next_attempt_at)? > now {
            return Err(Error::protocol("outbox backoff active"));
        }
        self.outbox.transition(id, OutboxState::Healthcheck, now)?;
        let hello = dial_handshake_with_trust(
            connection,
            self.peer_id(),
            "abra".into(),
            &mut self.trust,
            now,
        )
        .await?;
        if hello.session != "trusted" {
            return Err(Error::authz("delivery requires trusted session"));
        }
        if self.trust.get(&entry.peer_id).is_none()
            || self.trust.is_revoked_guest(&entry.peer_id, now)
        {
            return Err(Error::authz("recipient trust was revoked"));
        }
        let ping = Ping {
            message_type: "ping".into(),
            nonce: hex::encode(rand::random::<[u8; 16]>()),
            ts: format_time(now),
        };
        {
            let (send, _) = connection.control_mut();
            write_frame(send, &ping).await?;
        }
        loop {
            let value = read_value(connection).await?;
            match value.get("type").and_then(|x| x.as_str()) {
                Some("pong") => {
                    let pong: Pong = serde_json::from_value(value)?;
                    if pong.nonce != ping.nonce {
                        return Err(Error::protocol("invalid pong"));
                    }
                    break;
                }
                Some("ack") => {
                    let ack: Ack = serde_json::from_value(value)?;
                    let pending = {
                        self.outbox
                            .entries()
                            .find(|e| e.offer_id == ack.offer_id)
                            .map(|e| e.id.clone())
                    };
                    if let Some(pending) = pending {
                        let _ = self.outbox.apply_ack(&pending, &ack, self.peer_id(), now)?;
                    }
                }
                _ => return Err(Error::protocol("unexpected health-check frame")),
            }
        }
        let raw = RawManifest::parse(entry.manifest_raw.clone())?;
        if let LocalRole::Guest { token } = self.trust.local_role() {
            if !self.allow_agent_send
                || !token.scopes.allows(
                    raw.manifest().capsule_id,
                    &raw.manifest().kind,
                    Direction::Send,
                )
            {
                return Err(Error::authz("local guest send out of scope"));
            }
        }
        let closure_set = closure(&self.store.cas, raw.manifest())?;
        let native: BTreeSet<Hash> = raw
            .manifest()
            .native
            .iter()
            .flatten()
            .map(|object| object.blob)
            .collect();
        let mut objects = Vec::with_capacity(closure_set.len());
        let mut bytes_hint = 0u64;
        for digest in &closure_set {
            let path = self.store.cas.path_for(digest);
            let size = fs::metadata(&path)?.len();
            let limit = if native.contains(digest) {
                MAX_NATIVE_OBJECT_SIZE
            } else {
                MAX_OBJECT_SIZE
            };
            if size > limit {
                return Err(Error::protocol("CAS object exceeds delivery limit"));
            }
            bytes_hint = bytes_hint
                .checked_add(size)
                .ok_or_else(|| Error::protocol("offer byte count overflow"))?;
            objects.push(PlanObject {
                digest: *digest,
                kind: if !native.contains(digest)
                    && Tree::decode(&self.store.cas.get(digest)?).is_ok()
                {
                    "tree"
                } else {
                    "blob"
                }
                .into(),
                bytes: size,
            });
        }
        let capsule = raw
            .manifest()
            .capsule_id
            .and_then(|c| self.store.capsules.get(&c));
        let fork = capsule.is_some_and(|capsule| {
            capsule
                .active_lease(now)
                .is_none_or(|lease| lease.holder != raw.manifest().origin.peer_id)
        });
        let (bind_certificate_issuer, bind_certificate) =
            if has_feature(&hello.features, FEATURE_BIND_CERT) {
                self.offer_bind_certificate(raw.manifest().origin.peer_id)
            } else {
                (None, None)
            };
        let offer = Offer {
            message_type: "offer".into(),
            offer_id: entry.offer_id.clone(),
            snapshot_id: entry.snapshot_id,
            scope: raw.manifest().scope,
            kind: raw.manifest().kind.clone(),
            title: raw.manifest().title.clone(),
            capsule_id: raw.manifest().capsule_id,
            fork,
            bytes_hint,
            object_count: objects.len() as u64,
            manifest_raw: data_encoding::BASE64URL_NOPAD.encode(raw.bytes()),
            genesis: capsule.map(|x| x.genesis.clone()),
            genesis_grant: capsule.and_then(|x| {
                x.leases()
                    .iter()
                    .find(|lease| lease.epoch == 1 && lease.mode == LeaseMode::Grant)
                    .cloned()
            }),
            lease_chain: capsule.map(winning_lease_chain).unwrap_or_default(),
            main_label: capsule.and_then(|x| x.label("main").cloned()),
            bind_certificate_issuer,
            bind_certificate,
            revocations: if has_feature(&hello.features, FEATURE_REVOCATION) {
                self.trust.current_revocations(now)
            } else {
                Vec::new()
            },
        };
        {
            let (send, _) = connection.control_mut();
            write_frame(send, &offer).await?;
        }
        let response = read_value(connection).await?;
        if response.get("type").and_then(|x| x.as_str()) != Some("offer-accept") {
            let reason = sanitize_rejection_reason(
                response
                    .get("reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("offer rejected"),
            );
            return Err(Error::authz(reason));
        }
        self.outbox.transition(id, OutboxState::Offered, now)?;
        let plan = Plan {
            message_type: "plan".into(),
            offer_id: entry.offer_id.clone(),
            seq: 0,
            eof: true,
            objects: objects.clone(),
        };
        {
            let (send, _) = connection.control_mut();
            write_frame(send, &plan).await?;
        }
        let have_value = read_value(connection).await?;
        if have_value.get("type").and_then(|value| value.as_str()) == Some("offer-reject") {
            let reason = have_value
                .get("reason")
                .and_then(|value| value.as_str())
                .unwrap_or("offer rejected");
            return Err(Error::authz(sanitize_rejection_reason(reason)));
        }
        let have: Have = serde_json::from_value(have_value)?;
        if have.skip_native {
            let skipped: BTreeSet<Hash> = have
                .have
                .iter()
                .copied()
                .filter(|digest| native.contains(digest))
                .collect();
            if skipped != native {
                return Err(Error::protocol("skip_native did not cover native objects"));
            }
        }
        self.outbox.transition(id, OutboxState::Transferring, now)?;
        let have_set: BTreeSet<Hash> = have.have.iter().copied().collect();
        let mut stats = TransferStats {
            objects_reused: have_set.len() as u64,
            ..Default::default()
        };
        let mut budget = byte_limit.unwrap_or(u64::MAX);
        for object in objects.iter().filter(|x| !have_set.contains(&x.digest)) {
            let offset = have.resume.get(&object.digest).copied().unwrap_or(0);
            if offset > object.bytes {
                return Err(Error::protocol("invalid resume offset"));
            }
            let kind = if object.kind == "tree" {
                ObjectKind::Tree
            } else {
                ObjectKind::Blob
            };
            let header = ObjectHeader {
                kind,
                digest: object.digest,
                total_size: object.bytes,
                offset,
            };
            if offset == 0 && object.bytes <= self.streaming_threshold && object.bytes <= budget {
                let bytes = self.store.cas.get(&object.digest)?;
                let mut stream = Vec::with_capacity(ObjectHeader::LEN + bytes.len());
                stream.extend_from_slice(&header.encode());
                stream.extend_from_slice(&bytes);
                connection.open_uni(stream).await?;
                stats.bytes_transferred += object.bytes;
                stats.objects_transferred += 1;
                budget -= object.bytes;
                continue;
            }
            let mut position = offset;
            let mut file = self.store.cas.open_object(&object.digest)?;
            let mut hasher = blake3::Hasher::new();
            let mut buffer = vec![0u8; OBJECT_STREAM_CHUNK as usize];
            let mut hashed = 0u64;
            while hashed < offset {
                let take = (offset - hashed).min(OBJECT_STREAM_CHUNK) as usize;
                file.read_exact(&mut buffer[..take])?;
                hasher.update(&buffer[..take]);
                hashed += take as u64;
            }
            stats.resumed_bytes += offset;
            while position < object.bytes {
                let take = (object.bytes - position)
                    .min(budget)
                    .min(OBJECT_STREAM_CHUNK);
                if take == 0 {
                    return Ok(DeliveryOutcome::Interrupted { stats });
                }
                file.read_exact(&mut buffer[..take as usize])?;
                hasher.update(&buffer[..take as usize]);
                let chunk_header = ObjectHeader {
                    offset: position,
                    ..header
                };
                let mut stream = Vec::with_capacity(ObjectHeader::LEN + take as usize);
                stream.extend_from_slice(&chunk_header.encode());
                stream.extend_from_slice(&buffer[..take as usize]);
                connection.open_uni(stream).await?;
                stats.bytes_transferred += take;
                budget -= take;
                position += take;
            }
            if Hash::from_bytes(*hasher.finalize().as_bytes()) != object.digest {
                return Err(Error::protocol("CAS object changed while streaming"));
            }
            stats.objects_transferred += 1;
        }
        self.outbox.transition(id, OutboxState::AwaitingAck, now)?;
        let ack: Ack = serde_json::from_value(read_value(connection).await?)?;
        if !self.outbox.apply_ack(id, &ack, self.peer_id(), now)? {
            return Err(Error::Authentication("ack mismatch".into()));
        }
        Ok(DeliveryOutcome::Complete { ack, stats })
    }

    pub async fn handle_connection(
        &mut self,
        connection: &mut Connection,
        _now: u64,
    ) -> Result<()> {
        let session_started = abra_core::now_ms();
        let hello = accept_handshake(connection, self.peer_id(), &mut self.trust).await?;
        let trusted = hello.session == "trusted";
        if trusted {
            for ack in self.pending_acks()? {
                let (send, _) = connection.control_mut();
                write_frame(send, &ack).await?;
            }
        }
        let mut pending: Option<(Offer, RawManifest)> = None;
        loop {
            let value = match read_value(connection).await {
                Ok(v) => v,
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            let now = abra_core::now_ms();
            self.trust.reload()?;
            if self.trust.is_revoked_guest(&connection.peer_id(), now)
                || (trusted && self.trust.get(&connection.peer_id()).is_none())
            {
                return Err(Error::authz("token revoked"));
            }
            if let Some(peer) = self.trust.get(&connection.peer_id()) {
                if peer.role == crate::Role::Guest {
                    let token = peer
                        .token_id
                        .as_deref()
                        .ok_or_else(|| Error::authz("guest lacks token"))?;
                    if self.trust.is_revoked(token) {
                        return Err(Error::authz("token revoked"));
                    }
                    let expires = peer
                        .expires_at
                        .as_deref()
                        .map(crate::auth::parse_time)
                        .transpose()?
                        .ok_or_else(|| Error::authz("guest lacks expiry"))?;
                    if now > expires {
                        return Err(Error::authz("token expired"));
                    }
                    if now.saturating_sub(session_started) > 24 * 60 * 60 * 1000 {
                        return Err(Error::authz("guest session lifetime exceeded"));
                    }
                }
            }
            let kind = value
                .get("type")
                .and_then(|x| x.as_str())
                .ok_or_else(|| Error::protocol("frame lacks type"))?;
            if !trusted && !bootstrap_allowed(kind) {
                let error = ProtocolError {
                    message_type: "error".into(),
                    code: "untrusted".into(),
                    message: "message forbidden on bootstrap session".into(),
                };
                let (send, _) = connection.control_mut();
                write_frame(send, &error).await?;
                return Err(Error::authz("bootstrap message forbidden"));
            }
            match kind {
                "ping" => {
                    let ping: Ping = serde_json::from_value(value)?;
                    let pong = Pong {
                        message_type: "pong".into(),
                        nonce: ping.nonce,
                        ts: format_time(now),
                    };
                    let (send, _) = connection.control_mut();
                    write_frame(send, &pong).await?;
                }
                "offer" => {
                    let offer: Offer = serde_json::from_value(value)?;
                    let reply =
                        match self.validate_incoming_offer(&offer, connection.peer_id(), now) {
                            Ok(raw) => {
                                pending = Some((offer.clone(), raw));
                                serde_json::to_value(OfferAccept {
                                    message_type: "offer-accept".into(),
                                    offer_id: offer.offer_id,
                                })?
                            }
                            Err(error) => serde_json::to_value(OfferReject {
                                message_type: "offer-reject".into(),
                                offer_id: offer.offer_id,
                                reason: rejection_reason(&error),
                            })?,
                        };
                    let (send, _) = connection.control_mut();
                    write_frame(send, &reply).await?;
                }
                "plan" => {
                    let plan: Plan = serde_json::from_value(value)?;
                    let (offer, raw) = pending
                        .take()
                        .ok_or_else(|| Error::protocol("plan without offer"))?;
                    if plan.offer_id != offer.offer_id
                        || !plan.eof
                        || plan.objects.len() as u64 != offer.object_count
                    {
                        return Err(Error::protocol("plan mismatch"));
                    }
                    let allowed: BTreeMap<Hash, &PlanObject> =
                        plan.objects.iter().map(|x| (x.digest, x)).collect();
                    let native: BTreeSet<Hash> = raw
                        .manifest()
                        .native
                        .iter()
                        .flatten()
                        .map(|object| object.blob)
                        .collect();
                    let declared_native_bytes = raw
                        .manifest()
                        .native
                        .iter()
                        .flatten()
                        .map(|object| (object.blob, object.bytes))
                        .collect::<BTreeMap<_, _>>();
                    if allowed.len() != plan.objects.len()
                        || plan.objects.iter().any(|x| {
                            x.bytes
                                > if native.contains(&x.digest) {
                                    MAX_NATIVE_OBJECT_SIZE
                                } else {
                                    MAX_OBJECT_SIZE
                                }
                                || !matches!(x.kind.as_str(), "blob" | "tree")
                                || (native.contains(&x.digest) && x.kind != "blob")
                                || declared_native_bytes
                                    .get(&x.digest)
                                    .is_some_and(|bytes| *bytes != x.bytes)
                        })
                    {
                        return Err(Error::protocol("invalid plan"));
                    }
                    let planned_bytes = plan.objects.iter().try_fold(0u64, |sum, object| {
                        sum.checked_add(object.bytes)
                            .ok_or_else(|| Error::protocol("plan byte count overflow"))
                    })?;
                    if planned_bytes != offer.bytes_hint {
                        return Err(Error::protocol("plan quota mismatch"));
                    }
                    let guest_sender = self
                        .trust
                        .get(&connection.peer_id())
                        .is_some_and(|p| p.role == crate::Role::Guest);
                    let effective_skip_native = self.skip_native
                        && !guest_sender
                        && has_feature(&hello.features, FEATURE_SKIP_NATIVE);
                    let skipped_native_bytes = if effective_skip_native {
                        plan.objects
                            .iter()
                            .filter(|object| native.contains(&object.digest))
                            .try_fold(0u64, |sum, object| sum.checked_add(object.bytes))
                            .ok_or_else(|| Error::protocol("native byte count overflow"))?
                    } else {
                        0
                    };
                    let required_bytes = planned_bytes.saturating_sub(skipped_native_bytes);
                    if exceeds_storage_quota(
                        required_bytes,
                        self.offer_budget,
                        fs2::available_space(self.store.cas.root()),
                    ) {
                        let reject = OfferReject {
                            message_type: "offer-reject".into(),
                            offer_id: offer.offer_id,
                            reason: "quota".into(),
                        };
                        let (send, _) = connection.control_mut();
                        write_frame(send, &reject).await?;
                        return Err(Error::authz("offer exceeds quota"));
                    }
                    let mut have =
                        self.compute_have(&offer.offer_id, &allowed.keys().copied().collect())?;
                    if guest_sender {
                        have.have.clear();
                        have.resume.clear();
                        have.skip_native = false;
                    } else if self.skip_native && has_feature(&hello.features, FEATURE_SKIP_NATIVE)
                    {
                        for digest in &native {
                            if !have.have.contains(digest) {
                                have.have.push(*digest);
                            }
                            have.resume.remove(digest);
                        }
                    }
                    {
                        let (send, _) = connection.control_mut();
                        write_frame(send, &have).await?;
                    }
                    let have_set: BTreeSet<Hash> = have.have.iter().copied().collect();
                    let staged = abra_core::cas::BlobStore::open(
                        self.partial_dir.join(&offer.offer_id).join("staged"),
                    )?;
                    let _staged_cleanup = DirectoryCleanup(staged.root().to_path_buf());
                    for digest in &have_set {
                        if effective_skip_native && native.contains(digest) {
                            continue;
                        }
                        let destination = staged.path_for(digest);
                        if let Some(parent) = destination.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::hard_link(self.store.cas.path_for(digest), destination)?;
                    }
                    let wanted_count = plan
                        .objects
                        .iter()
                        .filter(|x| !have_set.contains(&x.digest))
                        .count();
                    let mut hashers = BTreeMap::new();
                    for object in plan
                        .objects
                        .iter()
                        .filter(|x| !have_set.contains(&x.digest))
                    {
                        let mut hasher = blake3::Hasher::new();
                        let partial = self.partial_path(&offer.offer_id, object.digest);
                        if partial.is_file() {
                            let mut file = fs::File::open(partial)?;
                            let mut buffer = vec![0u8; OBJECT_STREAM_CHUNK as usize];
                            loop {
                                let read = file.read(&mut buffer)?;
                                if read == 0 {
                                    break;
                                }
                                hasher.update(&buffer[..read]);
                            }
                        }
                        hashers.insert(object.digest, hasher);
                    }
                    let mut completed = BTreeSet::new();
                    while completed.len() < wanted_count {
                        let stream = connection
                            .accept_uni_bounded(STREAMING_THRESHOLD as usize + ObjectHeader::LEN)
                            .await?;
                        if stream.len() < ObjectHeader::LEN {
                            return Err(Error::protocol("short object header"));
                        }
                        let header = ObjectHeader::decode(
                            stream[..ObjectHeader::LEN]
                                .try_into()
                                .expect("header length"),
                        )?;
                        let wanted = wanted_plan_object(&allowed, &have_set, &header.digest)?;
                        if completed.contains(&header.digest) {
                            return Err(Error::protocol("object stream for completed object"));
                        }
                        let expected_kind = if wanted.kind == "tree" {
                            ObjectKind::Tree
                        } else {
                            ObjectKind::Blob
                        };
                        if header.kind != expected_kind
                            || header.total_size != wanted.bytes
                            || header.offset
                                != self
                                    .partial_len(&offer.offer_id, header.digest)?
                                    .unwrap_or(0)
                        {
                            return Err(Error::protocol("object header mismatch"));
                        }
                        self.append_partial(
                            &offer.offer_id,
                            header.digest,
                            header.total_size,
                            header.offset,
                            &stream[ObjectHeader::LEN..],
                        )?;
                        update_object_hasher(
                            &mut hashers,
                            header.digest,
                            &stream[ObjectHeader::LEN..],
                        )?;
                        if header.offset + (stream.len() - ObjectHeader::LEN) as u64
                            == header.total_size
                        {
                            let actual = Hash::from_bytes(
                                *hashers
                                    .remove(&header.digest)
                                    .ok_or_else(|| {
                                        Error::protocol("object stream for completed object")
                                    })?
                                    .finalize()
                                    .as_bytes(),
                            );
                            if actual != header.digest {
                                let _ = fs::remove_file(
                                    self.partial_path(&offer.offer_id, header.digest),
                                );
                                return Err(Error::protocol("object hash mismatch"));
                            }
                            self.commit_verified_partial(&offer.offer_id, header.digest)?;
                            completed.insert(header.digest);
                        }
                    }
                    let mut portable_manifest = raw.manifest().clone();
                    portable_manifest.native = None;
                    let portable = closure(&staged, &portable_manifest)?;
                    let skippable = native
                        .difference(&portable)
                        .copied()
                        .collect::<BTreeSet<_>>();
                    let mut actual = closure(&staged, raw.manifest())?;
                    actual.retain(|digest| !effective_skip_native || !skippable.contains(digest));
                    let planned = allowed
                        .keys()
                        .copied()
                        .filter(|digest| !effective_skip_native || !skippable.contains(digest))
                        .collect::<BTreeSet<_>>();
                    if actual != planned {
                        return Err(Error::protocol(
                            "plan differs from verified manifest closure",
                        ));
                    }
                    if actual.iter().any(|digest| !staged.has(digest)) {
                        return Err(Error::protocol("staged object is missing"));
                    }
                    for digest in &actual {
                        self.store
                            .cas
                            .commit_file(staged.path_for(digest), digest)?;
                    }
                    if raw.manifest().scope == Scope::Full {
                        let capsule_id = raw.manifest().capsule_id.expect("validated");
                        if !self.store.capsules.contains_key(&capsule_id) {
                            let genesis = offer
                                .genesis
                                .clone()
                                .ok_or_else(|| Error::protocol("missing genesis"))?;
                            let grant = offer
                                .genesis_grant
                                .clone()
                                .ok_or_else(|| Error::protocol("missing genesis grant"))?;
                            if genesis.capsule_id != capsule_id {
                                return Err(Error::protocol("genesis capsule mismatch"));
                            }
                            self.store.add_capsule(genesis, grant)?;
                        }
                    }
                    if raw.manifest().scope == Scope::Partial
                        && self.store.inbox.len() >= MAX_INBOX_ENTRIES
                    {
                        return Err(Error::authz("inbox quota exceeded"));
                    }
                    let mut shelf = self.commit_manifest(raw, connection.peer_id(), now)?;
                    if shelf == "capsule" {
                        shelf = match self.adopt_offer_capsule_state(&offer, now) {
                            Ok(true) => {
                                if let Some(capsule_id) = offer.capsule_id {
                                    self.retry_pending_main_labels(capsule_id, now);
                                }
                                "capsule-head".into()
                            }
                            Ok(false) | Err(_) => {
                                if let (Some(capsule_id), Some(op)) =
                                    (offer.capsule_id, offer.main_label.clone())
                                {
                                    let pending =
                                        self.pending_main_labels.entry(capsule_id).or_default();
                                    if pending.len() < MAX_LEASE_CHAIN_LEN
                                        && !pending.iter().any(|old| old.sig == op.sig)
                                    {
                                        pending.push(op);
                                    }
                                }
                                if let Some(capsule_id) = offer.capsule_id {
                                    let signer = Identity::from_secret_bytes(
                                        &self.store.keys.identity.secret_bytes(),
                                    );
                                    self.store.record_fork_label(
                                        capsule_id,
                                        offer.snapshot_id,
                                        format_time(now),
                                        &signer,
                                        now,
                                    )?;
                                }
                                "capsule-fork".into()
                            }
                        };
                    }
                    let ack = Ack::sign(
                        offer.offer_id,
                        offer.snapshot_id,
                        shelf,
                        now,
                        connection.peer_id(),
                        &self.store.keys.identity,
                    )?;
                    self.persist_pending_ack(&ack)?;
                    let (send, _) = connection.control_mut();
                    write_frame(send, &ack).await?;
                    self.clear_pending_ack(&ack.offer_id)?;
                    let event = match offer.scope {
                        Scope::Full => {
                            serde_json::json!({"event":"capsule-sync","snapshot_id":ack.snapshot_id,"capsule_id":offer.capsule_id,"scope":"full","from":connection.peer_id(),"at":ack.received_at})
                        }
                        Scope::Partial => {
                            serde_json::json!({"event":"inbox-arrival","snapshot_id":ack.snapshot_id,"scope":"partial","from":connection.peer_id(),"at":ack.received_at})
                        }
                    };
                    self.record_event(&event)?;
                    self.clear_partials(&ack.offer_id)?;
                }
                "ack" => {
                    let ack: Ack = serde_json::from_value(value)?;
                    let id = {
                        self.outbox
                            .entries()
                            .find(|e| e.offer_id == ack.offer_id)
                            .map(|e| e.id.clone())
                    };
                    if let Some(id) = id {
                        let _ = self.outbox.apply_ack(&id, &ack, self.peer_id(), now)?;
                    }
                }
                "control" => {
                    let msg: crate::ControlMessage = serde_json::from_value(value)?;
                    let result = msg.verify_and_record(connection.peer_id(), &mut self.trust, now);
                    if result.is_ok() {
                        self.record_event(&serde_json::json!({"event":"control","from":connection.peer_id(),"message":msg}))?;
                    }
                    let reply = crate::ControlAck {
                        message_type: "control-ack".into(),
                        nonce: msg.nonce,
                        ok: result.is_ok(),
                        error: result.err().map(|e| e.to_string()),
                    };
                    let (send, _) = connection.control_mut();
                    write_frame(send, &reply).await?;
                }
                "pair-request" => {
                    let request: crate::PairRequest = serde_json::from_value(value)?;
                    if request.peer_id != connection.peer_id() {
                        return Err(Error::Authentication(
                            "pair request differs from transport".into(),
                        ));
                    }
                    fs::create_dir_all(&self.pending_pair_dir)?;
                    fs::create_dir_all(&self.approved_pair_dir)?;
                    let pending_count = fs::read_dir(&self.pending_pair_dir)?.count();
                    if pending_count >= MAX_PENDING_PAIRS {
                        return Err(Error::authz("too many pending pair requests"));
                    }
                    let pending_path = self.pending_pair_dir.join(request.peer_id.to_hex());
                    let approved_path = self.approved_pair_dir.join(request.peer_id.to_hex());
                    fs::write(&pending_path, abra_core::canonical::to_vec(&request)?)?;
                    let approved = if self.auto_confirm_pairs {
                        true
                    } else {
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(600);
                        loop {
                            if approved_path.exists() {
                                break true;
                            }
                            if tokio::time::Instant::now() >= deadline {
                                let error = ProtocolError {
                                    message_type: "error".into(),
                                    code: "untrusted".into(),
                                    message: "pairing confirmation timed out".into(),
                                };
                                let (send, _) = connection.control_mut();
                                write_frame(send, &error).await?;
                                break false;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    };
                    let accept = self.trust.accept_pair_request(
                        &request,
                        connection.peer_id(),
                        now,
                        self.auto_confirm_pairs,
                        |_, _| approved,
                    );
                    let _ = fs::remove_file(&pending_path);
                    let _ = fs::remove_file(&approved_path);
                    let accept = accept?;
                    let (send, _) = connection.control_mut();
                    write_frame(send, &accept).await?;
                }
                "pair-confirm" => {
                    let confirm = serde_json::from_value(value)?;
                    self.trust.confirm_pair(&confirm, connection.peer_id())?;
                }
                "enroll-bind" => {
                    let bind: crate::EnrollBind = serde_json::from_value(value)?;
                    let secret = self.store.keys.identity.secret_bytes();
                    let issuer = Identity::from_secret_bytes(&secret);
                    let certificate =
                        self.trust
                            .bind_enrollment(&bind, connection.peer_id(), now, &issuer)?;
                    let mesh = self
                        .trust
                        .peers()
                        .values()
                        .filter(|peer| {
                            peer.role == crate::Role::Full
                                || self.trust.mesh_profile() == crate::MeshProfile::Fleet
                        })
                        .map(|peer| crate::EnrollMeshPeer {
                            peer_id: peer.peer_id,
                            name: peer.name.clone(),
                            role: peer.role.clone(),
                            x25519_pk: peer.x25519_pk,
                            token_id: peer.token_id.clone(),
                            scopes: peer.scopes.clone(),
                            expires_at: peer.expires_at.clone(),
                        })
                        .collect();
                    let reply = crate::EnrollOk {
                        message_type: "enroll-ok".into(),
                        mesh,
                        certificate,
                        mesh_profile: self.trust.mesh_profile(),
                    };
                    let (send, _) = connection.control_mut();
                    write_frame(send, &reply).await?;
                }
                _ => {
                    let error = ProtocolError {
                        message_type: "error".into(),
                        code: "unknown_type".into(),
                        message: "unknown frame type".into(),
                    };
                    let (send, _) = connection.control_mut();
                    write_frame(send, &error).await?;
                }
            }
        }
    }

    fn adopt_offer_capsule_state(&mut self, offer: &Offer, now: u64) -> Result<bool> {
        let capsule_id = offer
            .capsule_id
            .ok_or_else(|| Error::protocol("full offer lacks capsule id"))?;
        let capsule = self
            .store
            .capsules
            .get(&capsule_id)
            .ok_or_else(|| Error::protocol("receiver lacks offered capsule"))?;
        let mut expected = capsule
            .winning_lease()
            .ok_or_else(|| Error::protocol("capsule lacks winning lease"))?
            .clone();
        let known = capsule
            .leases()
            .iter()
            .map(LeaseRecord::hash)
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        let mut applicable = Vec::new();
        for lease in &offer.lease_chain {
            let hash = lease.hash()?;
            if known.contains(&hash) {
                continue;
            }
            if lease.epoch != expected.epoch + 1 || lease.prev_hash != expected.hash()? {
                return Err(Error::protocol("lease chain is not contiguous with winner"));
            }
            expected = lease.clone();
            applicable.push(lease.clone());
        }
        Ok(self.store.adopt_capsule_state(
            capsule_id,
            &applicable,
            offer.main_label.as_ref(),
            &|holder, mode| {
                self.trust
                    .authorize_lease(holder, mode == LeaseMode::Takeover, now)
                    .is_ok()
            },
            now,
        )?)
    }

    fn retry_pending_main_labels(&mut self, capsule_id: Hash, now: u64) {
        let Some(pending) = self.pending_main_labels.remove(&capsule_id) else {
            return;
        };
        let mut still_pending = Vec::new();
        for op in pending {
            if self.store.apply_label(op.clone(), op.by, now).is_err() {
                still_pending.push(op);
            }
        }
        if !still_pending.is_empty() {
            self.pending_main_labels.insert(capsule_id, still_pending);
        }
    }
}

fn winning_lease_chain(capsule: &abra_core::capsule::Capsule) -> Vec<LeaseRecord> {
    let Some(mut current) = capsule.winning_lease() else {
        return Vec::new();
    };
    let mut reverse = Vec::new();
    while current.epoch > 1 {
        reverse.push(current.clone());
        let prev = current.prev_hash;
        let Some(parent) = capsule
            .leases()
            .iter()
            .find(|lease| lease.hash().ok() == Some(prev))
        else {
            return Vec::new();
        };
        current = parent;
    }
    reverse.reverse();
    if reverse.len() > MAX_LEASE_CHAIN_LEN {
        reverse.drain(..reverse.len() - MAX_LEASE_CHAIN_LEN);
    }
    reverse
}

async fn read_value(connection: &mut Connection) -> Result<serde_json::Value> {
    let (_, recv) = connection.control_mut();
    tokio::time::timeout(HEALTH_TIMEOUT, read_frame(recv))
        .await
        .map_err(|_| Error::Timeout)?
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

#[cfg(test)]
mod tests {
    use super::{
        add_relay_object_bytes, exceeds_storage_quota, sanitize_rejection_reason,
        update_object_hasher, wanted_plan_object, DeliveryNode, PlanObject, MAX_OBJECT_SIZE,
        MAX_REJECTION_REASON_CHARS, STREAMING_THRESHOLD,
    };
    use abra_core::cas::Hash;
    use std::fs;

    #[test]
    fn received_rejection_reason_is_printable_and_bounded() {
        let reason = format!("{}\u{1b}[31m\n", "x".repeat(1024 * 1024));
        let sanitized = sanitize_rejection_reason(&reason);
        assert_eq!(sanitized.chars().count(), MAX_REJECTION_REASON_CHARS);
        assert!(sanitized.chars().all(|character| !character.is_control()));
    }

    #[test]
    fn corrupt_stream_is_rejected_without_partial_or_staged_object() {
        let root = tempfile::tempdir().unwrap();
        let node = DeliveryNode::open(root.path()).unwrap();
        let expected = Hash::of(b"correct bytes");
        node.append_partial("corrupt", expected, 13, 0, b"corrupt bytes")
            .unwrap();
        assert!(node.commit_partial("corrupt", expected).is_err());
        assert!(!node.partial_path("corrupt", expected).exists());
        let staged =
            abra_core::cas::BlobStore::open(root.path().join("net/partials/corrupt/staged"))
                .unwrap();
        assert!(!staged.has(&expected));
        assert!(
            fs::read_dir(root.path().join("net/partials/corrupt/staged/tmp"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn resent_completed_object_is_a_protocol_error_not_a_panic() {
        let digest = Hash::of(b"done");
        let error = update_object_hasher(&mut std::collections::BTreeMap::new(), digest, b"again")
            .unwrap_err();
        assert!(error.to_string().contains("completed object"));
    }

    #[test]
    #[should_panic]
    fn test_streaming_threshold_cannot_exceed_receiver_limit() {
        let root = tempfile::tempdir().unwrap();
        let mut node = DeliveryNode::open(root.path()).unwrap();
        node.set_streaming_threshold_for_tests(STREAMING_THRESHOLD + 1);
    }

    #[test]
    fn relay_sender_rejects_pack_before_base64_allocation() {
        let error = add_relay_object_bytes(MAX_OBJECT_SIZE, 1).unwrap_err();
        assert!(error.to_string().contains("use direct delivery"));
    }

    #[test]
    fn free_space_probe_failure_rejects_offer() {
        let error = std::io::Error::other("space probe unavailable");
        assert!(exceeds_storage_quota(1, 1024, Err(error)));
        assert!(exceeds_storage_quota(2, 1024, Ok(1)));
        assert!(!exceeds_storage_quota(1, 1024, Ok(1)));
    }

    #[test]
    fn sender_cannot_stream_a_skipped_native_object() {
        let digest = Hash::of(b"native");
        let object = PlanObject {
            digest,
            kind: "blob".into(),
            bytes: 6,
        };
        let allowed = [(digest, &object)].into_iter().collect();
        let have = [digest].into_iter().collect();
        let error = wanted_plan_object(&allowed, &have, &digest).unwrap_err();
        assert!(error.to_string().contains("object not wanted"));
    }

    #[test]
    fn startup_sweeps_abandoned_offer_directories() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let stale = root.path().join("net/partials/stale/staged");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("blob"), b"stale").unwrap();
        // Opening a node for a control request must leave in-flight
        // partials alone; only the daemon's one-time sweep removes them.
        DeliveryNode::open(root.path()).unwrap();
        assert!(root.path().join("net/partials/stale").exists());
        DeliveryNode::sweep_abandoned_partials(root.path()).unwrap();
        assert!(!root.path().join("net/partials/stale").exists());
    }
}
