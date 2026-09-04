use crate::{
    auth::{
        accept_handshake, bootstrap_allowed, dial_handshake_with_trust, format_time, has_feature,
        BindCertificate, Direction, HelloOk, LocalRole, MeshProfile, Ping, Pong, ProtocolError,
        Revocation, TrustStore, FEATURE_BIND_CERT, FEATURE_CONTROL_RESULT, FEATURE_REVOCATION,
        FEATURE_SKIP_NATIVE, MAX_REVOCATIONS_PER_MESSAGE,
    },
    framing::{ObjectHeader, ObjectKind},
    write_frame, Connection, Error, Outbox, OutboxState, Result,
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
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_OBJECT_SIZE: u64 = 256 * 1024 * 1024;
pub const MAX_NATIVE_OBJECT_SIZE: u64 = 8 * 1024 * 1024 * 1024;
pub const DEFAULT_OFFER_BUDGET: u64 = 16 * 1024 * 1024 * 1024;
pub const OBJECT_STREAM_CHUNK: u64 = 1024 * 1024;
pub const STREAMING_THRESHOLD: u64 = 8 * 1024 * 1024;
/// Ceiling on a registered control handler, matching cadabra's adapter
/// timeout: a stuck adapter must not hold the session open forever.
pub const CONTROL_HANDLER_TIMEOUT: Duration = Duration::from_secs(660);
const MAX_INBOX_ENTRIES: usize = 10_000;
const MAX_PENDING_PAIRS: usize = 128;
const MAX_EVENT_LOG_BYTES: u64 = 8 * 1024 * 1024;

pub fn append_event(root: &Path, value: &serde_json::Value) -> Result<()> {
    if value
        .get("event")
        .and_then(serde_json::Value::as_str)
        .is_none()
        || value
            .get("at")
            .and_then(serde_json::Value::as_str)
            .is_none()
    {
        return Err(Error::protocol("event line requires event and at"));
    }
    let path = root.join("net/events.ndjson");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    fs2::FileExt::lock_exclusive(&file)?;
    if file.metadata()?.len() >= MAX_EVENT_LOG_BYTES {
        file.set_len(0)?;
    }
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_data()?;
    fs2::FileExt::unlock(&file)?;
    Ok(())
}
pub const MAX_LEASE_CHAIN_LEN: usize = 256;
const MAX_REJECTION_REASON_CHARS: usize = 256;

/// How an accepted offer reached this node. Only relay arrivals are tagged
/// in the event log.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Via {
    Direct,
    Relay,
}

impl Via {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// What `finalize_received_offer` leaves for its caller: the signed ack and the
/// arrival event, which is only recorded once the ack is safely on the wire.
struct ReceivedOffer {
    ack: Ack,
    event: serde_json::Value,
}

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

/// A plain clone keeps `persist` on for the cloned outbox, so two clones write
/// the same files; callers that want a detached outbox for network I/O must use
/// `outgoing_session()`.
#[derive(Clone)]
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
    /// Receiver-side hook for verified control messages. `None` keeps the
    /// record-and-ack behaviour; the daemon installs one to route control to
    /// an adapter verb.
    pub control_handler: Option<Arc<dyn crate::ControlHandler>>,
    control_timeout: Duration,
    streaming_threshold: u64,
    pending_main_labels: BTreeMap<Hash, Vec<LabelOp>>,
    pending_main_labels_path: PathBuf,
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
        let pending_main_labels_path = root.join("net/pending-labels.json");
        let pending_main_labels = match fs::read(&pending_main_labels_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            store: AbraStore::open(root)?,
            trust: TrustStore::open(root)?,
            outbox: Outbox::open(root)?,
            allow_agent_send: false,
            auto_confirm_pairs: false,
            offer_budget: DEFAULT_OFFER_BUDGET,
            skip_native: false,
            control_handler: None,
            control_timeout: CONTROL_HANDLER_TIMEOUT,
            streaming_threshold: STREAMING_THRESHOLD,
            pending_main_labels,
            pending_main_labels_path,
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
            outbox: self.outbox.detached(),
            ..self.clone()
        }
    }

    /// Override the sender cutoff in tests so small fixtures exercise chunking.
    #[doc(hidden)]
    pub fn set_streaming_threshold_for_tests(&mut self, bytes: u64) {
        debug_assert!(bytes <= STREAMING_THRESHOLD);
        self.streaming_threshold = bytes.min(STREAMING_THRESHOLD);
    }

    /// Shorten the control handler timeout in tests so a hung handler is
    /// observable without waiting ten minutes.
    #[doc(hidden)]
    pub fn set_control_timeout_for_tests(&mut self, timeout: Duration) {
        debug_assert!(timeout <= CONTROL_HANDLER_TIMEOUT);
        self.control_timeout = timeout.min(CONTROL_HANDLER_TIMEOUT);
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
        // Relay envelopes have no preceding feature handshake.
        let offer = self.build_offer(entry, &raw, bytes_hint, objects.len() as u64, now, None);
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
        let received = self.finalize_received_offer(raw, &offer, sender, now, Via::Relay)?;
        self.record_event(&received.event)?;
        self.clear_partials(&offer.offer_id)?;
        Ok((sender, received.ack))
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
        abra_core::atomic_write(
            &self.pending_ack_path(&ack.offer_id),
            &abra_core::canonical::to_vec(ack)?,
        )?;
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
        append_event(
            self.event_log
                .parent()
                .and_then(Path::parent)
                .expect("event log root"),
            value,
        )
    }
    fn pending_acks(&self) -> Result<Vec<Ack>> {
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

    /// The shared tail of an accepted offer, direct or relayed: create the
    /// capsule on first sight, enforce the inbox limit, commit the manifest,
    /// adopt the offered capsule state, then sign and durably record the ack.
    /// The caller records the returned event and clears the partials, so a
    /// direct receiver can put the ack on the wire first.
    fn finalize_received_offer(
        &mut self,
        raw: RawManifest,
        offer: &Offer,
        sender: PeerId,
        now: u64,
        via: Via,
    ) -> Result<ReceivedOffer> {
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
        } else if self.store.inbox.len() >= MAX_INBOX_ENTRIES {
            return Err(Error::authz("inbox quota exceeded"));
        }
        let mut shelf = self.commit_manifest(raw, sender, now)?;
        if shelf == "capsule" {
            shelf = match self.adopt_offer_capsule_state(offer, now) {
                Ok(true) => "capsule-head".into(),
                Ok(false) | Err(_) => {
                    if let (Some(capsule_id), Some(op)) =
                        (offer.capsule_id, offer.main_label.clone())
                    {
                        self.insert_pending_main_label(capsule_id, op)?;
                    }
                    if let Some(capsule_id) = offer.capsule_id {
                        let signer =
                            Identity::from_secret_bytes(&self.store.keys.identity.secret_bytes());
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
            if let Some(capsule_id) = offer.capsule_id {
                self.retry_pending_main_labels(capsule_id, now)?;
            }
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
        let event = arrival_event(offer, &ack, sender, via);
        Ok(ReceivedOffer { ack, event })
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
        let entry = self.check_outbox_entry(id, connection.peer_id(), now)?;
        self.outbox.transition(id, OutboxState::Healthcheck, now)?;
        let hello = self
            .establish_trusted_session(connection, entry.peer_id, now)
            .await?;
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
        let native = native_blobs(&raw);
        let (objects, bytes_hint) = self.build_plan(&raw, &native)?;
        let offer = self.build_offer(
            &entry,
            &raw,
            bytes_hint,
            objects.len() as u64,
            now,
            Some(&hello.features),
        );
        let have = self
            .negotiate_have(connection, id, &offer, &objects, &native, now)
            .await?;
        let (stats, complete) = self
            .stream_objects(connection, &objects, &have, byte_limit)
            .await?;
        if !complete {
            return Ok(DeliveryOutcome::Interrupted { stats });
        }
        self.outbox.transition(id, OutboxState::AwaitingAck, now)?;
        let ack = self.await_ack(connection, id, now).await?;
        Ok(DeliveryOutcome::Complete { ack, stats })
    }

    /// The entry must belong to the connected recipient, still be live, and be
    /// past its retry backoff.
    fn check_outbox_entry(
        &mut self,
        id: &str,
        recipient: PeerId,
        now: u64,
    ) -> Result<crate::OutboxEntry> {
        let entry = self
            .outbox
            .get(id)
            .cloned()
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        if entry.peer_id != recipient {
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
        Ok(entry)
    }

    /// Handshakes, re-checks the recipient's trust, and health-checks the
    /// route. Acks the peer replays while we wait are applied to the outbox.
    async fn establish_trusted_session(
        &mut self,
        connection: &mut Connection,
        recipient: PeerId,
        now: u64,
    ) -> Result<HelloOk> {
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
        if self.trust.get(&recipient).is_none() || self.trust.is_revoked_guest(&recipient, now) {
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
                    return Ok(hello);
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
    }

    /// Walks the manifest closure into the object list the receiver plans
    /// against, plus the byte total the offer advertises.
    fn build_plan(
        &self,
        raw: &RawManifest,
        native: &BTreeSet<Hash>,
    ) -> Result<(Vec<PlanObject>, u64)> {
        let closure_set = closure(&self.store.cas, raw.manifest())?;
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
                return Err(Error::protocol("stored object exceeds delivery limit"));
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
        Ok((objects, bytes_hint))
    }

    /// Builds the offer envelope. `features` is the negotiated feature list of
    /// a live session; a relay envelope has no handshake and passes `None`.
    fn build_offer(
        &self,
        entry: &crate::OutboxEntry,
        raw: &RawManifest,
        bytes_hint: u64,
        object_count: u64,
        now: u64,
        features: Option<&[String]>,
    ) -> Offer {
        let manifest = raw.manifest();
        let capsule = manifest
            .capsule_id
            .and_then(|id| self.store.capsules.get(&id));
        let negotiated = |feature| features.is_some_and(|list| has_feature(list, feature));
        let (bind_certificate_issuer, bind_certificate) = if negotiated(FEATURE_BIND_CERT) {
            self.offer_bind_certificate(manifest.origin.peer_id)
        } else {
            (None, None)
        };
        Offer {
            message_type: "offer".into(),
            offer_id: entry.offer_id.clone(),
            snapshot_id: entry.snapshot_id,
            scope: manifest.scope,
            kind: manifest.kind.clone(),
            title: manifest.title.clone(),
            capsule_id: manifest.capsule_id,
            fork: capsule.is_some_and(|capsule| {
                capsule
                    .active_lease(now)
                    .is_none_or(|lease| lease.holder != manifest.origin.peer_id)
            }),
            bytes_hint,
            object_count,
            manifest_raw: data_encoding::BASE64URL_NOPAD.encode(raw.bytes()),
            genesis: capsule.map(|capsule| capsule.genesis.clone()),
            genesis_grant: capsule.and_then(|capsule| {
                capsule
                    .leases()
                    .iter()
                    .find(|lease| lease.epoch == 1 && lease.mode == LeaseMode::Grant)
                    .cloned()
            }),
            lease_chain: capsule.map(winning_lease_chain).unwrap_or_default(),
            main_label: capsule.and_then(|capsule| capsule.label("main").cloned()),
            bind_certificate_issuer,
            bind_certificate,
            revocations: if negotiated(FEATURE_REVOCATION) {
                self.trust.current_revocations(now)
            } else {
                Vec::new()
            },
        }
    }

    /// Offers the snapshot, sends the plan, and reads back what the receiver
    /// already has or wants resumed.
    async fn negotiate_have(
        &mut self,
        connection: &mut Connection,
        id: &str,
        offer: &Offer,
        objects: &[PlanObject],
        native: &BTreeSet<Hash>,
        now: u64,
    ) -> Result<Have> {
        {
            let (send, _) = connection.control_mut();
            write_frame(send, offer).await?;
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
            offer_id: offer.offer_id.clone(),
            seq: 0,
            eof: true,
            objects: objects.to_vec(),
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
            if skipped != *native {
                return Err(Error::protocol("skip_native did not cover native objects"));
            }
        }
        self.outbox.transition(id, OutboxState::Transferring, now)?;
        Ok(have)
    }

    /// Streams every wanted object. The bool is false when a byte limit cut the
    /// transfer short, leaving the rest for the next attempt to resume.
    async fn stream_objects(
        &self,
        connection: &mut Connection,
        objects: &[PlanObject],
        have: &Have,
        byte_limit: Option<u64>,
    ) -> Result<(TransferStats, bool)> {
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
                    return Ok((stats, false));
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
                return Err(Error::protocol("stored object changed while streaming"));
            }
            stats.objects_transferred += 1;
        }
        Ok((stats, true))
    }

    async fn await_ack(&mut self, connection: &mut Connection, id: &str, now: u64) -> Result<Ack> {
        let ack: Ack = serde_json::from_value(read_value(connection).await?)?;
        if !self.outbox.apply_ack(id, &ack, self.peer_id(), now)? {
            return Err(Error::Authentication("ack mismatch".into()));
        }
        Ok(ack)
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
                "ping" => self.handle_ping(connection, value, now).await?,
                "offer" => {
                    self.handle_offer(connection, value, now, &mut pending)
                        .await?
                }
                "plan" => {
                    self.handle_plan(connection, value, now, &mut pending, &hello.features)
                        .await?
                }
                "ack" => self.handle_ack(value, now)?,
                "control" => {
                    self.handle_control(connection, value, now, &hello.features)
                        .await?
                }
                "pair-request" => self.handle_pair_request(connection, value, now).await?,
                "pair-confirm" => {
                    let confirm = serde_json::from_value(value)?;
                    self.trust.confirm_pair(&confirm, connection.peer_id())?;
                }
                "enroll-bind" => self.handle_enroll_bind(connection, value, now).await?,
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

    async fn handle_ping(
        &self,
        connection: &mut Connection,
        value: serde_json::Value,
        now: u64,
    ) -> Result<()> {
        let ping: Ping = serde_json::from_value(value)?;
        let pong = Pong {
            message_type: "pong".into(),
            nonce: ping.nonce,
            ts: format_time(now),
        };
        let (send, _) = connection.control_mut();
        write_frame(send, &pong).await?;
        Ok(())
    }

    async fn handle_offer(
        &mut self,
        connection: &mut Connection,
        value: serde_json::Value,
        now: u64,
        pending: &mut Option<(Offer, RawManifest)>,
    ) -> Result<()> {
        let offer: Offer = serde_json::from_value(value)?;
        let reply = match self.validate_incoming_offer(&offer, connection.peer_id(), now) {
            Ok(raw) => {
                *pending = Some((offer.clone(), raw));
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
        Ok(())
    }

    /// Validates the plan against the accepted offer, stages every wanted
    /// object, then commits the snapshot and acknowledges it.
    async fn handle_plan(
        &mut self,
        connection: &mut Connection,
        value: serde_json::Value,
        now: u64,
        pending: &mut Option<(Offer, RawManifest)>,
        features: &[String],
    ) -> Result<()> {
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
        let native = native_blobs(&raw);
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
        let effective_skip_native =
            self.skip_native && !guest_sender && has_feature(features, FEATURE_SKIP_NATIVE);
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
        let mut have = self.compute_have(&offer.offer_id, &allowed.keys().copied().collect())?;
        if guest_sender {
            have.have.clear();
            have.resume.clear();
            have.skip_native = false;
        } else if self.skip_native && has_feature(features, FEATURE_SKIP_NATIVE) {
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
        let staged =
            abra_core::cas::BlobStore::open(self.partial_dir.join(&offer.offer_id).join("staged"))?;
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
            update_object_hasher(&mut hashers, header.digest, &stream[ObjectHeader::LEN..])?;
            if header.offset + (stream.len() - ObjectHeader::LEN) as u64 == header.total_size {
                let actual = Hash::from_bytes(
                    *hashers
                        .remove(&header.digest)
                        .ok_or_else(|| Error::protocol("object stream for completed object"))?
                        .finalize()
                        .as_bytes(),
                );
                if actual != header.digest {
                    let _ = fs::remove_file(self.partial_path(&offer.offer_id, header.digest));
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
        let received =
            self.finalize_received_offer(raw, &offer, connection.peer_id(), now, Via::Direct)?;
        let (send, _) = connection.control_mut();
        write_frame(send, &received.ack).await?;
        self.clear_pending_ack(&received.ack.offer_id)?;
        self.record_event(&received.event)?;
        self.clear_partials(&offer.offer_id)?;
        Ok(())
    }

    fn handle_ack(&mut self, value: serde_json::Value, now: u64) -> Result<()> {
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
        Ok(())
    }

    async fn handle_control(
        &mut self,
        connection: &mut Connection,
        value: serde_json::Value,
        now: u64,
        features: &[String],
    ) -> Result<()> {
        let msg: crate::ControlMessage = serde_json::from_value(value)?;
        let verified = msg.verify_and_record(connection.peer_id(), &mut self.trust, now);
        let mut ok = verified.is_ok();
        let mut error = verified.err().map(|e| e.to_string());
        let mut handler_result = None;
        if ok {
            self.record_event(
                &serde_json::json!({"event":"control","at":format_time(now),"from":connection.peer_id(),"message":msg}),
            )?;
            if let Some(handler) = self.control_handler.clone() {
                // The message stays recorded as received whatever the handler
                // does; only the acknowledgement reports its failure.
                match tokio::time::timeout(
                    self.control_timeout,
                    handler.handle(connection.peer_id(), &msg),
                )
                .await
                {
                    Ok(Ok(value)) => handler_result = Some(value),
                    Ok(Err(e)) => {
                        ok = false;
                        // The handler's error goes to the remote peer, so it
                        // gets the same scrubbing as a rejected offer: local
                        // paths never leave this node.
                        error = Some(rejection_reason(&e));
                    }
                    Err(_) => {
                        ok = false;
                        error = Some("control handler timed out".into());
                    }
                }
            }
        }
        let reply = crate::ControlAck {
            message_type: "control-ack".into(),
            nonce: msg.nonce,
            ok,
            error,
            // A dialer that never advertised the feature would reject an ack
            // carrying `result`, so the handler runs and its value is dropped.
            result: handler_result.filter(|_| has_feature(features, FEATURE_CONTROL_RESULT)),
        };
        let (send, _) = connection.control_mut();
        write_frame(send, &reply).await?;
        Ok(())
    }

    async fn handle_pair_request(
        &mut self,
        connection: &mut Connection,
        value: serde_json::Value,
        now: u64,
    ) -> Result<()> {
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
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
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
        Ok(())
    }

    async fn handle_enroll_bind(
        &mut self,
        connection: &mut Connection,
        value: serde_json::Value,
        now: u64,
    ) -> Result<()> {
        let bind: crate::EnrollBind = serde_json::from_value(value)?;
        let secret = self.store.keys.identity.secret_bytes();
        let issuer = Identity::from_secret_bytes(&secret);
        let certificate = self
            .trust
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
        Ok(())
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

    fn pending_main_labels_lock(&self) -> Result<fs::File> {
        if let Some(parent) = self.pending_main_labels_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut lock_name: OsString = self.pending_main_labels_path.as_os_str().to_owned();
        lock_name.push(".lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(PathBuf::from(lock_name))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        Ok(lock)
    }

    fn read_pending_main_labels(&self) -> Result<BTreeMap<Hash, Vec<LabelOp>>> {
        match fs::read(&self.pending_main_labels_path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(error.into()),
        }
    }

    fn save_pending_main_labels(&self, pending: &BTreeMap<Hash, Vec<LabelOp>>) -> Result<()> {
        abra_core::atomic_write(
            &self.pending_main_labels_path,
            &abra_core::canonical::to_vec(pending)?,
        )?;
        Ok(())
    }

    fn insert_pending_main_label(&mut self, capsule_id: Hash, op: LabelOp) -> Result<()> {
        let lock = self.pending_main_labels_lock()?;
        let mut pending_labels = self.read_pending_main_labels()?;
        let pending = pending_labels.entry(capsule_id).or_default();
        if pending.len() < MAX_LEASE_CHAIN_LEN && !pending.iter().any(|old| old.sig == op.sig) {
            pending.push(op);
        }
        self.save_pending_main_labels(&pending_labels)?;
        fs2::FileExt::unlock(&lock)?;
        self.pending_main_labels = pending_labels;
        Ok(())
    }

    fn retry_pending_main_labels(&mut self, capsule_id: Hash, now: u64) -> Result<()> {
        let lock = self.pending_main_labels_lock()?;
        let mut pending_labels = self.read_pending_main_labels()?;
        let Some(pending) = pending_labels.remove(&capsule_id) else {
            fs2::FileExt::unlock(&lock)?;
            self.pending_main_labels = pending_labels;
            return Ok(());
        };
        let mut still_pending = Vec::new();
        for op in pending {
            if self.store.apply_label(op.clone(), op.by, now).is_err() {
                still_pending.push(op);
            }
        }
        if !still_pending.is_empty() {
            pending_labels.insert(capsule_id, still_pending);
        }
        self.save_pending_main_labels(&pending_labels)?;
        fs2::FileExt::unlock(&lock)?;
        self.pending_main_labels = pending_labels;
        Ok(())
    }
}

fn native_blobs(raw: &RawManifest) -> BTreeSet<Hash> {
    raw.manifest()
        .native
        .iter()
        .flatten()
        .map(|object| object.blob)
        .collect()
}

/// Relay arrivals are tagged with `via`; direct arrivals carry the capsule and
/// scope fields the daemon's event feed already reads.
fn arrival_event(offer: &Offer, ack: &Ack, from: PeerId, via: Via) -> serde_json::Value {
    let event = if offer.scope == Scope::Full {
        "capsule-sync"
    } else {
        "inbox-arrival"
    };
    if via == Via::Relay {
        serde_json::json!({"event":event,"snapshot_id":ack.snapshot_id,"from":from,"at":ack.received_at,"via":via.as_str()})
    } else if offer.scope == Scope::Full {
        serde_json::json!({"event":event,"snapshot_id":ack.snapshot_id,"capsule_id":offer.capsule_id,"scope":"full","from":from,"at":ack.received_at})
    } else {
        serde_json::json!({"event":event,"snapshot_id":ack.snapshot_id,"scope":"partial","from":from,"at":ack.received_at})
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
    crate::framing::read_frame_timeout(recv, HEALTH_TIMEOUT).await
}

#[cfg(test)]
mod tests {
    use super::{
        add_relay_object_bytes, append_event, exceeds_storage_quota, sanitize_rejection_reason,
        update_object_hasher, wanted_plan_object, DeliveryNode, PlanObject, MAX_EVENT_LOG_BYTES,
        MAX_OBJECT_SIZE, MAX_REJECTION_REASON_CHARS, STREAMING_THRESHOLD,
    };
    use abra_core::cas::Hash;
    use std::fs;

    #[test]
    fn concurrent_event_appends_keep_every_fresh_line() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("net")).unwrap();
        fs::write(
            root.path().join("net/events.ndjson"),
            vec![b'x'; MAX_EVENT_LOG_BYTES as usize],
        )
        .unwrap();
        let root_a = root.path().to_path_buf();
        let root_b = root.path().to_path_buf();
        let first = std::thread::spawn(move || {
            append_event(&root_a, &serde_json::json!({"event":"first","at":"now"})).unwrap();
        });
        let second = std::thread::spawn(move || {
            append_event(&root_b, &serde_json::json!({"event":"second","at":"now"})).unwrap();
        });
        first.join().unwrap();
        second.join().unwrap();
        let text = fs::read_to_string(root.path().join("net/events.ndjson")).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines
            .iter()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()));
    }

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
