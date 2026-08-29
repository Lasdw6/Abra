use crate::{
    auth::{
        accept_handshake, bootstrap_allowed, dial_handshake, format_time, Direction, LocalRole,
        Ping, Pong, ProtocolError, TrustStore,
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
    path::{Path, PathBuf},
};

pub const HEALTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const MAX_OBJECT_STREAMS: usize = 8;
pub const MAX_OBJECT_SIZE: u64 = 256 * 1024 * 1024;
const MAX_INBOX_ENTRIES: usize = 10_000;
const MAX_PENDING_PAIRS: usize = 128;
const MAX_EVENT_LOG_BYTES: u64 = 8 * 1024 * 1024;

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
    /// Daemon policy for non-interactive pairing. Interactive daemons leave
    /// this false and approve requests before retrying; test/automation
    /// daemons opt in explicitly.
    pub auto_confirm_pairs: bool,
    /// Pair requests observed by an interactive daemon and approvals granted
    /// through its local control API. They are intentionally process-local;
    /// tickets remain the durable, bounded authorization.
    pub pending_pair_requests: BTreeMap<PeerId, crate::PairRequest>,
    pub approved_pair_requests: BTreeSet<PeerId>,
    partial_dir: PathBuf,
    pending_ack_dir: PathBuf,
    pending_pair_dir: PathBuf,
    approved_pair_dir: PathBuf,
    event_log: PathBuf,
}
impl DeliveryNode {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        Ok(Self {
            store: AbraStore::open(root)?,
            trust: TrustStore::open(root)?,
            outbox: Outbox::open(root)?,
            allow_agent_send: false,
            auto_confirm_pairs: false,
            pending_pair_requests: BTreeMap::new(),
            approved_pair_requests: BTreeSet::new(),
            partial_dir: root.join("net/partials"),
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
            pending_pair_requests: self.pending_pair_requests.clone(),
            approved_pair_requests: self.approved_pair_requests.clone(),
            partial_dir: self.partial_dir.clone(),
            pending_ack_dir: self.pending_ack_dir.clone(),
            pending_pair_dir: self.pending_pair_dir.clone(),
            approved_pair_dir: self.approved_pair_dir.clone(),
            event_log: self.event_log.clone(),
        }
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
        if self.trust.get(&peer).is_none() {
            return Err(Error::authz("unknown or untrusted recipient"));
        }
        if let LocalRole::Guest { token } = self.trust.local_role() {
            if !self.allow_agent_send || !token.scopes.send || token.verify(now).is_err() {
                return Err(Error::authz("local agent sending disabled"));
            }
        }
        self.outbox
            .enqueue(peer, raw.snapshot_id(), raw.bytes().to_vec(), now)
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
        if offset.saturating_add(bytes.len() as u64) > total || total > MAX_OBJECT_SIZE {
            return Err(Error::protocol("partial exceeds total size"));
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
        let staged = abra_core::cas::BlobStore::open(self.partial_dir.join(offer).join("staged"))?;
        staged.put(&b)?;
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
        &self,
        offer: &Offer,
        from: PeerId,
        now: u64,
    ) -> Result<RawManifest> {
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(offer.manifest_raw.as_bytes())
            .map_err(|_| Error::protocol("bad manifest base64"))?;
        let raw = RawManifest::parse(bytes)?;
        if raw.snapshot_id() != offer.snapshot_id {
            return Err(Error::protocol("offer snapshot id mismatch"));
        }
        let manifest = raw.manifest();
        let origin = manifest.origin.peer_id;
        if self.trust.get(&origin).is_none() {
            return Err(Error::authz("untrusted manifest origin"));
        }
        let sender = self
            .trust
            .get(&from)
            .ok_or_else(|| Error::authz("untrusted peer"))?;
        if sender.role == crate::Role::Guest {
            if !matches!(self.trust.local_role(), LocalRole::Full) {
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
            if self
                .trust
                .get(&from)
                .is_none_or(|p| p.role != crate::Role::Full)
            {
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
        let hello = dial_handshake(connection, self.peer_id(), "abra".into()).await?;
        if hello.session != "trusted" {
            return Err(Error::authz("delivery requires trusted session"));
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
        let mut objects = Vec::with_capacity(closure_set.len());
        let mut bytes_hint = 0u64;
        for digest in &closure_set {
            let bytes = self.store.cas.get(digest)?;
            let size =
                u64::try_from(bytes.len()).map_err(|_| Error::protocol("object too large"))?;
            bytes_hint = bytes_hint.saturating_add(size);
            objects.push(PlanObject {
                digest: *digest,
                kind: if Tree::decode(&bytes).is_ok() {
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
        let offer = Offer {
            message_type: "offer".into(),
            offer_id: entry.offer_id.clone(),
            snapshot_id: entry.snapshot_id,
            scope: raw.manifest().scope,
            kind: raw.manifest().kind.clone(),
            title: raw.manifest().title.clone(),
            capsule_id: raw.manifest().capsule_id,
            fork: false,
            bytes_hint,
            object_count: objects.len() as u64,
            manifest_raw: data_encoding::BASE64URL_NOPAD.encode(raw.bytes()),
            genesis: capsule.map(|x| x.genesis.clone()),
            genesis_grant: capsule.and_then(|x| x.leases().first().cloned()),
            lease_chain: capsule.map(winning_lease_chain).unwrap_or_default(),
            main_label: capsule.and_then(|x| x.label("main").cloned()),
        };
        {
            let (send, _) = connection.control_mut();
            write_frame(send, &offer).await?;
        }
        let response = read_value(connection).await?;
        if response.get("type").and_then(|x| x.as_str()) != Some("offer-accept") {
            return Err(Error::authz(
                response
                    .get("reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("offer rejected"),
            ));
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
        let have: Have = serde_json::from_value(read_value(connection).await?)?;
        self.outbox.transition(id, OutboxState::Transferring, now)?;
        let have_set: BTreeSet<Hash> = have.have.iter().copied().collect();
        let mut stats = TransferStats {
            objects_reused: have_set.len() as u64,
            ..Default::default()
        };
        let mut budget = byte_limit.unwrap_or(u64::MAX);
        for object in objects.iter().filter(|x| !have_set.contains(&x.digest)) {
            let bytes = self.store.cas.get(&object.digest)?;
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
            let remaining = object.bytes - offset;
            let take = remaining.min(budget);
            let mut stream = Vec::with_capacity(ObjectHeader::LEN + take as usize);
            stream.extend_from_slice(&header.encode());
            stream.extend_from_slice(&bytes[offset as usize..(offset + take) as usize]);
            connection.open_uni(stream).await?;
            stats.resumed_bytes += offset;
            stats.bytes_transferred += take;
            budget -= take;
            if take < remaining {
                return Ok(DeliveryOutcome::Interrupted { stats });
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
        let hello = accept_handshake(connection, self.peer_id(), &self.trust).await?;
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
                            Ok(raw) if offer.bytes_hint <= MAX_OBJECT_SIZE => {
                                pending = Some((offer.clone(), raw));
                                serde_json::to_value(OfferAccept {
                                    message_type: "offer-accept".into(),
                                    offer_id: offer.offer_id,
                                })?
                            }
                            Ok(_) => serde_json::to_value(OfferReject {
                                message_type: "offer-reject".into(),
                                offer_id: offer.offer_id,
                                reason: "quota".into(),
                            })?,
                            Err(_) => serde_json::to_value(OfferReject {
                                message_type: "offer-reject".into(),
                                offer_id: offer.offer_id,
                                reason: "invalid".into(),
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
                    if allowed.len() != plan.objects.len()
                        || plan.objects.iter().any(|x| {
                            x.bytes > MAX_OBJECT_SIZE || !matches!(x.kind.as_str(), "blob" | "tree")
                        })
                    {
                        return Err(Error::protocol("invalid plan"));
                    }
                    let planned_bytes = plan.objects.iter().try_fold(0u64, |sum, object| {
                        sum.checked_add(object.bytes)
                            .ok_or_else(|| Error::protocol("plan byte count overflow"))
                    })?;
                    if planned_bytes != offer.bytes_hint || planned_bytes > MAX_OBJECT_SIZE {
                        return Err(Error::protocol("plan quota mismatch"));
                    }
                    let mut have =
                        self.compute_have(&offer.offer_id, &allowed.keys().copied().collect())?;
                    if self
                        .trust
                        .get(&connection.peer_id())
                        .is_some_and(|p| p.role == crate::Role::Guest)
                    {
                        have.have.clear();
                        have.resume.clear();
                    }
                    {
                        let (send, _) = connection.control_mut();
                        write_frame(send, &have).await?;
                    }
                    let have_set: BTreeSet<Hash> = have.have.iter().copied().collect();
                    let staged = abra_core::cas::BlobStore::open(
                        self.partial_dir.join(&offer.offer_id).join("staged"),
                    )?;
                    for digest in &have_set {
                        staged.put(&self.store.cas.get(digest)?)?;
                    }
                    for _ in 0..plan
                        .objects
                        .iter()
                        .filter(|x| !have_set.contains(&x.digest))
                        .count()
                    {
                        let stream = connection
                            .accept_uni_bounded(MAX_OBJECT_SIZE as usize + ObjectHeader::LEN)
                            .await?;
                        if stream.len() < ObjectHeader::LEN {
                            return Err(Error::protocol("short object header"));
                        }
                        let header = ObjectHeader::decode(
                            stream[..ObjectHeader::LEN]
                                .try_into()
                                .expect("header length"),
                        )?;
                        let wanted = allowed
                            .get(&header.digest)
                            .ok_or_else(|| Error::protocol("object not wanted"))?;
                        let expected_kind = if wanted.kind == "tree" {
                            ObjectKind::Tree
                        } else {
                            ObjectKind::Blob
                        };
                        if header.kind != expected_kind
                            || header.total_size != wanted.bytes
                            || header.offset
                                != have.resume.get(&header.digest).copied().unwrap_or(0)
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
                        if header.offset + (stream.len() - ObjectHeader::LEN) as u64
                            == header.total_size
                        {
                            self.commit_partial(&offer.offer_id, header.digest)?;
                        }
                    }
                    let actual = closure(&staged, raw.manifest())?;
                    let planned = allowed.keys().copied().collect::<BTreeSet<_>>();
                    if actual != planned {
                        return Err(Error::protocol(
                            "plan differs from verified manifest closure",
                        ));
                    }
                    for digest in &actual {
                        self.store.cas.put(&staged.get(digest)?)?;
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
                    let shelf = self.commit_manifest(raw, connection.peer_id(), now)?;
                    if shelf == "capsule" {
                        let _ = self.adopt_offer_capsule_state(&offer, now);
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
                    self.record_event(&serde_json::json!({"event":"inbox-arrival","snapshot_id":ack.snapshot_id,"from":connection.peer_id(),"at":ack.received_at}))?;
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
                        .filter(|peer| peer.role == crate::Role::Full)
                        .map(|peer| crate::EnrollMeshPeer {
                            peer_id: peer.peer_id,
                            name: peer.name.clone(),
                            role: peer.role.clone(),
                        })
                        .collect();
                    let reply = crate::EnrollOk {
                        message_type: "enroll-ok".into(),
                        mesh,
                        certificate,
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

    fn adopt_offer_capsule_state(&mut self, offer: &Offer, now: u64) -> Result<()> {
        let capsule_id = offer
            .capsule_id
            .ok_or_else(|| Error::protocol("full offer lacks capsule id"))?;
        for lease in &offer.lease_chain {
            let already_known = self.store.capsules[&capsule_id]
                .leases()
                .iter()
                .any(|known| known.hash().ok() == lease.hash().ok());
            if already_known {
                continue;
            }
            self.store
                .accept_lease(capsule_id, lease.clone(), &|holder, mode| {
                    self.trust
                        .authorize_lease(holder, mode == LeaseMode::Takeover, now)
                        .is_ok()
                })?;
        }
        if let Some(op) = &offer.main_label {
            self.store.apply_label(op.clone(), op.by, now)?;
        }
        Ok(())
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
