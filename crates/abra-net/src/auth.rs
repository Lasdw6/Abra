use crate::{Error, Result, WIRE_VERSION};
use abra_core::{
    canonical,
    cas::Hash,
    identity::{Identity, PeerId, Signature},
};
use data_encoding::BASE64URL_NOPAD;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(
        value: &[u8; 32],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<[u8; 32], D::Error> {
        let value = String::deserialize(d)?;
        let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hex"))
    }
}
mod optional_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match value {
            Some(v) => s.serialize_some(&hex::encode(v)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Option<[u8; 32]>, D::Error> {
        let value = Option::<String>::deserialize(d)?;
        value
            .map(|x| {
                hex::decode(x)
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32-byte hex"))
            })
            .transpose()
    }
}

pub const CLOCK_SKEW_MS: u64 = 60_000;

fn random16() -> String {
    let mut b = [0; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
fn unsigned<T: Serialize>(x: &T, field: &str) -> Result<Vec<u8>> {
    let mut v = serde_json::to_value(x)?;
    v.as_object_mut()
        .ok_or_else(|| Error::protocol("signed record is not object"))?
        .remove(field);
    Ok(canonical::to_vec(&v)?)
}
pub fn parse_time(s: &str) -> Result<u64> {
    let b = s.as_bytes();
    if b.len() != 24
        || !b.is_ascii()
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
    {
        return Err(Error::protocol("noncanonical time"));
    }
    let n = |a: usize, z: usize| -> Result<i64> {
        b[a..z].iter().try_fold(0_i64, |v, c| {
            c.is_ascii_digit()
                .then(|| v * 10 + i64::from(c - b'0'))
                .ok_or_else(|| Error::protocol("bad time"))
        })
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
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let max_day = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if d < 1 || d > max_day || hh > 23 || mm > 59 || ss > 59 {
        return Err(Error::protocol("bad time"));
    }
    let y0 = y - i64::from(m <= 2);
    let era = if y0 >= 0 { y0 } else { y0 - 399 } / 400;
    let yoe = y0 - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let total = (days * 86400 + hh * 3600 + mm * 60 + ss) * 1000 + ms;
    u64::try_from(total).map_err(|_| Error::protocol("time before epoch"))
}
pub fn format_time(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let rem = ms % 86_400_000;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += i64::from(m <= 2);
    let sec = rem / 1000;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        sec / 3600,
        (sec / 60) % 60,
        sec % 60,
        rem % 1000
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Full,
    Guest,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeshProfile {
    #[default]
    Personal,
    Fleet,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase", deny_unknown_fields)]
pub enum LocalRole {
    #[default]
    Full,
    Guest {
        token: Box<EnrollmentToken>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scopes {
    pub capsules: Vec<String>,
    pub kinds: Vec<String>,
    pub send: bool,
    pub receive: bool,
    pub lease_acquire: bool,
    pub lease_takeover: bool,
}
impl Scopes {
    fn list_allows(list: &[String], value: &str) -> bool {
        list.iter().any(|x| x == "*" || x == value)
    }
    fn validate(&self) -> Result<()> {
        for list in [&self.capsules, &self.kinds] {
            if list.is_empty() || (list.iter().any(|x| x == "*") && list.len() != 1) {
                return Err(Error::protocol("invalid wildcard scope"));
            }
        }
        Ok(())
    }
    pub fn allows(&self, capsule: Option<Hash>, kind: &str, direction: Direction) -> bool {
        Self::list_allows(&self.kinds, kind)
            && capsule.map_or_else(
                || self.capsules.len() == 1 && self.capsules[0] == "*",
                |c| Self::list_allows(&self.capsules, &c.to_hex()),
            )
            && match direction {
                Direction::Send => self.send,
                Direction::Receive => self.receive,
            }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Direction {
    Send,
    Receive,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPeer {
    pub peer_id: PeerId,
    pub name: String,
    pub role: Role,
    pub x25519_pk: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_key: Option<[u8; 32]>,
    pub token_id: Option<String>,
    pub scopes: Option<Scopes>,
    pub expires_at: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct TrustDisk {
    #[serde(default)]
    mesh_profile: MeshProfile,
    #[serde(default)]
    local_role: LocalRole,
    peers: BTreeMap<PeerId, TrustedPeer>,
    pending_tickets: BTreeMap<String, PairTicket>,
    awaiting_pair_confirm: BTreeMap<String, TrustedPeer>,
    used_tickets: BTreeSet<String>,
    bound_tokens: BTreeMap<String, PeerId>,
    revoked: BTreeSet<String>,
    control_nonces: BTreeMap<String, u64>,
}
#[derive(Clone)]
pub struct TrustStore {
    path: PathBuf,
    disk: TrustDisk,
}
impl TrustStore {
    pub fn mesh_profile(&self) -> MeshProfile {
        self.disk.mesh_profile
    }

    pub fn set_mesh_profile(&mut self, profile: MeshProfile) -> Result<()> {
        self.disk.mesh_profile = profile;
        self.save()
    }

    fn operation_lock(&self, name: &str) -> Result<fs::File> {
        let path = self.path.with_extension(format!("{name}.lock"));
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        fs2::FileExt::lock_exclusive(&lock)?;
        Ok(lock)
    }
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let path = root.as_ref().join("net/trust.json");
        let disk = match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => TrustDisk::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, disk })
    }
    fn read_disk(&self) -> Result<TrustDisk> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(TrustDisk::default()),
            Err(error) => Err(error.into()),
        }
    }
    pub fn reload(&mut self) -> Result<()> {
        self.disk = self.read_disk()?;
        Ok(())
    }
    fn save(&self) -> Result<()> {
        if let Some(p) = self.path.parent() {
            fs::create_dir_all(p)?
        }
        let lock_path = self.path.with_extension("lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let mut merged = self.read_disk()?;
        merged.mesh_profile = self.disk.mesh_profile;
        merged.local_role = self.disk.local_role.clone();
        merged
            .pending_tickets
            .extend(self.disk.pending_tickets.clone());
        merged
            .awaiting_pair_confirm
            .extend(self.disk.awaiting_pair_confirm.clone());
        merged.used_tickets.extend(self.disk.used_tickets.clone());
        for (token, peer) in &self.disk.bound_tokens {
            merged.bound_tokens.entry(token.clone()).or_insert(*peer);
        }
        merged.revoked.extend(self.disk.revoked.clone());
        merged
            .control_nonces
            .extend(self.disk.control_nonces.clone());
        merged.peers.extend(self.disk.peers.clone());
        let revoked = merged.revoked.clone();
        merged.peers.retain(|_, peer| {
            peer.token_id
                .as_ref()
                .is_none_or(|token| !revoked.contains(token))
        });
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, canonical::to_vec(&merged)?)?;
        let f = fs::OpenOptions::new().read(true).open(&tmp)?;
        f.sync_all()?;
        fs::rename(tmp, &self.path)?;
        Ok(())
    }
    pub fn get(&self, p: &PeerId) -> Option<&TrustedPeer> {
        self.disk.peers.get(p)
    }
    pub fn peers(&self) -> &BTreeMap<PeerId, TrustedPeer> {
        &self.disk.peers
    }
    pub fn local_role(&self) -> &LocalRole {
        &self.disk.local_role
    }
    pub fn set_local_role(&mut self, role: LocalRole) -> Result<()> {
        self.disk.local_role = role;
        self.save()
    }
    pub fn insert(&mut self, p: TrustedPeer) -> Result<()> {
        self.disk.peers.insert(p.peer_id, p);
        self.save()
    }
    pub fn register_ticket(&mut self, ticket: PairTicket) -> Result<()> {
        self.disk
            .pending_tickets
            .insert(ticket.ticket_id.clone(), ticket);
        self.save()
    }
    pub fn accept_pair_request<F>(
        &mut self,
        request: &PairRequest,
        authenticated: PeerId,
        now: u64,
        confirm_immediately: bool,
        confirm: F,
    ) -> Result<PairAccept>
    where
        F: FnOnce(PeerId, PeerId) -> bool,
    {
        let _operation_lock = self.operation_lock("pair-op")?;
        self.reload()?;
        if authenticated != request.peer_id {
            return Err(Error::Authentication(
                "pair request differs from transport".into(),
            ));
        }
        request.verify()?;
        let ticket = self
            .disk
            .pending_tickets
            .get(&request.ticket_id)
            .ok_or_else(|| Error::authz("ticket is not pending"))?
            .clone();
        if self.disk.used_tickets.contains(&request.ticket_id) {
            return Err(Error::authz("ticket already used"));
        }
        if now > CLOCK_SKEW_MS + parse_time(&ticket.expires_at)? {
            return Err(Error::authz("ticket expired"));
        }
        if !confirm(ticket.peer_id, request.peer_id) {
            return Err(Error::authz("pairing declined"));
        }
        self.disk.used_tickets.insert(request.ticket_id.clone());
        self.disk.pending_tickets.remove(&request.ticket_id);
        let peer = TrustedPeer {
            peer_id: request.peer_id,
            name: request.name.clone(),
            role: Role::Full,
            x25519_pk: request.x25519_pk,
            relay_key: request.relay_key,
            token_id: None,
            scopes: None,
            expires_at: None,
        };
        if confirm_immediately {
            self.disk.peers.insert(peer.peer_id, peer);
        } else {
            self.disk
                .awaiting_pair_confirm
                .insert(request.ticket_id.clone(), peer);
        }
        self.save()?;
        Ok(PairAccept {
            message_type: "pair-accept".into(),
            peer_id: ticket.peer_id,
            name: ticket.name,
            nonce: request.nonce.clone(),
        })
    }
    pub fn confirm_pair(&mut self, confirm: &PairConfirm, authenticated: PeerId) -> Result<()> {
        let _operation_lock = self.operation_lock("pair-op")?;
        self.reload()?;
        let Some(peer) = self.disk.awaiting_pair_confirm.remove(&confirm.ticket_id) else {
            return if self.disk.peers.contains_key(&authenticated) {
                Ok(())
            } else {
                Err(Error::authz("pair confirmation is not pending"))
            };
        };
        if peer.peer_id != authenticated {
            return Err(Error::Authentication(
                "pair confirmation differs from transport".into(),
            ));
        }
        self.disk.peers.insert(peer.peer_id, peer);
        self.save()
    }
    pub fn complete_pair_as_joiner(
        &mut self,
        ticket: &PairTicket,
        accept: &PairAccept,
        expected_nonce: &str,
    ) -> Result<PairConfirm> {
        if accept.peer_id != ticket.peer_id || accept.nonce != expected_nonce {
            return Err(Error::Authentication("pair accept issuer mismatch".into()));
        }
        self.disk.peers.insert(
            ticket.peer_id,
            TrustedPeer {
                peer_id: ticket.peer_id,
                name: accept.name.clone(),
                role: Role::Full,
                x25519_pk: ticket.x25519_pk,
                relay_key: ticket.relay_key,
                token_id: None,
                scopes: None,
                expires_at: None,
            },
        );
        self.save()?;
        Ok(PairConfirm {
            message_type: "pair-confirm".into(),
            ticket_id: ticket.ticket_id.clone(),
        })
    }
    pub fn revoke_token(&mut self, id: &str) -> Result<()> {
        let _operation_lock = self.operation_lock("bind-op")?;
        self.reload()?;
        self.disk.revoked.insert(id.into());
        self.disk
            .peers
            .retain(|_, p| p.token_id.as_deref() != Some(id));
        self.disk.bound_tokens.remove(id);
        self.save()
    }

    pub fn is_revoked(&self, id: &str) -> bool {
        self.disk.revoked.contains(id)
    }
    pub fn bind_enrollment(
        &mut self,
        bind: &EnrollBind,
        authenticated: PeerId,
        now: u64,
        issuer: &Identity,
    ) -> Result<BindCertificate> {
        let _operation_lock = self.operation_lock("bind-op")?;
        self.reload()?;
        if authenticated != bind.guest_peer_id {
            return Err(Error::Authentication(
                "enroll bind differs from transport".into(),
            ));
        }
        bind.verify(now)?;
        let token = &bind.token;
        if issuer.peer_id() != token.issuer {
            return Err(Error::Authentication(
                "bind certificate signer is not token issuer".into(),
            ));
        }
        if self.is_revoked(&token.token_id) {
            return Err(Error::authz("token revoked"));
        }
        if let Some(audience) = token.audience {
            if audience != bind.guest_peer_id {
                return Err(Error::authz("token audience mismatch"));
            }
        } else {
            if now
                > parse_time(
                    token
                        .bind_by
                        .as_deref()
                        .ok_or_else(|| Error::protocol("unbound token lacks bind_by"))?,
                )?
            {
                return Err(Error::authz("bind window expired"));
            }
            if self
                .disk
                .bound_tokens
                .get(&token.token_id)
                .is_some_and(|p| *p != bind.guest_peer_id)
            {
                return Err(Error::authz("token already bound"));
            }
        }
        self.disk
            .bound_tokens
            .insert(token.token_id.clone(), bind.guest_peer_id);
        self.disk.peers.insert(
            bind.guest_peer_id,
            TrustedPeer {
                peer_id: bind.guest_peer_id,
                name: bind.name.clone().unwrap_or_else(|| token.label.clone()),
                role: Role::Guest,
                x25519_pk: bind.x25519_pk,
                relay_key: Some(bind.relay_discovery_key),
                token_id: Some(token.token_id.clone()),
                scopes: Some(token.scopes.clone()),
                expires_at: Some(token.expires_at.clone()),
            },
        );
        self.save()?;
        BindCertificate::sign(
            token.token_id.clone(),
            bind.guest_peer_id,
            now,
            bind.name.clone().unwrap_or_else(|| token.label.clone()),
            bind.x25519_pk,
            token.scopes.clone(),
            token.expires_at.clone(),
            issuer,
        )
    }
    pub fn authorize_offer(
        &self,
        actor: PeerId,
        other: PeerId,
        capsule: Option<Hash>,
        kind: &str,
        direction: Direction,
        now: u64,
    ) -> Result<()> {
        let actor = self
            .get(&actor)
            .ok_or_else(|| Error::authz("untrusted peer"))?;
        if actor.role == Role::Guest {
            let other_role = self
                .get(&other)
                .ok_or_else(|| Error::authz("unknown counterparty"))?;
            if other_role.role == Role::Guest && self.disk.mesh_profile == MeshProfile::Personal {
                return Err(Error::authz("guest-to-guest forbidden"));
            }
            let id = actor
                .token_id
                .as_deref()
                .ok_or_else(|| Error::authz("guest lacks token"))?;
            if self.is_revoked(id) {
                return Err(Error::authz("token revoked"));
            }
            if actor
                .expires_at
                .as_deref()
                .map(parse_time)
                .transpose()?
                .is_none_or(|e| now > e)
            {
                return Err(Error::authz("token expired"));
            }
            if !actor
                .scopes
                .as_ref()
                .is_some_and(|s| s.allows(capsule, kind, direction))
            {
                return Err(Error::authz("out of scope"));
            }
            if other_role.role == Role::Guest
                && !other_role.scopes.as_ref().is_some_and(|scopes| {
                    scopes.allows(
                        capsule,
                        kind,
                        match direction {
                            Direction::Send => Direction::Receive,
                            Direction::Receive => Direction::Send,
                        },
                    )
                })
            {
                return Err(Error::authz("guest counterparty out of scope"));
            }
        }
        Ok(())
    }
    pub fn authorize_ack(
        &self,
        actor: PeerId,
        other: PeerId,
        capsule: Option<Hash>,
        kind: &str,
        direction: Direction,
        now: u64,
    ) -> Result<()> {
        self.authorize_offer(actor, other, capsule, kind, direction, now)
    }
    pub fn authorize_fetch(
        &self,
        actor: PeerId,
        other: PeerId,
        capsule: Option<Hash>,
        kind: &str,
        direction: Direction,
        now: u64,
    ) -> Result<()> {
        self.authorize_offer(actor, other, capsule, kind, direction, now)
    }
    pub fn authorize_lease(&self, actor: PeerId, takeover: bool, now: u64) -> Result<()> {
        let peer = self
            .get(&actor)
            .ok_or_else(|| Error::authz("untrusted peer"))?;
        if peer.role == Role::Full {
            return Ok(());
        }
        let token = peer
            .token_id
            .as_deref()
            .ok_or_else(|| Error::authz("guest lacks token"))?;
        if self.is_revoked(token) {
            return Err(Error::authz("token revoked"));
        }
        if peer
            .expires_at
            .as_deref()
            .map(parse_time)
            .transpose()?
            .is_none_or(|e| now > e)
        {
            return Err(Error::authz("token expired"));
        }
        let scopes = peer
            .scopes
            .as_ref()
            .ok_or_else(|| Error::authz("guest lacks scopes"))?;
        if takeover && !scopes.lease_takeover || !takeover && !scopes.lease_acquire {
            return Err(Error::authz("lease operation out of scope"));
        }
        Ok(())
    }
    pub fn consume_control_nonce(&mut self, nonce: &str, now: u64) -> Result<()> {
        let _operation_lock = self.operation_lock("nonce-op")?;
        self.reload()?;
        self.disk
            .control_nonces
            .retain(|_, t| now.saturating_sub(*t) <= 600_000);
        if self.disk.control_nonces.contains_key(nonce) {
            return Err(Error::authz("replayed control"));
        }
        self.disk.control_nonces.insert(nonce.into(), now);
        self.save()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairTicket {
    pub v: u32,
    #[serde(rename = "type")]
    pub record_type: String,
    pub peer_id: PeerId,
    pub name: String,
    pub ticket_id: String,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(with = "hex32")]
    pub x25519_pk: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "optional_hex32")]
    pub relay_key: Option<[u8; 32]>,
    pub addresses: Vec<String>,
    pub sig: Signature,
}
impl PairTicket {
    pub fn mint(
        name: String,
        x25519_pk: [u8; 32],
        relay_key: Option<[u8; 32]>,
        addresses: Vec<String>,
        now: u64,
        ttl_ms: u64,
        id: &Identity,
    ) -> Result<Self> {
        if ttl_ms > 600_000 {
            return Err(Error::protocol("pair ticket TTL exceeds 10m"));
        }
        let mut x = Self {
            v: 1,
            record_type: "pair-ticket".into(),
            peer_id: id.peer_id(),
            name,
            ticket_id: random16(),
            issued_at: format_time(now),
            expires_at: format_time(now + ttl_ms),
            x25519_pk,
            relay_key,
            addresses,
            sig: Signature::from_bytes([0; 64]),
        };
        x.sig = id.sign("pair-ticket", &unsigned(&x, "sig")?);
        Ok(x)
    }
    pub fn encode(&self) -> Result<String> {
        Ok(format!(
            "abra-pair/1/{}",
            BASE64URL_NOPAD.encode(&canonical::to_vec(self)?)
        ))
    }
    pub fn parse(s: &str, now: u64) -> Result<Self> {
        let raw = s
            .strip_prefix("abra-pair/1/")
            .ok_or_else(|| Error::protocol("bad pair ticket prefix"))?;
        let b = BASE64URL_NOPAD
            .decode(raw.as_bytes())
            .map_err(|_| Error::protocol("bad ticket base64"))?;
        if b.len() > 8192 {
            return Err(Error::protocol("ticket too large"));
        }
        let x: Self = serde_json::from_slice(&b)?;
        if canonical::to_vec(&x)? != b || x.v != 1 || x.record_type != "pair-ticket" {
            return Err(Error::protocol("invalid ticket"));
        }
        x.peer_id
            .verify("pair-ticket", &unsigned(&x, "sig")?, &x.sig)?;
        if now > CLOCK_SKEW_MS + parse_time(&x.expires_at)? {
            return Err(Error::authz("ticket expired"));
        }
        Ok(x)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    #[serde(rename = "type")]
    pub message_type: String,
    pub ticket_id: String,
    pub peer_id: PeerId,
    pub name: String,
    pub nonce: String,
    #[serde(with = "hex32")]
    pub x25519_pk: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "optional_hex32")]
    pub relay_key: Option<[u8; 32]>,
    pub sig: Signature,
}
impl PairRequest {
    pub fn sign(
        ticket_id: String,
        name: String,
        x25519_pk: [u8; 32],
        relay_key: Option<[u8; 32]>,
        nonce: [u8; 16],
        id: &Identity,
    ) -> Result<Self> {
        let mut x = Self {
            message_type: "pair-request".into(),
            ticket_id,
            peer_id: id.peer_id(),
            name,
            nonce: hex::encode(nonce),
            x25519_pk,
            relay_key,
            sig: Signature::from_bytes([0; 64]),
        };
        let mut payload =
            hex::decode(&x.ticket_id).map_err(|_| Error::protocol("bad ticket id"))?;
        payload.extend_from_slice(&nonce);
        x.sig = id.sign("pair-request", &payload);
        Ok(x)
    }
    pub fn verify(&self) -> Result<()> {
        let ticket = hex::decode(&self.ticket_id).map_err(|_| Error::protocol("bad ticket id"))?;
        let nonce = hex::decode(&self.nonce).map_err(|_| Error::protocol("bad pair nonce"))?;
        if ticket.len() != 16 || nonce.len() != 16 {
            return Err(Error::protocol("bad pair request ids"));
        }
        let mut payload = ticket;
        payload.extend_from_slice(&nonce);
        self.peer_id.verify("pair-request", &payload, &self.sig)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairAccept {
    #[serde(rename = "type")]
    pub message_type: String,
    pub peer_id: PeerId,
    pub name: String,
    pub nonce: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairConfirm {
    #[serde(rename = "type")]
    pub message_type: String,
    pub ticket_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intro {
    pub peer_id: PeerId,
    pub name: String,
    #[serde(with = "hex32")]
    pub x25519_pk: [u8; 32],
    #[serde(with = "hex32")]
    pub relay_discovery_key: [u8; 32],
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollOk {
    #[serde(rename = "type")]
    pub message_type: String,
    pub mesh: Vec<EnrollMeshPeer>,
    pub certificate: BindCertificate,
    pub mesh_profile: MeshProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollMeshPeer {
    pub peer_id: PeerId,
    pub name: String,
    pub role: Role,
    #[serde(with = "hex32")]
    pub x25519_pk: [u8; 32],
    pub token_id: Option<String>,
    pub scopes: Option<Scopes>,
    pub expires_at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentToken {
    pub v: u32,
    #[serde(rename = "type")]
    pub record_type: String,
    pub token_id: String,
    pub issuer: PeerId,
    pub issued_at: String,
    pub expires_at: String,
    pub label: String,
    pub intro: Vec<Intro>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<PeerId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_by: Option<String>,
    pub scopes: Scopes,
    pub sig: Signature,
}
impl EnrollmentToken {
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        label: String,
        intro: Vec<Intro>,
        audience: Option<PeerId>,
        scopes: Scopes,
        now: u64,
        ttl_ms: u64,
        id: &Identity,
    ) -> Result<Self> {
        scopes.validate()?;
        if ttl_ms > 30 * 86_400_000 {
            return Err(Error::protocol("enrollment TTL exceeds 30d"));
        }
        let bind_by = audience
            .is_none()
            .then(|| format_time(now + ttl_ms.min(900_000)));
        let mut x = Self {
            v: 1,
            record_type: "enrollment".into(),
            token_id: random16(),
            issuer: id.peer_id(),
            issued_at: format_time(now),
            expires_at: format_time(now + ttl_ms),
            label,
            intro,
            audience,
            bind_by,
            scopes,
            sig: Signature::from_bytes([0; 64]),
        };
        x.sig = id.sign("enroll", &unsigned(&x, "sig")?);
        Ok(x)
    }
    pub fn encode(&self) -> Result<String> {
        Ok(format!(
            "abra-enroll/1/{}",
            BASE64URL_NOPAD.encode(&canonical::to_vec(self)?)
        ))
    }
    pub fn parse(s: &str, now: u64) -> Result<Self> {
        let s = s.strip_prefix("abra://join/").unwrap_or(s);
        let b = BASE64URL_NOPAD
            .decode(
                s.strip_prefix("abra-enroll/1/")
                    .ok_or_else(|| Error::protocol("bad enrollment prefix"))?
                    .as_bytes(),
            )
            .map_err(|_| Error::protocol("bad enrollment base64"))?;
        if b.len() > 8192 {
            return Err(Error::protocol("enrollment too large"));
        }
        let x: Self = serde_json::from_slice(&b)?;
        if canonical::to_vec(&x)? != b || x.v != 1 || x.record_type != "enrollment" {
            return Err(Error::protocol("invalid enrollment"));
        }
        x.scopes.validate()?;
        x.issuer.verify("enroll", &unsigned(&x, "sig")?, &x.sig)?;
        if now > parse_time(&x.expires_at)?.saturating_add(CLOCK_SKEW_MS) {
            return Err(Error::authz("token expired"));
        }
        if x.audience.is_none() && x.bind_by.is_none() {
            return Err(Error::protocol("unbound token lacks bind_by"));
        }
        Ok(x)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollBind {
    #[serde(rename = "type")]
    pub message_type: String,
    pub token: EnrollmentToken,
    pub guest_peer_id: PeerId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(with = "hex32")]
    pub x25519_pk: [u8; 32],
    #[serde(with = "hex32")]
    pub relay_discovery_key: [u8; 32],
    pub sig: Signature,
}
impl EnrollBind {
    pub fn sign(
        token: EnrollmentToken,
        name: Option<String>,
        x25519_pk: [u8; 32],
        relay_discovery_key: [u8; 32],
        guest: &Identity,
    ) -> Result<Self> {
        if token.audience.is_some_and(|p| p != guest.peer_id()) {
            return Err(Error::authz("token audience mismatch"));
        }
        let mut payload =
            hex::decode(&token.token_id).map_err(|_| Error::protocol("bad token id"))?;
        if payload.len() != 16 {
            return Err(Error::protocol("bad token id"));
        }
        payload.extend_from_slice(guest.peer_id().as_bytes());
        let sig = guest.sign("enroll-bind", &payload);
        Ok(Self {
            message_type: "enroll-bind".into(),
            token,
            guest_peer_id: guest.peer_id(),
            name,
            x25519_pk,
            relay_discovery_key,
            sig,
        })
    }
    pub fn verify(&self, now: u64) -> Result<()> {
        self.token.verify(now)?;
        let mut payload =
            hex::decode(&self.token.token_id).map_err(|_| Error::protocol("bad token id"))?;
        if payload.len() != 16 {
            return Err(Error::protocol("bad token id"));
        }
        payload.extend_from_slice(self.guest_peer_id.as_bytes());
        self.guest_peer_id
            .verify("enroll-bind", &payload, &self.sig)?;
        Ok(())
    }
}

impl EnrollmentToken {
    pub fn verify(&self, now: u64) -> Result<()> {
        self.scopes.validate()?;
        self.issuer
            .verify("enroll", &unsigned(self, "sig")?, &self.sig)?;
        let issued = parse_time(&self.issued_at)?;
        if now > parse_time(&self.expires_at)?.saturating_add(CLOCK_SKEW_MS) {
            return Err(Error::authz("token expired"));
        }
        if self.audience.is_none() {
            let bind_by = self
                .bind_by
                .as_deref()
                .ok_or_else(|| Error::protocol("unbound token lacks bind_by"))?;
            if parse_time(bind_by)? > issued.saturating_add(900_000) {
                return Err(Error::protocol("bind window exceeds 15m"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindCertificate {
    #[serde(rename = "type")]
    pub record_type: String,
    pub token_id: String,
    pub guest_peer_id: PeerId,
    pub bound_at: String,
    pub name: String,
    #[serde(with = "hex32")]
    pub x25519_pk: [u8; 32],
    pub scopes: Scopes,
    pub expires_at: String,
    pub sig: Signature,
}
impl BindCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        token_id: String,
        guest_peer_id: PeerId,
        now: u64,
        name: String,
        x25519_pk: [u8; 32],
        scopes: Scopes,
        expires_at: String,
        issuer: &Identity,
    ) -> Result<Self> {
        let mut x = Self {
            record_type: "bind-cert".into(),
            token_id,
            guest_peer_id,
            bound_at: format_time(now),
            name,
            x25519_pk,
            scopes,
            expires_at,
            sig: Signature::from_bytes([0; 64]),
        };
        x.sig = issuer.sign("bind-cert", &unsigned(&x, "sig")?);
        Ok(x)
    }
    pub fn verify(&self, issuer: PeerId) -> Result<()> {
        issuer.verify("bind-cert", &unsigned(self, "sig")?, &self.sig)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    #[serde(rename = "type")]
    pub message_type: String,
    pub wire: u32,
    pub spec: String,
    pub peer_id: PeerId,
    pub name: String,
    pub features: Vec<String>,
    pub nonce: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloOk {
    #[serde(rename = "type")]
    pub message_type: String,
    pub wire: u32,
    pub peer_id: PeerId,
    pub features: Vec<String>,
    pub nonce: String,
    pub session: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloReject {
    #[serde(rename = "type")]
    pub message_type: String,
    pub reason: String,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    #[serde(rename = "type")]
    pub message_type: String,
    pub code: String,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ping {
    #[serde(rename = "type")]
    pub message_type: String,
    pub nonce: String,
    pub ts: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pong {
    #[serde(rename = "type")]
    pub message_type: String,
    pub nonce: String,
    pub ts: String,
}
pub fn check_hello(hello: &Hello, authenticated: PeerId, trusted: bool) -> Result<HelloOk> {
    if hello.peer_id != authenticated {
        return Err(Error::Authentication(
            "hello peer differs from transport".into(),
        ));
    }
    if hello.wire != WIRE_VERSION || hello.spec != abra_core::SPEC {
        return Err(Error::protocol("wire version mismatch"));
    }
    if !["resume", "control"]
        .iter()
        .all(|x| hello.features.iter().any(|f| f == x))
    {
        return Err(Error::protocol("mandatory feature missing"));
    }
    Ok(HelloOk {
        message_type: "hello-ok".into(),
        wire: WIRE_VERSION,
        peer_id: authenticated,
        features: vec!["resume".into(), "control".into()],
        nonce: hello.nonce.clone(),
        session: if trusted { "trusted" } else { "bootstrap" }.into(),
    })
}
pub fn bootstrap_allowed(kind: &str) -> bool {
    matches!(
        kind,
        "pair-request"
            | "pair-abort"
            | "pair-accept"
            | "pair-confirm"
            | "enroll-bind"
            | "enroll-ok"
            | "error"
    )
}

pub async fn dial_handshake(
    connection: &mut crate::Connection,
    local: PeerId,
    name: String,
) -> Result<HelloOk> {
    let remote = connection.peer_id();
    let hello = Hello {
        message_type: "hello".into(),
        wire: WIRE_VERSION,
        spec: abra_core::SPEC.into(),
        peer_id: local,
        name,
        features: vec!["resume".into(), "control".into()],
        nonce: random16(),
    };
    let (send, recv) = connection.control_mut();
    crate::write_frame(send, &hello).await?;
    let value: serde_json::Value =
        tokio::time::timeout(crate::delivery::HEALTH_TIMEOUT, crate::read_frame(recv))
            .await
            .map_err(|_| Error::Timeout)??;
    match value.get("type").and_then(|v| v.as_str()) {
        Some("hello-ok") => {
            let ok: HelloOk = serde_json::from_value(value)?;
            if ok.nonce != hello.nonce || ok.peer_id != remote {
                return Err(Error::Authentication("invalid hello response".into()));
            }
            Ok(ok)
        }
        Some("hello-reject") => Err(Error::protocol(
            serde_json::from_value::<HelloReject>(value)?.message,
        )),
        _ => Err(Error::protocol("expected hello response")),
    }
}

pub async fn accept_handshake(
    connection: &mut crate::Connection,
    local: PeerId,
    trust: &TrustStore,
) -> Result<HelloOk> {
    let remote = connection.peer_id();
    let (send, recv) = connection.control_mut();
    let hello: Hello =
        tokio::time::timeout(crate::delivery::HEALTH_TIMEOUT, crate::read_frame(recv))
            .await
            .map_err(|_| Error::Timeout)??;
    match check_hello(&hello, remote, trust.get(&remote).is_some()) {
        Ok(mut ok) => {
            ok.peer_id = local;
            crate::write_frame(send, &ok).await?;
            Ok(ok)
        }
        Err(error) => {
            let reject = HelloReject {
                message_type: "hello-reject".into(),
                reason: "wire".into(),
                message: error.to_string(),
            };
            crate::write_frame(send, &reject).await?;
            Err(error)
        }
    }
}

pub async fn health_check(connection: &mut crate::Connection, now: u64) -> Result<()> {
    let ping = Ping {
        message_type: "ping".into(),
        nonce: random16(),
        ts: format_time(now),
    };
    let (send, recv) = connection.control_mut();
    crate::write_frame(send, &ping).await?;
    let pong: Pong = tokio::time::timeout(crate::delivery::HEALTH_TIMEOUT, crate::read_frame(recv))
        .await
        .map_err(|_| Error::Timeout)??;
    if pong.message_type != "pong" || pong.nonce != ping.nonce {
        return Err(Error::protocol("invalid pong"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_roundtrip() {
        for n in [0, 1_800_000_000_000] {
            assert_eq!(parse_time(&format_time(n)).unwrap(), n)
        }
    }
    #[test]
    fn strict_time_parser_never_panics_on_hostile_utf8_or_bad_calendar() {
        for value in [
            "202\u{e9}-01-01T00:00:00.00Z",
            "+123-01-01T00:00:00.000Z",
            "2024-02-30T00:00:00.000Z",
            "2024-13-01T00:00:00.000Z",
            "2024-01-01X00:00:00.000Z",
        ] {
            assert!(parse_time(value).is_err(), "accepted {value:?}");
        }
    }
    #[test]
    fn malformed_signed_enrollment_time_is_an_error_not_a_panic() {
        let issuer = Identity::generate();
        let mut token = EnrollmentToken::mint(
            "x".into(),
            vec![],
            Some(Identity::generate().peer_id()),
            Scopes {
                capsules: vec!["*".into()],
                kinds: vec!["*".into()],
                send: false,
                receive: true,
                lease_acquire: false,
                lease_takeover: false,
            },
            1_800_000_000_000,
            1000,
            &issuer,
        )
        .unwrap();
        token.expires_at = "202\u{e9}-01-01T00:00:00.00Z".into();
        token.sig = issuer.sign("enroll", &unsigned(&token, "sig").unwrap());
        assert!(token.verify(1_800_000_000_000).is_err());
    }
}
