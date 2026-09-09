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
pub const MAX_REVOCATIONS_PER_MESSAGE: usize = 128;
/// Peer carries revocations on its hello and offers.
pub const FEATURE_REVOCATION: &str = "revocation";
/// Receiver may decline optional native cache blobs.
pub const FEATURE_SKIP_NATIVE: &str = "skip-native";
/// Peer accepts guest bind certificates attached to forwarded offers.
pub const FEATURE_BIND_CERT: &str = "bind-cert";
/// Dialer accepts a `result` key on `ControlAck`; older peers reject the
/// unknown field, so the receiver drops the handler's value for them.
pub const FEATURE_CONTROL_RESULT: &str = "control-result";
const MAX_CERTIFICATE_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const MAX_PERSISTED_REVOCATIONS: usize = 4096;
const MAX_PERSISTED_BIND_CERTIFICATES: usize = 4096;

fn random16() -> String {
    let mut b = [0; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
fn supported_features() -> Vec<String> {
    [
        "resume",
        "control",
        FEATURE_REVOCATION,
        FEATURE_SKIP_NATIVE,
        FEATURE_BIND_CERT,
        FEATURE_CONTROL_RESULT,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
pub fn has_feature(features: &[String], feature: &str) -> bool {
    features.iter().any(|candidate| candidate == feature)
}

fn negotiated_hello_revocations(
    trust: &TrustStore,
    remote_features: &[String],
    now: u64,
) -> Vec<Revocation> {
    if matches!(trust.local_role(), LocalRole::Full)
        && has_feature(remote_features, FEATURE_REVOCATION)
    {
        trust.current_revocations(now)
    } else {
        Vec::new()
    }
}
fn revocation_key(issuer: PeerId, token_id: &str) -> String {
    format!("{}:{token_id}", issuer.to_hex())
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct TrustDisk {
    #[serde(default)]
    mesh_profile: MeshProfile,
    #[serde(default)]
    local_role: LocalRole,
    peers: BTreeMap<PeerId, TrustedPeer>,
    #[serde(default)]
    peer_versions: BTreeMap<PeerId, u64>,
    #[serde(default)]
    peer_pair_tickets: BTreeMap<PeerId, String>,
    #[serde(default)]
    cancelled_pairs: BTreeSet<String>,
    pending_tickets: BTreeMap<String, PairTicket>,
    awaiting_pair_confirm: BTreeMap<String, TrustedPeer>,
    used_tickets: BTreeSet<String>,
    bound_tokens: BTreeMap<String, PeerId>,
    #[serde(default)]
    bind_certificates: BTreeMap<PeerId, StoredBindCertificate>,
    revoked: BTreeSet<String>,
    #[serde(default)]
    revocations: BTreeMap<String, StoredRevocation>,
    control_nonces: BTreeMap<String, u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRevocation {
    record: Revocation,
    relevant_until: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredBindCertificate {
    pub issuer: PeerId,
    pub certificate: BindCertificate,
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
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
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
        let mut merged = self.merge_disk_state()?;
        prune_expired(&mut merged, abra_core::now_ms());
        enforce_limits(&mut merged);
        remove_revoked_guests(&mut merged);
        abra_core::atomic_write(&self.path, &canonical::to_vec(&merged)?)?;
        Ok(())
    }
    /// Folds this handle's in-memory state onto whatever another process has
    /// written since it was loaded, so a concurrent writer is never clobbered.
    fn merge_disk_state(&self) -> Result<TrustDisk> {
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
        merged
            .bind_certificates
            .extend(self.disk.bind_certificates.clone());
        merged.revoked.extend(self.disk.revoked.clone());
        merged.revocations.extend(self.disk.revocations.clone());
        merged
            .control_nonces
            .extend(self.disk.control_nonces.clone());
        merged
            .cancelled_pairs
            .extend(self.disk.cancelled_pairs.clone());
        // A removal is a versioned absence. Detached sessions with an older
        // trust snapshot must not restore a removed peer when saving hints.
        for peer in self.disk.peers.keys().chain(self.disk.peer_versions.keys()) {
            let version = self.disk.peer_versions.get(peer).copied().unwrap_or(0);
            if version < merged.peer_versions.get(peer).copied().unwrap_or(0) {
                continue;
            }
            if let Some(trusted) = self.disk.peers.get(peer) {
                merged.peers.insert(*peer, trusted.clone());
            } else if version > 0 {
                merged.peers.remove(peer);
            }
            if let Some(ticket) = self.disk.peer_pair_tickets.get(peer) {
                merged.peer_pair_tickets.insert(*peer, ticket.clone());
            } else if version > 0 {
                merged.peer_pair_tickets.remove(peer);
            }
            if version > 0 {
                merged.peer_versions.insert(*peer, version);
            }
        }
        merged
            .pending_tickets
            .retain(|ticket, _| !merged.used_tickets.contains(ticket));
        merged.awaiting_pair_confirm.retain(|ticket, peer| {
            !merged.cancelled_pairs.contains(ticket)
                && merged.peer_pair_tickets.get(&peer.peer_id) != Some(ticket)
        });
        Ok(merged)
    }
    pub fn get(&self, p: &PeerId) -> Option<&TrustedPeer> {
        self.disk.peers.get(p)
    }
    pub fn peers(&self) -> &BTreeMap<PeerId, TrustedPeer> {
        &self.disk.peers
    }
    pub fn bind_certificate(&self, guest: &PeerId) -> Option<&StoredBindCertificate> {
        self.disk.bind_certificates.get(guest)
    }

    pub fn current_revocations(&self, now: u64) -> Vec<Revocation> {
        let mut records = self
            .disk
            .revocations
            .values()
            .filter(|stored| parse_time(&stored.relevant_until).is_ok_and(|end| now <= end))
            .map(|stored| stored.record.clone())
            .collect::<Vec<_>>();
        records
            .sort_by_key(|record| std::cmp::Reverse(parse_time(&record.revoked_at).unwrap_or(0)));
        records.truncate(MAX_REVOCATIONS_PER_MESSAGE);
        records
    }

    pub fn apply_revocations(&mut self, records: &[Revocation], now: u64) -> Result<()> {
        if records.len() > MAX_REVOCATIONS_PER_MESSAGE {
            return Err(Error::protocol("revocation list exceeds 128 records"));
        }
        let _operation_lock = self.operation_lock("bind-op")?;
        self.reload()?;
        let mut changed = false;
        for record in records {
            if record.verify_at(now).is_err()
                || self
                    .get(&record.issuer)
                    .is_none_or(|peer| peer.role != Role::Full)
            {
                continue;
            }
            let matching_certificate = self
                .disk
                .bind_certificates
                .get(&record.guest_peer_id)
                .filter(|stored| {
                    stored.issuer == record.issuer && stored.certificate.token_id == record.token_id
                });
            let existing = self
                .disk
                .revocations
                .get(&revocation_key(record.issuer, &record.token_id))
                .filter(|stored| {
                    stored.record.issuer == record.issuer
                        && stored.record.guest_peer_id == record.guest_peer_id
                });
            if matching_certificate.is_none() && existing.is_none() {
                continue;
            }
            let relevant_until = matching_certificate
                .map(|stored| stored.certificate.expires_at.clone())
                .or_else(|| existing.map(|stored| stored.relevant_until.clone()))
                .unwrap_or_else(|| format_time(now.saturating_add(MAX_CERTIFICATE_LIFETIME_MS)));
            self.disk.revocations.insert(
                revocation_key(record.issuer, &record.token_id),
                StoredRevocation {
                    record: record.clone(),
                    relevant_until,
                },
            );
            self.disk.revoked.insert(record.token_id.clone());
            self.disk.peers.retain(|peer_id, peer| {
                *peer_id != record.guest_peer_id
                    || peer.token_id.as_deref() != Some(&record.token_id)
            });
            self.disk.bind_certificates.remove(&record.guest_peer_id);
            changed = true;
        }
        if changed {
            self.save()?;
        }
        Ok(())
    }

    pub fn install_bind_certificate(
        &mut self,
        issuer: PeerId,
        certificate: BindCertificate,
        now: u64,
    ) -> Result<()> {
        if certificate.record_type != "bind-cert" {
            return Err(Error::protocol("invalid bind certificate type"));
        }
        let _operation_lock = self.operation_lock("bind-op")?;
        self.reload()?;
        let issuer_peer = self
            .get(&issuer)
            .ok_or_else(|| Error::authz("untrusted bind certificate issuer"))?;
        if issuer_peer.role != Role::Full {
            return Err(Error::authz("bind certificate issuer is not full"));
        }
        certificate.verify(issuer)?;
        let expires_at = parse_time(&certificate.expires_at)?;
        if now > expires_at {
            return Err(Error::authz("bind certificate expired"));
        }
        let bound_at = parse_time(&certificate.bound_at)?;
        if expires_at.saturating_sub(bound_at) > MAX_CERTIFICATE_LIFETIME_MS {
            return Err(Error::authz("bind certificate lifetime exceeds 30 days"));
        }
        if self.is_revoked(&certificate.token_id) {
            return Err(Error::authz("token revoked"));
        }
        if self.disk.revocations.values().any(|stored| {
            stored.record.issuer == issuer
                && stored.record.token_id == certificate.token_id
                && stored.record.guest_peer_id == certificate.guest_peer_id
        }) {
            return Err(Error::authz("token revoked"));
        }
        if self
            .get(&certificate.guest_peer_id)
            .is_some_and(|peer| peer.role == Role::Full)
        {
            return Err(Error::authz("bind certificate subject is already full"));
        }
        certificate.scopes.validate()?;
        let guest = TrustedPeer {
            peer_id: certificate.guest_peer_id,
            name: certificate.name.clone(),
            role: Role::Guest,
            x25519_pk: certificate.x25519_pk,
            relay_key: None,
            token_id: Some(certificate.token_id.clone()),
            scopes: Some(certificate.scopes.clone()),
            expires_at: Some(certificate.expires_at.clone()),
            addresses: Vec::new(),
        };
        self.disk.peers.insert(guest.peer_id, guest);
        self.disk.bind_certificates.insert(
            certificate.guest_peer_id,
            StoredBindCertificate {
                issuer,
                certificate,
            },
        );
        self.save()
    }
    pub fn local_role(&self) -> &LocalRole {
        &self.disk.local_role
    }
    pub fn set_local_role(&mut self, role: LocalRole) -> Result<()> {
        self.disk.local_role = role;
        self.save()
    }
    pub fn insert(&mut self, p: TrustedPeer) -> Result<()> {
        if self.disk.peer_versions.contains_key(&p.peer_id)
            && !self.disk.peers.contains_key(&p.peer_id)
        {
            return Err(Error::authz(
                "peer was removed; pair again with a new ticket",
            ));
        }
        self.disk.peers.insert(p.peer_id, p);
        self.save()
    }
    fn advance_peer_version(&mut self, peer: PeerId) {
        let version = self.disk.peer_versions.entry(peer).or_default();
        *version += 1;
    }
    pub fn remove_peer(&mut self, peer: PeerId) -> Result<bool> {
        let _pair_lock = self.operation_lock("pair-op")?;
        let _bind_lock = self.operation_lock("bind-op")?;
        self.reload()?;
        let Some(removed) = self.disk.peers.remove(&peer) else {
            return Ok(false);
        };
        self.advance_peer_version(peer);
        if let Some(ticket) = self.disk.peer_pair_tickets.remove(&peer) {
            self.disk.cancelled_pairs.insert(ticket);
        }
        if let Some(token) = removed.token_id {
            self.disk.revoked.insert(token);
        }
        for stored in self.disk.bind_certificates.values() {
            if stored.issuer == peer {
                self.disk
                    .revoked
                    .insert(stored.certificate.token_id.clone());
            }
        }
        // Tickets minted before removal cannot put this peer back. Pairing
        // again requires a ticket registered after this operation.
        self.disk
            .used_tickets
            .extend(self.disk.pending_tickets.keys().cloned());
        self.disk.cancelled_pairs.extend(
            self.disk
                .awaiting_pair_confirm
                .iter()
                .filter(|(_, pending)| pending.peer_id == peer)
                .map(|(ticket, _)| ticket.clone()),
        );
        self.disk
            .awaiting_pair_confirm
            .retain(|_, pending| pending.peer_id != peer);
        self.save()?;
        self.reload()?;
        Ok(true)
    }
    pub fn update_addresses(&mut self, peer: PeerId, addresses: Vec<String>) -> Result<()> {
        if addresses.is_empty() {
            return Ok(());
        }
        let Some(trusted) = self.disk.peers.get_mut(&peer) else {
            return Ok(());
        };
        let mut merged = trusted.addresses.clone();
        for address in addresses {
            crate::transport::validate_peer_address(&address)?;
            if let Some((index, combined)) = merged.iter().enumerate().find_map(|(index, known)| {
                crate::transport::merge_peer_address_hints(known, &address)
                    .map(|combined| (index, combined))
            }) {
                merged[index] = combined;
                continue;
            }
            if !merged.contains(&address) {
                merged.push(address);
            }
        }
        merged.sort_by_key(|address| !crate::transport::peer_address_has_direct_hint(address));
        merged.truncate(8);
        trusted.addresses = merged;
        self.save()
    }
    pub fn register_ticket(&mut self, ticket: PairTicket) -> Result<()> {
        let _operation_lock = self.operation_lock("pair-op")?;
        self.reload()?;
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
        let addresses = request
            .addresses
            .iter()
            .map(|address| {
                crate::transport::validate_peer_address(address)?;
                Ok(address.clone())
            })
            .collect::<Result<Vec<_>>>()?;
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
            addresses,
        };
        if confirm_immediately {
            self.advance_peer_version(peer.peer_id);
            self.disk
                .peer_pair_tickets
                .insert(peer.peer_id, request.ticket_id.clone());
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
        if self.disk.cancelled_pairs.contains(&confirm.ticket_id) {
            return Err(Error::authz("pair confirmation was revoked"));
        }
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
        self.advance_peer_version(peer.peer_id);
        self.disk
            .peer_pair_tickets
            .insert(peer.peer_id, confirm.ticket_id.clone());
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
        let _operation_lock = self.operation_lock("pair-op")?;
        self.reload()?;
        if self.disk.cancelled_pairs.contains(&ticket.ticket_id) {
            return Err(Error::authz("pair ticket was revoked"));
        }
        self.advance_peer_version(ticket.peer_id);
        self.disk
            .peer_pair_tickets
            .insert(ticket.peer_id, ticket.ticket_id.clone());
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
                addresses: ticket.addresses.clone(),
            },
        );
        self.save()?;
        Ok(PairConfirm {
            message_type: "pair-confirm".into(),
            ticket_id: ticket.ticket_id.clone(),
        })
    }
    pub fn revoke_token(&mut self, id: &str, now: u64, issuer: &Identity) -> Result<()> {
        let _operation_lock = self.operation_lock("bind-op")?;
        self.reload()?;
        self.disk.revoked.insert(id.into());
        if let Some(stored) = self
            .disk
            .bind_certificates
            .values()
            .find(|stored| stored.certificate.token_id == id && stored.issuer == issuer.peer_id())
            .cloned()
        {
            let record =
                Revocation::sign(id.to_owned(), stored.certificate.guest_peer_id, now, issuer)?;
            self.disk.revocations.insert(
                revocation_key(issuer.peer_id(), id),
                StoredRevocation {
                    record,
                    relevant_until: stored.certificate.expires_at,
                },
            );
        }
        self.disk
            .peers
            .retain(|_, p| p.token_id.as_deref() != Some(id));
        self.disk.bound_tokens.remove(id);
        self.disk
            .bind_certificates
            .retain(|_, stored| stored.certificate.token_id != id);
        self.save()
    }

    pub fn is_revoked(&self, id: &str) -> bool {
        self.disk.revoked.contains(id)
    }
    pub fn is_revoked_guest(&self, peer: &PeerId, now: u64) -> bool {
        let token = self.disk.peers.get(peer).and_then(|trusted| {
            (trusted.role == Role::Guest)
                .then_some(trusted.token_id.as_deref())
                .flatten()
        });
        token.is_some_and(|token| self.disk.revoked.contains(token))
            || self.disk.revocations.values().any(|stored| {
                stored.record.guest_peer_id == *peer
                    && token.is_none_or(|token| stored.record.token_id == token)
                    && parse_time(&stored.relevant_until).is_ok_and(|until| now <= until)
            })
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
        if self.is_revoked(&token.token_id)
            || self.disk.revocations.values().any(|stored| {
                stored.record.issuer == token.issuer
                    && stored.record.token_id == token.token_id
                    && stored.record.guest_peer_id == bind.guest_peer_id
            })
        {
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
                addresses: bind.addresses.clone(),
            },
        );
        self.save()?;
        let certificate = BindCertificate::sign(
            token.token_id.clone(),
            bind.guest_peer_id,
            now,
            bind.name.clone().unwrap_or_else(|| token.label.clone()),
            bind.x25519_pk,
            token.scopes.clone(),
            token.expires_at.clone(),
            issuer,
        )?;
        self.disk.bind_certificates.insert(
            bind.guest_peer_id,
            StoredBindCertificate {
                issuer: issuer.peer_id(),
                certificate: certificate.clone(),
            },
        );
        self.save()?;
        Ok(certificate)
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

/// Drops revocations and bind certificates that can no longer authorize or
/// deny anything, so the file does not grow without bound.
fn prune_expired(disk: &mut TrustDisk, now: u64) {
    disk.revocations
        .retain(|_, stored| parse_time(&stored.relevant_until).is_ok_and(|until| until >= now));
    disk.bind_certificates.retain(|_, stored| {
        parse_time(&stored.certificate.expires_at).is_ok_and(|until| until >= now)
    });
}

fn enforce_limits(disk: &mut TrustDisk) {
    evict_oldest(&mut disk.revocations, MAX_PERSISTED_REVOCATIONS, |stored| {
        parse_time(&stored.relevant_until).unwrap_or(0)
    });
    evict_oldest(
        &mut disk.bind_certificates,
        MAX_PERSISTED_BIND_CERTIFICATES,
        |stored| parse_time(&stored.certificate.expires_at).unwrap_or(0),
    );
}

fn evict_oldest<K: Clone + Ord, V>(
    map: &mut BTreeMap<K, V>,
    limit: usize,
    age: impl Fn(&V) -> u64,
) {
    while map.len() > limit {
        let oldest = map
            .iter()
            .min_by_key(|(_, value)| age(value))
            .map(|(key, _)| key.clone())
            .expect("non-empty map");
        map.remove(&oldest);
    }
}

/// A revoked token takes its peer and its bind certificate with it, including
/// records another process merged in.
fn remove_revoked_guests(disk: &mut TrustDisk) {
    let revoked = disk.revoked.clone();
    let revocations = disk.revocations.clone();
    disk.peers.retain(|peer_id, peer| {
        peer.token_id.as_ref().is_none_or(|token| {
            !revoked.contains(token)
                && !revocations.values().any(|stored| {
                    stored.record.guest_peer_id == *peer_id && stored.record.token_id == *token
                })
        })
    });
    disk.bind_certificates.retain(|guest, stored| {
        !revoked.contains(&stored.certificate.token_id)
            && !revocations.values().any(|revocation| {
                revocation.record.issuer == stored.issuer
                    && revocation.record.guest_peer_id == *guest
                    && revocation.record.token_id == stored.certificate.token_id
            })
    });
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    pub sig: Signature,
}
impl PairRequest {
    pub fn sign(
        ticket_id: String,
        name: String,
        x25519_pk: [u8; 32],
        relay_key: Option<[u8; 32]>,
        addresses: Vec<String>,
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
            addresses,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    pub sig: Signature,
}
impl EnrollBind {
    pub fn sign(
        token: EnrollmentToken,
        name: Option<String>,
        x25519_pk: [u8; 32],
        relay_discovery_key: [u8; 32],
        addresses: Vec<String>,
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
            addresses,
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
pub struct Revocation {
    #[serde(rename = "type")]
    pub record_type: String,
    pub issuer: PeerId,
    pub token_id: String,
    pub guest_peer_id: PeerId,
    pub revoked_at: String,
    pub sig: Signature,
}
impl Revocation {
    pub fn sign(
        token_id: String,
        guest_peer_id: PeerId,
        now: u64,
        issuer: &Identity,
    ) -> Result<Self> {
        let mut record = Self {
            record_type: "revocation".into(),
            issuer: issuer.peer_id(),
            token_id,
            guest_peer_id,
            revoked_at: format_time(now),
            sig: Signature::from_bytes([0; 64]),
        };
        record.sig = issuer.sign("revoke", &unsigned(&record, "sig")?);
        Ok(record)
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_at(abra_core::now_ms())
    }

    pub fn verify_at(&self, now: u64) -> Result<()> {
        if self.record_type != "revocation"
            || hex::decode(&self.token_id).map_or(true, |bytes| bytes.len() != 16)
        {
            return Err(Error::protocol("invalid revocation record"));
        }
        let revoked_at = parse_time(&self.revoked_at)?;
        if revoked_at > now.saturating_add(CLOCK_SKEW_MS) {
            return Err(Error::protocol("revocation timestamp is in the future"));
        }
        self.issuer
            .verify("revoke", &unsigned(self, "sig")?, &self.sig)?;
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocations: Vec<Revocation>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocations: Vec<Revocation>,
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
    if hello.revocations.len() > MAX_REVOCATIONS_PER_MESSAGE {
        return Err(Error::protocol("revocation list exceeds 128 records"));
    }
    Ok(HelloOk {
        message_type: "hello-ok".into(),
        wire: WIRE_VERSION,
        peer_id: authenticated,
        features: supported_features(),
        nonce: hello.nonce.clone(),
        session: if trusted { "trusted" } else { "bootstrap" }.into(),
        revocations: Vec::new(),
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

async fn exchange_hello(
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
        features: supported_features(),
        nonce: random16(),
        // The dialer does not know the listener's features yet.
        revocations: Vec::new(),
    };
    let (send, recv) = connection.control_mut();
    crate::write_frame(send, &hello).await?;
    let value: serde_json::Value =
        crate::framing::read_frame_timeout(recv, crate::delivery::HEALTH_TIMEOUT).await?;
    match value.get("type").and_then(|value| value.as_str()) {
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

pub async fn dial_handshake(
    connection: &mut crate::Connection,
    local: PeerId,
    name: String,
) -> Result<HelloOk> {
    exchange_hello(connection, local, name).await
}

pub async fn dial_handshake_with_trust(
    connection: &mut crate::Connection,
    local: PeerId,
    name: String,
    trust: &mut TrustStore,
    now: u64,
) -> Result<HelloOk> {
    let ok = exchange_hello(connection, local, name).await?;
    if has_feature(&ok.features, FEATURE_REVOCATION) {
        trust.apply_revocations(&ok.revocations, now)?;
    }
    Ok(ok)
}

pub async fn accept_handshake(
    connection: &mut crate::Connection,
    local: PeerId,
    trust: &mut TrustStore,
) -> Result<HelloOk> {
    let remote = connection.peer_id();
    let (send, recv) = connection.control_mut();
    let hello: Hello =
        crate::framing::read_frame_timeout(recv, crate::delivery::HEALTH_TIMEOUT).await?;
    let now = abra_core::now_ms();
    let was_trusted = trust.get(&remote).is_some();
    let mut checked = if trust.is_revoked_guest(&remote, now) {
        Err(Error::authz("token revoked"))
    } else {
        check_hello(&hello, remote, was_trusted)
    };
    if checked.is_ok() && was_trusted {
        trust.apply_revocations(&hello.revocations, now)?;
        if trust.get(&remote).is_none() || trust.is_revoked_guest(&remote, now) {
            checked = Err(Error::authz("token revoked"));
        }
    }
    match checked {
        Ok(mut ok) => {
            ok.peer_id = local;
            ok.revocations = negotiated_hello_revocations(trust, &hello.features, now);
            crate::write_frame(send, &ok).await?;
            // Later responses must be gated by the dialer's advertised features.
            ok.features = hello.features;
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
    let pong: Pong =
        crate::framing::read_frame_timeout(recv, crate::delivery::HEALTH_TIMEOUT).await?;
    if pong.message_type != "pong" || pong.nonce != ping.nonce {
        return Err(Error::protocol("invalid pong"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_NOW: u64 = 1_800_000_000_000;

    fn scopes() -> Scopes {
        Scopes {
            capsules: vec!["*".into()],
            kinds: vec!["*".into()],
            send: true,
            receive: true,
            lease_acquire: false,
            lease_takeover: false,
        }
    }

    fn full_peer(identity: &Identity) -> TrustedPeer {
        TrustedPeer {
            peer_id: identity.peer_id(),
            name: "issuer".into(),
            role: Role::Full,
            x25519_pk: [1; 32],
            relay_key: None,
            token_id: None,
            scopes: None,
            expires_at: None,
            addresses: Vec::new(),
        }
    }
    #[test]
    fn time_roundtrip() {
        for n in [0, 1_800_000_000_000] {
            assert_eq!(parse_time(&format_time(n)).unwrap(), n)
        }
    }
    #[test]
    fn unknown_feature_peer_receives_no_new_hello_fields() {
        let identity = Identity::generate();
        let hello = Hello {
            message_type: "hello".into(),
            wire: WIRE_VERSION,
            spec: abra_core::SPEC.into(),
            peer_id: identity.peer_id(),
            name: "old-peer".into(),
            features: vec!["resume".into(), "control".into()],
            nonce: "00".repeat(16),
            revocations: Vec::new(),
        };
        let hello_json = serde_json::to_value(&hello).unwrap();
        assert!(hello_json.get("revocations").is_none());
        let ok = check_hello(&hello, identity.peer_id(), true).unwrap();
        let ok_json = serde_json::to_value(ok).unwrap();
        assert!(ok_json.get("revocations").is_none());

        let have = crate::Have {
            message_type: "have".into(),
            offer_id: "11".repeat(16),
            have: Vec::new(),
            resume: BTreeMap::new(),
            eof: true,
            skip_native: false,
        };
        assert!(serde_json::to_value(have)
            .unwrap()
            .get("skip_native")
            .is_none());

        let root = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let guest = Identity::generate();
        let mut trust = TrustStore::open(root.path()).unwrap();
        trust.disk.revocations.insert(
            revocation_key(issuer.peer_id(), "token"),
            StoredRevocation {
                record: Revocation::sign("token".into(), guest.peer_id(), TEST_NOW, &issuer)
                    .unwrap(),
                relevant_until: format_time(TEST_NOW + 60_000),
            },
        );
        assert!(negotiated_hello_revocations(&trust, &hello.features, TEST_NOW).is_empty());
        let mut features = hello.features;
        features.push(FEATURE_REVOCATION.into());
        assert_eq!(
            negotiated_hello_revocations(&trust, &features, TEST_NOW).len(),
            1
        );
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

    #[test]
    fn stored_revocation_can_be_reverified_without_bind_certificate() {
        let root = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let guest = Identity::generate();
        let mut trust = TrustStore::open(root.path()).unwrap();
        trust.insert(full_peer(&issuer)).unwrap();
        let record = Revocation::sign("42".repeat(16), guest.peer_id(), TEST_NOW, &issuer).unwrap();
        trust.disk.revocations.insert(
            revocation_key(issuer.peer_id(), &record.token_id),
            StoredRevocation {
                record: record.clone(),
                relevant_until: format_time(TEST_NOW + 60_000),
            },
        );
        trust.save().unwrap();
        trust.apply_revocations(&[record], TEST_NOW + 1).unwrap();
        assert_eq!(trust.current_revocations(TEST_NOW + 1).len(), 1);
    }

    #[test]
    fn revocation_matches_current_token_and_expires() {
        let root = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let guest = Identity::generate();
        let mut trust = TrustStore::open(root.path()).unwrap();
        let old_token = "42".repeat(16);
        trust.disk.revocations.insert(
            revocation_key(issuer.peer_id(), &old_token),
            StoredRevocation {
                record: Revocation::sign(old_token.clone(), guest.peer_id(), TEST_NOW, &issuer)
                    .unwrap(),
                relevant_until: format_time(TEST_NOW + 10),
            },
        );
        trust.disk.peers.insert(
            guest.peer_id(),
            TrustedPeer {
                peer_id: guest.peer_id(),
                name: "guest".into(),
                role: Role::Guest,
                x25519_pk: [2; 32],
                relay_key: None,
                token_id: Some(old_token),
                scopes: Some(scopes()),
                expires_at: Some(format_time(TEST_NOW + 60_000)),
                addresses: Vec::new(),
            },
        );
        assert!(trust.is_revoked_guest(&guest.peer_id(), TEST_NOW));
        assert!(!trust.is_revoked_guest(&guest.peer_id(), TEST_NOW + 11));
        trust.disk.peers.get_mut(&guest.peer_id()).unwrap().token_id = Some("43".repeat(16));
        assert!(!trust.is_revoked_guest(&guest.peer_id(), TEST_NOW));
    }

    #[test]
    fn save_prunes_expired_revocations_and_certificates() {
        let root = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let guest = Identity::generate();
        let now = abra_core::now_ms();
        let record = Revocation::sign("42".repeat(16), guest.peer_id(), now, &issuer).unwrap();
        let mut trust = TrustStore::open(root.path()).unwrap();
        trust.disk.revocations.insert(
            revocation_key(issuer.peer_id(), &record.token_id),
            StoredRevocation {
                record,
                relevant_until: format_time(now.saturating_sub(1)),
            },
        );
        let certificate = BindCertificate::sign(
            "43".repeat(16),
            guest.peer_id(),
            now.saturating_sub(2),
            "g".into(),
            [3; 32],
            scopes(),
            format_time(now.saturating_sub(1)),
            &issuer,
        )
        .unwrap();
        trust.disk.bind_certificates.insert(
            guest.peer_id(),
            StoredBindCertificate {
                issuer: issuer.peer_id(),
                certificate,
            },
        );
        trust.save().unwrap();
        let reopened = TrustStore::open(root.path()).unwrap();
        assert!(reopened.disk.revocations.is_empty());
        assert!(reopened.disk.bind_certificates.is_empty());
    }

    #[test]
    fn certificate_lifetime_and_future_revocation_are_bounded() {
        let issuer = Identity::generate();
        let guest = Identity::generate();
        let root = tempfile::tempdir().unwrap();
        let mut trust = TrustStore::open(root.path()).unwrap();
        trust.insert(full_peer(&issuer)).unwrap();
        let certificate = BindCertificate::sign(
            "42".repeat(16),
            guest.peer_id(),
            TEST_NOW,
            "g".into(),
            [4; 32],
            scopes(),
            format_time(TEST_NOW + MAX_CERTIFICATE_LIFETIME_MS + 1),
            &issuer,
        )
        .unwrap();
        assert!(trust
            .install_bind_certificate(issuer.peer_id(), certificate, TEST_NOW)
            .is_err());

        let future = Revocation::sign(
            "43".repeat(16),
            guest.peer_id(),
            TEST_NOW + CLOCK_SKEW_MS + 1,
            &issuer,
        )
        .unwrap();
        assert!(future.verify_at(TEST_NOW).is_err());
    }

    #[test]
    fn evicted_revocation_still_blocks_certificate_reinstall() {
        let root = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let guest = Identity::generate();
        let mut trust = TrustStore::open(root.path()).unwrap();
        trust.insert(full_peer(&issuer)).unwrap();
        let certificate = BindCertificate::sign(
            "42".repeat(16),
            guest.peer_id(),
            TEST_NOW,
            "g".into(),
            [4; 32],
            scopes(),
            format_time(TEST_NOW + 60_000),
            &issuer,
        )
        .unwrap();
        trust
            .install_bind_certificate(issuer.peer_id(), certificate.clone(), TEST_NOW)
            .unwrap();
        let record = Revocation::sign(
            certificate.token_id.clone(),
            guest.peer_id(),
            TEST_NOW + 1,
            &issuer,
        )
        .unwrap();
        trust.apply_revocations(&[record], TEST_NOW + 1).unwrap();
        trust.disk.revocations.clear();
        trust.save().unwrap();

        let mut reopened = TrustStore::open(root.path()).unwrap();
        assert!(reopened
            .install_bind_certificate(issuer.peer_id(), certificate, TEST_NOW + 2)
            .is_err());
    }

    #[test]
    fn current_revocations_prefers_newest_records() {
        let root = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let mut trust = TrustStore::open(root.path()).unwrap();
        for index in 0..=MAX_REVOCATIONS_PER_MESSAGE {
            let guest = Identity::generate();
            let record = Revocation::sign(
                format!("{index:032x}"),
                guest.peer_id(),
                TEST_NOW + index as u64,
                &issuer,
            )
            .unwrap();
            trust.disk.revocations.insert(
                revocation_key(issuer.peer_id(), &record.token_id),
                StoredRevocation {
                    record,
                    relevant_until: format_time(TEST_NOW + 60_000),
                },
            );
        }
        let records = trust.current_revocations(TEST_NOW);
        assert_eq!(records.len(), MAX_REVOCATIONS_PER_MESSAGE);
        assert_eq!(records[0].revoked_at, format_time(TEST_NOW + 128));
    }

    #[test]
    fn removing_peer_revokes_its_trust_and_delegated_guests() {
        let root = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let guest = Identity::generate();
        let other = Identity::generate();
        let token_id = "42".repeat(16);
        let mut trust = TrustStore::open(root.path()).unwrap();
        trust.insert(full_peer(&issuer)).unwrap();
        let certificate = BindCertificate::sign(
            token_id.clone(),
            guest.peer_id(),
            TEST_NOW,
            "guest".into(),
            [4; 32],
            scopes(),
            format_time(TEST_NOW + 60_000),
            &issuer,
        )
        .unwrap();
        trust
            .install_bind_certificate(issuer.peer_id(), certificate, TEST_NOW)
            .unwrap();

        assert!(trust.remove_peer(issuer.peer_id()).unwrap());
        assert!(!trust.remove_peer(issuer.peer_id()).unwrap());

        let reopened = TrustStore::open(root.path()).unwrap();
        assert!(reopened.get(&issuer.peer_id()).is_none());
        assert!(reopened.get(&guest.peer_id()).is_none());
        assert!(reopened.bind_certificate(&guest.peer_id()).is_none());
        assert!(reopened.is_revoked(&token_id));
        assert!(reopened
            .authorize_offer(
                issuer.peer_id(),
                other.peer_id(),
                None,
                "dev.abra.bundle",
                Direction::Send,
                TEST_NOW,
            )
            .is_err());
    }

    #[test]
    fn stale_save_cannot_restore_removed_peer() {
        let root = tempfile::tempdir().unwrap();
        let removed = Identity::generate();
        let unrelated = Identity::generate();
        let mut current = TrustStore::open(root.path()).unwrap();
        current.insert(full_peer(&removed)).unwrap();
        let mut stale = TrustStore::open(root.path()).unwrap();

        current.remove_peer(removed.peer_id()).unwrap();
        stale.insert(full_peer(&unrelated)).unwrap();

        let reopened = TrustStore::open(root.path()).unwrap();
        assert!(reopened.get(&removed.peer_id()).is_none());
        assert!(reopened.get(&unrelated.peer_id()).is_some());
    }

    #[test]
    fn stale_bind_certificate_cannot_outlive_removed_issuer() {
        let root = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let guest = Identity::generate();
        let mut current = TrustStore::open(root.path()).unwrap();
        current.insert(full_peer(&issuer)).unwrap();
        let mut stale = TrustStore::open(root.path()).unwrap();
        let certificate = BindCertificate::sign(
            "42".repeat(16),
            guest.peer_id(),
            TEST_NOW,
            "guest".into(),
            [4; 32],
            scopes(),
            format_time(TEST_NOW + 60_000),
            &issuer,
        )
        .unwrap();

        current.remove_peer(issuer.peer_id()).unwrap();
        assert!(stale
            .install_bind_certificate(issuer.peer_id(), certificate, TEST_NOW)
            .is_err());

        let reopened = TrustStore::open(root.path()).unwrap();
        assert!(reopened.get(&guest.peer_id()).is_none());
        assert!(reopened.bind_certificate(&guest.peer_id()).is_none());
    }

    #[test]
    fn removed_peer_needs_a_fresh_pairing_ticket() {
        let host_root = tempfile::tempdir().unwrap();
        let joiner_root = tempfile::tempdir().unwrap();
        let host = Identity::generate();
        let joiner = Identity::generate();
        let mut host_trust = TrustStore::open(host_root.path()).unwrap();
        let mut joiner_trust = TrustStore::open(joiner_root.path()).unwrap();

        let initial = PairTicket::mint(
            "host".into(),
            [1; 32],
            None,
            Vec::new(),
            TEST_NOW,
            60_000,
            &host,
        )
        .unwrap();
        host_trust.register_ticket(initial.clone()).unwrap();
        let initial_request = PairRequest::sign(
            initial.ticket_id.clone(),
            "joiner".into(),
            [2; 32],
            None,
            Vec::new(),
            [3; 16],
            &joiner,
        )
        .unwrap();
        let initial_accept = host_trust
            .accept_pair_request(
                &initial_request,
                joiner.peer_id(),
                TEST_NOW,
                true,
                |_, _| true,
            )
            .unwrap();
        joiner_trust
            .complete_pair_as_joiner(&initial, &initial_accept, &initial_request.nonce)
            .unwrap();

        let unused = PairTicket::mint(
            "host".into(),
            [1; 32],
            None,
            Vec::new(),
            TEST_NOW + 1,
            60_000,
            &host,
        )
        .unwrap();
        host_trust.register_ticket(unused.clone()).unwrap();
        let unused_request = PairRequest::sign(
            unused.ticket_id.clone(),
            "joiner".into(),
            [2; 32],
            None,
            Vec::new(),
            [4; 16],
            &joiner,
        )
        .unwrap();
        let pending = PairTicket::mint(
            "host".into(),
            [1; 32],
            None,
            Vec::new(),
            TEST_NOW + 2,
            60_000,
            &host,
        )
        .unwrap();
        host_trust.register_ticket(pending.clone()).unwrap();
        let pending_request = PairRequest::sign(
            pending.ticket_id.clone(),
            "joiner".into(),
            [2; 32],
            None,
            Vec::new(),
            [5; 16],
            &joiner,
        )
        .unwrap();
        host_trust
            .accept_pair_request(
                &pending_request,
                joiner.peer_id(),
                TEST_NOW + 2,
                false,
                |_, _| true,
            )
            .unwrap();

        host_trust.remove_peer(joiner.peer_id()).unwrap();
        joiner_trust.remove_peer(host.peer_id()).unwrap();
        assert!(host_trust
            .accept_pair_request(
                &unused_request,
                joiner.peer_id(),
                TEST_NOW + 3,
                true,
                |_, _| true,
            )
            .is_err());
        assert!(host_trust
            .confirm_pair(
                &PairConfirm {
                    message_type: "pair-confirm".into(),
                    ticket_id: pending.ticket_id,
                },
                joiner.peer_id(),
            )
            .is_err());
        assert!(joiner_trust
            .complete_pair_as_joiner(&initial, &initial_accept, &initial_request.nonce)
            .is_err());

        let fresh = PairTicket::mint(
            "host".into(),
            [1; 32],
            None,
            Vec::new(),
            TEST_NOW + 4,
            60_000,
            &host,
        )
        .unwrap();
        host_trust.register_ticket(fresh.clone()).unwrap();
        let fresh_request = PairRequest::sign(
            fresh.ticket_id.clone(),
            "joiner".into(),
            [2; 32],
            None,
            Vec::new(),
            [6; 16],
            &joiner,
        )
        .unwrap();
        let fresh_accept = host_trust
            .accept_pair_request(
                &fresh_request,
                joiner.peer_id(),
                TEST_NOW + 4,
                true,
                |_, _| true,
            )
            .unwrap();
        joiner_trust
            .complete_pair_as_joiner(&fresh, &fresh_accept, &fresh_request.nonce)
            .unwrap();
        assert!(host_trust.get(&joiner.peer_id()).is_some());
        assert!(joiner_trust.get(&host.peer_id()).is_some());
    }

    #[cfg(feature = "iroh")]
    #[test]
    fn persisted_observations_merge_relay_and_direct_address() {
        let root = tempfile::tempdir().unwrap();
        let peer = Identity::generate();
        let mut trust = TrustStore::open(root.path()).unwrap();
        let id = iroh::SecretKey::from_bytes(&[25; 32]).public();
        let direct = serde_json::to_string(
            &iroh::EndpointAddr::new(id).with_ip_addr("127.0.0.1:4242".parse().unwrap()),
        )
        .unwrap();
        let relay = serde_json::to_string(
            &iroh::EndpointAddr::new(id)
                .with_relay_url("https://relay.example.test".parse().unwrap()),
        )
        .unwrap();
        let mut trusted = full_peer(&peer);
        trusted.addresses = vec![direct.clone()];
        trust.insert(trusted).unwrap();
        trust
            .update_addresses(peer.peer_id(), vec![relay.clone()])
            .unwrap();
        let addresses = &trust.get(&peer.peer_id()).unwrap().addresses;
        assert_eq!(addresses.len(), 1);
        assert!(crate::transport::peer_address_has_direct_hint(
            &addresses[0]
        ));
        assert!(crate::transport::peer_address_has_relay_hint(&addresses[0]));
    }
}
