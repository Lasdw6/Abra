use crate::{auth::format_time, Error, Result};
use abra_core::{
    canonical,
    cas::Hash,
    identity::{PeerId, Signature},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

mod base64_bytes {
    use data_encoding::BASE64URL_NOPAD;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64URL_NOPAD.encode(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let value = String::deserialize(d)?;
        BASE64URL_NOPAD
            .decode(value.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

pub const OUTBOX_TTL_MS: u64 = 7 * 86_400_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    Queued,
    Healthcheck,
    Offered,
    Transferring,
    AwaitingAck,
    Acked,
    Failed,
    Cancelled,
    Expired,
}
impl OutboxState {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Acked | Self::Cancelled | Self::Expired)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxEntry {
    pub id: String,
    pub offer_id: String,
    pub peer_id: PeerId,
    pub snapshot_id: Hash,
    pub state: OutboxState,
    pub created_at: String,
    pub updated_at: String,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub ack_sig: Option<Signature>,
    pub next_attempt_at: String,
    #[serde(with = "base64_bytes")]
    pub manifest_raw: Vec<u8>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Disk {
    entries: BTreeMap<String, OutboxEntry>,
}
pub struct Outbox {
    path: PathBuf,
    disk: Disk,
    persist: bool,
}
fn random_id(bytes: usize) -> String {
    let mut v = vec![0; bytes];
    rand::thread_rng().fill(&mut v[..]);
    hex::encode(v)
}
impl Outbox {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let path = root.as_ref().join("outbox/net.cjson");
        let disk = match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Disk::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            disk,
            persist: true,
        })
    }
    fn save(&self) -> Result<()> {
        if !self.persist {
            return Ok(());
        }
        if let Some(p) = self.path.parent() {
            fs::create_dir_all(p)?
        }
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, canonical::to_vec(&self.disk)?)?;
        fs::OpenOptions::new().read(true).open(&tmp)?.sync_all()?;
        fs::rename(tmp, &self.path)?;
        fs::File::open(self.path.parent().expect("outbox parent"))?.sync_all()?;
        Ok(())
    }
    pub fn detached(&self) -> Self {
        Self {
            path: self.path.clone(),
            disk: self.disk.clone(),
            persist: false,
        }
    }
    pub fn sync_entry_from(&mut self, other: &Self, id: &str) -> Result<()> {
        if self.disk.entries.get(id).is_some_and(|entry| {
            matches!(entry.state, OutboxState::Cancelled | OutboxState::Expired)
        }) {
            return Ok(());
        }
        let entry = other
            .disk
            .entries
            .get(id)
            .cloned()
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        self.disk.entries.insert(id.to_owned(), entry);
        self.save()
    }
    pub fn enqueue(
        &mut self,
        peer_id: PeerId,
        snapshot_id: Hash,
        manifest_raw: Vec<u8>,
        now: u64,
    ) -> Result<String> {
        let id = random_id(16);
        let x = OutboxEntry {
            id: id.clone(),
            offer_id: random_id(16),
            peer_id,
            snapshot_id,
            state: OutboxState::Queued,
            created_at: format_time(now),
            updated_at: format_time(now),
            attempts: 0,
            last_error: None,
            ack_sig: None,
            next_attempt_at: format_time(now),
            manifest_raw,
        };
        self.disk.entries.insert(id.clone(), x);
        self.save()?;
        Ok(id)
    }
    pub fn get(&self, id: &str) -> Option<&OutboxEntry> {
        self.disk.entries.get(id)
    }
    pub fn entries(&self) -> impl Iterator<Item = &OutboxEntry> {
        self.disk.entries.values()
    }
    pub fn pending_ids(&self, now: u64) -> Vec<String> {
        self.disk
            .entries
            .values()
            .filter(|e| !e.state.terminal() && e.state != OutboxState::Failed)
            .filter(|e| crate::auth::parse_time(&e.next_attempt_at).is_ok_and(|t| t <= now))
            .map(|e| e.id.clone())
            .collect()
    }
    pub fn transition(&mut self, id: &str, state: OutboxState, now: u64) -> Result<()> {
        let e = self
            .disk
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        let legal = matches!(
            (e.state, state),
            (OutboxState::Queued, OutboxState::Healthcheck)
                | (
                    OutboxState::Offered | OutboxState::Transferring | OutboxState::AwaitingAck,
                    OutboxState::Healthcheck
                )
                | (OutboxState::Healthcheck, OutboxState::Offered)
                | (OutboxState::Offered, OutboxState::Transferring)
                | (OutboxState::Transferring, OutboxState::AwaitingAck)
                | (
                    OutboxState::Healthcheck
                        | OutboxState::Offered
                        | OutboxState::Transferring
                        | OutboxState::AwaitingAck,
                    OutboxState::Queued
                )
        );
        if !legal {
            return Err(Error::protocol("illegal outbox transition"));
        }
        e.state = state;
        e.updated_at = format_time(now);
        self.save()
    }
    pub fn fail_attempt(&mut self, id: &str, error: String, now: u64) -> Result<()> {
        let e = self
            .disk
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        e.attempts += 1;
        e.last_error = Some(error);
        if e.attempts >= 20 {
            e.state = OutboxState::Failed
        } else {
            e.state = OutboxState::Queued;
            let base =
                (1000u64.saturating_mul(1u64 << e.attempts.saturating_sub(1).min(18))).min(300_000);
            let pct = rand::thread_rng().gen_range(80..=120);
            e.next_attempt_at = format_time(now + base * pct / 100);
        }
        e.updated_at = format_time(now);
        self.save()
    }
    pub fn retry_fresh(&mut self, id: &str, now: u64) -> Result<String> {
        let e = self
            .disk
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        e.offer_id = random_id(16);
        e.state = OutboxState::Queued;
        e.attempts = 0;
        e.ack_sig = None;
        e.updated_at = format_time(now);
        e.next_attempt_at = format_time(now);
        let offer = e.offer_id.clone();
        self.save()?;
        Ok(offer)
    }
    pub fn apply_ack(
        &mut self,
        id: &str,
        ack: &crate::Ack,
        local_peer: PeerId,
        now: u64,
    ) -> Result<bool> {
        let e = self
            .disk
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        if !matches!(e.state, OutboxState::AwaitingAck | OutboxState::Healthcheck)
            || e.offer_id != ack.offer_id
            || e.snapshot_id != ack.snapshot_id
        {
            return Ok(false);
        }
        ack.verify(local_peer, e.peer_id)?;
        e.state = OutboxState::Acked;
        e.ack_sig = Some(ack.sig);
        e.updated_at = format_time(now);
        self.save()?;
        Ok(true)
    }
    pub fn mark_relay_deposited(&mut self, id: &str, now: u64) -> Result<()> {
        let e = self
            .disk
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        if !e.state.terminal() {
            e.state = OutboxState::AwaitingAck;
            e.updated_at = format_time(now);
            e.next_attempt_at = format_time(now.saturating_add(60_000));
            self.save()?;
        }
        Ok(())
    }
    pub fn expire(&mut self, now: u64) -> Result<()> {
        for e in self.disk.entries.values_mut() {
            if e.state == OutboxState::Queued && age_ms(&e.created_at, now) > OUTBOX_TTL_MS {
                e.state = OutboxState::Expired;
                e.updated_at = format_time(now)
            }
        }
        self.save()
    }
    pub fn cancel(&mut self, id: &str, now: u64) -> Result<()> {
        let e = self
            .disk
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        if e.state.terminal() || e.state == OutboxState::Failed {
            return Err(Error::protocol("cannot cancel terminal outbox entry"));
        }
        e.state = OutboxState::Cancelled;
        e.updated_at = format_time(now);
        self.save()
    }
}

fn age_ms(created: &str, now: u64) -> u64 {
    crate::auth::parse_time(created).map_or(u64::MAX, |t| now.saturating_sub(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use abra_core::identity::Identity;

    #[test]
    fn pending_selection_respects_backoff_and_preserves_failure() {
        let root = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::open(root.path()).unwrap();
        let id = outbox
            .enqueue(
                Identity::generate().peer_id(),
                Hash::of(b"snapshot"),
                b"manifest".to_vec(),
                1_000,
            )
            .unwrap();
        outbox
            .fail_attempt(&id, "first dial failed".into(), 1_000)
            .unwrap();

        let entry = outbox.get(&id).unwrap().clone();
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.last_error.as_deref(), Some("first dial failed"));
        assert!(!outbox.pending_ids(1_000).contains(&id));

        let retry_at = crate::auth::parse_time(&entry.next_attempt_at).unwrap();
        assert!(outbox.pending_ids(retry_at).contains(&id));
        let unchanged = outbox.get(&id).unwrap();
        assert_eq!(unchanged.attempts, 1);
        assert_eq!(unchanged.last_error.as_deref(), Some("first dial failed"));
    }
}
