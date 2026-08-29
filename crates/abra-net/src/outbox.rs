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
    pub manifest_raw: Vec<u8>,
}
#[derive(Default, Serialize, Deserialize)]
struct Disk {
    entries: BTreeMap<String, OutboxEntry>,
}
pub struct Outbox {
    path: PathBuf,
    disk: Disk,
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
        Ok(Self { path, disk })
    }
    fn save(&self) -> Result<()> {
        if let Some(p) = self.path.parent() {
            fs::create_dir_all(p)?
        }
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, canonical::to_vec(&self.disk)?)?;
        fs::OpenOptions::new().read(true).open(&tmp)?.sync_all()?;
        fs::rename(tmp, &self.path)?;
        Ok(())
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
    pub fn pending_ids(&self) -> Vec<String> {
        self.disk
            .entries
            .values()
            .filter(|e| !e.state.terminal() && e.state != OutboxState::Failed)
            .map(|e| e.id.clone())
            .collect()
    }
    pub fn transition(&mut self, id: &str, state: OutboxState, now: u64) -> Result<()> {
        let e = self
            .disk
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
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
            let base = (1000u64.saturating_mul(1u64 << e.attempts.min(18))).min(300_000);
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
    pub fn mark_acked(
        &mut self,
        id: &str,
        offer_id: &str,
        snapshot_id: Hash,
        sig: Signature,
        now: u64,
    ) -> Result<bool> {
        let e = self
            .disk
            .entries
            .get_mut(id)
            .ok_or_else(|| Error::protocol("unknown outbox id"))?;
        if e.offer_id != offer_id || e.snapshot_id != snapshot_id {
            return Ok(false);
        }
        e.state = OutboxState::Acked;
        e.ack_sig = Some(sig);
        e.updated_at = format_time(now);
        self.save()?;
        Ok(true)
    }
    pub fn expire(&mut self, now: u64) -> Result<()> {
        for e in self.disk.entries.values_mut() {
            if !e.state.terminal() && age_ms(&e.created_at, now) > OUTBOX_TTL_MS {
                e.state = OutboxState::Expired;
                e.updated_at = format_time(now)
            }
        }
        self.save()
    }
}
fn age_ms(created: &str, now: u64) -> u64 {
    crate::auth::parse_time(created).map_or(u64::MAX, |t| now.saturating_sub(t))
}
