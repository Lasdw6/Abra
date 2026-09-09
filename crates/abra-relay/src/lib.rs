#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_MAX_ENVELOPE: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_STORAGE_BYTES: usize = 1024 * 1024 * 1024;
pub const MAX_TTL_MS: u64 = 30 * 86_400_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueEnvelope {
    pub version: u8,
    pub tag: String,
    pub expires_at: u64,
    pub sealed: String,
}

#[derive(Clone)]
struct Item {
    envelope: Vec<u8>,
    expires_at: u64,
    tag: String,
}

pub struct RelayStore {
    secret: Vec<u8>,
    max_envelope_bytes: usize,
    max_storage_bytes: usize,
    storage_bytes: usize,
    entries_dir: Option<PathBuf>,
    _lock_file: Option<File>,
    items: BTreeMap<String, Item>,
}

impl RelayStore {
    /// Creates an in-memory store. The relay binary uses [`RelayStore::open`]
    /// so accepted envelopes survive process restarts.
    pub fn new(secret: impl Into<Vec<u8>>, max: usize) -> Self {
        Self {
            secret: secret.into(),
            max_envelope_bytes: max,
            max_storage_bytes: usize::MAX,
            storage_bytes: 0,
            entries_dir: None,
            _lock_file: None,
            items: BTreeMap::new(),
        }
    }

    /// Opens a durable queue rooted at `data_dir`.
    ///
    /// Startup fails if a stored envelope is corrupt. This avoids silently
    /// dropping data that the relay previously acknowledged.
    pub fn open(
        secret: impl Into<Vec<u8>>,
        max_envelope_bytes: usize,
        max_storage_bytes: usize,
        data_dir: impl AsRef<Path>,
        now: u64,
    ) -> Result<Self, String> {
        if max_storage_bytes < max_envelope_bytes {
            return Err("relay storage cap must be at least the envelope size cap".into());
        }
        let entries_dir = data_dir.as_ref().join("entries");
        fs::create_dir_all(&entries_dir).map_err(|e| {
            format!(
                "cannot create relay data directory {}: {e}",
                entries_dir.display()
            )
        })?;
        let lock_path = data_dir.as_ref().join("relay.lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| format!("cannot open relay data lock {}: {e}", lock_path.display()))?;
        fs2::FileExt::try_lock_exclusive(&lock_file).map_err(|e| {
            format!(
                "cannot lock relay data directory {}: {e}; another relay process may be using it",
                data_dir.as_ref().display()
            )
        })?;

        let mut store = Self {
            secret: secret.into(),
            max_envelope_bytes,
            max_storage_bytes,
            storage_bytes: 0,
            entries_dir: Some(entries_dir.clone()),
            _lock_file: Some(lock_file),
            items: BTreeMap::new(),
        };
        let entries = fs::read_dir(&entries_dir).map_err(|e| {
            format!(
                "cannot read relay data directory {}: {e}",
                entries_dir.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read relay queue entry: {e}"))?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".tmp-") {
                fs::remove_file(&path).map_err(|e| {
                    format!(
                        "cannot remove interrupted relay write {}: {e}",
                        path.display()
                    )
                })?;
                continue;
            }
            if !entry
                .file_type()
                .map_err(|e| format!("cannot inspect relay queue entry {}: {e}", path.display()))?
                .is_file()
            {
                return Err(format!(
                    "unexpected entry in relay queue: {}",
                    path.display()
                ));
            }
            let envelope = fs::read(&path)
                .map_err(|e| format!("cannot read relay queue entry {}: {e}", path.display()))?;
            let id = blake3::hash(&envelope).to_hex().to_string();
            if name.as_ref() != id {
                return Err(format!(
                    "relay queue entry has invalid name: {}",
                    path.display()
                ));
            }
            let parsed = parse_envelope(&envelope, max_envelope_bytes)
                .map_err(|e| format!("invalid stored relay envelope {}: {e}", path.display()))?;
            if parsed.expires_at <= now {
                fs::remove_file(&path).map_err(|e| {
                    format!(
                        "cannot remove expired relay envelope {}: {e}",
                        path.display()
                    )
                })?;
                continue;
            }
            store.storage_bytes = store
                .storage_bytes
                .checked_add(envelope.len())
                .ok_or("relay storage size overflow")?;
            if store.storage_bytes > max_storage_bytes {
                return Err(format!(
                    "stored relay queue exceeds configured {} byte storage cap",
                    max_storage_bytes
                ));
            }
            store.items.insert(
                id,
                Item {
                    envelope,
                    expires_at: parsed.expires_at,
                    tag: parsed.tag,
                },
            );
        }
        sync_directory(&entries_dir)?;
        Ok(store)
    }

    pub fn enqueue(
        &mut self,
        deploy_secret: &[u8],
        envelope: Vec<u8>,
        now: u64,
    ) -> Result<String, String> {
        self.authorize(deploy_secret)?;
        let parsed = parse_envelope(&envelope, self.max_envelope_bytes)?;
        if parsed.expires_at <= now || parsed.expires_at - now > MAX_TTL_MS {
            return Err("invalid relay TTL".into());
        }
        self.expire(now)?;
        let id = blake3::hash(&envelope).to_hex().to_string();
        if self.items.contains_key(&id) {
            return Ok(id);
        }
        let next_size = self
            .storage_bytes
            .checked_add(envelope.len())
            .ok_or("relay storage size overflow")?;
        if next_size > self.max_storage_bytes {
            return Err(format!(
                "relay storage cap reached ({} byte limit)",
                self.max_storage_bytes
            ));
        }
        self.persist_new(&id, &envelope)?;
        self.items.insert(
            id.clone(),
            Item {
                envelope,
                expires_at: parsed.expires_at,
                tag: parsed.tag,
            },
        );
        self.storage_bytes = next_size;
        Ok(id)
    }

    pub fn poll(
        &mut self,
        deploy_secret: &[u8],
        tags: &[String],
        now: u64,
        delete_on_fetch: bool,
    ) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.poll_bounded(
            deploy_secret,
            tags,
            now,
            delete_on_fetch,
            usize::MAX,
            usize::MAX,
        )
    }

    pub fn poll_bounded(
        &mut self,
        deploy_secret: &[u8],
        tags: &[String],
        now: u64,
        delete_on_fetch: bool,
        max_items: usize,
        max_bytes: usize,
    ) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.authorize(deploy_secret)?;
        self.expire(now)?;
        let mut ids = Vec::new();
        let mut bytes = 0usize;
        for (id, item) in self
            .items
            .iter()
            .filter(|(_, item)| tags.contains(&item.tag))
        {
            if ids.len() >= max_items {
                break;
            }
            let Some(next_bytes) = bytes.checked_add(item.envelope.len()) else {
                continue;
            };
            if next_bytes > max_bytes {
                continue;
            }
            bytes = next_bytes;
            ids.push(id.clone());
        }
        let mut found = Vec::with_capacity(ids.len());
        for id in ids {
            if delete_on_fetch {
                let envelope = self
                    .items
                    .get(&id)
                    .expect("id was collected from the store")
                    .envelope
                    .clone();
                self.remove(&id)?;
                found.push((id, envelope));
            } else if let Some(item) = self.items.get(&id) {
                found.push((id, item.envelope.clone()));
            }
        }
        Ok(found)
    }

    pub fn delete(&mut self, deploy_secret: &[u8], id: &str) -> Result<bool, String> {
        self.authorize(deploy_secret)?;
        self.remove(id)
    }

    pub fn expire(&mut self, now: u64) -> Result<(), String> {
        let expired = self
            .items
            .iter()
            .filter(|(_, item)| item.expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            self.remove(&id)?;
        }
        Ok(())
    }

    pub fn storage_bytes(&self) -> usize {
        self.storage_bytes
    }

    pub fn authenticate(&self, deploy_secret: &[u8]) -> Result<(), String> {
        self.authorize(deploy_secret)
    }

    fn authorize(&self, supplied: &[u8]) -> Result<(), String> {
        let expected = hmac_sha256(&self.secret, b"abra-relay-deploy-v1");
        let candidate = hmac_sha256(supplied, b"abra-relay-deploy-v1");
        if constant_time_eq(&expected, &candidate) {
            Ok(())
        } else {
            Err("unauthorized".into())
        }
    }

    fn persist_new(&self, id: &str, envelope: &[u8]) -> Result<(), String> {
        let Some(dir) = &self.entries_dir else {
            return Ok(());
        };
        let target = dir.join(id);
        let temporary = dir.join(format!(".tmp-{id}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| {
                format!(
                    "cannot create relay queue entry {}: {e}",
                    temporary.display()
                )
            })?;
        if let Err(error) = file.write_all(envelope).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(format!(
                "cannot persist relay queue entry {}: {error}",
                temporary.display()
            ));
        }
        if let Err(error) = fs::rename(&temporary, &target) {
            let _ = fs::remove_file(&temporary);
            return Err(format!(
                "cannot publish relay queue entry {}: {error}",
                target.display()
            ));
        }
        sync_directory(dir)
    }

    fn remove(&mut self, id: &str) -> Result<bool, String> {
        let Some(item) = self.items.get(id) else {
            return Ok(false);
        };
        if let Some(dir) = &self.entries_dir {
            let path = dir.join(id);
            match fs::remove_file(&path) {
                Ok(()) => sync_directory(dir)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(format!(
                        "cannot delete relay queue entry {}: {e}",
                        path.display()
                    ))
                }
            }
        }
        let size = item.envelope.len();
        self.items.remove(id);
        self.storage_bytes -= size;
        Ok(true)
    }
}

fn parse_envelope(envelope: &[u8], max: usize) -> Result<OpaqueEnvelope, String> {
    if envelope.len() > max {
        return Err("envelope exceeds relay size cap".into());
    }
    let parsed: OpaqueEnvelope =
        serde_json::from_slice(envelope).map_err(|_| "invalid relay envelope")?;
    if parsed.version != 1
        || parsed.tag.len() != 64
        || !parsed.tag.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid relay envelope".into());
    }
    Ok(parsed)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| format!("cannot sync relay data directory {}: {e}", path.display()))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..64 {
        inner[i] ^= block[i];
        outer[i] ^= block[i];
    }
    let ih = Sha256::digest([inner.as_slice(), message].concat());
    Sha256::digest([outer.as_slice(), ih.as_slice()].concat()).into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y
    }
    d == 0
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(tag: &str, expiry: u64, sealed: &str) -> Vec<u8> {
        serde_json::to_vec(&OpaqueEnvelope {
            version: 1,
            tag: tag.into(),
            expires_at: expiry,
            sealed: sealed.into(),
        })
        .unwrap()
    }

    #[test]
    fn caps_expiry_unknown_tags_and_blind_storage() {
        let mut store = RelayStore::new(b"secret".to_vec(), 1024);
        let tag = "aa".repeat(32);
        let bytes = env(&tag, 200, "ciphertext-not-plaintext");
        let id = store.enqueue(b"secret", bytes.clone(), 100).unwrap();
        assert!(store
            .poll(b"secret", &["bb".repeat(32)], 100, false)
            .unwrap()
            .is_empty());
        let fetched = store.poll(b"secret", &[tag], 100, false).unwrap();
        assert_eq!(fetched[0].1, bytes);
        assert!(!String::from_utf8_lossy(&fetched[0].1).contains("private payload"));
        assert!(store
            .poll(b"secret", &["aa".repeat(32)], 201, false)
            .unwrap()
            .is_empty());
        assert!(!store.delete(b"secret", &id).unwrap());
        assert!(store.enqueue(b"secret", vec![0; 1025], 100).is_err());
    }

    #[test]
    fn durable_queue_survives_restart_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let tag = "ab".repeat(32);
        let bytes = env(&tag, 500, "sealed");
        let id = {
            let mut store = RelayStore::open(b"secret", 1024, 4096, dir.path(), 100).unwrap();
            store.enqueue(b"secret", bytes.clone(), 100).unwrap()
        };
        let mut reopened = RelayStore::open(b"secret", 1024, 4096, dir.path(), 101).unwrap();
        assert_eq!(reopened.storage_bytes(), bytes.len());
        assert_eq!(
            reopened.poll(b"secret", &[tag], 101, false).unwrap(),
            vec![(id.clone(), bytes)]
        );
        assert!(reopened.delete(b"secret", &id).unwrap());
        drop(reopened);
        let mut reopened = RelayStore::open(b"secret", 1024, 4096, dir.path(), 102).unwrap();
        assert!(reopened
            .poll(b"secret", &["ab".repeat(32)], 102, false)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn durable_queue_rejects_corruption_instead_of_dropping_it() {
        let dir = tempfile::tempdir().unwrap();
        let entries = dir.path().join("entries");
        fs::create_dir(&entries).unwrap();
        fs::write(entries.join("not-an-envelope"), b"broken").unwrap();
        let error = RelayStore::open(b"secret", 1024, 4096, dir.path(), 100)
            .err()
            .expect("corrupt queue must fail startup");
        assert!(error.contains("invalid name"));
    }

    #[test]
    fn startup_cleans_an_interrupted_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let entries = dir.path().join("entries");
        fs::create_dir(&entries).unwrap();
        fs::write(entries.join(".tmp-interrupted"), b"partial envelope").unwrap();
        let store = RelayStore::open(b"secret", 1024, 4096, dir.path(), 100).unwrap();
        assert_eq!(store.storage_bytes(), 0);
        assert!(!entries.join(".tmp-interrupted").exists());
    }

    #[test]
    fn durable_queue_refuses_a_second_process_owner() {
        let dir = tempfile::tempdir().unwrap();
        let first = RelayStore::open(b"secret", 1024, 4096, dir.path(), 100).unwrap();
        let error = RelayStore::open(b"secret", 1024, 4096, dir.path(), 100)
            .err()
            .expect("second owner must not share the queue");
        assert!(error.contains("another relay process may be using it"));
        drop(first);
        assert!(RelayStore::open(b"secret", 1024, 4096, dir.path(), 100).is_ok());
    }

    #[test]
    fn storage_cap_backpressures_unique_items_but_allows_retry() {
        let dir = tempfile::tempdir().unwrap();
        let tag = "cd".repeat(32);
        let first = env(&tag, 500, "one");
        let second = env(&tag, 500, "two");
        let cap = first.len() + second.len() - 1;
        let max_envelope = first.len().max(second.len());
        let mut store = RelayStore::open(b"secret", max_envelope, cap, dir.path(), 100).unwrap();
        let first_id = store.enqueue(b"secret", first, 100).unwrap();
        assert_eq!(
            store.enqueue(b"secret", second, 100).unwrap_err(),
            format!("relay storage cap reached ({cap} byte limit)")
        );
        assert_eq!(
            store
                .enqueue(b"secret", env(&tag, 500, "one"), 100)
                .unwrap(),
            first_id
        );
    }

    #[test]
    fn unauthorized_requests_cannot_read_or_change_durable_queue() {
        let dir = tempfile::tempdir().unwrap();
        let tag = "ef".repeat(32);
        let bytes = env(&tag, 500, "sealed");
        let mut store = RelayStore::open(b"secret", 1024, 4096, dir.path(), 100).unwrap();
        let id = store.enqueue(b"secret", bytes.clone(), 100).unwrap();
        assert_eq!(
            store.poll(b"wrong", &[tag], 100, true).unwrap_err(),
            "unauthorized"
        );
        assert_eq!(store.delete(b"wrong", &id).unwrap_err(), "unauthorized");
        drop(store);
        let mut reopened = RelayStore::open(b"secret", 1024, 4096, dir.path(), 101).unwrap();
        assert_eq!(
            reopened
                .poll(b"secret", &["ef".repeat(32)], 101, false)
                .unwrap()[0]
                .1,
            bytes
        );
    }

    #[test]
    fn delete_reports_disk_failure_without_forgetting_the_item() {
        let dir = tempfile::tempdir().unwrap();
        let tag = "12".repeat(32);
        let bytes = env(&tag, 500, "sealed");
        let mut store = RelayStore::open(b"secret", 1024, 4096, dir.path(), 100).unwrap();
        let id = store.enqueue(b"secret", bytes.clone(), 100).unwrap();
        let entry = dir.path().join("entries").join(&id);
        fs::remove_file(&entry).unwrap();
        fs::create_dir(&entry).unwrap();

        let error = store.delete(b"secret", &id).unwrap_err();
        assert!(error.contains("cannot delete relay queue entry"));
        assert_eq!(store.storage_bytes(), bytes.len());
        assert_eq!(
            store.poll(b"secret", &[tag], 100, false).unwrap()[0].1,
            bytes
        );
    }

    #[test]
    fn bounded_poll_leaves_unreturned_items_queued() {
        let mut store = RelayStore::new(b"secret", 1024);
        let tag = "34".repeat(32);
        for sealed in ["one", "two", "three"] {
            store
                .enqueue(b"secret", env(&tag, 500, sealed), 100)
                .unwrap();
        }
        let first = store
            .poll_bounded(b"secret", std::slice::from_ref(&tag), 100, true, 1, 1024)
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(store.poll(b"secret", &[tag], 100, false).unwrap().len(), 2);
    }
}
