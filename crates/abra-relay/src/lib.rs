#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_MAX_ENVELOPE: usize = 16 * 1024 * 1024;
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
    max: usize,
    items: BTreeMap<String, Item>,
}

impl RelayStore {
    pub fn new(secret: impl Into<Vec<u8>>, max: usize) -> Self {
        Self {
            secret: secret.into(),
            max,
            items: BTreeMap::new(),
        }
    }
    pub fn enqueue(
        &mut self,
        deploy_secret: &[u8],
        envelope: Vec<u8>,
        now: u64,
    ) -> Result<String, String> {
        self.authorize(deploy_secret)?;
        if envelope.len() > self.max {
            return Err("envelope exceeds relay size cap".into());
        }
        let parsed: OpaqueEnvelope =
            serde_json::from_slice(&envelope).map_err(|_| "invalid relay envelope")?;
        if parsed.version != 1
            || parsed.tag.len() != 64
            || !parsed.tag.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid relay envelope".into());
        }
        if parsed.expires_at <= now || parsed.expires_at - now > MAX_TTL_MS {
            return Err("invalid relay TTL".into());
        }
        let id = blake3::hash(&envelope).to_hex().to_string();
        self.items.insert(
            id.clone(),
            Item {
                envelope,
                expires_at: parsed.expires_at,
                tag: parsed.tag,
            },
        );
        Ok(id)
    }
    pub fn poll(
        &mut self,
        deploy_secret: &[u8],
        tags: &[String],
        now: u64,
        delete_on_fetch: bool,
    ) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.authorize(deploy_secret)?;
        self.expire(now);
        let ids = self
            .items
            .iter()
            .filter(|(_, item)| tags.contains(&item.tag))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        Ok(ids
            .into_iter()
            .filter_map(|id| {
                if delete_on_fetch {
                    self.items.remove(&id).map(|x| (id, x.envelope))
                } else {
                    self.items.get(&id).map(|x| (id, x.envelope.clone()))
                }
            })
            .collect())
    }
    pub fn delete(&mut self, deploy_secret: &[u8], id: &str) -> Result<bool, String> {
        self.authorize(deploy_secret)?;
        Ok(self.items.remove(id).is_some())
    }
    pub fn expire(&mut self, now: u64) {
        self.items.retain(|_, item| item.expires_at > now);
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
}
