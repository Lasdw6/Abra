//! Browser-compatible capability links (SPEC §9 plus the AES-GCM erratum).
use crate::{
    canonical,
    cas::{materialize, Hash},
    identity::{Identity, Signature},
    manifest::{closure, RawManifest},
    store::AbraStore,
    util::atomic_write,
    Error, Result,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use data_encoding::BASE64URL_NOPAD;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

pub const MAGIC: &[u8; 8] = b"ABRACAP1";
pub const REVOKED_MAGIC: &[u8; 8] = b"ABRACAPX";
pub const ALG_AES_256_GCM: u8 = 2;
const HEADER_LEN: usize = 8 + 1 + 12 + 8 + 8;
/// Hard ceiling for an encrypted capability, including its header. This keeps
/// hostile links from forcing an unbounded allocation during decrypt/import.
pub const MAX_CAPABILITY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CAPABILITY_OBJECT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkMode {
    Floor,
    Full,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackBlob {
    pub digest: Hash,
    pub data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPack {
    pub spec: String,
    #[serde(rename = "type")]
    pub pack_type: String,
    pub snapshot_id: Hash,
    pub manifest_raw: String,
    pub blobs: Vec<PackBlob>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintRecord {
    pub link_id: String,
    pub snapshot_id: Hash,
    pub expires_at: String,
    pub mode: LinkMode,
    /// Deliberately fragment-free: the bearer key is never persisted.
    pub url: String,
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_hash: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_command: Option<String>,
    pub sig: Signature,
}

impl MintRecord {
    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value.as_object_mut().expect("record object").remove("sig");
        canonical::to_vec(&value)
    }

    pub fn verify(&self, identity: &Identity) -> Result<()> {
        identity
            .peer_id()
            .verify("cap-mint", &self.unsigned_bytes()?, &self.sig)
    }

    pub fn resign(&mut self, identity: &Identity) -> Result<()> {
        self.sig = identity.sign("cap-mint", &self.unsigned_bytes()?);
        Ok(())
    }
}

pub struct MintedLink {
    pub record: MintRecord,
    pub key: [u8; 32],
    pub blob: Vec<u8>,
}

pub fn find_snapshot(store: &AbraStore, id: Hash) -> Result<RawManifest> {
    if let Some(entry) = store.inbox.get(&id) {
        return RawManifest::parse(entry.manifest.clone());
    }
    for capsule in store.capsules.values() {
        if let Some(record) = capsule.snapshot(&id) {
            return Ok(record.raw.clone());
        }
    }
    Err(Error::not_found("snapshot", id.to_hex()))
}

pub fn mint(
    store: &AbraStore,
    raw: &RawManifest,
    expires_ms: u64,
    expires_at: String,
    mode: LinkMode,
    public_url: String,
) -> Result<MintedLink> {
    let hashes = match mode {
        LinkMode::Floor => raw
            .manifest()
            .thumbnail
            .iter()
            .map(|thumbnail| thumbnail.blob)
            .collect(),
        LinkMode::Full => closure(&store.cas, raw.manifest())?,
    };
    let mut encoded_bytes = base64_len(raw.bytes().len());
    let mut blobs = Vec::new();
    for digest in hashes {
        let bytes = store.cas.get(&digest)?;
        if bytes.len() > MAX_CAPABILITY_OBJECT_BYTES {
            return Err(Error::invalid("capability object exceeds 32 MiB limit"));
        }
        encoded_bytes = encoded_bytes
            .checked_add(base64_len(bytes.len()))
            .ok_or_else(|| Error::invalid("sealed capability bundle exceeds 64 MiB limit"))?;
        if encoded_bytes > MAX_CAPABILITY_BYTES - HEADER_LEN - 16 {
            return Err(Error::invalid(
                "sealed capability bundle exceeds 64 MiB limit",
            ));
        }
        blobs.push(PackBlob {
            digest,
            data: BASE64URL_NOPAD.encode(&bytes),
        });
    }
    let pack = CapabilityPack {
        spec: crate::SPEC.into(),
        pack_type: "capability-pack".into(),
        snapshot_id: raw.snapshot_id(),
        manifest_raw: BASE64URL_NOPAD.encode(raw.bytes()),
        blobs,
    };
    let plaintext = canonical::to_vec(&pack)?;
    let mut key = [0; 32];
    let mut nonce = [0; 12];
    let mut link_id = [0; 16];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(&mut link_id);
    let mut aad = Vec::with_capacity(29);
    aad.extend_from_slice(MAGIC);
    aad.push(ALG_AES_256_GCM);
    aad.extend_from_slice(&nonce);
    aad.extend_from_slice(&expires_ms.to_be_bytes());
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .expect("32-byte AES key")
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::invalid("capability encryption failed"))?;
    if HEADER_LEN + ciphertext.len() > MAX_CAPABILITY_BYTES {
        return Err(Error::invalid(
            "sealed capability bundle exceeds 64 MiB limit",
        ));
    }
    let mut blob = aad;
    blob.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    blob.extend_from_slice(&ciphertext);
    let mut record = MintRecord {
        link_id: hex::encode(link_id),
        snapshot_id: raw.snapshot_id(),
        expires_at,
        mode,
        url: public_url,
        revoked: false,
        ciphertext_hash: None,
        local_path: None,
        revoke_command: None,
        sig: Signature::from_bytes([0; 64]),
    };
    record.resign(&store.keys.identity)?;
    Ok(MintedLink { record, key, blob })
}

fn base64_len(bytes: usize) -> usize {
    bytes.saturating_mul(4).saturating_add(2) / 3
}

pub fn open(blob: &[u8], key: &[u8; 32], now_ms: u64) -> Result<CapabilityPack> {
    if blob.len() > MAX_CAPABILITY_BYTES {
        return Err(Error::invalid("capability blob exceeds 64 MiB limit"));
    }
    if blob.starts_with(REVOKED_MAGIC) {
        return Err(Error::invalid("capability link was revoked"));
    }
    if blob.len() < HEADER_LEN || &blob[..8] != MAGIC || blob[8] != ALG_AES_256_GCM {
        return Err(Error::invalid("invalid capability blob header"));
    }
    let expires = u64::from_be_bytes(blob[21..29].try_into().expect("header checked"));
    if now_ms > expires {
        return Err(Error::invalid("capability link expired"));
    }
    let ct_len_u64 = u64::from_be_bytes(blob[29..37].try_into().expect("header checked"));
    let ct_len = usize::try_from(ct_len_u64)
        .map_err(|_| Error::invalid("capability ciphertext length overflows platform"))?;
    if ct_len > MAX_CAPABILITY_BYTES - HEADER_LEN || blob.len() != HEADER_LEN + ct_len {
        return Err(Error::invalid("invalid capability ciphertext length"));
    }
    let plaintext = Aes256Gcm::new_from_slice(key)
        .expect("32-byte AES key")
        .decrypt(
            Nonce::from_slice(&blob[9..21]),
            Payload {
                msg: &blob[HEADER_LEN..],
                aad: &blob[..29],
            },
        )
        .map_err(|_| Error::invalid("wrong capability key or damaged blob"))?;
    let pack: CapabilityPack = serde_json::from_slice(&plaintext)?;
    if pack.spec != crate::SPEC || pack.pack_type != "capability-pack" {
        return Err(Error::invalid("invalid capability pack"));
    }
    let manifest = BASE64URL_NOPAD
        .decode(pack.manifest_raw.as_bytes())
        .map_err(|e| Error::encoding("base64url", e.to_string()))?;
    let raw = RawManifest::parse(manifest)?;
    if raw.snapshot_id() != pack.snapshot_id {
        return Err(Error::invalid("capability snapshot id mismatch"));
    }
    for object in &pack.blobs {
        let data = BASE64URL_NOPAD
            .decode(object.data.as_bytes())
            .map_err(|e| Error::encoding("base64url", e.to_string()))?;
        if Hash::of(&data) != object.digest {
            return Err(Error::invalid("capability object digest mismatch"));
        }
    }
    Ok(pack)
}

pub fn import(pack: &CapabilityPack, store: &AbraStore, destination: &Path) -> Result<RawManifest> {
    for object in &pack.blobs {
        let data = BASE64URL_NOPAD
            .decode(object.data.as_bytes())
            .map_err(|e| Error::encoding("base64url", e.to_string()))?;
        if store.cas.put(&data)? != object.digest {
            return Err(Error::invalid("capability object digest mismatch"));
        }
    }
    let raw = RawManifest::parse(
        BASE64URL_NOPAD
            .decode(pack.manifest_raw.as_bytes())
            .map_err(|e| Error::encoding("base64url", e.to_string()))?,
    )?;
    if let Some(root) = raw.manifest().files {
        materialize(&store.cas, &root, destination)?;
    } else {
        fs::create_dir_all(destination).map_err(|e| Error::io(destination, e))?;
    }
    Ok(raw)
}

pub fn save_record(store: &AbraStore, record: &MintRecord) -> Result<()> {
    let dir = store.root().join("links");
    fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    atomic_write(
        &dir.join(format!("{}.cjson", record.link_id)),
        &canonical::to_vec(record)?,
    )
}

pub fn list_records(store: &AbraStore) -> Result<Vec<MintRecord>> {
    let dir = store.root().join("links");
    let Ok(entries) = fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| Error::io(&dir, e))?.path();
        if path.extension().and_then(|x| x.to_str()) != Some("cjson") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|e| Error::io(&path, e))?;
        canonical::validate_canonical(&bytes)?;
        let record: MintRecord = serde_json::from_slice(&bytes)?;
        record.verify(&store.keys.identity)?;
        records.push(record);
    }
    records.sort_by(|a, b| a.link_id.cmp(&b.link_id));
    Ok(records)
}

pub fn revoke_record(store: &AbraStore, id: &str) -> Result<MintRecord> {
    let mut record = list_records(store)?
        .into_iter()
        .find(|record| record.link_id == id)
        .ok_or_else(|| Error::not_found("capability link", id))?;
    record.revoked = true;
    record.resign(&store.keys.identity)?;
    save_record(store, &record)?;
    if let Some(path) = record
        .local_path
        .as_deref()
        .or_else(|| record.url.strip_prefix("file://"))
    {
        let path = Path::new(path);
        if path.exists() {
            atomic_write(path, REVOKED_MAGIC)?;
        }
    }
    Ok(record)
}
