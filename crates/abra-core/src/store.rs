//! Filesystem shelves tying keys, CAS, capsules, and inbox together (SPEC §4).
use crate::{
    capsule::{Capsule, Genesis, WriteResult},
    cas::{BlobStore, Hash},
    identity::DeviceKeys,
    manifest::RawManifest,
    Error, Result,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
#[derive(Clone, Debug)]
pub struct InboxEntry {
    pub snapshot_id: Hash,
    pub manifest: Vec<u8>,
    pub from: String,
    pub received_at: String,
    pub read: bool,
}
/// Persisted pending delivery root (SPEC §4; protocol fields arrive in stage 2).
#[derive(Clone, Debug)]
pub struct OutboxEntry {
    pub snapshot_id: Hash,
    pub manifest: Vec<u8>,
}
pub struct AbraStore {
    root: PathBuf,
    pub cas: BlobStore,
    pub keys: DeviceKeys,
    pub capsules: BTreeMap<Hash, Capsule>,
    pub inbox: BTreeMap<Hash, InboxEntry>,
    pub outbox: BTreeMap<Hash, OutboxEntry>,
}
impl AbraStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        for d in ["capsules", "inbox", "outbox", "keys"] {
            fs::create_dir_all(root.join(d)).map_err(|e| Error::io(root.join(d), e))?
        }
        let cas = BlobStore::open(&root)?;
        let keys = DeviceKeys::load_or_generate(root.join("keys/device.json"))?;
        Ok(Self {
            root,
            cas,
            keys,
            capsules: BTreeMap::new(),
            inbox: BTreeMap::new(),
            outbox: BTreeMap::new(),
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn add_capsule(&mut self, g: Genesis) -> Result<()> {
        let id = g.capsule_id;
        let bytes = g.bytes()?;
        fs::create_dir_all(self.root.join("capsules").join(id.to_hex()))
            .map_err(|e| Error::io(&self.root, e))?;
        fs::write(
            self.root
                .join("capsules")
                .join(id.to_hex())
                .join("genesis.cjson"),
            bytes,
        )
        .map_err(|e| Error::io(&self.root, e))?;
        self.capsules.insert(id, Capsule::new(g)?);
        Ok(())
    }
    pub fn receive_partial(&mut self, raw: RawManifest, from: String, at: String) -> Result<Hash> {
        if raw.manifest().scope != crate::manifest::Scope::Partial {
            return Err(Error::invalid("inbox accepts partial snapshots only"));
        }
        let id = raw.snapshot_id();
        let bytes = raw.bytes().to_vec();
        fs::write(
            self.root.join("inbox").join(format!("{}.cjson", id)),
            &bytes,
        )
        .map_err(|e| Error::io(&self.root, e))?;
        self.inbox.insert(
            id,
            InboxEntry {
                snapshot_id: id,
                manifest: bytes,
                from,
                received_at: at,
                read: false,
            },
        );
        Ok(id)
    }

    /// Persist exact full-manifest bytes and update orphan/fork state (SPEC §§2, 5).
    pub fn receive_full(&mut self, raw: RawManifest, at: String) -> Result<WriteResult> {
        let capsule_id = raw
            .manifest()
            .capsule_id
            .ok_or_else(|| Error::invalid("full manifest lacks capsule id"))?;
        let writer = raw.manifest().origin.peer_id;
        let id = raw.snapshot_id();
        let bytes = raw.bytes().to_vec();
        let capsule = self
            .capsules
            .get_mut(&capsule_id)
            .ok_or_else(|| Error::not_found("capsule", capsule_id.to_hex()))?;
        let result = capsule.insert_snapshot(raw, at, writer)?;
        let dir = self
            .root
            .join("capsules")
            .join(capsule_id.to_hex())
            .join("snapshots");
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        fs::write(dir.join(format!("{}.cjson", id)), bytes).map_err(|e| Error::io(&dir, e))?;
        Ok(result)
    }
}
