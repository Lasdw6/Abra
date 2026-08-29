//! Durable filesystem shelves tying keys, CAS, capsules, and inbox together.
use crate::{
    canonical,
    capsule::{Capsule, Genesis, LabelOp, LeaseMode, LeaseRecord, WriteResult},
    cas::{BlobStore, Hash},
    identity::{DeviceKeys, Identity, PeerId},
    manifest::{RawManifest, Scope},
    Error, Result,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxEntry {
    pub snapshot_id: Hash,
    pub manifest: Vec<u8>,
    pub from: String,
    pub received_at: String,
    pub read: bool,
}
#[derive(Clone, Debug)]
pub struct OutboxEntry {
    pub snapshot_id: Hash,
    pub manifest: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxDisk {
    spec: String,
    snapshot_id: Hash,
    manifest: String,
    from: String,
    received_at: String,
    read: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMeta {
    spec: String,
    received_at: String,
}

#[derive(Clone)]
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
        if !root.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(&root).map_err(|e| Error::io(&root, e))?;
        }
        #[cfg(unix)]
        {
            let mode = fs::symlink_metadata(&root)
                .map_err(|e| Error::io(&root, e))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                if fs::read_dir(&root)
                    .map_err(|e| Error::io(&root, e))?
                    .next()
                    .is_none()
                {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                        .map_err(|e| Error::io(&root, e))?;
                } else {
                    return Err(Error::corrupt(
                        "store permissions",
                        format!(
                            "{} must not be group/world accessible (mode {:o})",
                            root.display(),
                            mode & 0o777
                        ),
                    ));
                }
            }
        }
        for d in [
            "capsules", "inbox", "outbox", "keys", "objects", "tmp", "net",
        ] {
            let path = root.join(d);
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(&path).map_err(|e| Error::io(&path, e))?;
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::io(&path, e))?;
        }
        let cas = BlobStore::open(&root)?;
        let keys = DeviceKeys::load_or_generate(root.join("keys/device.json"))?;
        let mut store = Self {
            root,
            cas,
            keys,
            capsules: BTreeMap::new(),
            inbox: BTreeMap::new(),
            outbox: BTreeMap::new(),
        };
        store.reload();
        Ok(store)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn add_capsule(&mut self, g: Genesis, grant: LeaseRecord) -> Result<()> {
        let capsule = Capsule::new(g.clone(), grant.clone())?;
        let id = g.capsule_id;
        let dir = self.capsule_dir(id);
        fs::create_dir_all(dir.join("leases")).map_err(|e| Error::io(&dir, e))?;
        fs::create_dir_all(dir.join("labels")).map_err(|e| Error::io(&dir, e))?;
        fs::create_dir_all(dir.join("snapshots")).map_err(|e| Error::io(&dir, e))?;
        atomic_write(&dir.join("genesis.cjson"), &g.bytes()?)?;
        atomic_write(&lease_path(&dir, &grant)?, &grant.bytes()?)?;
        self.capsules.insert(id, capsule);
        Ok(())
    }
    pub fn accept_lease(
        &mut self,
        capsule_id: Hash,
        record: LeaseRecord,
        authorize: &dyn Fn(PeerId, LeaseMode) -> bool,
    ) -> Result<bool> {
        let dir = self.capsule_dir(capsule_id);
        let mut staged = self
            .capsules
            .get(&capsule_id)
            .ok_or_else(|| Error::not_found("capsule", capsule_id.to_hex()))?
            .clone();
        let won = staged.accept_lease(record.clone(), authorize)?;
        if won {
            atomic_write(&lease_path(&dir, &record)?, &record.bytes()?)?;
        }
        self.capsules.insert(capsule_id, staged);
        Ok(won)
    }
    pub fn apply_label(&mut self, op: LabelOp, caller: PeerId, now_ms: u64) -> Result<bool> {
        let id = op.capsule_id;
        let dir = self.capsule_dir(id);
        let mut staged = self
            .capsules
            .get(&id)
            .ok_or_else(|| Error::not_found("capsule", id.to_hex()))?
            .clone();
        let won = staged.apply_label(op.clone(), caller, now_ms)?;
        if won {
            atomic_write(&label_path(&dir, &op), &op.bytes()?)?;
        }
        self.capsules.insert(id, staged);
        Ok(won)
    }

    /// Atomically validate and adopt a contiguous lease suffix and optional label.
    /// The snapshot itself may already be durable; no capsule state is persisted
    /// unless every supplied record applies to the same staged capsule.
    pub fn adopt_capsule_state(
        &mut self,
        capsule_id: Hash,
        leases: &[LeaseRecord],
        label: Option<&LabelOp>,
        authorize: &dyn Fn(PeerId, LeaseMode) -> bool,
        now_ms: u64,
    ) -> Result<bool> {
        let dir = self.capsule_dir(capsule_id);
        let mut staged = self
            .capsules
            .get(&capsule_id)
            .ok_or_else(|| Error::not_found("capsule", capsule_id.to_hex()))?
            .clone();
        for lease in leases {
            if !staged.accept_lease(lease.clone(), authorize)? {
                return Err(Error::invalid("lease chain does not extend winner"));
            }
        }
        let label_won = match label {
            Some(op) => staged.apply_label(op.clone(), op.by, now_ms)?,
            None => false,
        };
        for lease in leases {
            atomic_write(&lease_path(&dir, lease)?, &lease.bytes()?)?;
        }
        if let Some(op) = label.filter(|_| label_won) {
            atomic_write(&label_path(&dir, op), &op.bytes()?)?;
        }
        self.capsules.insert(capsule_id, staged);
        Ok(label.is_some_and(|op| {
            self.capsules
                .get(&capsule_id)
                .and_then(|capsule| capsule.label(&op.name))
                .is_some_and(|current| current.snapshot_id == op.snapshot_id)
        }))
    }

    pub fn record_fork_label(
        &mut self,
        capsule_id: Hash,
        snapshot_id: Hash,
        at: String,
        signer: &Identity,
        now_ms: u64,
    ) -> Result<()> {
        let dir = self.capsule_dir(capsule_id);
        let mut staged = self
            .capsules
            .get(&capsule_id)
            .ok_or_else(|| Error::not_found("capsule", capsule_id.to_hex()))?
            .clone();
        let name = format!("fork/{}", &snapshot_id.to_hex()[..8]);
        let seq = staged.label(&name).map_or(1, |old| old.seq + 1);
        let epoch = staged.winning_lease().map_or(0, |lease| lease.epoch);
        let op = LabelOp::new(capsule_id, seq, name, snapshot_id, epoch, at, signer)?;
        staged.apply_label(op.clone(), signer.peer_id(), now_ms)?;
        atomic_write(&label_path(&dir, &op), &op.bytes()?)?;
        self.capsules.insert(capsule_id, staged);
        Ok(())
    }
    pub fn receive_partial(&mut self, raw: RawManifest, from: String, at: String) -> Result<Hash> {
        if raw.manifest().scope != Scope::Partial {
            return Err(Error::invalid("inbox accepts partial snapshots only"));
        }
        let id = raw.snapshot_id();
        let disk = InboxDisk {
            spec: crate::SPEC.into(),
            snapshot_id: id,
            manifest: String::from_utf8(raw.bytes().to_vec())
                .map_err(|_| Error::invalid("manifest is not utf-8"))?,
            from: from.clone(),
            received_at: at.clone(),
            read: false,
        };
        atomic_write(
            &self.root.join("inbox").join(format!("{id}.cjson")),
            &canonical::to_vec(&disk)?,
        )?;
        self.inbox.insert(
            id,
            InboxEntry {
                snapshot_id: id,
                manifest: raw.bytes().to_vec(),
                from,
                received_at: at,
                read: false,
            },
        );
        Ok(id)
    }
    pub fn receive_full(
        &mut self,
        raw: RawManifest,
        at: String,
        now_ms: u64,
        fork_signer: Option<&Identity>,
    ) -> Result<WriteResult> {
        let capsule_id = raw
            .manifest()
            .capsule_id
            .ok_or_else(|| Error::invalid("full manifest lacks capsule id"))?;
        raw.manifest().validate_kind_with_store(&self.cas)?;
        let id = raw.snapshot_id();
        let bytes = raw.bytes().to_vec();
        let dir = self.capsule_dir(capsule_id);
        let snapshot_dir = dir.join("snapshots");
        let mut staged = self
            .capsules
            .get(&capsule_id)
            .ok_or_else(|| Error::not_found("capsule", capsule_id.to_hex()))?
            .clone();
        let result = staged.insert_snapshot(raw, at.clone(), now_ms)?;
        let mut fork_op = None;
        if let (true, Some(signer)) = (result.forked, fork_signer) {
            let name = result.fork_label.clone().expect("fork label");
            let seq = staged.label(&name).map_or(1, |old| old.seq + 1);
            let epoch = staged.winning_lease().map_or(0, |lease| lease.epoch);
            let op = LabelOp::new(capsule_id, seq, name, id, epoch, at.clone(), signer)?;
            staged.apply_label(op.clone(), signer.peer_id(), now_ms)?;
            fork_op = Some(op);
        }
        fs::create_dir_all(&snapshot_dir).map_err(|e| Error::io(&snapshot_dir, e))?;
        atomic_write(&snapshot_dir.join(format!("{id}.cjson")), &bytes)?;
        atomic_write(
            &snapshot_dir.join(format!("{id}.meta.cjson")),
            &canonical::to_vec(&SnapshotMeta {
                spec: crate::SPEC.into(),
                received_at: at.clone(),
            })?,
        )?;
        if let Some(op) = fork_op {
            atomic_write(&label_path(&dir, &op), &op.bytes()?)?;
        }
        self.capsules.insert(capsule_id, staged);
        Ok(result)
    }

    /// Mark an inbox delivery read and persist the change.
    pub fn mark_inbox_read(&mut self, id: Hash) -> Result<()> {
        let entry = self
            .inbox
            .get_mut(&id)
            .ok_or_else(|| Error::not_found("inbox entry", id.to_hex()))?;
        entry.read = true;
        let raw = RawManifest::parse(entry.manifest.clone())?;
        let disk = InboxDisk {
            spec: crate::SPEC.into(),
            snapshot_id: id,
            manifest: String::from_utf8(raw.bytes().to_vec())
                .map_err(|_| Error::invalid("manifest is not utf-8"))?,
            from: entry.from.clone(),
            received_at: entry.received_at.clone(),
            read: true,
        };
        atomic_write(
            &self.root.join("inbox").join(format!("{id}.cjson")),
            &canonical::to_vec(&disk)?,
        )
    }

    fn capsule_dir(&self, id: Hash) -> PathBuf {
        self.root.join("capsules").join(id.to_hex())
    }
    fn reload(&mut self) {
        let Ok(entries) = fs::read_dir(self.root.join("capsules")) else {
            return;
        };
        for entry in entries.flatten() {
            if let Err(error) = self.reload_capsule(&entry.path()) {
                eprintln!(
                    "abra-core: skipping corrupt capsule {}: {error}",
                    entry.path().display()
                );
            }
        }
        let Ok(entries) = fs::read_dir(self.root.join("inbox")) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|x| x.to_str()) != Some("cjson") {
                continue;
            }
            match read_canonical::<InboxDisk>(&entry.path()).and_then(|disk| {
                if disk.spec != crate::SPEC {
                    return Err(Error::invalid("invalid inbox spec"));
                }
                let raw = RawManifest::parse(disk.manifest.as_bytes().to_vec())?;
                if raw.manifest().scope != Scope::Partial || raw.snapshot_id() != disk.snapshot_id {
                    return Err(Error::invalid("invalid inbox record"));
                }
                Ok((disk, raw))
            }) {
                Ok((disk, raw)) => {
                    self.inbox.insert(
                        disk.snapshot_id,
                        InboxEntry {
                            snapshot_id: disk.snapshot_id,
                            manifest: raw.bytes().to_vec(),
                            from: disk.from,
                            received_at: disk.received_at,
                            read: disk.read,
                        },
                    );
                }
                Err(error) => eprintln!(
                    "abra-core: skipping corrupt inbox record {}: {error}",
                    entry.path().display()
                ),
            }
        }
    }
    fn reload_capsule(&mut self, dir: &Path) -> Result<()> {
        let genesis = read_canonical::<Genesis>(&dir.join("genesis.cjson"))?;
        genesis.verify()?;
        let mut leases = read_records::<LeaseRecord>(&dir.join("leases"))?;
        leases.sort_by_key(|r| (r.epoch, r.sig.to_bytes()));
        let grant_pos = leases
            .iter()
            .position(|r| r.epoch == 1 && r.mode == LeaseMode::Grant)
            .ok_or_else(|| Error::invalid("genesis lacks epoch-1 grant"))?;
        let grant = leases.remove(grant_pos);
        let mut capsule = Capsule::new(genesis.clone(), grant)?;
        for lease in leases {
            if let Err(error) = capsule.accept_lease(lease, &|_, _| true) {
                eprintln!(
                    "abra-core: skipping invalid lease in {}: {error}",
                    dir.display()
                );
            }
        }
        let mut snapshots = Vec::new();
        if let Ok(entries) = fs::read_dir(dir.join("snapshots")) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.ends_with(".meta.cjson"))
                {
                    continue;
                }
                if path.extension().and_then(|x| x.to_str()) != Some("cjson") {
                    continue;
                }
                let loaded = (|| {
                    let raw =
                        RawManifest::parse(fs::read(&path).map_err(|e| Error::io(&path, e))?)?;
                    let meta_path =
                        path.with_file_name(format!("{}.meta.cjson", raw.snapshot_id()));
                    let meta = read_canonical::<SnapshotMeta>(&meta_path)?;
                    Ok::<_, Error>((raw, meta.received_at))
                })();
                match loaded {
                    Ok(snapshot) => snapshots.push(snapshot),
                    Err(error) => eprintln!(
                        "abra-core: skipping corrupt snapshot {}: {error}",
                        path.display()
                    ),
                }
            }
        }
        while !snapshots.is_empty() {
            let (raw, at) = snapshots.remove(0);
            if let Err(error) = capsule.insert_snapshot(raw, at, u64::MAX) {
                eprintln!(
                    "abra-core: skipping invalid snapshot in {}: {error}",
                    dir.display()
                );
            }
        }
        for op in read_records::<LabelOp>(&dir.join("labels"))? {
            if let Err(error) = capsule.apply_label(op.clone(), op.by, 0) {
                eprintln!(
                    "abra-core: skipping invalid label-op in {}: {error}",
                    dir.display()
                );
            }
        }
        self.capsules.insert(genesis.capsule_id, capsule);
        Ok(())
    }
}

fn read_canonical<T: DeserializeOwned + Serialize>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(|e| Error::io(path, e))?;
    canonical::validate_canonical(&bytes)?;
    let value: T = serde_json::from_slice(&bytes)?;
    if canonical::to_vec(&value)? != bytes {
        return Err(Error::invalid("record does not round-trip exactly"));
    }
    Ok(value)
}
fn read_records<T: DeserializeOwned + Serialize>(dir: &Path) -> Result<Vec<T>> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        if entry.path().extension().and_then(|x| x.to_str()) == Some("cjson") {
            match read_canonical(&entry.path()) {
                Ok(record) => out.push(record),
                Err(error) => eprintln!(
                    "abra-core: skipping corrupt record {}: {error}",
                    entry.path().display()
                ),
            }
        }
    }
    Ok(out)
}
fn lease_path(dir: &Path, lease: &LeaseRecord) -> Result<PathBuf> {
    Ok(dir
        .join("leases")
        .join(format!("{:020}-{}.cjson", lease.epoch, lease.hash()?)))
}
fn label_path(dir: &Path, op: &LabelOp) -> PathBuf {
    dir.join("labels").join(format!(
        "{:020}-{}.cjson",
        op.seq,
        Hash::of(&op.sig.to_bytes())
    ))
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::invalid("record path has no parent"))?;
    fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    let tmp = parent.join(format!(".tmp-{}", rand::random::<u64>()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| Error::io(&tmp, e))?;
    file.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
    file.sync_all().map_err(|e| Error::io(&tmp, e))?;
    fs::rename(&tmp, path).map_err(|e| Error::io(path, e))?;
    fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| Error::io(parent, e))
}
