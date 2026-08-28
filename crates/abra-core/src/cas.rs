//! Content-addressed storage: blake3 blobs, git-like tree objects, and the
//! walk/write pair that turns a directory into a hash and back.
//!
//! See `docs/SPEC.md` §2 and §3.
//!
//! Dedup is by content, so an unchanged file across a hundred snapshots is
//! stored once and an incremental teleport only needs the hashes the receiver
//! is missing.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::util::hex_newtype;

/// A blake3-256 content hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; 32]);
hex_newtype!(Hash, 32, "hash");

impl Hash {
    /// Hash of these bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Hash(*blake3::hash(bytes).as_bytes())
    }
}

/// The metadata directory `snapshot_dir` refuses to walk.
///
/// It is the *only* exclusion. There is no ignore-file logic and no secret
/// filtering: v1 syncs byte for byte, `.git` included (DESIGN §8).
pub const ABRA_DIR: &str = ".abra";

const TREE_MAGIC: &[u8] = b"abra.tree.v1\n";

/// What a [`TreeEntry`]'s hash points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryMode {
    /// A blob: the file's bytes.
    File,
    /// A blob: the file's bytes; the file is executable.
    Exec,
    /// A blob: the symlink's target path, as raw bytes.
    Link,
    /// Another tree object.
    Tree,
}

impl EntryMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryMode::File => "file",
            EntryMode::Exec => "exec",
            EntryMode::Link => "link",
            EntryMode::Tree => "tree",
        }
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        match b {
            b"file" => Ok(EntryMode::File),
            b"exec" => Ok(EntryMode::Exec),
            b"link" => Ok(EntryMode::Link),
            b"tree" => Ok(EntryMode::Tree),
            other => Err(Error::corrupt(
                "tree",
                format!("unknown mode {:?}", String::from_utf8_lossy(other)),
            )),
        }
    }
}

impl std::fmt::Display for EntryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One name in a directory.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TreeEntry {
    pub name: String,
    pub mode: EntryMode,
    pub hash: Hash,
}

/// A directory state. Entries are always sorted by name, so a directory state
/// has exactly one encoding and therefore exactly one hash.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    entries: Vec<TreeEntry>,
}

impl Tree {
    /// Build a tree, sorting entries and rejecting illegal or duplicate names.
    pub fn new(mut entries: Vec<TreeEntry>) -> Result<Self> {
        for e in &entries {
            check_name(&e.name)?;
        }
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        for pair in entries.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(Error::invalid(format!(
                    "duplicate tree entry name {:?}",
                    pair[0].name
                )));
            }
        }
        Ok(Tree { entries })
    }

    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&TreeEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Encode to the canonical byte form (SPEC §3).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(TREE_MAGIC);
        for e in &self.entries {
            out.extend_from_slice(e.mode.as_str().as_bytes());
            out.push(b' ');
            out.extend_from_slice(e.name.as_bytes());
            out.push(0);
            out.extend_from_slice(e.hash.as_bytes());
        }
        out
    }

    /// Decode the canonical byte form.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut rest = bytes
            .strip_prefix(TREE_MAGIC)
            .ok_or_else(|| Error::corrupt("tree", "bad magic"))?;

        let mut entries = Vec::new();
        while !rest.is_empty() {
            let sp = rest
                .iter()
                .position(|b| *b == b' ')
                .ok_or_else(|| Error::corrupt("tree", "entry has no mode separator"))?;
            let mode = EntryMode::from_bytes(&rest[..sp])?;
            rest = &rest[sp + 1..];

            let nul = rest
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| Error::corrupt("tree", "entry has no name terminator"))?;
            let name = std::str::from_utf8(&rest[..nul])
                .map_err(|e| Error::corrupt("tree", format!("name is not utf-8: {e}")))?
                .to_string();
            rest = &rest[nul + 1..];

            if rest.len() < 32 {
                return Err(Error::corrupt("tree", "truncated entry hash"));
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&rest[..32]);
            rest = &rest[32..];

            entries.push(TreeEntry {
                name,
                mode,
                hash: Hash::from_bytes(raw),
            });
        }

        // Re-check ordering rather than trusting the encoder: a tree that
        // decodes to the same entries must also re-encode to the same bytes.
        let decoded_order: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        let tree = Tree::new(entries.clone())?;
        let sorted_order: Vec<&str> = tree.entries.iter().map(|e| e.name.as_str()).collect();
        if decoded_order != sorted_order {
            return Err(Error::corrupt("tree", "entries are not sorted by name"));
        }
        Ok(tree)
    }

    /// The tree object's own hash.
    pub fn hash(&self) -> Hash {
        Hash::of(&self.encode())
    }
}

fn check_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::invalid("empty tree entry name"));
    }
    if name == "." || name == ".." {
        return Err(Error::invalid(format!("illegal tree entry name {name:?}")));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(Error::invalid(format!(
            "tree entry name {name:?} contains a separator"
        )));
    }
    Ok(())
}

/// A blake3-addressed blob store, sharded `blobs/ab/cdef...`.
///
/// Writes are atomic: content lands in a temp file inside the store and is
/// renamed into place, so a blob path either does not exist or holds complete,
/// correct content.
#[derive(Clone, Debug)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let store = BlobStore { root };
        fs::create_dir_all(store.blobs_dir()).map_err(|e| Error::io(store.blobs_dir(), e))?;
        fs::create_dir_all(store.tmp_dir()).map_err(|e| Error::io(store.tmp_dir(), e))?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Where a blob lives, whether or not it exists.
    pub fn path_for(&self, hash: &Hash) -> PathBuf {
        let hex = hash.to_hex();
        self.blobs_dir().join(&hex[..2]).join(&hex[2..])
    }

    pub fn has(&self, hash: &Hash) -> bool {
        self.path_for(hash).is_file()
    }

    /// Store bytes, returning their hash. Storing the same bytes twice is a
    /// no-op the second time.
    pub fn put(&self, bytes: &[u8]) -> Result<Hash> {
        let hash = Hash::of(bytes);
        let dest = self.path_for(&hash);
        if dest.is_file() {
            return Ok(hash);
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }

        let tmp = self
            .tmp_dir()
            .join(format!("{}.{}", hash.to_hex(), rand::random::<u64>()));
        {
            let mut f = fs::File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
            f.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
            f.sync_all().map_err(|e| Error::io(&tmp, e))?;
        }
        fs::rename(&tmp, &dest).map_err(|e| Error::io(&dest, e))?;
        Ok(hash)
    }

    /// Store the contents of a file.
    pub fn put_file(&self, path: impl AsRef<Path>) -> Result<Hash> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| Error::io(path, e))?;
        self.put(&bytes)
    }

    /// Read a blob back.
    pub fn get(&self, hash: &Hash) -> Result<Vec<u8>> {
        let path = self.path_for(hash);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::not_found("blob", hash.to_hex()))
            }
            Err(e) => return Err(Error::io(&path, e)),
        };
        if Hash::of(&bytes) != *hash {
            return Err(Error::corrupt(
                "blob",
                format!("content of {hash} does not hash to its name"),
            ));
        }
        Ok(bytes)
    }

    /// Store a tree object, returning its hash.
    pub fn put_tree(&self, tree: &Tree) -> Result<Hash> {
        self.put(&tree.encode())
    }

    /// Read a tree object back.
    pub fn get_tree(&self, hash: &Hash) -> Result<Tree> {
        Tree::decode(&self.get(hash)?)
    }
}

/// Walk `dir`, storing every file as a blob and every directory as a tree.
/// Returns the root tree hash.
///
/// Skips nothing except [`ABRA_DIR`]. Symlinks are stored as links, not
/// followed.
pub fn snapshot_dir(store: &BlobStore, dir: impl AsRef<Path>) -> Result<Hash> {
    let dir = dir.as_ref();
    let meta = fs::symlink_metadata(dir).map_err(|e| Error::io(dir, e))?;
    if !meta.is_dir() {
        return Err(Error::invalid(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    let tree = walk(store, dir)?;
    store.put_tree(&tree)
}

fn walk(store: &BlobStore, dir: &Path) -> Result<Tree> {
    let mut entries = Vec::new();
    let read = fs::read_dir(dir).map_err(|e| Error::io(dir, e))?;

    for entry in read {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|raw| Error::invalid(format!("non-utf-8 file name {raw:?}")))?;
        if name == ABRA_DIR {
            continue;
        }

        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| Error::io(&path, e))?;
        let ty = meta.file_type();

        let (mode, hash) = if ty.is_symlink() {
            let target = fs::read_link(&path).map_err(|e| Error::io(&path, e))?;
            let bytes = path_to_bytes(&target)?;
            (EntryMode::Link, store.put(&bytes)?)
        } else if ty.is_dir() {
            let sub = walk(store, &path)?;
            (EntryMode::Tree, store.put_tree(&sub)?)
        } else if ty.is_file() {
            let mode = if is_executable(&meta) {
                EntryMode::Exec
            } else {
                EntryMode::File
            };
            (mode, store.put_file(&path)?)
        } else {
            return Err(Error::invalid(format!(
                "{} is neither a file, directory nor symlink",
                path.display()
            )));
        };

        entries.push(TreeEntry { name, mode, hash });
    }

    Tree::new(entries)
}

/// Write a tree out to `dest`, creating it if needed.
///
/// Files get mode 0644, executables 0755, symlinks their stored target. mtimes,
/// ownership and non-execute permission bits are not preserved: the tree object
/// does not carry them.
pub fn materialize(store: &BlobStore, root: &Hash, dest: impl AsRef<Path>) -> Result<()> {
    let dest = dest.as_ref();
    fs::create_dir_all(dest).map_err(|e| Error::io(dest, e))?;
    let tree = store.get_tree(root)?;

    for entry in tree.entries() {
        let path = dest.join(&entry.name);
        match entry.mode {
            EntryMode::Tree => materialize(store, &entry.hash, &path)?,
            EntryMode::Link => {
                let target = bytes_to_path(&store.get(&entry.hash)?)?;
                remove_existing(&path)?;
                symlink(&target, &path)?;
            }
            EntryMode::File | EntryMode::Exec => {
                let bytes = store.get(&entry.hash)?;
                remove_existing(&path)?;
                fs::write(&path, &bytes).map_err(|e| Error::io(&path, e))?;
                set_mode(&path, entry.mode == EntryMode::Exec)?;
            }
        }
    }
    Ok(())
}

/// Every hash reachable from a root tree, the root included: the blobs a
/// receiver needs to materialize this directory state.
pub fn collect_tree_hashes(store: &BlobStore, root: &Hash) -> Result<BTreeSet<Hash>> {
    let mut out = BTreeSet::new();
    collect_inner(store, root, &mut out)?;
    Ok(out)
}

fn collect_inner(store: &BlobStore, root: &Hash, out: &mut BTreeSet<Hash>) -> Result<()> {
    if !out.insert(*root) {
        return Ok(());
    }
    let tree = store.get_tree(root)?;
    for entry in tree.entries() {
        match entry.mode {
            EntryMode::Tree => collect_inner(store, &entry.hash, out)?,
            _ => {
                out.insert(entry.hash);
            }
        }
    }
    Ok(())
}

fn remove_existing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            fs::remove_dir_all(path).map_err(|e| Error::io(path, e))
        }
        Ok(_) => fs::remove_file(path).map_err(|e| Error::io(path, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(path, e)),
    }
}

#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_mode(path: &Path, exec: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if exec { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| Error::io(path, e))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _exec: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &Path, at: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, at).map_err(|e| Error::io(at, e))
}

#[cfg(not(unix))]
fn symlink(_target: &Path, at: &Path) -> Result<()> {
    Err(Error::invalid(format!(
        "cannot create symlink at {} on this platform",
        at.display()
    )))
}

#[cfg(unix)]
fn path_to_bytes(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(path.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn path_to_bytes(path: &Path) -> Result<Vec<u8>> {
    path.to_str()
        .map(|s| s.as_bytes().to_vec())
        .ok_or_else(|| Error::invalid("symlink target is not utf-8"))
}

#[cfg(unix)]
fn bytes_to_path(bytes: &[u8]) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

#[cfg(not(unix))]
fn bytes_to_path(bytes: &[u8]) -> Result<PathBuf> {
    std::str::from_utf8(bytes)
        .map(PathBuf::from)
        .map_err(|e| Error::corrupt("symlink target", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path().join("cas")).unwrap();
        (dir, store)
    }

    #[test]
    fn hash_matches_blake3() {
        assert_eq!(
            Hash::of(b"abra").as_bytes(),
            blake3::hash(b"abra").as_bytes()
        );
    }

    #[test]
    fn hash_hex_roundtrip() {
        let h = Hash::of(b"abra");
        assert_eq!(Hash::from_str(&h.to_string()).unwrap(), h);
        assert_eq!(h.to_hex().len(), 64);
    }

    #[test]
    fn put_get_has() {
        let (_d, store) = store();
        let h = store.put(b"hello").unwrap();
        assert!(store.has(&h));
        assert_eq!(store.get(&h).unwrap(), b"hello");
        assert!(!store.has(&Hash::of(b"nope")));
        assert!(store.get(&Hash::of(b"nope")).is_err());
    }

    #[test]
    fn put_is_idempotent_and_dedups() {
        let (_d, store) = store();
        let a = store.put(b"same").unwrap();
        let b = store.put(b"same").unwrap();
        assert_eq!(a, b);
        assert_eq!(store.path_for(&a), store.path_for(&b));
    }

    #[test]
    fn blobs_are_sharded_like_git() {
        let (_d, store) = store();
        let h = store.put(b"hello").unwrap();
        let hex = h.to_hex();
        let path = store.path_for(&h);
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), &hex[2..]);
        assert_eq!(
            path.parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            &hex[..2]
        );
        assert!(path.is_file());
    }

    #[test]
    fn put_empty_blob() {
        let (_d, store) = store();
        let h = store.put(b"").unwrap();
        assert_eq!(store.get(&h).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn get_detects_corruption() {
        let (_d, store) = store();
        let h = store.put(b"hello").unwrap();
        fs::write(store.path_for(&h), b"tampered").unwrap();
        assert!(matches!(store.get(&h), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn tree_encode_decode_roundtrip() {
        let tree = Tree::new(vec![
            TreeEntry {
                name: "z.txt".into(),
                mode: EntryMode::File,
                hash: Hash::of(b"z"),
            },
            TreeEntry {
                name: "a.sh".into(),
                mode: EntryMode::Exec,
                hash: Hash::of(b"a"),
            },
            TreeEntry {
                name: "sub".into(),
                mode: EntryMode::Tree,
                hash: Hash::of(b"sub"),
            },
            TreeEntry {
                name: "l".into(),
                mode: EntryMode::Link,
                hash: Hash::of(b"target"),
            },
        ])
        .unwrap();

        let bytes = tree.encode();
        assert!(bytes.starts_with(b"abra.tree.v1\n"));
        let back = Tree::decode(&bytes).unwrap();
        assert_eq!(back, tree);
        assert_eq!(back.hash(), tree.hash());
    }

    #[test]
    fn tree_entries_are_sorted_so_hash_is_order_independent() {
        let a = TreeEntry {
            name: "a".into(),
            mode: EntryMode::File,
            hash: Hash::of(b"a"),
        };
        let b = TreeEntry {
            name: "b".into(),
            mode: EntryMode::File,
            hash: Hash::of(b"b"),
        };
        let one = Tree::new(vec![a.clone(), b.clone()]).unwrap();
        let two = Tree::new(vec![b, a]).unwrap();
        assert_eq!(one.hash(), two.hash());
        assert_eq!(one.entries()[0].name, "a");
    }

    #[test]
    fn tree_rejects_bad_names() {
        for name in ["", ".", "..", "a/b", "a\0b"] {
            let r = Tree::new(vec![TreeEntry {
                name: name.into(),
                mode: EntryMode::File,
                hash: Hash::of(b"x"),
            }]);
            assert!(r.is_err(), "accepted {name:?}");
        }
    }

    #[test]
    fn tree_rejects_duplicate_names() {
        let e = TreeEntry {
            name: "dup".into(),
            mode: EntryMode::File,
            hash: Hash::of(b"x"),
        };
        assert!(Tree::new(vec![e.clone(), e]).is_err());
    }

    #[test]
    fn tree_decode_rejects_garbage() {
        assert!(Tree::decode(b"").is_err(), "no magic");
        assert!(Tree::decode(b"abra.tree.v1\nfile").is_err(), "truncated");
        assert!(
            Tree::decode(b"abra.tree.v1\nweird a\0").is_err(),
            "bad mode + truncated hash"
        );
    }

    #[test]
    fn tree_decode_rejects_unsorted_entries() {
        let mut bytes = Vec::from(TREE_MAGIC);
        for name in ["b", "a"] {
            bytes.extend_from_slice(b"file ");
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(Hash::of(name.as_bytes()).as_bytes());
        }
        assert!(matches!(Tree::decode(&bytes), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn empty_tree_roundtrips() {
        let t = Tree::new(vec![]).unwrap();
        assert!(t.is_empty());
        assert_eq!(Tree::decode(&t.encode()).unwrap(), t);
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn sample_dir(root: &Path) {
        write(&root.join("readme.md"), "hello\n");
        write(&root.join("src").join("main.rs"), "fn main() {}\n");
        write(&root.join("src").join("deep").join("x.txt"), "deep\n");
        write(&root.join("run.sh"), "#!/bin/sh\necho hi\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn snapshot_dir_is_deterministic_and_content_addressed() {
        let (_d, store) = store();
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        sample_dir(&a);
        sample_dir(&b);

        let ha = snapshot_dir(&store, &a).unwrap();
        let hb = snapshot_dir(&store, &b).unwrap();
        assert_eq!(ha, hb, "same content, same hash");

        write(&b.join("readme.md"), "changed\n");
        let hb2 = snapshot_dir(&store, &b).unwrap();
        assert_ne!(ha, hb2);
    }

    #[test]
    fn snapshot_dir_skips_only_the_abra_dir() {
        let (_d, store) = store();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("w");
        sample_dir(&root);
        write(&root.join(ABRA_DIR).join("state.json"), "{}");
        write(&root.join(".git").join("HEAD"), "ref: refs/heads/main\n");
        write(&root.join(".env"), "SECRET=hunter2\n");

        let h = snapshot_dir(&store, &root).unwrap();
        let tree = store.get_tree(&h).unwrap();

        assert!(tree.get(ABRA_DIR).is_none(), ".abra must be skipped");
        assert!(tree.get(".git").is_some(), ".git must be kept");
        assert!(tree.get(".env").is_some(), "no secret filtering in v1");
    }

    #[test]
    fn snapshot_dir_rejects_a_file_argument() {
        let (_d, store) = store();
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("f");
        fs::write(&f, "x").unwrap();
        assert!(snapshot_dir(&store, &f).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn materialize_roundtrips_content_structure_and_exec_bit() {
        use std::os::unix::fs::PermissionsExt;

        let (_d, store) = store();
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        sample_dir(&src);
        std::os::unix::fs::symlink("readme.md", src.join("link-to-readme")).unwrap();

        let root = snapshot_dir(&store, &src).unwrap();
        let out = tmp.path().join("out");
        materialize(&store, &root, &out).unwrap();

        assert_eq!(fs::read(out.join("readme.md")).unwrap(), b"hello\n");
        assert_eq!(
            fs::read(out.join("src").join("deep").join("x.txt")).unwrap(),
            b"deep\n"
        );
        let sh = fs::metadata(out.join("run.sh")).unwrap();
        assert_eq!(sh.permissions().mode() & 0o777, 0o755);
        let md = fs::metadata(out.join("readme.md")).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o644);
        assert_eq!(
            fs::read_link(out.join("link-to-readme")).unwrap(),
            PathBuf::from("readme.md")
        );

        // Re-snapshotting the materialized copy yields the same root hash.
        assert_eq!(snapshot_dir(&store, &out).unwrap(), root);
    }

    #[test]
    fn materialize_overwrites_existing_paths() {
        let (_d, store) = store();
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        sample_dir(&src);
        let root = snapshot_dir(&store, &src).unwrap();

        let out = tmp.path().join("out");
        write(&out.join("readme.md"), "stale\n");
        materialize(&store, &root, &out).unwrap();
        assert_eq!(fs::read(out.join("readme.md")).unwrap(), b"hello\n");
    }

    #[test]
    fn materialize_fails_on_missing_root() {
        let (_d, store) = store();
        let tmp = tempfile::tempdir().unwrap();
        assert!(materialize(&store, &Hash::of(b"absent"), tmp.path().join("out")).is_err());
    }

    #[test]
    fn collect_tree_hashes_covers_everything_needed() {
        let (_d, store) = store();
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        sample_dir(&src);
        let root = snapshot_dir(&store, &src).unwrap();

        let hashes = collect_tree_hashes(&store, &root).unwrap();
        assert!(hashes.contains(&root));
        assert!(hashes.contains(&Hash::of(b"hello\n")));
        assert!(hashes.contains(&Hash::of(b"deep\n")));
        for h in &hashes {
            assert!(store.has(h));
        }

        // Copying exactly those blobs into a fresh store is enough to
        // materialize: that is what a link bundle carries.
        let other_dir = tempfile::tempdir().unwrap();
        let other = BlobStore::open(other_dir.path()).unwrap();
        for h in &hashes {
            other.put(&store.get(h).unwrap()).unwrap();
        }
        let out = tmp.path().join("out");
        materialize(&other, &root, &out).unwrap();
        assert_eq!(fs::read(out.join("readme.md")).unwrap(), b"hello\n");
    }
}
