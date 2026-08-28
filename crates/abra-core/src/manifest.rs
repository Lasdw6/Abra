//! Snapshot manifest schema, signing, and byte-authoritative verification (SPEC §§1–2).
use crate::{
    canonical,
    cas::Hash,
    identity::{Identity, PeerId, Signature},
    Error, Result,
};

/// Return the complete object closure for a manifest (SPEC §3.4).
pub fn closure(store: &crate::cas::BlobStore, manifest: &Manifest) -> Result<BTreeSet<Hash>> {
    let mut out = if let Some(root) = &manifest.files {
        crate::cas::collect_tree_hashes(store, root)?
    } else {
        BTreeSet::new()
    };
    if let Some(t) = &manifest.thumbnail {
        out.insert(t.blob);
    }
    if let Some(native) = &manifest.native {
        out.extend(native.iter().map(|n| n.blob));
    }
    Ok(out)
}
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Full,
    Partial,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub peer_id: PeerId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thumbnail {
    pub blob: Hash,
    pub media_type: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub name: String,
    pub value: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub capsule_id: Hash,
    pub snapshot_id: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub argv: Vec<String>,
    pub cwd: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub os: String,
    pub arch: String,
    pub hypervisor: String,
    pub snapshot_format_major: u64,
    pub cpu_template: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlobRef {
    pub role: String,
    pub blob: Hash,
    pub bytes: u64,
    pub fingerprint: Fingerprint,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub spec: String,
    pub scope: Scope,
    pub kind: String,
    pub title: String,
    pub origin: Origin,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<Thumbnail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capsule_id: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parents: Option<Vec<Hash>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<Label>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipes: Option<Vec<Recipe>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native: Option<Vec<NativeBlobRef>>,
    pub payload: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Map<String, Value>>,
    pub signature: Signature,
}
impl Manifest {
    pub fn unsigned_value(&self) -> Result<Value> {
        let mut v = serde_json::to_value(self)?;
        v.as_object_mut().unwrap().remove("signature");
        Ok(v)
    }
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        canonical::to_vec(&self.unsigned_value()?)
    }
    pub fn snapshot_id(&self) -> Result<Hash> {
        let mut b = b"abra-snap-v1\0".to_vec();
        b.extend(self.unsigned_bytes()?);
        Ok(Hash::of(&b))
    }
    pub fn sign(&mut self, id: &Identity) -> Result<()> {
        if id.peer_id() != self.origin.peer_id {
            return Err(Error::invalid(
                "manifest signer differs from origin.peer_id",
            ));
        }
        self.signature = id.sign("snapshot", &self.unsigned_bytes()?);
        Ok(())
    }
    pub fn verify(&self) -> Result<()> {
        self.validate()
    }
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical::to_vec(self)
    }
    pub fn validate(&self) -> Result<()> {
        if self.spec != crate::SPEC {
            return Err(Error::UnsupportedSpec {
                found: self.spec.clone(),
                expected: crate::SPEC.into(),
            });
        }
        if !reverse_dns(&self.kind) || self.kind.len() > 128 {
            return Err(Error::invalid("invalid manifest kind"));
        }
        text(&self.title, 1, 512, true, "title")?;
        time(&self.created_at)?;
        if let Some(x) = &self.origin.name {
            text(x, 0, 80, false, "origin.name")?
        }
        if let Some(x) = &self.origin.adapter {
            if !adapter(x) {
                return Err(Error::invalid("invalid adapter name"));
            }
        }
        if let Some(x) = &self.summary {
            text(x, 0, 4096, false, "summary")?
        }
        if let Some(x) = &self.link {
            if x.len() > 4096 || !absolute_uri(x) {
                return Err(Error::invalid("invalid absolute link URI"));
            }
        }
        if let Some(t) = &self.thumbnail {
            if !matches!(
                t.media_type.as_str(),
                "image/png" | "image/jpeg" | "image/webp"
            ) || !(1..=524288).contains(&t.bytes)
            {
                return Err(Error::invalid("invalid thumbnail"));
            }
        }
        match self.scope {
            Scope::Full => {
                if self.capsule_id.is_none() || self.parents.is_none() || self.files.is_none() {
                    return Err(Error::invalid(
                        "full requires capsule_id, parents, and files",
                    ));
                }
                if self.provenance.is_some() {
                    return Err(Error::invalid("full forbids provenance"));
                }
            }
            Scope::Partial => {
                if self.capsule_id.is_some()
                    || self.parents.is_some()
                    || self.labels.is_some()
                    || self.recipes.is_some()
                    || self.native.is_some()
                {
                    return Err(Error::invalid("partial contains full-only field"));
                }
            }
        }
        if let Some(p) = &self.parents {
            if p.len() > 16 || p.iter().collect::<BTreeSet<_>>().len() != p.len() {
                return Err(Error::invalid("invalid parents"));
            }
        }
        if let Some(ls) = &self.labels {
            if ls.len() > 16 {
                return Err(Error::invalid("too many labels"));
            }
            let mut prev = None;
            for l in ls {
                if !label_name(&l.name) {
                    return Err(Error::invalid("invalid label name"));
                }
                if let Some(v) = &l.value {
                    text(v, 0, 512, false, "label value")?
                }
                if prev.as_ref().is_some_and(|p: &Label| p >= l) {
                    return Err(Error::invalid("labels not strictly sorted"));
                }
                prev = Some(l.clone())
            }
        }
        if let Some(p) = &self.provenance {
            if let Some(t) = &p.turn {
                text(t, 0, 64, false, "turn")?
            }
        }
        if let Some(rs) = &self.recipes {
            if rs.len() > 256 {
                return Err(Error::invalid("too many recipes"));
            }
            for r in rs {
                if r.argv.is_empty() || r.argv.len() > 256 || !relative(&r.cwd) {
                    return Err(Error::invalid("invalid recipe"));
                }
                if r.ports.windows(2).any(|x| x[0] >= x[1]) || r.ports.contains(&0) {
                    return Err(Error::invalid("invalid recipe ports"));
                }
                if let Some(t) = &r.started_at {
                    time(t)?
                }
            }
        }
        if let Some(ns) = &self.native {
            if ns.len() > 32 {
                return Err(Error::invalid("too many native refs"));
            }
            for n in ns {
                if !label_name(&n.role) {
                    return Err(Error::invalid("invalid native role"));
                }
            }
        }
        if let Some(e) = &self.extensions {
            if e.keys().any(|k| !reverse_dns(k)) {
                return Err(Error::invalid("invalid extension key"));
            }
        }
        canonical::validate_value(&serde_json::to_value(self)?)?;
        self.origin
            .peer_id
            .verify("snapshot", &self.unsigned_bytes()?, &self.signature)
    }
}

/// Exact accepted manifest bytes plus parsed view (SPEC §2 byte authority).
#[derive(Clone, Debug)]
pub struct RawManifest {
    bytes: Vec<u8>,
    manifest: Manifest,
    id: Hash,
}
impl RawManifest {
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        canonical::validate_canonical(&bytes)?;
        let m: Manifest = serde_json::from_slice(&bytes)?;
        m.verify()?;
        let id = m.snapshot_id()?;
        Ok(Self {
            bytes,
            manifest: m,
            id,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn snapshot_id(&self) -> Hash {
        self.id
    }
}

fn text(s: &str, min: usize, max: usize, controls: bool, n: &str) -> Result<()> {
    let l = s.chars().count();
    if l < min || l > max || (controls && s.chars().any(|c| (c as u32) <= 31)) {
        return Err(Error::invalid(format!("invalid {n}")));
    }
    Ok(())
}
fn reverse_dns(s: &str) -> bool {
    let p: Vec<_> = s.split('.').collect();
    p.len() >= 2
        && p.iter().all(|x| {
            !x.is_empty()
                && x.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}
fn adapter(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        })
}
fn label_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn relative(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('/') && !s.contains('\0') && !s.split('/').any(|x| x == "..")
}
fn absolute_uri(s: &str) -> bool {
    s.split_once(':').is_some_and(|(a, b)| {
        !a.is_empty()
            && !b.is_empty()
            && a.bytes().enumerate().all(|(i, c)| {
                if i == 0 {
                    c.is_ascii_alphabetic()
                } else {
                    c.is_ascii_alphanumeric() || b"+-.".contains(&c)
                }
            })
    })
}
fn time(s: &str) -> Result<()> {
    let b = s.as_bytes();
    if b.len() != 24
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, c)| ![4, 7, 10, 13, 16, 19, 23].contains(&i) && !c.is_ascii_digit())
    {
        return Err(Error::invalid("noncanonical time"));
    }
    let num = |a: usize, z: usize| s[a..z].parse::<u32>().unwrap();
    let (year, month, day, hour, minute, second) = (
        num(0, 4),
        num(5, 7),
        num(8, 10),
        num(11, 13),
        num(14, 16),
        num(17, 19),
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err(Error::invalid("invalid canonical time value"));
    }
    Ok(())
}
