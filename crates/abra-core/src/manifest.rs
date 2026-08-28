//! The snapshot envelope: one manifest format, split by a `scope` field.
//!
//! See `docs/SPEC.md` §4.
//!
//! A snapshot is the noun. Its manifest is always JSON and always carries the
//! floor fields — `kind`, `title`, `origin`, `created_at` — so a receiver that
//! has never heard of the payload type can still render a card. A snapshot is
//! never an opaque blob.
//!
//! Everything past the floor is *data*, not a rendering. [`Recipe`]s describe
//! how processes were running; this crate never executes one. [`NativeBlobRef`]s
//! point at opaque acceleration artifacts that are only valid on a host whose
//! [`Fingerprint`] matches.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::canonical;
use crate::capsule::CapsuleId;
use crate::cas::{BlobStore, Hash};
use crate::error::{Error, Result};
use crate::identity::PeerId;

/// `kind` for a whole workspace or sandbox version.
pub const KIND_WORKSPACE: &str = "abra.workspace";
/// `kind` for a plain file or folder delivery.
pub const KIND_FILES: &str = "abra.files";
/// `kind` for a handoff: pointers into a piece of work, not the work itself.
pub const KIND_HANDOFF: &str = "abra.handoff.v1";

/// The top-level field names this build knows about.
///
/// Anything else a peer sends is preserved verbatim in [`Manifest::unknown`] so
/// that the snapshot hash still verifies after a round trip through an older
/// build.
const KNOWN_FIELDS: &[&str] = &[
    "abra_spec",
    "scope",
    "kind",
    "title",
    "origin",
    "created_at",
    "summary",
    "link",
    "thumbnail",
    "files",
    "recipes",
    "native",
    "extra",
    "capsule_id",
    "parents",
    "label",
    "lease",
    "provenance",
];

/// Which of the two shapes a manifest is.
///
/// One envelope format; this field decides which fields are meaningful and
/// where a receiver files the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// A version of a continuing thing: has a capsule, lineage, and a lease.
    Full,
    /// A delivery: a file, a folder, a browser session, a handoff. No lineage.
    Partial,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Full => "full",
            Scope::Partial => "partial",
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a partial came from. A reference, not membership: a partial carrying
/// provenance is still not part of the capsule's DAG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub capsule_id: CapsuleId,
    pub snapshot_hash: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Who was driving the capsule when this version was authored.
///
/// Coordination, not enforcement. A device that authors against a stale lease
/// creates a fork, which is representable: `parents` is a list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub holder: PeerId,
    pub acquired_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl Lease {
    /// A lease held by `holder` from `now`, with no expiry.
    pub fn new(holder: PeerId, now: u64) -> Self {
        Lease {
            holder,
            acquired_at: now,
            expires_at: None,
        }
    }

    /// A lease held by `holder` from `now` for `ttl_ms`.
    pub fn expiring(holder: PeerId, now: u64, ttl_ms: u64) -> Self {
        Lease {
            holder,
            acquired_at: now,
            expires_at: Some(now.saturating_add(ttl_ms)),
        }
    }

    /// Whether this lease has lapsed by `now`. A lease with no expiry never has.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }
}

/// Where a [`Recipe`] came from.
///
/// Recipes are derived, not declared, and this records by what. It is optional:
/// a manifest written by a peer that does not track provenance of its recipes
/// simply omits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecipeSource {
    /// Captured by watching what actually ran.
    Observer,
    /// Recorded by the thing that started the process.
    Launcher,
    /// Written down by a human or a config file.
    Declared,
}

/// How to recreate one process.
///
/// Data only: `abra-core` stores and moves recipes and never runs them. `cwd` is
/// relative to the workspace root precisely so the receiver decides where that
/// root lands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipe {
    /// Program and arguments; `argv[0]` is the program. Non-empty.
    pub argv: Vec<String>,
    /// Working directory **relative** to the workspace root.
    pub cwd: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// TCP ports the process was observed listening on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<RecipeSource>,
}

impl Recipe {
    /// A recipe running `argv` at the workspace root.
    pub fn new(argv: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Recipe {
            argv: argv.into_iter().map(Into::into).collect(),
            cwd: String::new(),
            env: BTreeMap::new(),
            ports: Vec::new(),
            started_at: None,
            source: None,
        }
    }

    /// Set the working directory, relative to the workspace root.
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.argv.is_empty() {
            return Err(Error::invalid("recipe argv is empty"));
        }
        check_relative(&self.cwd)
    }
}

/// A `cwd` must keep the receiver in control of where the root lands: no
/// absolute paths, no escaping upward.
fn check_relative(cwd: &str) -> Result<()> {
    if cwd.starts_with('/') {
        return Err(Error::invalid(format!("recipe cwd {cwd:?} is absolute")));
    }
    if cwd.split('/').any(|c| c == "..") {
        return Err(Error::invalid(format!(
            "recipe cwd {cwd:?} escapes the workspace root"
        )));
    }
    Ok(())
}

/// A host class that can use a given [`NativeBlobRef`].
///
/// Rendered as `{os}-{hypervisor}-{arch}` followed by `/{key}-{value}` for each
/// extra, sorted by key:
///
/// ```text
/// linux-kvm-x86_64/cpu-template-none/fc-snap-v11
/// ```
///
/// Comparison is on the rendered string. It is deliberately one-way: a receiver
/// only ever needs to ask "is this mine?", and an opaque token that either
/// matches or does not is the safest possible answer to that question.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fingerprint {
    pub os: String,
    pub arch: String,
    /// `none` for a bare host.
    pub hypervisor: String,
    pub extra: BTreeMap<String, String>,
}

impl Fingerprint {
    pub fn new(
        os: impl Into<String>,
        arch: impl Into<String>,
        hypervisor: impl Into<String>,
    ) -> Self {
        Fingerprint {
            os: os.into(),
            arch: arch.into(),
            hypervisor: hypervisor.into(),
            extra: BTreeMap::new(),
        }
    }

    /// Add a qualifier, e.g. `("fc-snap", "v11")` or `("cpu-template", "none")`.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// This host, with no qualifiers. Callers that know about a hypervisor or a
    /// snapshot format version add them with [`Fingerprint::with_extra`].
    pub fn of_host() -> Self {
        Fingerprint::new(std::env::consts::OS, std::env::consts::ARCH, "none")
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}-{}", self.os, self.hypervisor, self.arch)?;
        for (k, v) in &self.extra {
            write!(f, "/{k}-{v}")?;
        }
        Ok(())
    }
}

/// An opaque acceleration artifact, carried unchanged.
///
/// The clearest example is a Firecracker memory file plus VM state file. Abra
/// does not parse, transform, or version them. They are an evictable cache and
/// never the source of truth: dropping one costs time, not data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBlobRef {
    /// The host class that can use this blob. See [`Fingerprint`].
    pub fingerprint: String,
    /// Distinguishes blobs sharing a fingerprint: `memory`, `vmstate`, ...
    pub role: String,
    pub hash: Hash,
    pub size: u64,
}

impl NativeBlobRef {
    pub fn new(fingerprint: &Fingerprint, role: impl Into<String>, hash: Hash, size: u64) -> Self {
        NativeBlobRef {
            fingerprint: fingerprint.to_string(),
            role: role.into(),
            hash,
            size,
        }
    }

    /// Whether this blob is usable on `host`.
    pub fn matches(&self, host: &Fingerprint) -> bool {
        self.fingerprint == host.to_string()
    }
}

/// The snapshot envelope.
///
/// Construct with [`Manifest::full`] or [`Manifest::partial`], which set the
/// scope-specific fields correctly, then fill in the optional ones.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub abra_spec: u32,
    pub scope: Scope,

    // --- floor fields: enough to render a card with zero integration ---
    /// Payload type, e.g. `abra.workspace` or a vendor id like `com.example.x`.
    pub kind: String,
    pub title: String,
    pub origin: PeerId,
    pub created_at: u64,

    // --- standard optional cargo ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<Hash>,
    /// Root tree object: the file cargo. See `cas`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipes: Vec<Recipe>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native: Vec<NativeBlobRef>,
    /// Payload-specific structured data. The extension point: structured data,
    /// never a rendering.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,

    // --- full only ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_id: Option<CapsuleId>,
    /// Parent snapshot hashes. A list, so a fork is representable and a merge is
    /// just two parents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,

    // --- partial only ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,

    /// Fields this build does not know about, preserved verbatim.
    ///
    /// Forward compatibility is a hash property, not a nicety: drop an unknown
    /// field and the snapshot hash no longer verifies, so an older build would
    /// silently corrupt everything it relayed.
    #[serde(flatten)]
    pub unknown: Map<String, Value>,
}

impl Manifest {
    /// A new version of a capsule.
    pub fn full(
        kind: impl Into<String>,
        title: impl Into<String>,
        origin: PeerId,
        created_at: u64,
        capsule_id: CapsuleId,
    ) -> Self {
        Manifest {
            capsule_id: Some(capsule_id),
            ..Manifest::bare(Scope::Full, kind, title, origin, created_at)
        }
    }

    /// A delivery: a file, a folder, a session, a handoff.
    pub fn partial(
        kind: impl Into<String>,
        title: impl Into<String>,
        origin: PeerId,
        created_at: u64,
    ) -> Self {
        Manifest::bare(Scope::Partial, kind, title, origin, created_at)
    }

    fn bare(
        scope: Scope,
        kind: impl Into<String>,
        title: impl Into<String>,
        origin: PeerId,
        created_at: u64,
    ) -> Self {
        Manifest {
            abra_spec: crate::ABRA_SPEC,
            scope,
            kind: kind.into(),
            title: title.into(),
            origin,
            created_at,
            summary: None,
            link: None,
            thumbnail: None,
            files: None,
            recipes: Vec::new(),
            native: Vec::new(),
            extra: Map::new(),
            capsule_id: None,
            parents: Vec::new(),
            label: None,
            lease: None,
            provenance: None,
            unknown: Map::new(),
        }
    }

    /// The canonical bytes this manifest hashes and travels as.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical::to_vec(self)
    }

    /// `blake3(canonical_json(manifest))`. See `docs/SPEC.md` §1.6.
    ///
    /// The hash covers the manifest only, but the manifest commits to the file
    /// tree and to every blob by hash, so the whole bundle is covered
    /// transitively.
    pub fn hash(&self) -> Result<Hash> {
        Ok(Hash::of(&self.to_canonical_bytes()?))
    }

    /// Check the invariants in `docs/SPEC.md` §4.6.
    pub fn validate(&self) -> Result<()> {
        if self.abra_spec != crate::ABRA_SPEC {
            return Err(Error::UnsupportedSpec {
                found: self.abra_spec,
                expected: crate::ABRA_SPEC,
            });
        }
        if self.kind.is_empty() {
            return Err(Error::invalid("manifest kind is empty"));
        }
        if self.title.is_empty() {
            return Err(Error::invalid("manifest title is empty"));
        }
        if self.created_at == 0 {
            return Err(Error::invalid("manifest created_at is zero"));
        }

        match self.scope {
            Scope::Full => {
                if self.capsule_id.is_none() {
                    return Err(Error::invalid("a full snapshot needs a capsule_id"));
                }
                if self.provenance.is_some() {
                    return Err(Error::invalid(
                        "provenance is a partial-only field; a full snapshot has parents",
                    ));
                }
            }
            Scope::Partial => {
                if self.capsule_id.is_some() {
                    return Err(Error::invalid("a partial snapshot has no capsule_id"));
                }
                if !self.parents.is_empty() {
                    return Err(Error::invalid("a partial snapshot has no lineage"));
                }
                if self.lease.is_some() {
                    return Err(Error::invalid("a partial snapshot has no lease"));
                }
            }
        }

        for r in &self.recipes {
            r.validate()?;
        }
        for n in &self.native {
            if n.fingerprint.is_empty() {
                return Err(Error::invalid("native blob has an empty fingerprint"));
            }
            if n.role.is_empty() {
                return Err(Error::invalid("native blob has an empty role"));
            }
        }

        // A preserved unknown field that shadows a known one would serialize
        // twice and make the manifest ambiguous.
        for key in self.unknown.keys() {
            if KNOWN_FIELDS.contains(&key.as_str()) {
                return Err(Error::invalid(format!(
                    "unknown-field map shadows the known field {key:?}"
                )));
            }
        }
        Ok(())
    }

    /// Validate, then store the canonical bytes as a blob. Returns the snapshot
    /// hash.
    pub fn store(&self, blobs: &BlobStore) -> Result<Hash> {
        self.validate()?;
        blobs.put(&self.to_canonical_bytes()?)
    }

    /// Load and validate a manifest by its snapshot hash.
    ///
    /// Re-hashes what was parsed, which catches both a tampered blob and a
    /// parser that silently dropped a field it did not understand.
    pub fn load(blobs: &BlobStore, hash: &Hash) -> Result<Self> {
        let bytes = blobs.get(hash)?;
        let manifest = Manifest::from_bytes(&bytes)?;
        if manifest.hash()? != *hash {
            return Err(Error::corrupt(
                "manifest",
                format!("{hash} does not round-trip to its own hash"),
            ));
        }
        Ok(manifest)
    }

    /// Parse and validate a manifest from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let manifest: Manifest = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// The native blobs usable on `host`.
    pub fn native_for<'a>(&'a self, host: &Fingerprint) -> Vec<&'a NativeBlobRef> {
        self.native.iter().filter(|n| n.matches(host)).collect()
    }

    /// A one-line rendering derived from the floor fields alone: what a receiver
    /// with zero knowledge of `kind` can always show.
    pub fn card(&self) -> String {
        let mut card = format!("{} — {}", self.title, self.kind);
        if let Some(s) = &self.summary {
            card.push_str(&format!(" — {s}"));
        }
        card.push_str(&format!(" (from {}, {})", self.origin, self.created_at));
        card
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn peer() -> PeerId {
        Identity::generate().peer_id()
    }

    fn full() -> Manifest {
        Manifest::full(
            KIND_WORKSPACE,
            "abra workspace",
            peer(),
            1_756_300_000_000,
            CapsuleId::generate(),
        )
    }

    fn partial() -> Manifest {
        Manifest::partial(KIND_HANDOFF, "handoff", peer(), 1_756_300_000_000)
    }

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        (dir, blobs)
    }

    #[test]
    fn full_and_partial_validate() {
        full().validate().unwrap();
        partial().validate().unwrap();
    }

    #[test]
    fn serde_roundtrip_is_lossless() {
        let mut m = full();
        m.summary = Some("a summary".into());
        m.link = Some("https://example.com/x".into());
        m.thumbnail = Some(Hash::of(b"thumb"));
        m.files = Some(Hash::of(b"tree"));
        m.parents = vec![Hash::of(b"p1"), Hash::of(b"p2")];
        m.label = Some("turn 14".into());
        m.lease = Some(Lease::expiring(peer(), 1_756_299_000_000, 3_600_000));
        m.recipes = vec![Recipe::new(["npm", "run", "dev"]).with_cwd("app")];
        m.native = vec![NativeBlobRef::new(
            &Fingerprint::new("linux", "x86_64", "kvm").with_extra("fc-snap", "v11"),
            "memory",
            Hash::of(b"mem"),
            2048,
        )];
        m.extra.insert("cursor".into(), serde_json::json!({"line": 240}));

        let bytes = m.to_canonical_bytes().unwrap();
        let back = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.hash().unwrap(), m.hash().unwrap());
    }

    #[test]
    fn absent_optionals_are_omitted_never_null() {
        let json = String::from_utf8(full().to_canonical_bytes().unwrap()).unwrap();
        assert!(!json.contains("null"), "{json}");
        for absent in ["summary", "link", "thumbnail", "files", "recipes", "extra"] {
            assert!(!json.contains(absent), "{absent} should be omitted: {json}");
        }
    }

    #[test]
    fn hash_is_stable_across_field_order_and_reparse() {
        let m = full();
        let expected = m.hash().unwrap();

        // Same value, keys shuffled by a round trip through a plain map.
        let value: Value = serde_json::from_slice(&m.to_canonical_bytes().unwrap()).unwrap();
        let shuffled = serde_json::to_vec(&value).unwrap();
        let back = Manifest::from_bytes(&shuffled).unwrap();
        assert_eq!(back.hash().unwrap(), expected);
    }

    #[test]
    fn hash_changes_when_any_field_changes() {
        let m = full();
        let base = m.hash().unwrap();

        let mut other = m.clone();
        other.title = "different".into();
        assert_ne!(other.hash().unwrap(), base);

        let mut other = m.clone();
        other.files = Some(Hash::of(b"tree"));
        assert_ne!(other.hash().unwrap(), base);

        let mut other = m;
        other.parents = vec![Hash::of(b"p")];
        assert_ne!(other.hash().unwrap(), base);
    }

    #[test]
    fn unknown_fields_are_preserved_so_the_hash_still_verifies() {
        // A manifest written by a future build, with a field we know nothing
        // about.
        let mut value: Value =
            serde_json::from_slice(&full().to_canonical_bytes().unwrap()).unwrap();
        value["future_field"] = serde_json::json!({ "b": 2, "a": [1] });
        let bytes = canonical::to_vec(&value).unwrap();
        let hash = Hash::of(&bytes);

        let m = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(
            m.unknown.get("future_field"),
            Some(&serde_json::json!({ "b": 2, "a": [1] }))
        );
        assert_eq!(
            m.hash().unwrap(),
            hash,
            "an unknown field must survive the round trip"
        );
        assert_eq!(m.to_canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn unknown_map_may_not_shadow_a_known_field() {
        let mut m = full();
        m.unknown.insert("title".into(), Value::from("shadow"));
        assert!(m.validate().is_err());
    }

    #[test]
    fn floor_fields_are_required() {
        let mut m = full();
        m.kind = String::new();
        assert!(m.validate().is_err());

        let mut m = full();
        m.title = String::new();
        assert!(m.validate().is_err());

        let mut m = full();
        m.created_at = 0;
        assert!(m.validate().is_err());
    }

    #[test]
    fn a_card_renders_from_the_floor_alone() {
        let mut m = partial();
        m.summary = Some("picking up the lease path".into());
        let card = m.card();
        assert!(card.contains("handoff"));
        assert!(card.contains(KIND_HANDOFF));
        assert!(card.contains("picking up the lease path"));
        assert!(card.contains(&m.origin.to_hex()));
    }

    #[test]
    fn full_requires_a_capsule_and_rejects_provenance() {
        let mut m = full();
        m.capsule_id = None;
        assert!(m.validate().is_err());

        let mut m = full();
        m.provenance = Some(Provenance {
            capsule_id: CapsuleId::generate(),
            snapshot_hash: Hash::of(b"s"),
            label: None,
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn partial_rejects_lineage_and_lease() {
        let mut m = partial();
        m.capsule_id = Some(CapsuleId::generate());
        assert!(m.validate().is_err());

        let mut m = partial();
        m.parents = vec![Hash::of(b"p")];
        assert!(m.validate().is_err());

        let mut m = partial();
        m.lease = Some(Lease::new(peer(), 1));
        assert!(m.validate().is_err());
    }

    #[test]
    fn partial_may_carry_provenance_without_joining_the_dag() {
        let mut m = partial();
        m.provenance = Some(Provenance {
            capsule_id: CapsuleId::generate(),
            snapshot_hash: Hash::of(b"s"),
            label: Some("turn 14".into()),
        });
        m.validate().unwrap();
        assert!(m.parents.is_empty());
        assert!(m.capsule_id.is_none());
    }

    #[test]
    fn unsupported_spec_is_rejected() {
        let mut m = full();
        m.abra_spec = 99;
        assert!(matches!(
            m.validate(),
            Err(Error::UnsupportedSpec { found: 99, .. })
        ));
    }

    #[test]
    fn recipes_must_be_runnable_somewhere_relative() {
        let mut m = full();
        m.recipes = vec![Recipe::new(Vec::<String>::new())];
        assert!(m.validate().is_err(), "empty argv");

        for bad in ["/abs/path", "../escape", "a/../../b"] {
            let mut m = full();
            m.recipes = vec![Recipe::new(["sh"]).with_cwd(bad)];
            assert!(m.validate().is_err(), "accepted cwd {bad:?}");
        }

        for good in ["", "app", "a/b/c", "a..b"] {
            let mut m = full();
            m.recipes = vec![Recipe::new(["sh"]).with_cwd(good)];
            m.validate().unwrap();
        }
    }

    #[test]
    fn native_blobs_need_a_fingerprint_and_role() {
        let fp = Fingerprint::new("linux", "x86_64", "kvm");
        let mut m = full();
        m.native = vec![NativeBlobRef::new(&fp, "", Hash::of(b"x"), 1)];
        assert!(m.validate().is_err());

        let mut m = full();
        m.native = vec![NativeBlobRef {
            fingerprint: String::new(),
            role: "memory".into(),
            hash: Hash::of(b"x"),
            size: 1,
        }];
        assert!(m.validate().is_err());
    }

    #[test]
    fn fingerprint_renders_the_documented_shape() {
        let fp = Fingerprint::new("linux", "x86_64", "kvm")
            .with_extra("fc-snap", "v11")
            .with_extra("cpu-template", "none");
        assert_eq!(
            fp.to_string(),
            "linux-kvm-x86_64/cpu-template-none/fc-snap-v11"
        );
        assert_eq!(
            Fingerprint::new("linux", "x86_64", "kvm").to_string(),
            "linux-kvm-x86_64"
        );
    }

    #[test]
    fn native_blobs_are_only_offered_to_a_matching_host() {
        let mine = Fingerprint::new("linux", "x86_64", "kvm").with_extra("fc-snap", "v11");
        let theirs = Fingerprint::new("macos", "aarch64", "none");

        let mut m = full();
        m.native = vec![NativeBlobRef::new(&mine, "memory", Hash::of(b"mem"), 4)];

        assert_eq!(m.native_for(&mine).len(), 1);
        assert!(
            m.native_for(&theirs).is_empty(),
            "a mismatched host must not be offered the fast path"
        );

        // Same host class, different snapshot format version: not a match.
        let newer = Fingerprint::new("linux", "x86_64", "kvm").with_extra("fc-snap", "v12");
        assert!(m.native_for(&newer).is_empty());
    }

    #[test]
    fn lease_expiry() {
        let p = peer();
        let l = Lease::expiring(p, 1000, 500);
        assert_eq!(l.expires_at, Some(1500));
        assert!(!l.is_expired(1499));
        assert!(l.is_expired(1500));
        assert!(!Lease::new(p, 1000).is_expired(u64::MAX));
    }

    #[test]
    fn store_and_load_from_the_blob_store() {
        let (_d, blobs) = store();
        let mut m = full();
        m.summary = Some("stored".into());

        let hash = m.store(&blobs).unwrap();
        assert_eq!(hash, m.hash().unwrap());
        assert_eq!(Manifest::load(&blobs, &hash).unwrap(), m);
    }

    #[test]
    fn store_refuses_an_invalid_manifest() {
        let (_d, blobs) = store();
        let mut m = full();
        m.capsule_id = None;
        assert!(m.store(&blobs).is_err());
    }

    #[test]
    fn load_rejects_a_manifest_stored_under_the_wrong_hash() {
        let (_d, blobs) = store();
        let m = full();
        // Store non-canonical bytes: they hash to something the manifest itself
        // would never produce.
        let value: Value = serde_json::from_slice(&m.to_canonical_bytes().unwrap()).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        let hash = blobs.put(&pretty).unwrap();

        assert!(matches!(
            Manifest::load(&blobs, &hash),
            Err(Error::Corrupt { .. })
        ));
    }

    #[test]
    fn load_reports_a_missing_manifest() {
        let (_d, blobs) = store();
        assert!(matches!(
            Manifest::load(&blobs, &Hash::of(b"absent")),
            Err(Error::NotFound { .. })
        ));
    }
}
