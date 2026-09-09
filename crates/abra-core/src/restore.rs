//! Read-only restore planning for portable files and optional native state.
//!
//! Native eligibility requires a receiver-supplied fingerprint and the roles its
//! adapter needs. Portable availability verifies the file tree, not whether the
//! workload's dependencies, credentials or application checkpoints are complete.

use crate::{
    cas::{validate_materialization, BlobStore, Hash},
    manifest::{Fingerprint, NativeBlobRef, RawManifest, Recipe},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreMode {
    Native,
    Portable,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeStatus {
    /// Required objects and declared fingerprints match; the adapter must try loading them.
    Eligible,
    Absent,
    TargetRequired,
    RolesRequired,
    FingerprintMismatch,
    MissingRoles,
    AmbiguousRoles,
    UnavailableObjects,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortableRestore {
    pub available: bool,
    pub files: Option<Hash>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectIssue {
    pub blob: Hash,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeRestore {
    pub status: NativeStatus,
    pub artifacts: Vec<NativeBlobRef>,
    pub missing_roles: Vec<String>,
    pub unavailable_objects: Vec<ObjectIssue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestorePlan {
    pub snapshot_id: Hash,
    pub mode: RestoreMode,
    pub portable: PortableRestore,
    pub native: NativeRestore,
    /// Suggestions only. Planning and materialization never execute recipes.
    pub recipes: Vec<Recipe>,
    /// Original observations, including missing requirements and capture limits.
    pub observation: Option<Value>,
}

/// Plan a restore without writing files, starting processes, or trusting captured
/// host facts as the receiver's identity. Objects are hash-verified on disk.
/// Callers must still verify objects when using the plan: files may change later.
pub fn plan_restore(
    store: &BlobStore,
    snapshot: &RawManifest,
    target: Option<&Fingerprint>,
    required_roles: &[&str],
) -> Result<RestorePlan> {
    let roles: BTreeSet<_> = required_roles.iter().copied().collect();
    if roles.len() != required_roles.len() || roles.iter().any(|role| role.is_empty()) {
        return Err(Error::invalid("native roles must be nonempty and unique"));
    }
    let manifest = snapshot.manifest();
    let portable_check = (|| -> Result<()> {
        let root = manifest
            .files
            .ok_or_else(|| Error::invalid("snapshot lacks a portable file tree"))?;
        validate_materialization(store, &root)?;
        manifest.validate_kind_with_store(store)
    })();
    let portable = PortableRestore {
        available: portable_check.is_ok(),
        files: manifest.files,
        error: portable_check.err().map(|error| error.to_string()),
    };
    let native = plan_native(
        store,
        manifest.native.as_deref().unwrap_or_default(),
        target,
        &roles,
    );
    let mode = if native.status == NativeStatus::Eligible {
        RestoreMode::Native
    } else if portable.available {
        RestoreMode::Portable
    } else {
        RestoreMode::Unavailable
    };
    Ok(RestorePlan {
        snapshot_id: snapshot.snapshot_id(),
        mode,
        portable,
        native,
        recipes: manifest.recipes.clone().unwrap_or_default(),
        observation: manifest
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get("dev.abra.observed"))
            .cloned(),
    })
}

fn plan_native(
    store: &BlobStore,
    native: &[NativeBlobRef],
    target: Option<&Fingerprint>,
    required_roles: &BTreeSet<&str>,
) -> NativeRestore {
    let mut plan = NativeRestore {
        status: NativeStatus::Absent,
        artifacts: Vec::new(),
        missing_roles: Vec::new(),
        unavailable_objects: Vec::new(),
    };
    if native.is_empty() {
        return plan;
    }
    let Some(target) = target else {
        plan.status = NativeStatus::TargetRequired;
        return plan;
    };
    if required_roles.is_empty() {
        plan.status = NativeStatus::RolesRequired;
        return plan;
    }
    let matching: Vec<_> = native
        .iter()
        .filter(|artifact| &artifact.fingerprint == target)
        .collect();
    if matching.is_empty() {
        plan.status = NativeStatus::FingerprintMismatch;
        return plan;
    }
    let mut ambiguous = false;
    for role in required_roles {
        let entries: Vec<_> = matching
            .iter()
            .filter(|artifact| artifact.role == *role)
            .collect();
        match entries.as_slice() {
            [] => plan.missing_roles.push((*role).to_owned()),
            [artifact] => plan.artifacts.push((***artifact).clone()),
            _ => ambiguous = true,
        }
    }
    if ambiguous {
        plan.status = NativeStatus::AmbiguousRoles;
    } else if !plan.missing_roles.is_empty() {
        plan.status = NativeStatus::MissingRoles;
    } else {
        for artifact in &plan.artifacts {
            let checked = store.verify_object(&artifact.blob).and_then(|bytes| {
                if bytes == artifact.bytes {
                    Ok(())
                } else {
                    Err(Error::invalid("native object size differs from manifest"))
                }
            });
            if let Err(error) = checked {
                plan.unavailable_objects.push(ObjectIssue {
                    blob: artifact.blob,
                    error: error.to_string(),
                });
            }
        }
        plan.status = if plan.unavailable_objects.is_empty() {
            NativeStatus::Eligible
        } else {
            NativeStatus::UnavailableObjects
        };
    }
    plan
}
