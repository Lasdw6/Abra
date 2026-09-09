use abra_core::{
    cas::{
        collect_tree_hashes, materialize, snapshot_dir, BlobStore, EntryMode, Hash, Tree, TreeEntry,
    },
    identity::{Identity, Signature},
    manifest::{Fingerprint, Manifest, NativeBlobRef, Origin, RawManifest, Recipe, Scope},
    restore::{plan_restore, NativeStatus, RestoreMode},
};
use serde_json::json;
use std::{collections::BTreeMap, fs};

const ROLES: &[&str] = &["vmstate", "memory", "disk"];

fn fingerprint(arch: &str) -> Fingerprint {
    Fingerprint {
        os: "linux".into(),
        arch: arch.into(),
        hypervisor: "firecracker".into(),
        snapshot_format_major: 11,
        cpu_template: "none".into(),
        cpu_identity: "test-cpu".into(),
    }
}

fn fixture(store: &BlobStore, directory: &std::path::Path) -> Manifest {
    fs::write(
        directory.join("checkpoint.json"),
        b"{\"completed_steps\":7}\n",
    )
    .unwrap();
    let identity = Identity::from_secret_bytes(&[3; 32]);
    Manifest {
        spec: abra_core::SPEC.into(),
        scope: Scope::Full,
        kind: "dev.abra.workspace".into(),
        title: "Portable checkpoint".into(),
        origin: Origin {
            peer_id: identity.peer_id(),
            name: None,
            adapter: None,
        },
        created_at: "2026-09-06T00:00:00.000Z".into(),
        summary: None,
        link: None,
        thumbnail: None,
        capsule_id: Some(Hash::of(b"portable-capsule")),
        parents: Some(vec![]),
        labels: None,
        provenance: None,
        files: Some(snapshot_dir(store, directory).unwrap()),
        recipes: Some(vec![Recipe {
            argv: vec!["python3".into(), "resume.py".into()],
            cwd: ".".into(),
            env: BTreeMap::new(),
            ports: vec![],
            started_at: None,
        }]),
        native: Some(
            ROLES
                .iter()
                .map(|role| {
                    let bytes = format!("opaque x86 native {role}");
                    NativeBlobRef {
                        role: (*role).into(),
                        blob: store.put(bytes.as_bytes()).unwrap(),
                        bytes: bytes.len() as u64,
                        fingerprint: fingerprint("x86_64"),
                    }
                })
                .collect(),
        ),
        payload: serde_json::Map::new(),
        extensions: Some(serde_json::Map::from_iter([(
            "dev.abra.observed".into(),
            json!({
                "schema":"dev.abra.observed/3", "platform":{"arch":"x86_64"},
                "coverage":{"consistency":"best-effort","applications_quiesced":false},
                "service_candidates":[{"restartability":"blocked","missing_requirements":["DATABASE_URL"]}]
            }),
        )])),
        signature: Signature::from_bytes([0; 64]),
    }
}

fn signed(mut manifest: Manifest) -> RawManifest {
    manifest
        .sign(&Identity::from_secret_bytes(&[3; 32]))
        .unwrap();
    RawManifest::parse(manifest.to_canonical_bytes().unwrap()).unwrap()
}

#[test]
fn different_cpu_architecture_restores_portable_checkpoint_without_native_objects() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let cas = BlobStore::open(root.path()).unwrap();
    let manifest = fixture(&cas, workspace.path());
    for artifact in manifest.native.as_ref().unwrap() {
        fs::remove_file(cas.path_for(&artifact.blob)).unwrap();
    }
    let raw = signed(manifest);
    let plan = plan_restore(&cas, &raw, Some(&fingerprint("aarch64")), ROLES).unwrap();
    assert_eq!(plan.mode, RestoreMode::Portable);
    assert_eq!(plan.native.status, NativeStatus::FingerprintMismatch);
    assert!(plan.native.artifacts.is_empty());
    assert_eq!(
        plan.observation.as_ref().unwrap()["service_candidates"][0]["missing_requirements"][0],
        "DATABASE_URL"
    );
    let restored = tempfile::tempdir().unwrap();
    materialize(&cas, &plan.portable.files.unwrap(), restored.path()).unwrap();
    assert_eq!(
        fs::read(restored.path().join("checkpoint.json")).unwrap(),
        b"{\"completed_steps\":7}\n"
    );
    assert_eq!(
        fs::read_dir(restored.path()).unwrap().count(),
        1,
        "recipes stay data"
    );
}

#[test]
fn exact_native_match_is_verified_and_corrupt_cache_falls_back_without_deletion() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let cas = BlobStore::open(root.path()).unwrap();
    let raw = signed(fixture(&cas, workspace.path()));
    let plan = plan_restore(&cas, &raw, Some(&fingerprint("x86_64")), ROLES).unwrap();
    assert_eq!(plan.mode, RestoreMode::Native);
    assert!(plan.portable.available);
    let broken = cas.path_for(&plan.native.artifacts[0].blob);
    fs::write(&broken, b"corrupt").unwrap();
    let plan = plan_restore(&cas, &raw, Some(&fingerprint("x86_64")), ROLES).unwrap();
    assert_eq!(plan.mode, RestoreMode::Portable);
    assert_eq!(plan.native.status, NativeStatus::UnavailableObjects);
    assert_eq!(plan.native.unavailable_objects.len(), 1);
    assert_eq!(fs::read(broken).unwrap(), b"corrupt");
}

#[test]
fn captured_host_is_never_used_as_receiver_and_cpu_model_must_match() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let cas = BlobStore::open(root.path()).unwrap();
    let raw = signed(fixture(&cas, workspace.path()));
    let plan = plan_restore(&cas, &raw, None, ROLES).unwrap();
    assert_eq!(plan.native.status, NativeStatus::TargetRequired);
    let plan = plan_restore(&cas, &raw, Some(&fingerprint("x86_64")), &[]).unwrap();
    assert_eq!(plan.native.status, NativeStatus::RolesRequired);
    let mut target = fingerprint("x86_64");
    target.cpu_identity = "another-cpu".into();
    assert_eq!(
        plan_restore(&cas, &raw, Some(&target), ROLES)
            .unwrap()
            .native
            .status,
        NativeStatus::FingerprintMismatch
    );
}

#[test]
fn incomplete_and_ambiguous_native_roles_never_resume() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let cas = BlobStore::open(root.path()).unwrap();
    let mut manifest = fixture(&cas, workspace.path());
    manifest.native.as_mut().unwrap().pop();
    let plan = plan_restore(
        &cas,
        &signed(manifest.clone()),
        Some(&fingerprint("x86_64")),
        ROLES,
    )
    .unwrap();
    assert_eq!(plan.native.status, NativeStatus::MissingRoles);
    assert_eq!(plan.native.missing_roles, ["disk"]);
    let duplicate = manifest.native.as_ref().unwrap()[0].clone();
    manifest.native.as_mut().unwrap().push(duplicate);
    assert_eq!(
        plan_restore(&cas, &signed(manifest), Some(&fingerprint("x86_64")), ROLES)
            .unwrap()
            .native
            .status,
        NativeStatus::AmbiguousRoles
    );
}

#[test]
fn unavailable_portable_objects_are_reported_before_materialization() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let cas = BlobStore::open(root.path()).unwrap();
    let manifest = fixture(&cas, workspace.path());
    let leaf = cas.get_tree(&manifest.files.unwrap()).unwrap().entries()[0].hash;
    fs::remove_file(cas.path_for(&leaf)).unwrap();
    let raw = signed(manifest);
    let plan = plan_restore(&cas, &raw, Some(&fingerprint("aarch64")), ROLES).unwrap();
    assert_eq!(plan.mode, RestoreMode::Unavailable);
    assert!(plan
        .portable
        .error
        .as_ref()
        .unwrap()
        .contains(&leaf.to_hex()));
    assert!(plan_restore(&cas, &raw, None, &["memory", "memory"]).is_err());
}

#[test]
fn portable_preflight_and_materialization_reject_the_same_invalid_trees() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let cas = BlobStore::open(root.path()).unwrap();
    let base = fixture(&cas, workspace.path());
    let blob = cas.put(b"data").unwrap();
    let sized_wrong = cas
        .put_tree(
            &Tree::new(vec![TreeEntry {
                name: "file".into(),
                mode: EntryMode::File,
                hash: blob,
                size: 5,
            }])
            .unwrap(),
        )
        .unwrap();
    let invalid_link = cas.put(b"bad\0target").unwrap();
    let linked_wrong = cas
        .put_tree(
            &Tree::new(vec![TreeEntry {
                name: "link".into(),
                mode: EntryMode::Link,
                hash: invalid_link,
                size: 10,
            }])
            .unwrap(),
        )
        .unwrap();
    let empty = cas.put_tree(&Tree::new(vec![]).unwrap()).unwrap();
    let wrap = |mut hash, count, name: &str| {
        for _ in 0..count {
            hash = cas
                .put_tree(
                    &Tree::new(vec![TreeEntry {
                        name: name.into(),
                        mode: EntryMode::Tree,
                        hash,
                        size: 0,
                    }])
                    .unwrap(),
                )
                .unwrap();
        }
        hash
    };
    let too_deep = wrap(empty, 513, "d");
    let too_long = wrap(empty, 17, &"d".repeat(255));
    for (tree, reason) in [
        (sized_wrong, "size mismatch"),
        (linked_wrong, "NUL"),
        (too_deep, "depth exceeds"),
        (too_long, "path exceeds"),
    ] {
        let mut manifest = base.clone();
        manifest.files = Some(tree);
        manifest.native = None;
        let plan = plan_restore(&cas, &signed(manifest), None, &[]).unwrap();
        assert_eq!(plan.mode, RestoreMode::Unavailable);
        assert!(plan.portable.error.unwrap().contains(reason));
        let destination = workspace.path().join(format!("restore-{tree}"));
        assert!(materialize(&cas, &tree, &destination)
            .unwrap_err()
            .to_string()
            .contains(reason));
        assert!(
            !destination.exists(),
            "invalid tree must fail before any writes"
        );
    }
    assert!(collect_tree_hashes(&cas, &too_deep)
        .unwrap_err()
        .to_string()
        .contains("depth exceeds"));
    assert!(collect_tree_hashes(&cas, &too_long)
        .unwrap_err()
        .to_string()
        .contains("path exceeds"));
}
