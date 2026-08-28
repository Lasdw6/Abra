use abra_core::{
    canonical,
    capsule::{Capsule, Genesis, LabelOp, LeaseMode, LeaseRecord},
    cas::{Hash, Tree},
    identity::{Identity, Signature},
    manifest::{Manifest, Origin, RawManifest, Scope},
};
use serde_json::json;
#[test]
fn cjson_profile() {
    assert_eq!(
        canonical::to_string(&json!({"z":"\u{2028}\\\"","a":"\u{0001}\n"})).unwrap(),
        "{\"a\":\"\\u0001\\n\",\"z\":\"\u{2028}\\\\\\\"\"}"
    );
    for b in [
        b"{\"b\":1,\"a\":2}".as_slice(),
        b"{ \"a\":1}".as_slice(),
        b"{\"a\":1.0}".as_slice(),
        b"{\"a\":1,\"a\":1}".as_slice(),
    ] {
        assert!(canonical::validate_canonical(b).is_err())
    }
    assert!(canonical::to_vec(&json!({"core":-1})).is_err());
    assert!(canonical::to_vec(&json!({"payload":{"n":-1}})).is_ok());
    assert!(canonical::to_vec(&json!({"nested":{"payload":{"n":-1}}})).is_err());
}

fn signed_manifest(scope: Scope) -> (Identity, Manifest) {
    let id = Identity::from_secret_bytes(&[3; 32]);
    let full = scope == Scope::Full;
    let mut m = Manifest {
        spec: abra_core::SPEC.into(),
        scope,
        kind: "dev.abra.test".into(),
        title: "title".into(),
        origin: Origin {
            peer_id: id.peer_id(),
            name: None,
            adapter: None,
        },
        created_at: "2026-08-28T13:00:00.000Z".into(),
        summary: None,
        link: None,
        thumbnail: None,
        capsule_id: full.then(|| Hash::from_bytes([1; 32])),
        parents: full.then(Vec::new),
        labels: None,
        provenance: None,
        files: full.then(|| Tree::default().hash()),
        recipes: None,
        native: None,
        payload: Default::default(),
        extensions: None,
        signature: Signature::from_bytes([0; 64]),
    };
    m.sign(&id).unwrap();
    (id, m)
}

#[test]
fn manifest_validation_matrix_and_id_excludes_signature() {
    let (id, mut m) = signed_manifest(Scope::Full);
    m.validate().unwrap();
    let sid = m.snapshot_id().unwrap();
    m.signature = Signature::from_bytes([9; 64]);
    assert_eq!(m.snapshot_id().unwrap(), sid);
    assert!(m.validate().is_err());
    for mutate in [
        |x: &mut Manifest| x.spec = "abra/9".into(),
        |x: &mut Manifest| x.title = "".into(),
        |x: &mut Manifest| x.title = "bad\n".into(),
        |x: &mut Manifest| x.capsule_id = None,
        |x: &mut Manifest| x.parents = None,
        |x: &mut Manifest| x.files = None,
        |x: &mut Manifest| x.created_at = "2026-02-30T00:00:00.000Z".into(),
    ] {
        let mut x = signed_manifest(Scope::Full).1;
        mutate(&mut x);
        x.sign(&id).unwrap();
        assert!(x.validate().is_err());
    }
    let (pid, mut p) = signed_manifest(Scope::Partial);
    p.capsule_id = Some(Hash::from_bytes([2; 32]));
    p.sign(&pid).unwrap();
    assert!(p.validate().is_err());
    let raw = String::from_utf8(
        signed_manifest(Scope::Partial)
            .1
            .to_canonical_bytes()
            .unwrap(),
    )
    .unwrap();
    assert!(RawManifest::parse(raw.replacen("{", "{\"unknown\":1,", 1).into_bytes()).is_err());
}

#[test]
fn raw_manifest_rejects_null_and_empty_default_injection_and_hashes_stored_bytes() {
    let (_, manifest) = signed_manifest(Scope::Partial);
    let bytes = manifest.to_canonical_bytes().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["summary"] = serde_json::Value::Null;
    assert!(RawManifest::parse(canonical::to_vec(&value).unwrap()).is_err());

    let (identity, mut recipe_manifest) = signed_manifest(Scope::Full);
    recipe_manifest.recipes = Some(vec![abra_core::manifest::Recipe {
        argv: vec!["true".into()],
        cwd: ".".into(),
        env: Default::default(),
        ports: vec![],
        started_at: None,
    }]);
    recipe_manifest.sign(&identity).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&recipe_manifest.to_canonical_bytes().unwrap()).unwrap();
    value["recipes"][0]["env"] = serde_json::json!({});
    assert!(RawManifest::parse(canonical::to_vec(&value).unwrap()).is_err());

    let raw = RawManifest::parse(bytes).unwrap();
    let mut stored: serde_json::Value = serde_json::from_slice(raw.bytes()).unwrap();
    stored.as_object_mut().unwrap().remove("signature");
    let mut preimage = b"abra-snap-v1\0".to_vec();
    preimage.extend(canonical::to_vec(&stored).unwrap());
    assert_eq!(raw.snapshot_id(), Hash::of(&preimage));
}

#[test]
fn handoff_link_must_match_payload_url() {
    let (identity, mut manifest) = signed_manifest(Scope::Partial);
    manifest.kind = "dev.abra.handoff.v1".into();
    manifest.link = Some("https://example.test/a".into());
    manifest
        .payload
        .insert("url".into(), json!("https://example.test/b"));
    manifest.sign(&identity).unwrap();
    assert!(manifest.validate().is_err());
}

#[test]
fn lease_gap_race_and_live_takeover() {
    let creator = Identity::from_secret_bytes(&[4; 32]);
    let a = Identity::from_secret_bytes(&[5; 32]);
    let b = Identity::from_secret_bytes(&[6; 32]);
    let g = Genesis::new(
        Hash::from_bytes([8; 32]),
        "2026-08-28T00:00:00.000Z".into(),
        "dev.abra.workspace".into(),
        "x".into(),
        &creator,
    )
    .unwrap();
    let l1 = LeaseRecord::new(
        g.capsule_id,
        creator.peer_id(),
        1,
        LeaseMode::Grant,
        "2026-08-28T00:00:00.000Z".into(),
        "2026-08-29T00:00:00.000Z".into(),
        g.hash().unwrap(),
        &creator,
    )
    .unwrap();
    let mut c = Capsule::new(g.clone(), l1.clone()).unwrap();
    let gap = LeaseRecord::new(
        g.capsule_id,
        a.peer_id(),
        3,
        LeaseMode::Takeover,
        "2026-08-28T01:00:00.000Z".into(),
        "2026-08-29T01:00:00.000Z".into(),
        l1.hash().unwrap(),
        &a,
    )
    .unwrap();
    assert!(!c.accept_lease(gap, &|_, _| true).unwrap());
    let mut race = [
        LeaseRecord::new(
            g.capsule_id,
            a.peer_id(),
            2,
            LeaseMode::Takeover,
            "2026-08-28T01:00:00.000Z".into(),
            "2026-08-29T01:00:00.000Z".into(),
            l1.hash().unwrap(),
            &a,
        )
        .unwrap(),
        LeaseRecord::new(
            g.capsule_id,
            b.peer_id(),
            2,
            LeaseMode::Takeover,
            "2026-08-28T01:00:00.000Z".into(),
            "2026-08-29T01:00:00.000Z".into(),
            l1.hash().unwrap(),
            &b,
        )
        .unwrap(),
    ];
    race.sort_by_key(|x| x.sig.to_bytes());
    assert!(c.accept_lease(race[0].clone(), &|_, _| true).unwrap());
    assert!(c.accept_lease(race[1].clone(), &|_, _| true).unwrap());
    assert_eq!(c.winning_lease().unwrap().holder, race[1].holder);
}

#[test]
fn lease_gap_requires_signature_is_bounded_and_takeover_is_authorized() {
    let creator = Identity::from_secret_bytes(&[51; 32]);
    let attacker = Identity::from_secret_bytes(&[52; 32]);
    let capsule_id = Hash::from_bytes([53; 32]);
    let genesis = Genesis::new(
        capsule_id,
        "2026-08-28T00:00:00.000Z".into(),
        "dev.abra.workspace".into(),
        "x".into(),
        &creator,
    )
    .unwrap();
    let grant = LeaseRecord::new(
        capsule_id,
        creator.peer_id(),
        1,
        LeaseMode::Grant,
        "2026-08-28T00:00:00.000Z".into(),
        "2026-08-29T00:00:00.000Z".into(),
        genesis.hash().unwrap(),
        &creator,
    )
    .unwrap();
    let mut capsule = Capsule::new(genesis, grant.clone()).unwrap();
    let mut forged = LeaseRecord::new(
        capsule_id,
        attacker.peer_id(),
        99,
        LeaseMode::Takeover,
        "2026-08-28T00:00:00.000Z".into(),
        "2026-08-29T00:00:00.000Z".into(),
        grant.hash().unwrap(),
        &attacker,
    )
    .unwrap();
    forged.sig = Signature::from_bytes([0xaa; 64]);
    assert!(capsule.accept_lease(forged, &|_, _| true).is_err());
    assert!(capsule.evidence().is_empty());
    for epoch in 3..100 {
        let gap = LeaseRecord::new(
            capsule_id,
            attacker.peer_id(),
            epoch,
            LeaseMode::Takeover,
            "2026-08-28T00:00:00.000Z".into(),
            "2026-08-29T00:00:00.000Z".into(),
            grant.hash().unwrap(),
            &attacker,
        )
        .unwrap();
        capsule.accept_lease(gap, &|_, _| true).unwrap();
    }
    assert_eq!(capsule.evidence().len(), 64);
    let takeover = LeaseRecord::new(
        capsule_id,
        attacker.peer_id(),
        2,
        LeaseMode::Takeover,
        "2026-08-28T00:00:00.000Z".into(),
        "2026-08-29T00:00:00.000Z".into(),
        grant.hash().unwrap(),
        &attacker,
    )
    .unwrap();
    assert!(capsule.accept_lease(takeover, &|_, _| false).is_err());
}

#[test]
fn expired_lease_forces_fork_and_rejects_main() {
    let creator = Identity::from_secret_bytes(&[61; 32]);
    let capsule_id = Hash::from_bytes([62; 32]);
    let genesis = Genesis::new(
        capsule_id,
        "2026-08-28T00:00:00.000Z".into(),
        "dev.abra.workspace".into(),
        "x".into(),
        &creator,
    )
    .unwrap();
    let grant = LeaseRecord::new(
        capsule_id,
        creator.peer_id(),
        1,
        LeaseMode::Grant,
        "2026-08-28T00:00:00.000Z".into(),
        "2026-08-28T00:01:00.000Z".into(),
        genesis.hash().unwrap(),
        &creator,
    )
    .unwrap();
    let mut capsule = Capsule::new(genesis, grant).unwrap();
    let (_, mut full) = signed_manifest(Scope::Full);
    full.origin.peer_id = creator.peer_id();
    full.capsule_id = Some(capsule_id);
    full.sign(&creator).unwrap();
    let raw = RawManifest::parse(full.to_canonical_bytes().unwrap()).unwrap();
    let result = capsule
        .insert_snapshot(raw, "2026-08-28T00:02:00.000Z".into(), u64::MAX)
        .unwrap();
    assert!(result.forked);
    let main = LabelOp::new(
        capsule_id,
        1,
        "main".into(),
        result.snapshot_id,
        1,
        "2026-08-28T00:02:00.000Z".into(),
        &creator,
    )
    .unwrap();
    assert!(capsule
        .apply_label(main, creator.peer_id(), u64::MAX)
        .is_err());
}

#[test]
fn fork_on_write_creates_and_persists_label_op() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = abra_core::store::AbraStore::open(temp.path()).unwrap();
    let writer = Identity::from_secret_bytes(&store.keys.identity.secret_bytes());
    let capsule_id = Hash::from_bytes([71; 32]);
    let genesis = Genesis::new(
        capsule_id,
        "2026-08-28T00:00:00.000Z".into(),
        "dev.abra.workspace".into(),
        "fork".into(),
        &writer,
    )
    .unwrap();
    let grant = LeaseRecord::new(
        capsule_id,
        writer.peer_id(),
        1,
        LeaseMode::Grant,
        "2026-08-28T00:00:00.000Z".into(),
        "2026-08-28T00:01:00.000Z".into(),
        genesis.hash().unwrap(),
        &writer,
    )
    .unwrap();
    store.add_capsule(genesis, grant).unwrap();
    let (_, mut full) = signed_manifest(Scope::Full);
    full.origin.peer_id = writer.peer_id();
    full.capsule_id = Some(capsule_id);
    full.sign(&writer).unwrap();
    let raw = RawManifest::parse(full.to_canonical_bytes().unwrap()).unwrap();
    let result = store
        .receive_full(
            raw,
            "2026-08-28T00:02:00.000Z".into(),
            u64::MAX,
            Some(&writer),
        )
        .unwrap();
    let name = result.fork_label.unwrap();
    assert_eq!(
        store.capsules[&capsule_id].label(&name).unwrap().by,
        writer.peer_id()
    );
    drop(store);
    let reopened = abra_core::store::AbraStore::open(temp.path()).unwrap();
    assert!(reopened.capsules[&capsule_id].label(&name).is_some());
}

#[test]
fn store_restart_round_trip_restores_capsule_snapshot_lease_label_and_inbox() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = abra_core::store::AbraStore::open(temp.path()).unwrap();
    let creator_secret = store.keys.identity.secret_bytes();
    let creator = Identity::from_secret_bytes(&creator_secret);
    let capsule_id = Hash::from_bytes([41; 32]);
    let genesis = Genesis::new(
        capsule_id,
        "2026-08-28T00:00:00.000Z".into(),
        "dev.abra.workspace".into(),
        "restart".into(),
        &creator,
    )
    .unwrap();
    let grant = LeaseRecord::new(
        capsule_id,
        creator.peer_id(),
        1,
        LeaseMode::Grant,
        "2026-08-28T00:00:00.000Z".into(),
        "2026-08-29T00:00:00.000Z".into(),
        genesis.hash().unwrap(),
        &creator,
    )
    .unwrap();
    store.add_capsule(genesis.clone(), grant.clone()).unwrap();

    let (_, mut full) = signed_manifest(Scope::Full);
    full.origin.peer_id = creator.peer_id();
    full.capsule_id = Some(capsule_id);
    full.sign(&creator).unwrap();
    let full_raw = RawManifest::parse(full.to_canonical_bytes().unwrap()).unwrap();
    let full_id = full_raw.snapshot_id();
    store
        .receive_full(full_raw, "2026-08-28T00:01:00.000Z".into(), 0, None)
        .unwrap();
    let main = LabelOp::new(
        capsule_id,
        1,
        "main".into(),
        full_id,
        1,
        "2026-08-28T00:02:00.000Z".into(),
        &creator,
    )
    .unwrap();
    store.apply_label(main, creator.peer_id(), 0).unwrap();
    let (_, partial) = signed_manifest(Scope::Partial);
    let partial_raw = RawManifest::parse(partial.to_canonical_bytes().unwrap()).unwrap();
    let partial_id = store
        .receive_partial(
            partial_raw,
            "peer".into(),
            "2026-08-28T00:03:00.000Z".into(),
        )
        .unwrap();
    drop(store);

    let reopened = abra_core::store::AbraStore::open(temp.path()).unwrap();
    let capsule = reopened.capsules.get(&capsule_id).unwrap();
    assert_eq!(
        capsule.winning_lease().unwrap().bytes().unwrap(),
        grant.bytes().unwrap()
    );
    assert_eq!(
        capsule.snapshot(&full_id).unwrap().received_at,
        "2026-08-28T00:01:00.000Z"
    );
    assert_eq!(capsule.label("main").unwrap().snapshot_id, full_id);
    assert_eq!(reopened.inbox.get(&partial_id).unwrap().from, "peer");
}

#[test]
fn invalid_genesis_is_never_persisted() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = abra_core::store::AbraStore::open(temp.path()).unwrap();
    let creator = Identity::from_secret_bytes(&[81; 32]);
    let capsule_id = Hash::from_bytes([82; 32]);
    let mut genesis = Genesis::new(
        capsule_id,
        "2026-08-28T00:00:00.000Z".into(),
        "dev.abra.workspace".into(),
        "x".into(),
        &creator,
    )
    .unwrap();
    let grant = LeaseRecord::new(
        capsule_id,
        creator.peer_id(),
        1,
        LeaseMode::Grant,
        "2026-08-28T00:00:00.000Z".into(),
        "2026-08-29T00:00:00.000Z".into(),
        genesis.hash().unwrap(),
        &creator,
    )
    .unwrap();
    genesis.sig = Signature::from_bytes([0; 64]);
    assert!(store.add_capsule(genesis, grant).is_err());
    assert!(!temp
        .path()
        .join("capsules")
        .join(capsule_id.to_hex())
        .join("genesis.cjson")
        .exists());
}
#[test]
fn signature_preimage_and_short_id() {
    let i = Identity::from_secret_bytes(&[1; 32]);
    assert_eq!(i.short_id().to_hex().len(), 8);
    let s = i.sign("snapshot", b"x");
    i.peer_id().verify("snapshot", b"x", &s).unwrap();
    assert!(i.peer_id().verify("lease", b"x", &s).is_err())
}
#[test]
fn vectors_are_canonical_and_ids_match() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../../spec-vectors/vectors.json")).unwrap();
    for k in ["full", "partial"] {
        let raw = v[k]["canonical"].as_str().unwrap().as_bytes().to_vec();
        let m = RawManifest::parse(raw).unwrap();
        assert_eq!(
            m.snapshot_id().to_hex(),
            v[k]["snapshot_id"].as_str().unwrap()
        )
    }
    assert_eq!(
        Tree::default().hash().to_hex(),
        v["empty_tree_id"].as_str().unwrap()
    );
    let chain = v["lease_chain"].as_array().unwrap();
    let genesis: Genesis = serde_json::from_str(chain[0].as_str().unwrap()).unwrap();
    genesis.verify().unwrap();
    let mut previous = genesis.hash().unwrap();
    let mut holder = genesis.created_by;
    for item in &chain[1..] {
        let lease: LeaseRecord = serde_json::from_str(item.as_str().unwrap()).unwrap();
        assert_eq!(lease.prev_hash, previous);
        let signer = if lease.mode == LeaseMode::Takeover {
            lease.holder
        } else {
            holder
        };
        lease.verify_with(&signer).unwrap();
        previous = lease.hash().unwrap();
        holder = lease.holder;
    }
}
