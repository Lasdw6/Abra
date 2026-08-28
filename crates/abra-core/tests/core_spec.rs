use abra_core::{
    canonical,
    capsule::{Capsule, Genesis, LeaseMode, LeaseRecord},
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
    assert!(canonical::to_vec(&json!({"payload":{"n":-1}})).is_ok())
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
    let mut c = Capsule::new(g.clone()).unwrap();
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
    assert!(c.accept_lease(l1.clone()).unwrap());
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
    assert!(!c.accept_lease(gap).unwrap());
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
    assert!(c.accept_lease(race[0].clone()).unwrap());
    assert!(c.accept_lease(race[1].clone()).unwrap());
    assert_eq!(c.winning_lease().unwrap().holder, race[1].holder);
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
