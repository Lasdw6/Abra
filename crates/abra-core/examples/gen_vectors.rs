use abra_core::{
    canonical,
    capsule::{Genesis, LeaseMode, LeaseRecord},
    cas::{Hash, Tree},
    identity::{Identity, Signature},
    manifest::{Manifest, Origin, Scope},
};
use serde_json::{json, Map};
fn manifest(scope: Scope, id: &Identity) -> Manifest {
    Manifest {
        spec: abra_core::SPEC.into(),
        scope,
        kind: match scope {
            Scope::Full => "dev.abra.workspace",
            Scope::Partial => "dev.abra.handoff.v1",
        }
        .into(),
        title: match scope {
            Scope::Full => "Vector workspace",
            Scope::Partial => "Vector handoff",
        }
        .into(),
        origin: Origin {
            peer_id: id.peer_id(),
            name: Some("test device".into()),
            adapter: None,
        },
        created_at: "2026-08-28T13:00:00.000Z".into(),
        summary: None,
        link: None,
        thumbnail: None,
        capsule_id: (scope == Scope::Full).then(|| Hash::from_bytes([0x11; 32])),
        parents: (scope == Scope::Full).then(Vec::new),
        labels: None,
        provenance: None,
        files: (scope == Scope::Full).then(|| Tree::default().hash()),
        recipes: None,
        native: None,
        payload: Map::new(),
        extensions: None,
        signature: Signature::from_bytes([0; 64]),
    }
}
fn main() {
    let key = Identity::from_secret_bytes(&[7; 32]);
    let mut full = manifest(Scope::Full, &key);
    full.sign(&key).unwrap();
    let mut partial = manifest(Scope::Partial, &key);
    partial.payload.insert("delta".into(), json!(-7));
    partial.sign(&key).unwrap();
    let genesis = Genesis::new(
        Hash::from_bytes([0x22; 32]),
        "2026-08-28T13:00:00.000Z".into(),
        "dev.abra.workspace".into(),
        "Lease vector".into(),
        &key,
    )
    .unwrap();
    let l1 = LeaseRecord::new(
        genesis.capsule_id,
        key.peer_id(),
        1,
        LeaseMode::Grant,
        "2026-08-28T13:00:00.000Z".into(),
        "2026-08-29T13:00:00.000Z".into(),
        genesis.hash().unwrap(),
        &key,
    )
    .unwrap();
    let l2 = LeaseRecord::new(
        genesis.capsule_id,
        key.peer_id(),
        2,
        LeaseMode::Refresh,
        "2026-08-28T14:00:00.000Z".into(),
        "2026-08-29T14:00:00.000Z".into(),
        l1.hash().unwrap(),
        &key,
    )
    .unwrap();
    let other = Identity::from_secret_bytes(&[8; 32]);
    let l3 = LeaseRecord::new(
        genesis.capsule_id,
        other.peer_id(),
        3,
        LeaseMode::Transfer,
        "2026-08-28T15:00:00.000Z".into(),
        "2026-08-29T15:00:00.000Z".into(),
        l2.hash().unwrap(),
        &key,
    )
    .unwrap();
    let out = json!({"warning":"TEST KEY ONLY: Ed25519 seed is 32 bytes of 0x07","full":{"canonical":String::from_utf8(full.to_canonical_bytes().unwrap()).unwrap(),"snapshot_id":full.snapshot_id().unwrap()},"partial":{"canonical":String::from_utf8(partial.to_canonical_bytes().unwrap()).unwrap(),"snapshot_id":partial.snapshot_id().unwrap()},"empty_tree_id":Tree::default().hash(),"lease_chain":[String::from_utf8(genesis.bytes().unwrap()).unwrap(),String::from_utf8(l1.bytes().unwrap()).unwrap(),String::from_utf8(l2.bytes().unwrap()).unwrap(),String::from_utf8(l3.bytes().unwrap()).unwrap()]});
    println!("{}", canonical::to_string(&out).unwrap())
}
