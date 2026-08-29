use abra_core::{
    cas::{materialize, snapshot_dir, Hash},
    identity::{Identity, PeerId, Signature},
    manifest::{Manifest, Origin, RawManifest, Scope},
};
use abra_net::{
    bootstrap_allowed, check_hello, DeliveryNode, DeliveryOutcome, EnrollmentToken, Hello,
    OutboxState, Role, Scopes, TrustedPeer, WIRE_VERSION,
};
use serde_json::Map;
use std::{fs, path::Path};

const NOW: u64 = 1_800_000_000_000;

fn partial(node: &mut DeliveryNode, source: &Path, title: &str) -> RawManifest {
    let files = snapshot_dir(&node.store.cas, source).unwrap();
    let mut manifest = Manifest {
        spec: abra_core::SPEC.into(),
        scope: Scope::Partial,
        kind: "dev.abra.bundle".into(),
        title: title.into(),
        origin: Origin {
            peer_id: node.peer_id(),
            name: Some("sender".into()),
            adapter: None,
        },
        created_at: abra_net::format_time(NOW),
        summary: None,
        link: None,
        thumbnail: None,
        capsule_id: None,
        parents: None,
        labels: None,
        provenance: None,
        files: Some(files),
        recipes: None,
        native: None,
        payload: Map::new(),
        extensions: None,
        signature: Signature::from_bytes([0; 64]),
    };
    manifest.sign(&node.store.keys.identity).unwrap();
    RawManifest::parse(manifest.to_canonical_bytes().unwrap()).unwrap()
}

fn full_peer(peer_id: PeerId) -> TrustedPeer {
    TrustedPeer {
        peer_id,
        name: "peer".into(),
        role: Role::Full,
        x25519_pk: [7; 32],
        token_id: None,
        scopes: None,
        expires_at: None,
    }
}

fn trust_each_other(a: &mut DeliveryNode, b: &mut DeliveryNode) {
    a.trust.insert(full_peer(b.peer_id())).unwrap();
    b.trust.insert(full_peer(a.peer_id())).unwrap();
}

#[cfg(unix)]
#[test]
fn loopback_teleport_preserves_files_exec_and_symlink() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("plain"), b"hello\n").unwrap();
    fs::write(input.path().join("run"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(input.path().join("run"), fs::Permissions::from_mode(0o755)).unwrap();
    symlink("plain", input.path().join("alias")).unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let raw = partial(&mut a, input.path(), "teleport");
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    let outcome = a.deliver(&id, &mut b, NOW + 1).unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Complete { .. }));
    assert_eq!(a.outbox.get(&id).unwrap().state, OutboxState::Acked);
    let output = b_dir.path().join("materialized");
    materialize(
        &b.store.cas,
        raw.manifest().files.as_ref().unwrap(),
        &output,
    )
    .unwrap();
    assert_eq!(fs::read(output.join("plain")).unwrap(), b"hello\n");
    assert_eq!(
        fs::read_link(output.join("alias")).unwrap(),
        Path::new("plain")
    );
    assert_ne!(
        fs::metadata(output.join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
}

#[test]
fn delta_sync_transfers_only_changed_objects() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("a"), b"one").unwrap();
    fs::write(input.path().join("b"), b"same").unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let v1 = partial(&mut a, input.path(), "v1");
    let id = a.enqueue(b.peer_id(), &v1, NOW).unwrap();
    a.deliver(&id, &mut b, NOW).unwrap();
    fs::write(input.path().join("a"), b"two").unwrap();
    let v2 = partial(&mut a, input.path(), "v2");
    let id = a.enqueue(b.peer_id(), &v2, NOW + 1).unwrap();
    let DeliveryOutcome::Complete { stats, .. } = a.deliver(&id, &mut b, NOW + 1).unwrap() else {
        panic!()
    };
    assert_eq!(
        stats.objects_transferred, 2,
        "changed blob plus changed root tree"
    );
    assert!(stats.objects_reused >= 1);
}

#[test]
fn outbox_survives_restart_and_old_ack_cannot_clear_fresh_attempt() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("x"), b"x").unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let raw = partial(&mut a, input.path(), "queued");
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    let old = a.outbox.get(&id).unwrap().offer_id.clone();
    drop(a);
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    a.deliver(&id, &mut b, NOW + 1).unwrap();
    let new = a.outbox.retry_fresh(&id, NOW + 2).unwrap();
    assert_ne!(old, new);
    let fake = Signature::from_bytes([1; 64]);
    assert!(!a
        .outbox
        .mark_acked(&id, &old, raw.snapshot_id(), fake, NOW + 3)
        .unwrap());
    assert_eq!(a.outbox.get(&id).unwrap().state, OutboxState::Queued);
}

#[test]
fn scope_expiry_revocation_and_guest_to_guest_are_enforced() {
    let root = tempfile::tempdir().unwrap();
    let mut trust = abra_net::TrustStore::open(root.path()).unwrap();
    let guest = Identity::generate();
    let other = Identity::generate();
    let scopes = Scopes {
        capsules: vec![Hash::from_bytes([1; 32]).to_hex()],
        kinds: vec!["dev.abra.workspace".into()],
        send: true,
        receive: true,
        lease_acquire: false,
        lease_takeover: false,
    };
    trust
        .insert(TrustedPeer {
            peer_id: guest.peer_id(),
            name: "g".into(),
            role: Role::Guest,
            x25519_pk: [0; 32],
            token_id: Some("aa".repeat(16)),
            scopes: Some(scopes),
            expires_at: Some(abra_net::format_time(NOW + 1000)),
        })
        .unwrap();
    assert!(trust
        .authorize_offer(
            guest.peer_id(),
            other.peer_id(),
            Some(Hash::from_bytes([2; 32])),
            "dev.abra.workspace",
            abra_net::Direction::Send,
            NOW
        )
        .is_err());
    assert!(trust
        .authorize_offer(
            guest.peer_id(),
            other.peer_id(),
            Some(Hash::from_bytes([1; 32])),
            "dev.abra.workspace",
            abra_net::Direction::Send,
            NOW + 1001
        )
        .is_err());
    trust.revoke_token(&"aa".repeat(16)).unwrap();
    assert!(trust
        .authorize_offer(
            guest.peer_id(),
            other.peer_id(),
            None,
            "dev.abra.workspace",
            abra_net::Direction::Send,
            NOW
        )
        .is_err());
}

#[test]
fn handshake_versions_and_bootstrap_allowlist() {
    let id = Identity::generate();
    let mut hello = Hello {
        message_type: "hello".into(),
        wire: 99,
        spec: abra_core::SPEC.into(),
        peer_id: id.peer_id(),
        name: "x".into(),
        features: vec!["resume".into(), "control".into()],
        nonce: "00".repeat(16),
    };
    assert!(check_hello(&hello, id.peer_id(), false).is_err());
    hello.wire = WIRE_VERSION;
    assert_eq!(
        check_hello(&hello, id.peer_id(), false).unwrap().session,
        "bootstrap"
    );
    assert!(bootstrap_allowed("pair-request"));
    assert!(!bootstrap_allowed("offer"));
}

#[test]
fn interrupted_transfer_resumes_without_resending_prefix() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("large"), vec![3u8; 128 * 1024]).unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let raw = partial(&mut a, input.path(), "resume");
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    let DeliveryOutcome::Interrupted { stats: first } =
        a.deliver_limited(&id, &mut b, NOW, Some(4096)).unwrap()
    else {
        panic!()
    };
    assert_eq!(first.bytes_transferred, 4096);
    let DeliveryOutcome::Complete { stats: second, .. } = a.deliver(&id, &mut b, NOW + 1).unwrap()
    else {
        panic!()
    };
    assert!(second.resumed_bytes >= 4096);
    assert!(second.bytes_transferred < 128 * 1024 + 4096);
}

#[test]
fn enrollment_token_validation() {
    let issuer = Identity::generate();
    let scopes = Scopes {
        capsules: vec!["*".into()],
        kinds: vec!["*".into()],
        send: true,
        receive: true,
        lease_acquire: false,
        lease_takeover: false,
    };
    let token =
        EnrollmentToken::mint("guest".into(), vec![], None, scopes, NOW, 1000, &issuer).unwrap();
    assert!(token.verify(NOW).is_ok());
    assert!(token.verify(NOW + 1001).is_err());
}
