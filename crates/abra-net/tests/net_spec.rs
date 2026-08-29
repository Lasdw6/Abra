use abra_core::{
    capsule::{Genesis, LeaseMode, LeaseRecord},
    cas::{materialize, snapshot_dir, Hash},
    identity::{Identity, PeerId, Signature},
    manifest::{Manifest, Origin, RawManifest, Scope},
};
use abra_net::{
    bootstrap_allowed, check_hello, Ack, DeliveryNode, DeliveryOutcome, EnrollmentToken, Hello,
    LoopbackNetwork, LoopbackTransport, Offer, OutboxState, Role, Scopes, Transport, TrustedPeer,
    WIRE_VERSION,
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

fn full(node: &mut DeliveryNode, source: &Path, capsule_id: Hash, title: &str) -> RawManifest {
    let files = snapshot_dir(&node.store.cas, source).unwrap();
    let mut manifest = Manifest {
        spec: abra_core::SPEC.into(),
        scope: Scope::Full,
        kind: "dev.abra.workspace".into(),
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
        capsule_id: Some(capsule_id),
        parents: Some(vec![]),
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

async fn wire_deliver(
    a: &mut DeliveryNode,
    b: &mut DeliveryNode,
    id: &str,
    now: u64,
) -> abra_net::Result<DeliveryOutcome> {
    let network = LoopbackNetwork::default();
    let ta = LoopbackTransport::bind(&network, a.peer_id());
    let tb = LoopbackTransport::bind(&network, b.peer_id());
    let mut outgoing = ta.dial(b.peer_id()).await?;
    let mut incoming = tb.accept().await?;
    let (sent, handled) = tokio::join!(
        async {
            let x = a.send_offer(id, &mut outgoing, now).await;
            drop(outgoing);
            x
        },
        b.handle_connection(&mut incoming, now)
    );
    handled?;
    sent
}

#[cfg(unix)]
#[tokio::test]
async fn loopback_teleport_preserves_files_exec_and_symlink() {
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
    let network = LoopbackNetwork::default();
    let ta = LoopbackTransport::bind(&network, a.peer_id());
    let tb = LoopbackTransport::bind(&network, b.peer_id());
    let mut outgoing = ta.dial(b.peer_id()).await.unwrap();
    let mut incoming = tb.accept().await.unwrap();
    let (outcome, handled) = tokio::join!(
        async {
            let x = a.send_offer(&id, &mut outgoing, NOW + 1).await;
            drop(outgoing);
            x
        },
        b.handle_connection(&mut incoming, NOW + 1)
    );
    handled.unwrap();
    let outcome = outcome.unwrap();
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

#[tokio::test]
async fn delta_sync_transfers_only_changed_objects() {
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
    wire_deliver(&mut a, &mut b, &id, NOW).await.unwrap();
    fs::write(input.path().join("a"), b"two").unwrap();
    let v2 = partial(&mut a, input.path(), "v2");
    let id = a.enqueue(b.peer_id(), &v2, NOW + 1).unwrap();
    let DeliveryOutcome::Complete { stats, .. } =
        wire_deliver(&mut a, &mut b, &id, NOW + 1).await.unwrap()
    else {
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
    let new = a.outbox.retry_fresh(&id, NOW + 2).unwrap();
    assert_ne!(old, new);
    a.outbox
        .transition(&id, OutboxState::Healthcheck, NOW + 3)
        .unwrap();
    a.outbox
        .transition(&id, OutboxState::Offered, NOW + 3)
        .unwrap();
    a.outbox
        .transition(&id, OutboxState::Transferring, NOW + 3)
        .unwrap();
    a.outbox
        .transition(&id, OutboxState::AwaitingAck, NOW + 3)
        .unwrap();
    let fake = Ack {
        message_type: "ack".into(),
        offer_id: new,
        snapshot_id: raw.snapshot_id(),
        received_at: abra_net::format_time(NOW + 3),
        shelf: "inbox".into(),
        sig: Signature::from_bytes([1; 64]),
    };
    assert!(a
        .outbox
        .apply_ack(&id, &fake, a.peer_id(), NOW + 3)
        .is_err());
    assert_eq!(a.outbox.get(&id).unwrap().state, OutboxState::AwaitingAck);
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

#[tokio::test]
async fn interrupted_transfer_resumes_without_resending_prefix() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("large"), vec![3u8; 128 * 1024]).unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let raw = partial(&mut a, input.path(), "resume");
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    let network = LoopbackNetwork::default();
    let ta = LoopbackTransport::bind(&network, a.peer_id());
    let tb = LoopbackTransport::bind(&network, b.peer_id());
    let mut outgoing = ta.dial(b.peer_id()).await.unwrap();
    let mut incoming = tb.accept().await.unwrap();
    let (first_result, receiver_result) = tokio::join!(
        async {
            let x = a.send_offer_limited(&id, &mut outgoing, NOW, 4096).await;
            drop(outgoing);
            x
        },
        b.handle_connection(&mut incoming, NOW)
    );
    assert!(receiver_result.is_err());
    let DeliveryOutcome::Interrupted { stats: first } = first_result.unwrap() else {
        panic!()
    };
    assert_eq!(first.bytes_transferred, 4096);
    let DeliveryOutcome::Complete { stats: second, .. } =
        wire_deliver(&mut a, &mut b, &id, NOW + 1).await.unwrap()
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
    assert!(token.verify(NOW + 61_001).is_err());
}

#[test]
fn guest_send_requires_scope_and_local_switch() {
    let root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("x"), b"x").unwrap();
    let mut node = DeliveryNode::open(root.path()).unwrap();
    let issuer = Identity::generate();
    let token = EnrollmentToken::mint(
        "guest".into(),
        vec![],
        Some(node.peer_id()),
        Scopes {
            capsules: vec!["*".into()],
            kinds: vec!["*".into()],
            send: true,
            receive: true,
            lease_acquire: false,
            lease_takeover: false,
        },
        NOW,
        60_000,
        &issuer,
    )
    .unwrap();
    node.trust
        .set_local_role(abra_net::LocalRole::Guest {
            token: Box::new(token),
        })
        .unwrap();
    let raw = partial(&mut node, input.path(), "x");
    assert!(node
        .enqueue(Identity::generate().peer_id(), &raw, NOW)
        .is_err());
    node.allow_agent_send = true;
    assert!(node
        .enqueue(Identity::generate().peer_id(), &raw, NOW)
        .is_ok());
}

#[tokio::test]
async fn bootstrap_session_rejects_trusted_messages_over_loopback() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    let network = LoopbackNetwork::default();
    let ta = LoopbackTransport::bind(&network, a.peer_id());
    let tb = LoopbackTransport::bind(&network, b.peer_id());
    let mut outgoing = ta.dial(b.peer_id()).await.unwrap();
    let mut incoming = tb.accept().await.unwrap();
    let (client, server) = tokio::join!(
        async {
            let hello = abra_net::dial_handshake(&mut outgoing, a.peer_id(), "a".into())
                .await
                .unwrap();
            assert_eq!(hello.session, "bootstrap");
            let (send, recv) = outgoing.control_mut();
            abra_net::write_frame(
                send,
                &serde_json::json!({"type":"ping","nonce":"00","ts":abra_net::format_time(NOW)}),
            )
            .await
            .unwrap();
            abra_net::read_frame::<_, abra_net::ProtocolError>(recv)
                .await
                .unwrap()
        },
        b.handle_connection(&mut incoming, NOW)
    );
    assert_eq!(client.code, "untrusted");
    assert!(server.is_err());
}

#[tokio::test]
async fn full_first_send_installs_genesis_and_non_holder_write_is_stored_as_fork() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("x"), b"full").unwrap();
    let mut a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let creator = Identity::generate();
    let capsule_id = Hash::from_bytes([42; 32]);
    let genesis = Genesis::new(
        capsule_id,
        abra_net::format_time(NOW),
        "dev.abra.workspace".into(),
        "capsule".into(),
        &creator,
    )
    .unwrap();
    let grant = LeaseRecord::new(
        capsule_id,
        creator.peer_id(),
        1,
        LeaseMode::Grant,
        abra_net::format_time(NOW),
        abra_net::format_time(NOW + 86_400_000),
        genesis.hash().unwrap(),
        &creator,
    )
    .unwrap();
    a.store.add_capsule(genesis, grant).unwrap();
    let raw = full(&mut a, input.path(), capsule_id, "forked");
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    let network = LoopbackNetwork::default();
    let ta = LoopbackTransport::bind(&network, a.peer_id());
    let tb = LoopbackTransport::bind(&network, b.peer_id());
    let mut outgoing = ta.dial(b.peer_id()).await.unwrap();
    let mut incoming = tb.accept().await.unwrap();
    let (sent, handled) = tokio::join!(
        async {
            let x = a.send_offer(&id, &mut outgoing, NOW + 1).await;
            drop(outgoing);
            x
        },
        b.handle_connection(&mut incoming, NOW + 1)
    );
    handled.unwrap();
    sent.unwrap();
    let capsule = b.store.capsules.get(&capsule_id).unwrap();
    assert!(capsule.snapshot(&raw.snapshot_id()).is_some());
    assert!(capsule
        .active_lease(NOW + 1)
        .is_some_and(|lease| lease.holder == creator.peer_id()));
}

#[test]
fn receiver_rejects_noncanonical_mismatched_and_untrusted_origin_manifest_bytes() {
    let sender_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("x"), b"x").unwrap();
    let mut sender = DeliveryNode::open(sender_root.path()).unwrap();
    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    trust_each_other(&mut sender, &mut receiver);
    let raw = partial(&mut sender, input.path(), "authority");
    let base = Offer {
        message_type: "offer".into(),
        offer_id: "11".repeat(16),
        snapshot_id: raw.snapshot_id(),
        scope: raw.manifest().scope,
        kind: "ignored.copy".into(),
        title: "ignored".into(),
        capsule_id: None,
        fork: false,
        bytes_hint: 0,
        object_count: 0,
        manifest_raw: data_encoding::BASE64URL_NOPAD.encode(raw.bytes()),
        genesis: None,
        genesis_grant: None,
    };
    assert_eq!(
        receiver
            .validate_incoming_offer(&base, sender.peer_id(), NOW)
            .unwrap()
            .bytes(),
        raw.bytes()
    );
    let mut noncanonical = base.clone();
    let mut bytes = raw.bytes().to_vec();
    bytes.push(b' ');
    noncanonical.manifest_raw = data_encoding::BASE64URL_NOPAD.encode(&bytes);
    assert!(receiver
        .validate_incoming_offer(&noncanonical, sender.peer_id(), NOW)
        .is_err());
    let mut mismatch = base.clone();
    mismatch.snapshot_id = Hash::from_bytes([99; 32]);
    assert!(receiver
        .validate_incoming_offer(&mismatch, sender.peer_id(), NOW)
        .is_err());

    let attacker_root = tempfile::tempdir().unwrap();
    let mut attacker = DeliveryNode::open(attacker_root.path()).unwrap();
    let hostile = partial(&mut attacker, input.path(), "hostile");
    let mut relayed = base;
    relayed.snapshot_id = hostile.snapshot_id();
    relayed.manifest_raw = data_encoding::BASE64URL_NOPAD.encode(hostile.bytes());
    assert!(receiver
        .validate_incoming_offer(&relayed, sender.peer_id(), NOW)
        .is_err());
}
