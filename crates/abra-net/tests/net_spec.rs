use abra_core::{
    capsule::{Genesis, LabelOp, LeaseMode, LeaseRecord},
    cas::{materialize, snapshot_dir, Hash},
    identity::{Identity, PeerId, Signature},
    manifest::{Fingerprint, Manifest, NativeBlobRef, Origin, RawManifest, Scope},
};
use abra_net::{
    bootstrap_allowed, check_hello, Ack, BindCertificate, ControlHandler, ControlMessage,
    ControlOp, DeliveryNode, DeliveryOutcome, EnrollmentToken, Hello, LoopbackNetwork,
    LoopbackTransport, Offer, OutboxState, PairRequest, PairTicket, Ping, Revocation, Role, Scopes,
    Transport, TrustedPeer, MAX_LEASE_CHAIN_LEN, WIRE_VERSION,
};
use serde_json::Map;
use std::{fs, path::Path, time::Duration};

const NOW: u64 = 1_800_000_000_000;

#[test]
fn pairing_rejects_invalid_dial_hints_before_persisting_peer() {
    let root = tempfile::tempdir().unwrap();
    let issuer = Identity::generate();
    let joiner = Identity::generate();
    let ticket = PairTicket::mint(
        "issuer".into(),
        [1; 32],
        None,
        Vec::new(),
        NOW,
        60_000,
        &issuer,
    )
    .unwrap();
    let mut trust = abra_net::TrustStore::open(root.path()).unwrap();
    trust.register_ticket(ticket.clone()).unwrap();
    let request = PairRequest::sign(
        ticket.ticket_id,
        "joiner".into(),
        [2; 32],
        None,
        vec!["this is not a dial address".into()],
        [3; 16],
        &joiner,
    )
    .unwrap();

    let error = trust
        .accept_pair_request(&request, joiner.peer_id(), NOW, true, |_, _| true)
        .unwrap_err();
    assert!(error.to_string().contains("address"));
    assert!(trust.get(&joiner.peer_id()).is_none());
}

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

fn full_native(
    node: &mut DeliveryNode,
    source: &Path,
    capsule_id: Hash,
    blob: Hash,
    bytes: u64,
) -> RawManifest {
    let raw = full(node, source, capsule_id, "native transfer");
    let mut manifest = raw.manifest().clone();
    manifest.native = Some(vec![NativeBlobRef {
        role: "memory".into(),
        blob,
        bytes,
        fingerprint: Fingerprint {
            os: "linux".into(),
            arch: "x86_64".into(),
            hypervisor: "firecracker".into(),
            snapshot_format_major: 1,
            cpu_template: "-".into(),
            cpu_identity: "test-cpu".into(),
        },
    }]);
    manifest.sign(&node.store.keys.identity).unwrap();
    RawManifest::parse(manifest.to_canonical_bytes().unwrap()).unwrap()
}

fn add_test_capsule(node: &mut DeliveryNode, capsule_id: Hash) {
    let creator = Identity::from_secret_bytes(&node.store.keys.identity.secret_bytes());
    let genesis = Genesis::new(
        capsule_id,
        abra_net::format_time(NOW),
        "dev.abra.workspace".into(),
        "native".into(),
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
    node.store.add_capsule(genesis, grant).unwrap();
}

fn full_peer(peer_id: PeerId) -> TrustedPeer {
    TrustedPeer {
        peer_id,
        name: "peer".into(),
        role: Role::Full,
        x25519_pk: [7; 32],
        relay_key: Some([8; 32]),
        token_id: None,
        scopes: None,
        expires_at: None,
        addresses: Vec::new(),
    }
}

fn trust_each_other(a: &mut DeliveryNode, b: &mut DeliveryNode) {
    a.trust.insert(full_peer(b.peer_id())).unwrap();
    b.trust.insert(full_peer(a.peer_id())).unwrap();
}

fn guest_certificate(
    host: &DeliveryNode,
    guest: &DeliveryNode,
    expires_at: u64,
) -> BindCertificate {
    BindCertificate::sign(
        "42".repeat(16),
        guest.peer_id(),
        NOW,
        "firecracker guest".into(),
        [9; 32],
        Scopes {
            capsules: vec!["*".into()],
            kinds: vec!["*".into()],
            send: true,
            receive: true,
            lease_acquire: false,
            lease_takeover: false,
        },
        abra_net::format_time(expires_at),
        &host.store.keys.identity,
    )
    .unwrap()
}

fn offer_for(raw: &RawManifest) -> Offer {
    Offer {
        message_type: "offer".into(),
        offer_id: "11".repeat(16),
        snapshot_id: raw.snapshot_id(),
        scope: raw.manifest().scope,
        kind: raw.manifest().kind.clone(),
        title: raw.manifest().title.clone(),
        capsule_id: raw.manifest().capsule_id,
        fork: false,
        bytes_hint: 0,
        object_count: 0,
        manifest_raw: data_encoding::BASE64URL_NOPAD.encode(raw.bytes()),
        genesis: None,
        genesis_grant: None,
        lease_chain: Vec::new(),
        main_label: None,
        bind_certificate_issuer: None,
        bind_certificate: None,
        revocations: Vec::new(),
    }
}

#[test]
fn untrusted_and_guest_forwarders_cannot_install_bind_certificates() {
    let receiver_root = tempfile::tempdir().unwrap();
    let issuer_root = tempfile::tempdir().unwrap();
    let guest_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("x"), b"x").unwrap();
    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    let issuer = DeliveryNode::open(issuer_root.path()).unwrap();
    let mut guest = DeliveryNode::open(guest_root.path()).unwrap();
    receiver.trust.insert(full_peer(issuer.peer_id())).unwrap();
    let raw = partial(&mut guest, input.path(), "guest");
    let mut offer = offer_for(&raw);
    offer.bind_certificate_issuer = Some(issuer.peer_id());
    offer.bind_certificate = Some(guest_certificate(&issuer, &guest, NOW + 60_000));

    let untrusted = Identity::generate();
    assert!(receiver
        .validate_incoming_offer(&offer, untrusted.peer_id(), NOW)
        .is_err());
    assert!(receiver.trust.get(&guest.peer_id()).is_none());

    let mut guest_forwarder = full_peer(untrusted.peer_id());
    guest_forwarder.role = Role::Guest;
    guest_forwarder.token_id = Some("33".repeat(16));
    guest_forwarder.scopes = Some(Scopes {
        capsules: vec!["*".into()],
        kinds: vec!["*".into()],
        send: true,
        receive: true,
        lease_acquire: false,
        lease_takeover: false,
    });
    guest_forwarder.expires_at = Some(abra_net::format_time(NOW + 60_000));
    receiver.trust.insert(guest_forwarder).unwrap();
    assert!(receiver
        .validate_incoming_offer(&offer, untrusted.peer_id(), NOW)
        .is_err());
    assert!(receiver.trust.get(&guest.peer_id()).is_none());
}

#[test]
fn expired_guest_manifest_origin_is_rejected() {
    let receiver_root = tempfile::tempdir().unwrap();
    let sender_root = tempfile::tempdir().unwrap();
    let guest_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("x"), b"x").unwrap();
    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    let sender = DeliveryNode::open(sender_root.path()).unwrap();
    let mut guest = DeliveryNode::open(guest_root.path()).unwrap();
    receiver.trust.insert(full_peer(sender.peer_id())).unwrap();
    let mut expired_origin = full_peer(guest.peer_id());
    expired_origin.role = Role::Guest;
    expired_origin.token_id = Some("44".repeat(16));
    expired_origin.expires_at = Some(abra_net::format_time(NOW - 1));
    receiver.trust.insert(expired_origin).unwrap();
    let raw = partial(&mut guest, input.path(), "expired origin");

    let error = receiver
        .validate_incoming_offer(&offer_for(&raw), sender.peer_id(), NOW)
        .unwrap_err();
    assert_eq!(error.to_string(), "authorization: manifest origin expired");
}

#[test]
fn revocation_removes_the_certificate_used_for_forwarded_offers() {
    let host_root = tempfile::tempdir().unwrap();
    let guest_root = tempfile::tempdir().unwrap();
    let mut host = DeliveryNode::open(host_root.path()).unwrap();
    let guest = DeliveryNode::open(guest_root.path()).unwrap();
    host.trust.insert(full_peer(host.peer_id())).unwrap();
    let certificate = guest_certificate(&host, &guest, NOW + 60_000);
    let token_id = certificate.token_id.clone();
    host.trust
        .install_bind_certificate(host.peer_id(), certificate, NOW)
        .unwrap();
    assert!(host.trust.bind_certificate(&guest.peer_id()).is_some());

    let identity = host.store.keys.identity.clone();
    host.trust.revoke_token(&token_id, NOW, &identity).unwrap();
    assert!(host.trust.bind_certificate(&guest.peer_id()).is_none());
}

#[test]
fn propagated_revocation_drops_guest_and_rejects_its_offer() {
    let issuer_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let guest_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("x"), b"x").unwrap();
    let mut issuer = DeliveryNode::open(issuer_root.path()).unwrap();
    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    let mut guest = DeliveryNode::open(guest_root.path()).unwrap();
    trust_each_other(&mut issuer, &mut receiver);
    issuer.trust.insert(full_peer(issuer.peer_id())).unwrap();
    let certificate = guest_certificate(&issuer, &guest, NOW + 60_000);
    let token_id = certificate.token_id.clone();
    issuer
        .trust
        .install_bind_certificate(issuer.peer_id(), certificate.clone(), NOW)
        .unwrap();
    receiver
        .trust
        .install_bind_certificate(issuer.peer_id(), certificate, NOW)
        .unwrap();
    let identity = issuer.store.keys.identity.clone();
    issuer
        .trust
        .revoke_token(&token_id, NOW + 1, &identity)
        .unwrap();

    let issuer_raw = partial(&mut issuer, input.path(), "issuer contact");
    let mut contact = offer_for(&issuer_raw);
    contact.revocations = issuer.trust.current_revocations(NOW + 2);
    receiver
        .validate_incoming_offer(&contact, issuer.peer_id(), NOW + 2)
        .unwrap();
    assert!(receiver.trust.get(&guest.peer_id()).is_none());

    let guest_raw = partial(&mut guest, input.path(), "revoked guest");
    assert!(receiver
        .validate_incoming_offer(&offer_for(&guest_raw), guest.peer_id(), NOW + 3)
        .is_err());
}

#[tokio::test]
async fn queued_delivery_is_blocked_after_recipient_revocation() {
    let issuer_root = tempfile::tempdir().unwrap();
    let guest_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("secret"), b"queued before revoke").unwrap();
    let mut issuer = DeliveryNode::open(issuer_root.path()).unwrap();
    let mut guest = DeliveryNode::open(guest_root.path()).unwrap();
    guest.trust.insert(full_peer(issuer.peer_id())).unwrap();
    issuer.trust.insert(full_peer(issuer.peer_id())).unwrap();
    let certificate = guest_certificate(&issuer, &guest, NOW + 60_000);
    let token_id = certificate.token_id.clone();
    issuer
        .trust
        .install_bind_certificate(issuer.peer_id(), certificate, NOW)
        .unwrap();
    let raw = partial(&mut issuer, input.path(), "queued secret");
    let id = issuer.enqueue(guest.peer_id(), &raw, NOW).unwrap();
    let identity = issuer.store.keys.identity.clone();
    issuer
        .trust
        .revoke_token(&token_id, NOW + 1, &identity)
        .unwrap();

    assert!(wire_deliver(&mut issuer, &mut guest, &id, NOW + 2)
        .await
        .is_err());
    assert!(!guest.store.inbox.contains_key(&raw.snapshot_id()));
}

#[test]
fn forged_revocation_from_non_issuer_is_ignored() {
    let issuer_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let guest_root = tempfile::tempdir().unwrap();
    let issuer = DeliveryNode::open(issuer_root.path()).unwrap();
    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    let guest = DeliveryNode::open(guest_root.path()).unwrap();
    let attacker = Identity::generate();
    receiver.trust.insert(full_peer(issuer.peer_id())).unwrap();
    receiver
        .trust
        .insert(full_peer(attacker.peer_id()))
        .unwrap();
    let certificate = guest_certificate(&issuer, &guest, NOW + 60_000);
    receiver
        .trust
        .install_bind_certificate(issuer.peer_id(), certificate.clone(), NOW)
        .unwrap();
    let forged =
        Revocation::sign(certificate.token_id, guest.peer_id(), NOW + 1, &attacker).unwrap();

    receiver
        .trust
        .apply_revocations(&[forged], NOW + 1)
        .unwrap();
    assert!(receiver.trust.get(&guest.peer_id()).is_some());
}

#[test]
fn propagated_revocation_survives_reload_and_blocks_reinstall() {
    let issuer_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let guest_root = tempfile::tempdir().unwrap();
    let mut issuer = DeliveryNode::open(issuer_root.path()).unwrap();
    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    let guest = DeliveryNode::open(guest_root.path()).unwrap();
    receiver.trust.insert(full_peer(issuer.peer_id())).unwrap();
    issuer.trust.insert(full_peer(issuer.peer_id())).unwrap();
    let certificate = guest_certificate(&issuer, &guest, NOW + 60_000);
    let token_id = certificate.token_id.clone();
    issuer
        .trust
        .install_bind_certificate(issuer.peer_id(), certificate.clone(), NOW)
        .unwrap();
    receiver
        .trust
        .install_bind_certificate(issuer.peer_id(), certificate.clone(), NOW)
        .unwrap();
    let identity = issuer.store.keys.identity.clone();
    issuer
        .trust
        .revoke_token(&token_id, NOW + 1, &identity)
        .unwrap();
    receiver
        .trust
        .apply_revocations(&issuer.trust.current_revocations(NOW + 2), NOW + 2)
        .unwrap();

    let mut reopened = abra_net::TrustStore::open(receiver_root.path()).unwrap();
    assert_eq!(reopened.current_revocations(NOW + 3).len(), 1);
    let error = reopened
        .install_bind_certificate(issuer.peer_id(), certificate, NOW + 3)
        .unwrap_err();
    assert_eq!(error.to_string(), "authorization: token revoked");
}

#[tokio::test]
async fn full_peer_distributes_guest_bind_certificate_with_forwarded_snapshot() {
    let network = LoopbackNetwork::default();
    let guest_root = tempfile::tempdir().unwrap();
    let host_root = tempfile::tempdir().unwrap();
    let laptop_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("guest.txt"), b"from the microVM").unwrap();
    let mut guest = DeliveryNode::open(guest_root.path()).unwrap();
    let mut host = DeliveryNode::open(host_root.path()).unwrap();
    let mut laptop = DeliveryNode::open(laptop_root.path()).unwrap();
    trust_each_other(&mut host, &mut laptop);
    guest.trust.insert(full_peer(host.peer_id())).unwrap();
    host.trust.insert(full_peer(host.peer_id())).unwrap();
    let certificate = guest_certificate(&host, &guest, NOW + 60_000);
    host.trust
        .install_bind_certificate(host.peer_id(), certificate, NOW)
        .unwrap();

    let raw = partial(&mut guest, input.path(), "guest workspace");
    let guest_send = guest.enqueue(host.peer_id(), &raw, NOW).unwrap();
    let guest_transport = LoopbackTransport::bind(&network, guest.peer_id());
    let host_transport = LoopbackTransport::bind(&network, host.peer_id());
    let mut outgoing = guest_transport.dial(host.peer_id()).await.unwrap();
    let mut incoming = host_transport.accept().await.unwrap();
    let (sent, handled) = tokio::join!(
        async {
            let result = guest.send_offer(&guest_send, &mut outgoing, NOW + 1).await;
            drop(outgoing);
            result
        },
        host.handle_connection(&mut incoming, NOW + 1)
    );
    sent.unwrap();
    handled.unwrap();

    let forwarded = host.enqueue(laptop.peer_id(), &raw, NOW + 2).unwrap();
    let laptop_transport = LoopbackTransport::bind(&network, laptop.peer_id());
    let mut outgoing = host_transport.dial(laptop.peer_id()).await.unwrap();
    let mut incoming = laptop_transport.accept().await.unwrap();
    let (sent, handled) = tokio::join!(
        async {
            let result = host.send_offer(&forwarded, &mut outgoing, NOW + 3).await;
            drop(outgoing);
            result
        },
        laptop.handle_connection(&mut incoming, NOW + 3)
    );
    sent.unwrap();
    handled.unwrap();
    assert!(laptop.store.inbox.contains_key(&raw.snapshot_id()));
    assert_eq!(
        laptop.trust.get(&guest.peer_id()).unwrap().role,
        Role::Guest
    );
    assert!(laptop
        .trust
        .get(&guest.peer_id())
        .unwrap()
        .addresses
        .is_empty());
}

#[tokio::test]
async fn expired_distributed_bind_certificate_reports_generic_outbox_error() {
    let test_now = abra_core::now_ms();
    let network = LoopbackNetwork::default();
    let guest_root = tempfile::tempdir().unwrap();
    let host_root = tempfile::tempdir().unwrap();
    let laptop_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("guest.txt"), b"expired authority").unwrap();
    let mut guest = DeliveryNode::open(guest_root.path()).unwrap();
    let mut host = DeliveryNode::open(host_root.path()).unwrap();
    let mut laptop = DeliveryNode::open(laptop_root.path()).unwrap();
    trust_each_other(&mut host, &mut laptop);
    host.trust.insert(full_peer(host.peer_id())).unwrap();
    let certificate = guest_certificate(&host, &guest, test_now - 1);
    host.trust
        .install_bind_certificate(host.peer_id(), certificate, test_now - 2)
        .unwrap();
    let raw = partial(&mut guest, input.path(), "expired guest workspace");
    for digest in abra_core::manifest::closure(&guest.store.cas, raw.manifest()).unwrap() {
        host.store
            .cas
            .put(&guest.store.cas.get(&digest).unwrap())
            .unwrap();
    }
    let id = host.enqueue(laptop.peer_id(), &raw, test_now - 2).unwrap();
    let host_transport = LoopbackTransport::bind(&network, host.peer_id());
    let laptop_transport = LoopbackTransport::bind(&network, laptop.peer_id());
    let mut outgoing = host_transport.dial(laptop.peer_id()).await.unwrap();
    let mut incoming = laptop_transport.accept().await.unwrap();
    let (sent, handled) = tokio::join!(
        async {
            let result = host.send_offer(&id, &mut outgoing, test_now).await;
            drop(outgoing);
            result
        },
        laptop.handle_connection(&mut incoming, test_now)
    );
    assert!(sent.is_err());
    handled.unwrap();
    assert_eq!(
        host.outbox.get(&id).unwrap().last_error.as_deref(),
        Some("authorization: untrusted manifest origin")
    );
    assert!(laptop.trust.get(&guest.peer_id()).is_none());
}

#[test]
fn trusted_peer_addresses_persist_and_old_rows_default_empty() {
    let root = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let mut peer = full_peer(identity.peer_id());
    peer.addresses = vec![r#"{"id":"test","addrs":[]}"#.into()];
    let mut trust = abra_net::TrustStore::open(root.path()).unwrap();
    trust.insert(peer).unwrap();
    let reopened = abra_net::TrustStore::open(root.path()).unwrap();
    assert_eq!(
        reopened.get(&identity.peer_id()).unwrap().addresses.len(),
        1
    );
}

#[test]
fn relay_pack_commits_partial_and_full_then_only_verified_acks_clear_outbox() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("relay.txt"), b"receiver was offline").unwrap();
    let mut a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    trust_each_other(&mut a, &mut b);

    let partial = partial(&mut a, input.path(), "secret relay manifest marker");
    let partial_id = a.enqueue(b.peer_id(), &partial, NOW).unwrap();
    a.outbox.mark_relay_deposited(&partial_id, NOW + 1).unwrap();
    let (_, partial_ack) = b
        .receive_relay_delivery(a.relay_delivery(&partial_id, NOW + 1).unwrap(), NOW + 2)
        .unwrap();
    assert!(b.store.inbox.contains_key(&partial.snapshot_id()));

    let mut forged = partial_ack.clone();
    forged.sig = Signature::from_bytes([0; 64]);
    assert!(a
        .outbox
        .apply_ack(&partial_id, &forged, a.peer_id(), NOW + 3)
        .is_err());
    assert_eq!(
        a.outbox.get(&partial_id).unwrap().state,
        OutboxState::AwaitingAck
    );
    assert!(a
        .outbox
        .apply_ack(&partial_id, &partial_ack, a.peer_id(), NOW + 4)
        .unwrap());

    let creator = Identity::generate();
    let capsule_id = Hash::from_bytes([91; 32]);
    let genesis = Genesis::new(
        capsule_id,
        abra_net::format_time(NOW),
        "dev.abra.workspace".into(),
        "relay capsule".into(),
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
    let full = full(&mut a, input.path(), capsule_id, "full relay snapshot");
    let full_id = a.enqueue(b.peer_id(), &full, NOW).unwrap();
    a.outbox.mark_relay_deposited(&full_id, NOW + 1).unwrap();
    let (_, full_ack) = b
        .receive_relay_delivery(a.relay_delivery(&full_id, NOW + 1).unwrap(), NOW + 2)
        .unwrap();
    assert!(b.store.capsules[&capsule_id]
        .snapshot(&full.snapshot_id())
        .is_some());
    assert!(a
        .outbox
        .apply_ack(&full_id, &full_ack, a.peer_id(), NOW + 3)
        .unwrap());
    assert_eq!(a.outbox.get(&full_id).unwrap().state, OutboxState::Acked);
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

#[tokio::test]
async fn native_object_over_streaming_threshold_streams_and_can_be_skipped() {
    const LARGE_BYTES: u64 = 40 * 1024 * 1024;
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(a_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(b_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(input.path().join("portable"), b"portable").unwrap();
    let source = a_dir.path().join("large-native-memory");
    fs::File::create(&source)
        .unwrap()
        .set_len(LARGE_BYTES)
        .unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    a.set_streaming_threshold_for_tests(1024 * 1024);
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let (blob, bytes) = a.store.cas.put_file(&source).unwrap();
    assert_eq!(bytes, LARGE_BYTES);
    let capsule_id = Hash::of(b"large-native-capsule");
    add_test_capsule(&mut a, capsule_id);
    let raw = full_native(&mut a, input.path(), capsule_id, blob, bytes);
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    let DeliveryOutcome::Complete { stats, .. } =
        wire_deliver(&mut a, &mut b, &id, NOW + 1).await.unwrap()
    else {
        panic!()
    };
    assert!(stats.bytes_transferred >= LARGE_BYTES);
    assert!(b.store.cas.has(&blob));

    let c_dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(c_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut c = DeliveryNode::open(c_dir.path()).unwrap();
    c.skip_native = true;
    trust_each_other(&mut a, &mut c);
    let id = a.enqueue(c.peer_id(), &raw, NOW + 2).unwrap();
    let DeliveryOutcome::Complete { stats, .. } =
        wire_deliver(&mut a, &mut c, &id, NOW + 3).await.unwrap()
    else {
        panic!()
    };
    assert!(stats.bytes_transferred < LARGE_BYTES);
    assert!(!c.store.cas.has(&blob));
    assert!(c.store.capsules[&capsule_id]
        .snapshot(&raw.snapshot_id())
        .is_some());
}

#[tokio::test]
async fn skip_native_rejects_blob_shared_with_portable_tree() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("shared"), b"same bytes").unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    b.skip_native = true;
    trust_each_other(&mut a, &mut b);
    let blob = Hash::of(b"same bytes");
    let capsule = Hash::of(b"shared-native-capsule");
    add_test_capsule(&mut a, capsule);
    let raw = full_native(&mut a, input.path(), capsule, blob, 10);
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    assert!(wire_deliver(&mut a, &mut b, &id, NOW + 1).await.is_err());
    assert!(!b.store.capsules.contains_key(&capsule));
}

#[tokio::test]
async fn inflated_native_byte_claim_is_rejected_against_plan() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("portable"), b"portable").unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    b.skip_native = true;
    trust_each_other(&mut a, &mut b);
    let blob = a.store.cas.put(b"native").unwrap();
    let capsule = Hash::of(b"inflated-native-capsule");
    add_test_capsule(&mut a, capsule);
    let mut manifest = full_native(&mut a, input.path(), capsule, blob, 6)
        .manifest()
        .clone();
    manifest.native.as_mut().unwrap()[0].bytes = 9_007_199_254_740_991;
    manifest.sign(&a.store.keys.identity).unwrap();
    let raw = RawManifest::parse(manifest.to_canonical_bytes().unwrap()).unwrap();
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    assert!(wire_deliver(&mut a, &mut b, &id, NOW + 1).await.is_err());
    assert!(!b.store.capsules.contains_key(&capsule));
}

#[tokio::test]
async fn offer_budget_rejects_plan_with_quota_reason() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("file"), b"larger than one byte").unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    b.offer_budget = 1;
    trust_each_other(&mut a, &mut b);
    let raw = partial(&mut a, input.path(), "over budget");
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    let error = wire_deliver(&mut a, &mut b, &id, NOW + 1)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("quota"));
    assert!(!b.store.inbox.contains_key(&raw.snapshot_id()));
}

#[tokio::test]
async fn guest_sender_disables_skip_native_without_breaking_delivery() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("portable"), b"portable").unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    b.skip_native = true;
    a.trust.insert(full_peer(b.peer_id())).unwrap();
    let mut guest = full_peer(a.peer_id());
    guest.role = Role::Guest;
    guest.token_id = Some("55".repeat(16));
    guest.scopes = Some(Scopes {
        capsules: vec!["*".into()],
        kinds: vec!["*".into()],
        send: true,
        receive: true,
        lease_acquire: false,
        lease_takeover: false,
    });
    guest.expires_at = Some(abra_net::format_time(NOW + 60_000));
    b.trust.insert(guest).unwrap();
    let blob = a.store.cas.put(b"native").unwrap();
    let capsule = Hash::of(b"guest-native-capsule");
    add_test_capsule(&mut a, capsule);
    let raw = full_native(&mut a, input.path(), capsule, blob, 6);
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    wire_deliver(&mut a, &mut b, &id, NOW + 1).await.unwrap();
    assert!(b.store.cas.has(&blob));
}

#[tokio::test]
async fn small_object_delivery_keeps_single_object_path() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("small"), vec![7u8; 64 * 1024]).unwrap();
    let mut a = DeliveryNode::open(a_dir.path()).unwrap();
    let mut b = DeliveryNode::open(b_dir.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let raw = partial(&mut a, input.path(), "small");
    let id = a.enqueue(b.peer_id(), &raw, NOW).unwrap();
    let DeliveryOutcome::Complete { stats, .. } =
        wire_deliver(&mut a, &mut b, &id, NOW + 1).await.unwrap()
    else {
        panic!()
    };
    assert!(stats.objects_transferred > 0);
    assert!(b.store.inbox.contains_key(&raw.snapshot_id()));
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
            relay_key: None,
            token_id: Some("aa".repeat(16)),
            scopes: Some(scopes),
            expires_at: Some(abra_net::format_time(NOW + 1000)),
            addresses: Vec::new(),
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
    trust
        .revoke_token(&"aa".repeat(16), NOW, &Identity::generate())
        .unwrap();
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
fn capsule_scope_blocks_capsule_less_traffic() {
    let scopes = Scopes {
        capsules: vec![Hash::from_bytes([7; 32]).to_hex()],
        kinds: vec!["dev.abra.bundle".into()],
        send: true,
        receive: true,
        lease_acquire: false,
        lease_takeover: false,
    };
    assert!(!scopes.allows(None, "dev.abra.bundle", abra_net::Direction::Send));
    let wildcard = Scopes {
        capsules: vec!["*".into()],
        ..scopes
    };
    assert!(wildcard.allows(None, "dev.abra.bundle", abra_net::Direction::Receive));
}

#[test]
fn mesh_profiles_gate_guest_to_guest_with_both_scopes() {
    let root = tempfile::tempdir().unwrap();
    let mut trust = abra_net::TrustStore::open(root.path()).unwrap();
    let sender = Identity::generate();
    let receiver = Identity::generate();
    let capsule = Hash::from_bytes([13; 32]);
    for (identity, send, receive, token) in [
        (&sender, true, false, "31".repeat(16)),
        (&receiver, false, true, "32".repeat(16)),
    ] {
        trust
            .insert(TrustedPeer {
                peer_id: identity.peer_id(),
                name: "guest".into(),
                role: Role::Guest,
                x25519_pk: [0; 32],
                relay_key: None,
                token_id: Some(token),
                scopes: Some(Scopes {
                    capsules: vec![capsule.to_hex()],
                    kinds: vec!["dev.abra.workspace".into()],
                    send,
                    receive,
                    lease_acquire: false,
                    lease_takeover: false,
                }),
                expires_at: Some(abra_net::format_time(NOW + 10_000)),
                addresses: Vec::new(),
            })
            .unwrap();
    }
    assert!(trust
        .authorize_offer(
            sender.peer_id(),
            receiver.peer_id(),
            Some(capsule),
            "dev.abra.workspace",
            abra_net::Direction::Send,
            NOW
        )
        .is_err());
    trust
        .set_mesh_profile(abra_net::MeshProfile::Fleet)
        .unwrap();
    trust
        .authorize_offer(
            sender.peer_id(),
            receiver.peer_id(),
            Some(capsule),
            "dev.abra.workspace",
            abra_net::Direction::Send,
            NOW,
        )
        .unwrap();
    assert!(trust
        .authorize_offer(
            sender.peer_id(),
            receiver.peer_id(),
            Some(capsule),
            "dev.abra.other",
            abra_net::Direction::Send,
            NOW
        )
        .is_err());
    assert_eq!(
        abra_net::TrustStore::open(root.path())
            .unwrap()
            .mesh_profile(),
        abra_net::MeshProfile::Fleet
    );
}

#[test]
fn revocation_survives_concurrent_stale_save() {
    let root = tempfile::tempdir().unwrap();
    let guest = Identity::generate();
    let unrelated = Identity::generate();
    let token_id = "ab".repeat(16);
    let mut original = abra_net::TrustStore::open(root.path()).unwrap();
    original
        .insert(TrustedPeer {
            peer_id: guest.peer_id(),
            name: "guest".into(),
            role: Role::Guest,
            x25519_pk: [0; 32],
            relay_key: None,
            token_id: Some(token_id.clone()),
            scopes: Some(Scopes {
                capsules: vec!["*".into()],
                kinds: vec!["*".into()],
                send: true,
                receive: true,
                lease_acquire: false,
                lease_takeover: false,
            }),
            expires_at: Some(abra_net::format_time(NOW + 10_000)),
            addresses: Vec::new(),
        })
        .unwrap();
    let mut stale = abra_net::TrustStore::open(root.path()).unwrap();
    original
        .revoke_token(&token_id, NOW, &Identity::generate())
        .unwrap();
    stale
        .insert(TrustedPeer {
            peer_id: unrelated.peer_id(),
            name: "peer".into(),
            role: Role::Full,
            x25519_pk: [0; 32],
            relay_key: None,
            token_id: None,
            scopes: None,
            expires_at: None,
            addresses: Vec::new(),
        })
        .unwrap();
    let reopened = abra_net::TrustStore::open(root.path()).unwrap();
    assert!(reopened.is_revoked(&token_id));
    assert!(reopened.get(&guest.peer_id()).is_none());
    assert!(reopened.get(&unrelated.peer_id()).is_some());
}

#[tokio::test]
async fn guest_expiry_mid_session_cuts_off_next_frame() {
    let network = LoopbackNetwork::default();
    let guest_root = tempfile::tempdir().unwrap();
    let host_root = tempfile::tempdir().unwrap();
    let guest = DeliveryNode::open(guest_root.path()).unwrap();
    let mut host = DeliveryNode::open(host_root.path()).unwrap();
    let guest_transport = LoopbackTransport::bind(&network, guest.peer_id());
    let host_transport = LoopbackTransport::bind(&network, host.peer_id());
    let now = abra_core::now_ms();
    host.trust
        .insert(TrustedPeer {
            peer_id: guest.peer_id(),
            name: "short-lived".into(),
            role: Role::Guest,
            x25519_pk: [0; 32],
            relay_key: None,
            token_id: Some("cd".repeat(16)),
            scopes: Some(Scopes {
                capsules: vec!["*".into()],
                kinds: vec!["*".into()],
                send: true,
                receive: true,
                lease_acquire: false,
                lease_takeover: false,
            }),
            expires_at: Some(abra_net::format_time(now + 100)),
            addresses: Vec::new(),
        })
        .unwrap();
    let mut outgoing = guest_transport.dial(host.peer_id()).await.unwrap();
    let mut incoming = host_transport.accept().await.unwrap();
    let host_task = tokio::spawn(async move {
        host.handle_connection(&mut incoming, abra_core::now_ms())
            .await
    });
    abra_net::dial_handshake(&mut outgoing, guest.peer_id(), "guest".into())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let (send, _) = outgoing.control_mut();
    abra_net::write_frame(
        send,
        &Ping {
            message_type: "ping".into(),
            nonce: "00".repeat(16),
            ts: abra_net::format_time(abra_core::now_ms()),
        },
    )
    .await
    .unwrap();
    let error = host_task.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("expired"));
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
        revocations: Vec::new(),
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
    const LARGE_BYTES: usize = 10 * 1024 * 1024;
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("large"), vec![3u8; LARGE_BYTES]).unwrap();
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
    assert!(second.bytes_transferred < LARGE_BYTES as u64 + 4096);
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
    let encoded = token.encode().unwrap();
    let from_url = EnrollmentToken::parse(&format!("abra://join/{encoded}"), NOW).unwrap();
    assert_eq!(from_url.token_id, token.token_id);
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
    let recipient = Identity::generate().peer_id();
    node.trust.insert(full_peer(recipient)).unwrap();
    let raw = partial(&mut node, input.path(), "x");
    assert!(node.enqueue(recipient, &raw, NOW).is_err());
    node.allow_agent_send = true;
    assert!(node.enqueue(recipient, &raw, NOW).is_ok());
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
        lease_chain: Vec::new(),
        main_label: None,
        bind_certificate_issuer: None,
        bind_certificate: None,
        revocations: Vec::new(),
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

#[test]
fn receiver_rejects_cross_capsule_and_oversized_state_bundles() {
    let sender_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("x"), b"x").unwrap();
    let mut sender = DeliveryNode::open(sender_root.path()).unwrap();
    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    trust_each_other(&mut sender, &mut receiver);
    let capsule_id = Hash::from_bytes([81; 32]);
    let raw = full(&mut sender, input.path(), capsule_id, "bound");
    let genesis = Genesis::new(
        capsule_id,
        abra_net::format_time(NOW),
        "dev.abra.workspace".into(),
        "bound".into(),
        &sender.store.keys.identity,
    )
    .unwrap();
    let grant = LeaseRecord::new(
        capsule_id,
        sender.peer_id(),
        1,
        LeaseMode::Grant,
        abra_net::format_time(NOW),
        abra_net::format_time(NOW + 86_400_000),
        genesis.hash().unwrap(),
        &sender.store.keys.identity,
    )
    .unwrap();
    let base = Offer {
        message_type: "offer".into(),
        offer_id: "22".repeat(16),
        snapshot_id: raw.snapshot_id(),
        scope: Scope::Full,
        kind: raw.manifest().kind.clone(),
        title: raw.manifest().title.clone(),
        capsule_id: Some(capsule_id),
        fork: false,
        bytes_hint: 0,
        object_count: 0,
        manifest_raw: data_encoding::BASE64URL_NOPAD.encode(raw.bytes()),
        genesis: Some(genesis),
        genesis_grant: Some(grant.clone()),
        lease_chain: Vec::new(),
        main_label: None,
        bind_certificate_issuer: None,
        bind_certificate: None,
        revocations: Vec::new(),
    };
    assert!(receiver
        .validate_incoming_offer(&base, sender.peer_id(), NOW)
        .is_ok());
    let mut cross_capsule = base.clone();
    cross_capsule.capsule_id = Some(Hash::from_bytes([82; 32]));
    assert!(receiver
        .validate_incoming_offer(&cross_capsule, sender.peer_id(), NOW)
        .is_err());
    assert!(receiver.store.capsules.is_empty());

    let mut oversized = base;
    oversized.lease_chain = vec![grant; MAX_LEASE_CHAIN_LEN + 1];
    assert!(receiver
        .validate_incoming_offer(&oversized, sender.peer_id(), NOW)
        .is_err());
    assert!(receiver.store.capsules.is_empty());
}

struct ValueHandler(serde_json::Value);
#[async_trait::async_trait]
impl ControlHandler for ValueHandler {
    async fn handle(
        &self,
        _from: PeerId,
        message: &ControlMessage,
    ) -> abra_net::Result<serde_json::Value> {
        Ok(serde_json::json!({"echo": message.text, "result": self.0}))
    }
}

struct FailingHandler;
#[async_trait::async_trait]
impl ControlHandler for FailingHandler {
    async fn handle(
        &self,
        _from: PeerId,
        _message: &ControlMessage,
    ) -> abra_net::Result<serde_json::Value> {
        Err(abra_net::Error::Protocol("adapter refused".into()))
    }
}

/// Fails the way a local adapter would: an `io::Error` whose message names a
/// file on this machine.
struct IoFailingHandler(String);
#[async_trait::async_trait]
impl ControlHandler for IoFailingHandler {
    async fn handle(
        &self,
        _from: PeerId,
        _message: &ControlMessage,
    ) -> abra_net::Result<serde_json::Value> {
        Err(abra_net::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no such file: {}", self.0),
        )))
    }
}

struct SleepingHandler(Duration);
#[async_trait::async_trait]
impl ControlHandler for SleepingHandler {
    async fn handle(
        &self,
        _from: PeerId,
        _message: &ControlMessage,
    ) -> abra_net::Result<serde_json::Value> {
        tokio::time::sleep(self.0).await;
        Ok(serde_json::json!("never"))
    }
}

fn control_message(sender: &DeliveryNode, nonce: u8) -> ControlMessage {
    ControlMessage::new(
        Hash::from_bytes([7; 32]),
        ControlOp::Instruct,
        Some("run the tests".into()),
        abra_core::now_ms(),
        [nonce; 16],
        &sender.store.keys.identity,
    )
    .unwrap()
}

fn control_events(root: &Path) -> Vec<serde_json::Value> {
    let path = root.join("net/events.ndjson");
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value.get("event").and_then(|x| x.as_str()) == Some("control"))
        .collect()
}

/// Sends `message` over loopback and returns the acknowledgement as raw JSON.
/// `features` is the dialer's hello feature list; `None` uses the ordinary
/// handshake, which advertises everything this build supports.
async fn control_exchange(
    sender: &DeliveryNode,
    receiver: &mut DeliveryNode,
    message: &ControlMessage,
    features: Option<Vec<String>>,
) -> serde_json::Value {
    let network = LoopbackNetwork::default();
    let ts = LoopbackTransport::bind(&network, sender.peer_id());
    let tr = LoopbackTransport::bind(&network, receiver.peer_id());
    let mut outgoing = ts.dial(receiver.peer_id()).await.unwrap();
    let mut incoming = tr.accept().await.unwrap();
    let sender_id = sender.peer_id();
    let (ack, handled) = tokio::join!(
        async {
            match features {
                None => {
                    abra_net::dial_handshake(&mut outgoing, sender_id, "sender".into())
                        .await
                        .unwrap();
                }
                Some(features) => {
                    let hello = Hello {
                        message_type: "hello".into(),
                        wire: WIRE_VERSION,
                        spec: abra_core::SPEC.into(),
                        peer_id: sender_id,
                        name: "old-peer".into(),
                        features,
                        nonce: "00".repeat(16),
                        revocations: Vec::new(),
                    };
                    let (send, recv) = outgoing.control_mut();
                    abra_net::write_frame(send, &hello).await.unwrap();
                    let ok: serde_json::Value = abra_net::read_frame(recv).await.unwrap();
                    assert_eq!(ok.get("type").and_then(|x| x.as_str()), Some("hello-ok"));
                }
            }
            let (send, recv) = outgoing.control_mut();
            abra_net::write_frame(send, message).await.unwrap();
            let ack: serde_json::Value = abra_net::read_frame(recv).await.unwrap();
            drop(outgoing);
            ack
        },
        receiver.handle_connection(&mut incoming, abra_core::now_ms())
    );
    handled.unwrap();
    ack
}

#[tokio::test]
async fn control_handler_result_reaches_the_sender_and_the_event_is_recorded() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    b.control_handler = Some(std::sync::Arc::new(ValueHandler(
        serde_json::json!({"status": "queued"}),
    )));
    let message = control_message(&a, 1);
    let ack = control_exchange(&a, &mut b, &message, None).await;
    assert_eq!(ack["type"], "control-ack");
    assert_eq!(ack["nonce"], message.nonce);
    assert_eq!(ack["ok"], true);
    assert_eq!(ack["result"]["echo"], "run the tests");
    assert_eq!(ack["result"]["result"]["status"], "queued");
    let ack: abra_net::ControlAck = serde_json::from_value(ack).unwrap();
    assert!(ack.result.is_some());
    assert_eq!(control_events(b_root.path()).len(), 1);
}

#[tokio::test]
async fn failing_control_handler_acks_not_ok_but_still_records_the_message() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    b.control_handler = Some(std::sync::Arc::new(FailingHandler));
    let ack = control_exchange(&a, &mut b, &control_message(&a, 2), None).await;
    assert_eq!(ack["ok"], false);
    assert!(ack["error"].as_str().unwrap().contains("adapter refused"));
    assert!(ack.get("result").is_none());
    assert_eq!(control_events(b_root.path()).len(), 1);
}

#[tokio::test]
async fn hung_control_handler_times_out_without_holding_the_session() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    b.control_handler = Some(std::sync::Arc::new(SleepingHandler(Duration::from_secs(
        60,
    ))));
    b.set_control_timeout_for_tests(Duration::from_millis(50));
    let ack = control_exchange(&a, &mut b, &control_message(&a, 3), None).await;
    assert_eq!(ack["ok"], false);
    assert_eq!(ack["error"], "control handler timed out");
    assert!(ack.get("result").is_none());
    assert_eq!(control_events(b_root.path()).len(), 1);
}

#[tokio::test]
async fn dialer_without_control_result_feature_gets_an_ack_with_no_result_key() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    b.control_handler = Some(std::sync::Arc::new(ValueHandler(serde_json::json!("x"))));
    let ack = control_exchange(
        &a,
        &mut b,
        &control_message(&a, 4),
        Some(vec!["resume".into(), "control".into()]),
    )
    .await;
    assert_eq!(ack["ok"], true);
    assert!(ack.get("result").is_none(), "{ack}");
    // The handler still ran and the message is still recorded.
    assert_eq!(control_events(b_root.path()).len(), 1);
}

#[tokio::test]
async fn control_handler_io_error_is_scrubbed_before_it_reaches_the_sender() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    trust_each_other(&mut a, &mut b);
    let secret_path = b_root.path().join("adapters/secret-workspace.sock");
    b.control_handler = Some(std::sync::Arc::new(IoFailingHandler(
        secret_path.display().to_string(),
    )));
    let ack = control_exchange(&a, &mut b, &control_message(&a, 5), None).await;
    assert_eq!(ack["ok"], false);
    let error = ack["error"].as_str().unwrap();
    assert!(
        !error.contains(&secret_path.display().to_string()),
        "{error}"
    );
    assert!(!error.contains("secret-workspace"), "{error}");
    assert_eq!(error, "delivery validation failed");
}

/// A relayed capsule snapshot whose lease chain the receiver cannot authorize
/// is shelved as a fork: the main move is withheld, a `fork/<8 hex>` label
/// points at the snapshot, and the withheld main lands on a later delivery once
/// the chain does apply.
#[test]
fn relay_delivery_with_unapplicable_main_label_records_a_fork_label() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let first_input = tempfile::tempdir().unwrap();
    let second_input = tempfile::tempdir().unwrap();
    fs::write(first_input.path().join("x"), b"first").unwrap();
    fs::write(second_input.path().join("x"), b"second").unwrap();
    let mut a = DeliveryNode::open(a_root.path()).unwrap();
    let mut b = DeliveryNode::open(b_root.path()).unwrap();
    trust_each_other(&mut a, &mut b);

    let creator = Identity::generate();
    let holder = Identity::generate();
    let capsule_id = Hash::from_bytes([55; 32]);
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
    a.store.add_capsule(genesis, grant.clone()).unwrap();

    // The sender's capsule is at epoch 2 under a holder the receiver does not
    // trust, so the receiver can adopt neither the lease chain nor the main
    // move that depends on it.
    let takeover = LeaseRecord::new(
        capsule_id,
        holder.peer_id(),
        2,
        LeaseMode::Takeover,
        abra_net::format_time(NOW),
        abra_net::format_time(NOW + 86_400_000),
        grant.hash().unwrap(),
        &holder,
    )
    .unwrap();
    let first = full(&mut a, first_input.path(), capsule_id, "first");
    a.store
        .receive_full(first.clone(), abra_net::format_time(NOW), NOW, None)
        .unwrap();
    let main = LabelOp::new(
        capsule_id,
        1,
        "main".into(),
        first.snapshot_id(),
        2,
        abra_net::format_time(NOW),
        &holder,
    )
    .unwrap();
    assert!(a
        .store
        .adopt_capsule_state(capsule_id, &[takeover], Some(&main), &|_, _| true, NOW)
        .unwrap());

    let first_id = a.enqueue(b.peer_id(), &first, NOW).unwrap();
    a.outbox.mark_relay_deposited(&first_id, NOW + 1).unwrap();
    let main_before = b
        .store
        .capsules
        .get(&capsule_id)
        .and_then(|capsule| capsule.label("main").map(|label| label.snapshot_id));
    let (_, ack) = b
        .receive_relay_delivery(a.relay_delivery(&first_id, NOW + 1).unwrap(), NOW + 2)
        .unwrap();
    assert_eq!(ack.shelf, "capsule-fork");
    let fork_label = format!("fork/{}", &first.snapshot_id().to_hex()[..8]);
    let capsule = b.store.capsules.get(&capsule_id).unwrap();
    assert_eq!(
        capsule.label(&fork_label).unwrap().snapshot_id,
        first.snapshot_id()
    );
    assert_eq!(
        capsule.label("main").map(|label| label.snapshot_id),
        main_before
    );
    let events = fs::read_to_string(b_root.path().join("net/events.ndjson")).unwrap();
    assert!(events.lines().any(|line| {
        line.contains(&first.snapshot_id().to_hex()) && line.contains(r#""via":"relay""#)
    }));

    // With the holder trusted the chain applies, and the main label the fork
    // held back moves the receiver's head.
    b.trust.insert(full_peer(holder.peer_id())).unwrap();
    let mut manifest = full(&mut a, second_input.path(), capsule_id, "second")
        .manifest()
        .clone();
    manifest.parents = Some(vec![first.snapshot_id()]);
    manifest.sign(&a.store.keys.identity).unwrap();
    let second = RawManifest::parse(manifest.to_canonical_bytes().unwrap()).unwrap();
    let second_id = a.enqueue(b.peer_id(), &second, NOW).unwrap();
    a.outbox.mark_relay_deposited(&second_id, NOW + 3).unwrap();
    let (_, ack) = b
        .receive_relay_delivery(a.relay_delivery(&second_id, NOW + 3).unwrap(), NOW + 4)
        .unwrap();
    assert_eq!(ack.shelf, "capsule-head");
    let capsule = b.store.capsules.get(&capsule_id).unwrap();
    assert_eq!(
        capsule.label("main").unwrap().snapshot_id,
        first.snapshot_id()
    );
    assert!(capsule.label(&fork_label).is_some());
}

#[test]
fn pending_main_label_survives_reopen_until_parent_arrives() {
    let sender_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let parent_input = tempfile::tempdir().unwrap();
    let child_input = tempfile::tempdir().unwrap();
    fs::write(parent_input.path().join("x"), b"parent").unwrap();
    fs::write(child_input.path().join("x"), b"child").unwrap();
    let mut sender = DeliveryNode::open(sender_root.path()).unwrap();
    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    trust_each_other(&mut sender, &mut receiver);
    let capsule_id = Hash::from_bytes([56; 32]);
    add_test_capsule(&mut sender, capsule_id);

    let parent = full(&mut sender, parent_input.path(), capsule_id, "parent");
    sender
        .store
        .receive_full(parent.clone(), abra_net::format_time(NOW), NOW, None)
        .unwrap();
    let parent_id = sender.enqueue(receiver.peer_id(), &parent, NOW).unwrap();
    sender
        .outbox
        .mark_relay_deposited(&parent_id, NOW + 1)
        .unwrap();
    let parent_delivery = sender.relay_delivery(&parent_id, NOW + 1).unwrap();

    let mut child_manifest = full(&mut sender, child_input.path(), capsule_id, "child")
        .manifest()
        .clone();
    child_manifest.parents = Some(vec![parent.snapshot_id()]);
    child_manifest.sign(&sender.store.keys.identity).unwrap();
    let child = RawManifest::parse(child_manifest.to_canonical_bytes().unwrap()).unwrap();
    sender
        .store
        .receive_full(child.clone(), abra_net::format_time(NOW + 2), NOW + 2, None)
        .unwrap();
    let signer = Identity::from_secret_bytes(&sender.store.keys.identity.secret_bytes());
    let main = LabelOp::new(
        capsule_id,
        1,
        "main".into(),
        child.snapshot_id(),
        1,
        abra_net::format_time(NOW + 2),
        &signer,
    )
    .unwrap();
    assert!(sender
        .store
        .adopt_capsule_state(capsule_id, &[], Some(&main), &|_, _| true, NOW + 2)
        .unwrap());
    let child_id = sender.enqueue(receiver.peer_id(), &child, NOW + 2).unwrap();
    sender
        .outbox
        .mark_relay_deposited(&child_id, NOW + 3)
        .unwrap();
    let child_delivery = sender.relay_delivery(&child_id, NOW + 3).unwrap();

    let (_, ack) = receiver
        .receive_relay_delivery(child_delivery, NOW + 4)
        .unwrap();
    assert_eq!(ack.shelf, "capsule-fork");
    drop(receiver);

    let mut receiver = DeliveryNode::open(receiver_root.path()).unwrap();
    receiver
        .receive_relay_delivery(parent_delivery, NOW + 5)
        .unwrap();
    assert_eq!(
        receiver.store.capsules[&capsule_id]
            .label("main")
            .unwrap()
            .snapshot_id,
        child.snapshot_id()
    );
}
