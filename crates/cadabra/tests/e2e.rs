#![cfg(unix)]

use abra_net::LoopbackNetwork;
use cadabra::{control_call, Daemon};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};

async fn wait_for<F, Fut>(mut check: F) -> Value
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = cadabra::Result<Value>>,
{
    for _ in 0..100 {
        if let Ok(value) = check().await {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition did not become ready")
}

#[tokio::test]
async fn relay_add_keeps_configured_deposit_and_polling_tuning() {
    let network = LoopbackNetwork::default();
    let root = tempfile::tempdir().unwrap();
    let daemon = Daemon::loopback(root.path(), &network, true).unwrap();
    let mut config = cadabra::relay::RelayConfig::load(root.path()).unwrap();
    config.relay_after_attempts = 0;
    config.relay_poll_seconds = 5;
    config.save(root.path()).unwrap();
    daemon
        .handle(json!({"op":"relay-add","url":"http://127.0.0.1:1"}))
        .await
        .unwrap();
    let config = cadabra::relay::RelayConfig::load(root.path()).unwrap();
    assert_eq!(config.relays.len(), 1);
    assert_eq!(config.relay_after_attempts, 0);
    assert_eq!(config.relay_poll_seconds, 5);
}

#[tokio::test]
async fn failed_adapter_import_keeps_inbox_unread_and_reports_materialized_path() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    fs::set_permissions(a_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(b_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let failing = b_root.path().join("failing-adapter");
    fs::create_dir(&failing).unwrap();
    fs::write(
        failing.join("abra-adapter.json"),
        serde_json::to_vec(&json!({
            "spec":"abra-adapter/1",
            "name":"failing-folder",
            "version":"1",
            "kinds":["dev.abra.folder"],
            "verbs":["import"],
            "executable":"run"
        }))
        .unwrap(),
    )
    .unwrap();
    let executable = failing.join("run");
    fs::write(
        &executable,
        r###"#!/bin/sh
read line
id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
printf '{"request_id":"%s","ok":false,"error":{"code":"import_failed"}}\n' "$id"
"###,
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    a.handle(json!({
        "op":"adapters-add",
        "dir":Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/reference-folder")
    }))
    .await
    .unwrap();
    b.handle(json!({"op":"adapters-add","dir":failing}))
        .await
        .unwrap();
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    let ticket = b.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    a.handle(json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("kept.txt"), "kept").unwrap();
    a.handle(json!({
        "op":"send",
        "peer":b.peer_id().await,
        "kind":"dev.abra.folder",
        "source":source.path()
    }))
    .await
    .unwrap();
    let inbox = wait_for(|| async {
        let inbox = b.handle(json!({"op":"inbox"})).await?;
        (!inbox.as_array().unwrap().is_empty())
            .then_some(inbox)
            .ok_or_else(|| "empty inbox".into())
    })
    .await;
    let id = inbox[0]["id"].as_str().unwrap();
    let destination = b_root.path().join("materialized");
    let error = b
        .handle(json!({"op":"accept","id":id,"to":destination}))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("inbox entry remains unread"));
    assert!(error.contains(&format!("files_materialized_at={}", destination.display())));
    assert_eq!(
        fs::read_to_string(destination.join("kept.txt")).unwrap(),
        "kept"
    );
    let inbox = b.handle(json!({"op":"inbox"})).await.unwrap();
    assert_eq!(inbox[0]["read"], false);
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[cfg(feature = "tcp")]
#[tokio::test]
async fn tcp_daemon_writes_port_and_opens_control_socket_under_three_seconds() {
    let root = tempfile::tempdir().unwrap();
    let started = std::time::Instant::now();
    let daemon = Arc::new(Daemon::tcp(root.path(), true).await.unwrap());

    let port = fs::read_to_string(root.path().join("net/tcp-port"))
        .unwrap()
        .trim()
        .parse::<u16>()
        .unwrap();
    assert_ne!(port, 0);

    let running = daemon.start().await.unwrap();
    assert!(root.path().join("cadabra.sock").exists());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "TCP daemon startup took {:?}",
        started.elapsed()
    );
    running.shutdown().await;
}

#[tokio::test]
async fn capsule_round_trip_and_replace_workspace() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();

    let ticket = b.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    a.handle(json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();
    wait_for(|| async {
        let peers = b.handle(json!({"op":"peers"})).await?;
        (!peers.as_array().unwrap().is_empty())
            .then_some(peers)
            .ok_or_else(|| "not paired".into())
    })
    .await;
    let a_workspace = a_root.path().join("workspace");
    fs::create_dir(&a_workspace).unwrap();
    fs::write(a_workspace.join("turn"), "a1").unwrap();
    let created = a
        .handle(json!({"op":"capsule-create","path":a_workspace}))
        .await
        .unwrap();
    let capsule = created["capsule_id"].clone();
    let first = a
        .handle(json!({"op":"snapshot","path":a_workspace}))
        .await
        .unwrap();
    a.handle(json!({"op":"send","peer":b.peer_id().await,"snapshot_id":first["snapshot_id"]}))
        .await
        .unwrap();
    wait_for(|| async {
        let log = b.handle(json!({"op":"log","capsule":capsule})).await?;
        (log.as_array().unwrap().len() == 1)
            .then_some(log)
            .ok_or_else(|| "first hop pending".into())
    })
    .await;

    let b_workspace = b_root.path().join("workspace");
    b.handle(json!({"op":"accept","id":first["snapshot_id"],"to":b_workspace}))
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(b_workspace.join(".abra/capsule_id")).unwrap(),
        capsule.as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(b_workspace.join(".abra/snapshot_id")).unwrap(),
        first["snapshot_id"].as_str().unwrap()
    );
    b.handle(json!({"op":"lease-take","capsule":capsule}))
        .await
        .unwrap();
    fs::write(b_workspace.join("turn"), "b2").unwrap();
    let second = b
        .handle(json!({"op":"snapshot","path":b_workspace}))
        .await
        .unwrap();
    b.handle(json!({"op":"send","peer":a.peer_id().await,"snapshot_id":second["snapshot_id"]}))
        .await
        .unwrap();
    wait_for(|| async {
        let log = a.handle(json!({"op":"log","capsule":capsule})).await?;
        (log.as_array().unwrap().len() == 2)
            .then_some(log)
            .ok_or_else(|| "second hop pending".into())
    })
    .await;

    a.handle(json!({"op":"lease-take","capsule":capsule}))
        .await
        .unwrap();
    fs::write(a_workspace.join("turn"), "a3").unwrap();
    let third = a
        .handle(json!({"op":"snapshot","path":a_workspace}))
        .await
        .unwrap();
    a.handle(json!({"op":"send","peer":b.peer_id().await,"snapshot_id":third["snapshot_id"]}))
        .await
        .unwrap();
    wait_for(|| async {
        let log = b.handle(json!({"op":"log","capsule":capsule})).await?;
        (log.as_array().unwrap().len() == 3)
            .then_some(log)
            .ok_or_else(|| "third hop pending".into())
    })
    .await;
    fs::write(b_workspace.join("stale"), "remove me").unwrap();
    let correct_capsule = fs::read_to_string(b_workspace.join(".abra/capsule_id")).unwrap();
    fs::write(b_workspace.join(".abra/capsule_id"), "00".repeat(32)).unwrap();
    let mismatch = b
        .handle(json!({"op":"accept","id":third["snapshot_id"],"to":b_workspace,"replace":true}))
        .await
        .unwrap_err();
    assert!(mismatch.to_string().contains("different capsule"));
    assert_eq!(
        fs::read_to_string(b_workspace.join("stale")).unwrap(),
        "remove me"
    );
    fs::write(b_workspace.join(".abra/capsule_id"), correct_capsule).unwrap();
    let replaced = b
        .handle(json!({"op":"accept","id":third["snapshot_id"],"to":b_workspace,"replace":true}))
        .await
        .unwrap();
    assert_eq!(replaced["replace"], true);
    assert_eq!(fs::read_to_string(b_workspace.join("turn")).unwrap(), "a3");
    assert!(!b_workspace.join("stale").exists());

    b_run.shutdown().await;
    a_run.shutdown().await;
    for root in [a_root.path(), b_root.path()] {
        let node = abra_net::DeliveryNode::open(root).unwrap();
        let id = capsule.as_str().unwrap().parse().unwrap();
        let cap = &node.store.capsules[&id];
        assert_eq!(cap.snapshots().len(), 3);
        assert_eq!(
            cap.label("main").unwrap().snapshot_id.to_hex(),
            third["snapshot_id"]
        );
        assert!(cap.labels().keys().all(|name| !name.starts_with("fork/")));
        let first_id = first["snapshot_id"].as_str().unwrap().parse().unwrap();
        let second_id = second["snapshot_id"].as_str().unwrap().parse().unwrap();
        let third_id = third["snapshot_id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            cap.snapshot(&first_id).unwrap().raw.manifest().parents,
            Some(Vec::new())
        );
        assert_eq!(
            cap.snapshot(&second_id).unwrap().raw.manifest().parents,
            Some(vec![first_id])
        );
        assert_eq!(
            cap.snapshot(&third_id).unwrap().raw.manifest().parents,
            Some(vec![second_id])
        );
    }
    assert!(a_workspace.join(".abra/capsule_id").is_file());
    assert!(b_workspace.join(".abra/capsule_id").is_file());
    assert_eq!(second["forked"], false);
    assert_eq!(third["forked"], false);
}

#[tokio::test]
async fn full_snapshot_grant_materializes_and_updates_capsule_workspace() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    let ticket = b.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    a.handle(json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();
    let workspace = a_root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("value"), "first").unwrap();
    let capsule = a
        .handle(json!({"op":"capsule-create","path":workspace}))
        .await
        .unwrap()["capsule_id"]
        .clone();
    let destination_root = b_root.path().join("granted-workspaces");
    b.handle(json!({"op":"policy-grant","peer":a.peer_id().await,"kind":"dev.abra.workspace","capsule":capsule,"auto_accept":true,"to":destination_root})).await.unwrap();
    let excluded_workspace = a_root.path().join("excluded-workspace");
    fs::create_dir(&excluded_workspace).unwrap();
    fs::write(excluded_workspace.join("value"), "excluded").unwrap();
    let excluded_capsule = a
        .handle(json!({"op":"capsule-create","path":excluded_workspace}))
        .await
        .unwrap()["capsule_id"]
        .clone();
    let excluded = a
        .handle(json!({"op":"snapshot","path":excluded_workspace}))
        .await
        .unwrap();
    a.handle(json!({"op":"send","peer":b.peer_id().await,"snapshot_id":excluded["snapshot_id"]}))
        .await
        .unwrap();
    wait_for(|| async {
        let log = b
            .handle(json!({"op":"log","capsule":excluded_capsule}))
            .await?;
        (!log.as_array().unwrap().is_empty())
            .then_some(log)
            .ok_or_else(|| "excluded capsule pending".into())
    })
    .await;
    assert!(!destination_root
        .join(excluded_capsule.as_str().unwrap())
        .exists());
    let first = a
        .handle(json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap();
    a.handle(json!({"op":"send","peer":b.peer_id().await,"snapshot_id":first["snapshot_id"]}))
        .await
        .unwrap();
    let destination = destination_root.join(capsule.as_str().unwrap());
    wait_for(|| async {
        (fs::read_to_string(destination.join("value"))
            .ok()
            .as_deref()
            == Some("first"))
        .then_some(json!({"ready":true}))
        .ok_or_else(|| "full grant pending".into())
    })
    .await;
    fs::write(workspace.join("value"), "second").unwrap();
    fs::write(destination.join("stale"), "old").unwrap();
    let second = a
        .handle(json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap();
    a.handle(json!({"op":"send","peer":b.peer_id().await,"snapshot_id":second["snapshot_id"]}))
        .await
        .unwrap();
    wait_for(|| async {
        (fs::read_to_string(destination.join("value"))
            .ok()
            .as_deref()
            == Some("second"))
        .then_some(json!({"ready":true}))
        .ok_or_else(|| "full grant update pending".into())
    })
    .await;
    assert!(!destination.join("stale").exists());
    // The mirror leaves the lease with the driving peer.
    let lease = b
        .handle(json!({"op":"lease-status","capsule":capsule}))
        .await
        .unwrap();
    assert_eq!(lease["winning"]["holder"], a.peer_id().await.to_string());
    assert!(b
        .handle(json!({"op":"events"}))
        .await
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["event"] == "auto-accepted-full"));
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn full_snapshot_grant_requires_the_granted_delivering_peer() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let c_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let c = Arc::new(Daemon::loopback(c_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    let c_run = c.start().await.unwrap();

    for (issuer, joiner) in [(&b, &a), (&c, &a), (&c, &b)] {
        let ticket = issuer.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
            .as_str()
            .unwrap()
            .to_owned();
        joiner
            .handle(json!({"op":"pair-add","ticket":ticket}))
            .await
            .unwrap();
    }
    let workspace = a_root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("value"), "from a").unwrap();
    let capsule = a
        .handle(json!({"op":"capsule-create","path":workspace}))
        .await
        .unwrap()["capsule_id"]
        .clone();
    let snapshot = a
        .handle(json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap();
    a.handle(json!({"op":"send","peer":b.peer_id().await,"snapshot_id":snapshot["snapshot_id"]}))
        .await
        .unwrap();
    wait_for(|| async {
        b.handle(json!({"op":"log","capsule":capsule}))
            .await
            .and_then(|log| {
                (!log.as_array().unwrap().is_empty())
                    .then_some(log)
                    .ok_or_else(|| "relay peer lacks snapshot".into())
            })
    })
    .await;

    let destination_root = c_root.path().join("granted-workspaces");
    c.handle(json!({"op":"policy-grant","peer":a.peer_id().await,"kind":"dev.abra.workspace","capsule":capsule,"auto_accept":true,"to":destination_root})).await.unwrap();
    b.handle(json!({"op":"send","peer":c.peer_id().await,"snapshot_id":snapshot["snapshot_id"]}))
        .await
        .unwrap();
    wait_for(|| async {
        c.handle(json!({"op":"log","capsule":capsule}))
            .await
            .and_then(|log| {
                (!log.as_array().unwrap().is_empty())
                    .then_some(log)
                    .ok_or_else(|| "recipient lacks snapshot".into())
            })
    })
    .await;
    assert!(!destination_root.join(capsule.as_str().unwrap()).exists());

    c_run.shutdown().await;
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn auto_confirm_pairing_persists_both_trust_stores() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_id = a.peer_id().await;
    let b_id = b.peer_id().await;
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();

    let ticket = b.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    a.handle(json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();

    for (root, expected) in [(a_root.path(), b_id), (b_root.path(), a_id)] {
        let trust: Value =
            serde_json::from_slice(&fs::read(root.join("net/trust.json")).unwrap()).unwrap();
        assert!(trust["peers"].get(expected.to_hex()).is_some());
        assert!(trust["awaiting_pair_confirm"]
            .as_object()
            .unwrap()
            .is_empty());
    }

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn control_inbox_reads_partial_committed_by_inbound_session() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();

    assert_eq!(
        control_call(b_root.path(), &json!({"op":"log"}))
            .await
            .unwrap(),
        json!([])
    );
    let ticket = control_call(b_root.path(), &json!({"op":"pair-ticket"}))
        .await
        .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    control_call(a_root.path(), &json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();

    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("payload"), b"teleport me\n").unwrap();
    let sent = control_call(
        a_root.path(),
        &json!({"op":"send","peer":b.peer_id().await,"path":source.path()}),
    )
    .await
    .unwrap();
    wait_for(|| async {
        let rows = control_call(a_root.path(), &json!({"op":"outbox"})).await?;
        if rows
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == sent["outbox_id"] && row["state"] == "acked")
        {
            Ok(rows)
        } else {
            Err("outbox not acked".into())
        }
    })
    .await;

    let inbox = control_call(b_root.path(), &json!({"op":"inbox"}))
        .await
        .unwrap();
    assert!(inbox
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == sent["snapshot_id"]));
    let into_error = control_call(
        b_root.path(),
        &json!({"op":"accept","id":sent["snapshot_id"],"to":b_root.path().join("replace"),"replace":true}),
    )
    .await
    .unwrap_err();
    assert!(into_error
        .to_string()
        .contains("--replace requires a full capsule snapshot"));

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn control_lease_ops_see_capsule_committed_after_daemon_start() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();

    let unknown = "00".repeat(32);
    let log_error = control_call(b_root.path(), &json!({"op":"log","capsule":unknown}))
        .await
        .unwrap_err();
    assert_eq!(log_error.to_string(), "unknown capsule");
    let lease_error = control_call(
        b_root.path(),
        &json!({"op":"lease-status","capsule":unknown}),
    )
    .await
    .unwrap_err();
    assert_eq!(lease_error.to_string(), "unknown capsule");

    let ticket = control_call(b_root.path(), &json!({"op":"pair-ticket"}))
        .await
        .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    control_call(a_root.path(), &json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();

    let workspace = a_root.path().join("late-capsule");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("turn"), "one").unwrap();
    let created = control_call(
        a_root.path(),
        &json!({"op":"capsule-create","path":workspace}),
    )
    .await
    .unwrap();
    let capsule = created["capsule_id"].clone();
    let snapshot = control_call(a_root.path(), &json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap();
    control_call(
        a_root.path(),
        &json!({"op":"send","peer":b.peer_id().await,"snapshot_id":snapshot["snapshot_id"]}),
    )
    .await
    .unwrap();

    wait_for(|| async {
        let log = control_call(b_root.path(), &json!({"op":"log","capsule":capsule})).await?;
        (!log.as_array().unwrap().is_empty())
            .then_some(log)
            .ok_or_else(|| "capsule not committed".into())
    })
    .await;

    let status = control_call(
        b_root.path(),
        &json!({"op":"lease-status","capsule":capsule}),
    )
    .await
    .unwrap();
    assert!(status["winning"].is_object());
    let taken = control_call(b_root.path(), &json!({"op":"lease-take","capsule":capsule}))
        .await
        .unwrap();
    assert_eq!(taken["epoch"], 2);
    assert_eq!(taken["holder"], b.peer_id().await.to_string());

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn daemons_pair_sync_handoff_and_resume_outbox() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();

    let ticket = b.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_string();
    a.handle(json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();
    wait_for(|| async {
        let p = b.handle(json!({"op":"peers"})).await?;
        if p.as_array().unwrap().is_empty() {
            Err("not paired".into())
        } else {
            Ok(p)
        }
    })
    .await;

    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("plain"), b"hello\n").unwrap();
    fs::write(source.path().join("run"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(source.path().join("run"), fs::Permissions::from_mode(0o755)).unwrap();
    symlink("plain", source.path().join("alias")).unwrap();
    a.handle(json!({"op":"capsule-create","path":source.path()}))
        .await
        .unwrap();
    let snapshot = a
        .handle(json!({"op":"snapshot","path":source.path(),"label":"first"}))
        .await
        .unwrap();
    let snapshot_id = snapshot["snapshot_id"].as_str().unwrap();
    a.handle(json!({"op":"send","peer":b.peer_id().await,"snapshot_id":snapshot_id}))
        .await
        .unwrap();
    wait_for(|| async {
        let log = b
            .handle(json!({"op":"log","capsule":snapshot["capsule_id"]}))
            .await?;
        if log.as_array().unwrap().is_empty() {
            Err("not delivered".into())
        } else {
            Ok(log)
        }
    })
    .await;
    let dest = b_root.path().join("accepted");
    b.handle(json!({"op":"accept","id":snapshot_id,"to":dest}))
        .await
        .unwrap();
    assert_eq!(fs::read(dest.join("plain")).unwrap(), b"hello\n");
    assert_eq!(
        fs::read_link(dest.join("alias")).unwrap(),
        Path::new("plain")
    );
    assert_ne!(
        fs::metadata(dest.join("run")).unwrap().permissions().mode() & 0o111,
        0
    );

    a.handle(json!({"op":"send","peer":b.peer_id().await,"link":"https://example.test/x","title":"Example","note":"carry this"})).await.unwrap();
    let inbox = wait_for(|| async {
        let rows = b.handle(json!({"op":"inbox"})).await?;
        if rows.as_array().unwrap().is_empty() {
            Err("empty".into())
        } else {
            Ok(rows)
        }
    })
    .await;
    let card = &inbox[0];
    assert_eq!(card["kind"], "dev.abra.handoff.v1");
    assert_eq!(card["title"], "Example");
    assert_eq!(card["link"], "https://example.test/x");
    let empty = b_root.path().join("handoff-empty");
    b.handle(json!({"op":"accept","id":card["id"],"to":empty}))
        .await
        .unwrap();
    assert!(!empty.exists());
    assert!(b.handle(json!({"op":"inbox"})).await.unwrap()[0]["read"]
        .as_bool()
        .unwrap());

    b_run.shutdown().await;
    drop(b);
    fs::write(source.path().join("plain"), b"offline update\n").unwrap();
    let second = a
        .handle(json!({"op":"snapshot","path":source.path()}))
        .await
        .unwrap();
    // Queue against B's persisted peer id, then recreate B on the same root.
    let b_id = a.handle(json!({"op":"peers"})).await.unwrap()[0]["peer_id"].clone();
    let out = a
        .handle(json!({"op":"send","peer":b_id,"snapshot_id":second["snapshot_id"]}))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    let states = a.handle(json!({"op":"outbox"})).await.unwrap();
    assert!(states
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["id"] == out["outbox_id"] && x["state"] != "acked"));
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let b_run = b.start().await.unwrap();
    wait_for(|| async {
        let rows = a.handle(json!({"op":"outbox"})).await?;
        if rows
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["id"] == out["outbox_id"] && x["state"] == "acked")
        {
            Ok(rows)
        } else {
            Err("pending".into())
        }
    })
    .await;

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn revoke_propagates_on_next_offer_and_blocks_guest_at_peer() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let guest_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let guest = Arc::new(Daemon::loopback(guest_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    let guest_run = guest.start().await.unwrap();

    let ticket = b.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    a.handle(json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();
    let minted = a
        .handle(json!({
            "op":"enroll-mint",
            "capsules":["*"],
            "kinds":["*"],
            "ttl_ms":60_000,
            "send":true,
            "receive":true
        }))
        .await
        .unwrap();
    let joined = guest
        .handle(json!({"op":"enroll-join","token":minted["token"]}))
        .await
        .unwrap();
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("guest.txt"), "guest").unwrap();
    let guest_peer_id = guest.peer_id().await;
    let issuer_trust = abra_net::TrustStore::open(a_root.path()).unwrap();
    let stored = issuer_trust
        .bind_certificate(&guest_peer_id)
        .unwrap()
        .clone();
    let mut receiver_trust = abra_net::TrustStore::open(b_root.path()).unwrap();
    receiver_trust
        .install_bind_certificate(stored.issuer, stored.certificate, abra_core::now_ms())
        .unwrap();

    a.handle(json!({"op":"revoke","token_id":joined["token_id"]}))
        .await
        .unwrap();
    a.handle(json!({
        "op":"send",
        "peer":b.peer_id().await,
        "link":"https://example.test/revocation-contact",
        "title":"revocation contact"
    }))
    .await
    .unwrap();
    wait_for(|| async {
        let inbox = b.handle(json!({"op":"inbox"})).await?;
        inbox
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["title"] == "revocation contact")
            .then_some(inbox)
            .ok_or_else(|| "revocation contact not received".into())
    })
    .await;

    guest
        .handle(json!({
            "op":"send",
            "peer":b.peer_id().await,
            "path":source.path(),
            "title":"must be rejected"
        }))
        .await
        .unwrap();
    let outbox = wait_for(|| async {
        let rows = guest.handle(json!({"op":"outbox"})).await?;
        rows.as_array()
            .unwrap()
            .iter()
            .any(|row| row["last_error"].as_str().is_some())
            .then_some(rows)
            .ok_or_else(|| "guest offer has not been rejected".into())
    })
    .await;
    assert!(outbox.as_array().unwrap().iter().any(|row| {
        row["last_error"]
            .as_str()
            .is_some_and(|error| error.contains("revoked"))
    }));

    guest_run.shutdown().await;
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn guest_lease_take_uses_the_local_enrollment_scope() {
    let network = LoopbackNetwork::default();
    let owner_root = private_root();
    let allowed_root = private_root();
    let denied_root = private_root();
    let owner = Arc::new(Daemon::loopback(owner_root.path(), &network, true).unwrap());
    let allowed = Arc::new(Daemon::loopback(allowed_root.path(), &network, true).unwrap());
    let denied = Arc::new(Daemon::loopback(denied_root.path(), &network, true).unwrap());
    let owner_run = owner.start().await.unwrap();
    let allowed_run = allowed.start().await.unwrap();
    let denied_run = denied.start().await.unwrap();

    let workspace = owner_root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("value"), "one").unwrap();
    owner
        .handle(json!({"op":"capsule-create","path":workspace}))
        .await
        .unwrap();
    let snapshot = owner
        .handle(json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap();

    for (guest, takeover) in [(&allowed, true), (&denied, false)] {
        let minted = owner
            .handle(json!({
                "op":"enroll-mint",
                "capsules":["*"],
                "kinds":["*"],
                "ttl_ms":60_000,
                "send":true,
                "receive":true,
                "lease_takeover":takeover
            }))
            .await
            .unwrap();
        guest
            .handle(json!({"op":"enroll-join","token":minted["token"]}))
            .await
            .unwrap();
        owner
            .handle(json!({
                "op":"send",
                "peer":guest.peer_id().await,
                "snapshot_id":snapshot["snapshot_id"],
                "wait":true,
                "timeout_ms":30_000
            }))
            .await
            .unwrap();
    }

    allowed
        .handle(json!({"op":"lease-take","capsule":snapshot["capsule_id"]}))
        .await
        .unwrap();
    let error = denied
        .handle(json!({"op":"lease-take","capsule":snapshot["capsule_id"]}))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "local guest token does not allow lease takeover");

    denied_run.shutdown().await;
    allowed_run.shutdown().await;
    owner_run.shutdown().await;
}

#[tokio::test]
async fn standing_grant_fires_repeatedly_into_per_snapshot_directories() {
    let network = LoopbackNetwork::default();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    let ticket = b.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    a.handle(json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();
    let destination = b_root.path().join("granted");
    b.handle(json!({
        "op":"policy-grant",
        "peer":a.peer_id().await,
        "kind":"dev.abra.bundle",
        "auto_accept":true,
        "to":destination
    }))
    .await
    .unwrap();
    let source = tempfile::tempdir().unwrap();
    for content in ["one", "two"] {
        fs::write(source.path().join("value"), content).unwrap();
        a.handle(json!({
            "op":"send",
            "peer":b.peer_id().await,
            "path":source.path(),
            "title":content
        }))
        .await
        .unwrap();
    }
    wait_for(|| async {
        let entries = fs::read_dir(&destination)
            .map_err(|error| error.to_string())?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if entries.len() == 2 {
            Ok(json!({"ready":true}))
        } else {
            Err("deliveries not materialized".into())
        }
    })
    .await;
    let mut contents = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path().join("value")).unwrap())
        .collect::<Vec<_>>();
    contents.sort();
    assert_eq!(contents, ["one", "two"]);
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn reciprocal_forward_grants_do_not_bounce_deliveries() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;
    let a_peer = a.peer_id().await;
    let b_peer = b.peer_id().await;

    a.handle(json!({"op":"policy-grant","peer":b_peer,"kind":"dev.abra.handoff.v1","auto_accept":true,"to":a_root.path().join("accepted"),"forward":b_peer})).await.unwrap();
    b.handle(json!({"op":"policy-grant","peer":a_peer,"kind":"dev.abra.handoff.v1","auto_accept":true,"to":b_root.path().join("accepted"),"forward":a_peer})).await.unwrap();
    a.handle(json!({"op":"send","peer":b_peer,"link":"https://example.test/a","wait":true,"timeout_ms":30_000})).await.unwrap();
    b.handle(json!({"op":"send","peer":a_peer,"link":"https://example.test/b","wait":true,"timeout_ms":30_000})).await.unwrap();

    for daemon in [&a, &b] {
        let events = wait_for(|| async {
            let events = daemon.handle(json!({"op":"events"})).await?;
            events
                .as_array()
                .unwrap()
                .iter()
                .any(|event| {
                    event["event"] == "auto-forward-skipped" && event["reason"] == "delivering-peer"
                })
                .then_some(events)
                .ok_or_else(|| "forward was not skipped".into())
        })
        .await;
        assert!(!events
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event"] == "auto-forwarded"));
        assert_eq!(
            daemon
                .handle(json!({"op":"outbox"}))
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    b_run.shutdown().await;
    a_run.shutdown().await;
}

/// Write a shell adapter that answers one request and exits.
fn shell_adapter(
    dir: &Path,
    name: &str,
    kind: &str,
    verbs: &[&str],
    body: &str,
) -> std::path::PathBuf {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("abra-adapter.json"),
        serde_json::to_vec(&json!({
            "spec":"abra-adapter/1",
            "name":name,
            "version":"1",
            "kinds":[kind],
            "verbs":verbs,
            "executable":"run"
        }))
        .unwrap(),
    )
    .unwrap();
    let executable = dir.join("run");
    fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    dir.to_path_buf()
}

const EXPORT_BODY: &str = r###"read line
id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
staging=$(printf '%s' "$line" | sed -n 's/.*"staging_dir":"\([^"]*\)".*/\1/p')
printf 'session bytes' > "$staging/session.txt"
printf '{"request_id":"%s","ok":true,"payload":{"schema":"test/1"},"files_path":"%s","floor":{"title":"linked handoff"}}\n' "$id" "$staging"
"###;

fn import_body(capture: &Path) -> String {
    format!(
        r###"read line
printf '%s' "$line" > '{}'
id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
printf '{{"request_id":"%s","ok":true,"result":"imported"}}\n' "$id"
"###,
        capture.display()
    )
}

async fn pair_daemons(a: &Arc<Daemon>, b: &Arc<Daemon>) {
    let ticket = b.handle(json!({"op":"pair-ticket"})).await.unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    a.handle(json!({"op":"pair-add","ticket":ticket}))
        .await
        .unwrap();
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[tokio::test]
async fn send_wait_returns_the_acked_entry_and_reports_a_stalled_delivery() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;

    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("value"), "waited").unwrap();
    let sent = a
        .handle(json!({
            "op":"send",
            "peer":b.peer_id().await,
            "path":source.path(),
            "wait":true,
            "timeout_ms":30_000
        }))
        .await
        .unwrap();
    assert_eq!(sent["entry"]["state"], "acked");
    assert_eq!(sent["entry"]["id"], sent["outbox_id"]);
    assert_eq!(sent["entry"]["snapshot_id"], sent["snapshot_id"]);
    assert!(sent["entry"]["acked_at"].is_string());
    assert!(sent["entry"]["ack_sig"].is_string());

    // With the peer gone the wait reports the state it stalled in.
    b_run.shutdown().await;
    drop(b);
    let b_peer = a.handle(json!({"op":"peers"})).await.unwrap()[0]["peer_id"].clone();
    let error = a
        .handle(json!({
            "op":"send",
            "peer":b_peer,
            "link":"https://example.test/stalled",
            "wait":true,
            "timeout_ms":400
        }))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("was not acknowledged within 400ms"),
        "{error}"
    );
    a_run.shutdown().await;
}

#[tokio::test]
async fn inbox_filters_and_waits_and_accept_latest_picks_the_one_unread_match() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;
    let a_peer = a.peer_id().await;

    let waiting = {
        let b = Arc::clone(&b);
        tokio::spawn(async move {
            b.handle(json!({
                "op":"inbox",
                "kind":"dev.abra.bundle",
                "from":a_peer.to_string(),
                "wait":true,
                "timeout_ms":30_000
            }))
            .await
        })
    };
    a.handle(json!({"op":"send","peer":b.peer_id().await,"link":"https://example.test/other"}))
        .await
        .unwrap();
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("value"), "bundle").unwrap();
    let bundle = a
        .handle(json!({"op":"send","peer":b.peer_id().await,"path":source.path()}))
        .await
        .unwrap();
    let rows = waiting.await.unwrap().unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["id"], bundle["snapshot_id"]);
    assert_eq!(rows[0]["kind"], "dev.abra.bundle");

    let destination = b_root.path().join("latest");
    let accepted = b
        .handle(json!({"op":"accept","latest":true,"kind":"dev.abra.bundle","to":destination}))
        .await
        .unwrap();
    assert_eq!(accepted["accepted"], bundle["snapshot_id"]);
    assert_eq!(
        fs::read_to_string(destination.join("value")).unwrap(),
        "bundle"
    );
    let repeated = b
        .handle(json!({"op":"accept","latest":true,"kind":"dev.abra.bundle","to":destination}))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(repeated, "no unread dev.abra.bundle delivery found");

    for _ in 0..2 {
        fs::write(source.path().join("value"), "again").unwrap();
        a.handle(json!({"op":"send","peer":b.peer_id().await,"path":source.path(),"wait":true,"timeout_ms":30_000}))
            .await
            .unwrap();
    }
    let ambiguous = b
        .handle(json!({"op":"accept","latest":true,"kind":"dev.abra.bundle","to":b_root.path().join("ambiguous")}))
        .await
        .unwrap_err()
        .to_string();
    assert!(ambiguous.starts_with("multiple unread dev.abra.bundle deliveries match"));

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn linked_handoff_restores_the_workspace_before_the_adapter_import() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let capture = b_root.path().join("import-request.json");
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    a.handle(json!({"op":"adapters-add","dir":shell_adapter(
        &a_root.path().join("export-adapter"),
        "test.session",
        "com.test.session",
        &["export"],
        EXPORT_BODY
    )}))
    .await
    .unwrap();
    b.handle(json!({"op":"adapters-add","dir":shell_adapter(
        &b_root.path().join("import-adapter"),
        "test.session",
        "com.test.session",
        &["import"],
        &import_body(&capture)
    )}))
    .await
    .unwrap();
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;

    let workspace = a_root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("turn"), "a1").unwrap();
    let sent = a
        .handle(json!({
            "op":"send",
            "peer":b.peer_id().await,
            "kind":"com.test.session",
            "source":"session-1",
            "workspace":workspace,
            "wait":true,
            "timeout_ms":30_000
        }))
        .await
        .unwrap();
    // One command produced both deliveries and waited for both acks.
    assert!(sent["workspace_outbox_id"].is_string());
    assert!(sent["workspace_snapshot_id"].is_string());
    assert!(sent["capsule_id"].is_string());
    assert_eq!(sent["entries"].as_array().unwrap().len(), 2);
    assert!(sent["entries"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["state"] == "acked"));
    // `abra init` ran for us.
    assert!(workspace.join(".abra/capsule_id").is_file());

    let inbox = wait_for(|| async {
        let rows = b
            .handle(json!({"op":"inbox","kind":"com.test.session"}))
            .await?;
        (!rows.as_array().unwrap().is_empty())
            .then_some(rows)
            .ok_or_else(|| "handoff not delivered".into())
    })
    .await;
    assert_eq!(inbox[0]["provenance"]["capsule_id"], sent["capsule_id"]);
    assert_eq!(
        inbox[0]["provenance"]["snapshot_id"],
        sent["workspace_snapshot_id"]
    );

    let b_workspace = b_root.path().join("received-workspace");
    let accepted = b
        .handle(json!({
            "op":"accept",
            "latest":true,
            "kind":"com.test.session",
            "to":b_root.path().join("materialized"),
            "workspace":b_workspace,
            "destination":"{\"codex_home\":\"/tmp/codex\"}",
            "timeout_ms":30_000
        }))
        .await
        .unwrap();
    assert_eq!(accepted["workspace"], json!(b_workspace));
    assert_eq!(fs::read_to_string(b_workspace.join("turn")).unwrap(), "a1");
    assert_eq!(
        fs::read_to_string(b_workspace.join(".abra/capsule_id")).unwrap(),
        sent["capsule_id"].as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(b_workspace.join(".abra/snapshot_id")).unwrap(),
        sent["workspace_snapshot_id"].as_str().unwrap()
    );
    // The adapter is told where the workspace landed.
    let request: Value = serde_json::from_slice(&fs::read(&capture).unwrap()).unwrap();
    assert_eq!(request["destination"]["workspace"], json!(b_workspace));
    assert_eq!(request["destination"]["codex_home"], "/tmp/codex");
    // The receiver drives the capsule now, without a separate `lease take`.
    let lease = b
        .handle(json!({"op":"lease-status","capsule":sent["capsule_id"]}))
        .await
        .unwrap();
    assert_eq!(lease["winning"]["holder"], b.peer_id().await.to_string());

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn adapter_provenance_enqueues_the_full_snapshot_first() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;

    let workspace = a_root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("turn"), "a1").unwrap();
    a.handle(json!({"op":"capsule-create","path":workspace}))
        .await
        .unwrap();
    let snapshot = a
        .handle(json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap();
    let body = format!(
        r###"read line
id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
printf '{{"request_id":"%s","ok":true,"payload":{{"schema":"test/1"}},"provenance":{{"capsule_id":"{}","snapshot_id":"{}"}}}}\n' "$id"
"###,
        snapshot["capsule_id"].as_str().unwrap(),
        snapshot["snapshot_id"].as_str().unwrap()
    );
    a.handle(json!({"op":"adapters-add","dir":shell_adapter(
        &a_root.path().join("provenance-adapter"),
        "test.provenance",
        "com.test.provenance",
        &["export"],
        &body
    )}))
    .await
    .unwrap();
    let sent = a
        .handle(json!({
            "op":"send",
            "peer":b.peer_id().await,
            "kind":"com.test.provenance",
            "source":"session-1"
        }))
        .await
        .unwrap();
    assert_eq!(sent["provenance_snapshot_id"], snapshot["snapshot_id"]);
    let outbox = a.handle(json!({"op":"outbox"})).await.unwrap();
    let entries = outbox.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    // Outbox listing order is by random id, so look entries up by id.
    let by_id = |id: &Value| {
        entries
            .iter()
            .find(|entry| entry["id"] == *id)
            .cloned()
            .unwrap()
    };
    let full = by_id(&sent["provenance_outbox_id"]);
    let partial = by_id(&sent["outbox_id"]);
    assert_eq!(full["snapshot_id"], snapshot["snapshot_id"]);
    assert!(full["created_at"].as_str().unwrap() <= partial["created_at"].as_str().unwrap());

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn a_failed_linked_import_restores_the_previous_workspace() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    a.handle(json!({"op":"adapters-add","dir":shell_adapter(
        &a_root.path().join("export-adapter"),
        "test.session",
        "com.test.session",
        &["export"],
        EXPORT_BODY
    )}))
    .await
    .unwrap();
    b.handle(json!({"op":"adapters-add","dir":shell_adapter(
        &b_root.path().join("import-adapter"),
        "test.session",
        "com.test.session",
        &["import"],
        r###"read line
id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
printf '{"request_id":"%s","ok":false,"error":{"code":"internal","message":"no"}}\n' "$id"
"###
    )}))
    .await
    .unwrap();
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;

    // B already holds an older version of the same workspace.
    let workspace = a_root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("turn"), "a1").unwrap();
    a.handle(json!({"op":"capsule-create","path":workspace}))
        .await
        .unwrap();
    let first = a
        .handle(json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap();
    a.handle(json!({"op":"send","peer":b.peer_id().await,"snapshot_id":first["snapshot_id"],"wait":true,"timeout_ms":30_000}))
        .await
        .unwrap();
    let b_workspace = b_root.path().join("received-workspace");
    b.handle(json!({"op":"accept","id":first["snapshot_id"],"to":b_workspace}))
        .await
        .unwrap();
    fs::write(b_workspace.join("local-only"), "keep me").unwrap();

    fs::write(workspace.join("turn"), "a2").unwrap();
    let sent = a
        .handle(json!({
            "op":"send",
            "peer":b.peer_id().await,
            "kind":"com.test.session",
            "source":"session-1",
            "workspace":workspace,
            "wait":true,
            "timeout_ms":30_000
        }))
        .await
        .unwrap();
    wait_for(|| async {
        let rows = b
            .handle(json!({"op":"inbox","kind":"com.test.session"}))
            .await?;
        (!rows.as_array().unwrap().is_empty())
            .then_some(rows)
            .ok_or_else(|| "handoff not delivered".into())
    })
    .await;
    let error = b
        .handle(json!({
            "op":"accept",
            "latest":true,
            "kind":"com.test.session",
            "to":b_root.path().join("materialized"),
            "workspace":b_workspace,
            "timeout_ms":30_000
        }))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("adapter import failed"), "{error}");
    assert!(error.contains("workspace was restored"), "{error}");
    assert_eq!(fs::read_to_string(b_workspace.join("turn")).unwrap(), "a1");
    assert_eq!(
        fs::read_to_string(b_workspace.join("local-only")).unwrap(),
        "keep me"
    );
    assert_eq!(
        fs::read_to_string(b_workspace.join(".abra/snapshot_id")).unwrap(),
        first["snapshot_id"].as_str().unwrap()
    );
    let handoffs = b.handle(json!({"op":"handoffs"})).await.unwrap();
    assert!(handoffs.as_array().unwrap().iter().any(|row| {
        row["capsule"]["capsule_id"] == first["capsule_id"]
            && row["capsule"]["snapshot_id"] == first["snapshot_id"]
            && row["capsule"]["path"] == json!(b_workspace)
    }));
    // The entry stays unread so the handoff can be retried.
    let inbox = b
        .handle(json!({"op":"inbox","kind":"com.test.session"}))
        .await
        .unwrap();
    assert_eq!(inbox[0]["read"], false);
    assert_eq!(inbox[0]["id"], sent["snapshot_id"]);

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn sending_a_workspace_path_sends_the_capsule_snapshot_and_leases_follow_the_driver() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;

    let workspace = a_root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("turn"), "a1").unwrap();
    let capsule = a
        .handle(json!({"op":"capsule-create","path":workspace}))
        .await
        .unwrap()["capsule_id"]
        .clone();
    // A plain folder is still a partial bundle.
    let plain = a_root.path().join("plain");
    fs::create_dir(&plain).unwrap();
    fs::write(plain.join("value"), "loose").unwrap();
    let bundle = a
        .handle(json!({"op":"send","peer":b.peer_id().await,"path":plain,"wait":true,"timeout_ms":30_000}))
        .await
        .unwrap();
    assert!(bundle.get("workspace_detected").is_none());

    let sent = a
        .handle(json!({"op":"send","peer":b.peer_id().await,"path":workspace,"wait":true,"timeout_ms":30_000}))
        .await
        .unwrap();
    assert_eq!(sent["workspace_detected"], true);
    assert_eq!(sent["capsule_id"], capsule);
    let log = b
        .handle(json!({"op":"log","capsule":capsule}))
        .await
        .unwrap();
    assert_eq!(log.as_array().unwrap().len(), 1);

    // B accepts, edits, and snapshots without ever calling `lease take`.
    // `--latest` finds the arrived capsule head, not just inbox partials.
    let b_workspace = b_root.path().join("workspace");
    let accepted = b
        .handle(json!({"op":"accept","latest":true,"kind":"dev.abra.workspace","to":b_workspace}))
        .await
        .unwrap();
    assert_eq!(accepted["accepted"], sent["snapshot_id"]);
    fs::write(b_workspace.join("turn"), "b2").unwrap();
    let second = b
        .handle(json!({"op":"snapshot","path":b_workspace}))
        .await
        .unwrap();
    assert_eq!(second["forked"], false);
    let lease = b
        .handle(json!({"op":"lease-status","capsule":capsule}))
        .await
        .unwrap();
    assert_eq!(lease["winning"]["holder"], b.peer_id().await.to_string());

    b.handle(json!({"op":"send","peer":a.peer_id().await,"snapshot_id":second["snapshot_id"],"wait":true,"timeout_ms":30_000}))
        .await
        .unwrap();
    // The lease travels with the snapshot, so A knows B is driving now.
    wait_for(|| async {
        let lease = a
            .handle(json!({"op":"lease-status","capsule":capsule}))
            .await?;
        (lease["winning"]["holder"] == b.peer_id().await.to_string())
            .then_some(lease)
            .ok_or_else(|| "lease has not propagated".into())
    })
    .await;
    // --no-lease keeps today's forking behaviour on the device that is not driving.
    fs::write(workspace.join("turn"), "a3-fork").unwrap();
    let forked = a
        .handle(json!({"op":"snapshot","path":workspace,"no_lease":true}))
        .await
        .unwrap();
    assert_eq!(forked["forked"], true);
    // Replacing the workspace takes the lease back, so the next snapshot is a head.
    a.handle(json!({"op":"accept","id":second["snapshot_id"],"to":workspace,"replace":true}))
        .await
        .unwrap();
    assert_eq!(fs::read_to_string(workspace.join("turn")).unwrap(), "b2");
    fs::write(workspace.join("turn"), "a4").unwrap();
    let fourth = a
        .handle(json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap();
    assert_eq!(fourth["forked"], false);

    // A workspace never touches either queue, so `handoffs` reads its capsule.
    let rows = a
        .handle(json!({"op":"handoffs","kind":"dev.abra.workspace"}))
        .await
        .unwrap();
    assert_eq!(rows[0]["capsule"]["capsule_id"], capsule);
    assert_eq!(rows[0]["capsule"]["snapshot_id"], fourth["snapshot_id"]);
    assert_eq!(rows[0]["capsule"]["driving"], true);
    // B has had no delivery since A took the lease back, so B still reads its
    // own last-known state. Lease knowledge travels with snapshots.
    let rows = b
        .handle(json!({"op":"handoffs","kind":"dev.abra.workspace"}))
        .await
        .unwrap();
    assert_eq!(rows[0]["capsule"]["driving"], true);
    assert_eq!(rows[0]["capsule"]["snapshot_id"], second["snapshot_id"]);

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn handoffs_summarizes_sends_and_receives_per_kind() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;
    let a_peer = a.peer_id().await;
    let b_peer = b.peer_id().await;

    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("value"), "one").unwrap();
    let bundle = a
        .handle(
            json!({"op":"send","peer":b_peer,"path":source.path(),"wait":true,"timeout_ms":30_000}),
        )
        .await
        .unwrap();
    a.handle(json!({"op":"send","peer":b_peer,"link":"https://example.test/handoff","wait":true,"timeout_ms":30_000}))
        .await
        .unwrap();

    let rows = a.handle(json!({"op":"handoffs"})).await.unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let bundle_row = rows
        .iter()
        .find(|row| row["kind"] == "dev.abra.bundle")
        .unwrap();
    assert_eq!(bundle_row["last_acked_send"]["id"], bundle["outbox_id"]);
    assert_eq!(bundle_row["last_acked_send"]["peer_id"], b_peer.to_string());
    assert!(bundle_row["last_acked_send"]["acked_at"].is_string());
    assert!(bundle_row["last_pending_send"].is_null());
    assert!(bundle_row["last_unread_receive"].is_null());

    let filtered = a
        .handle(json!({"op":"handoffs","kind":"dev.abra.bundle"}))
        .await
        .unwrap();
    assert_eq!(filtered.as_array().unwrap().len(), 1);
    assert!(
        a.handle(json!({"op":"handoffs","peer":b_peer.to_string()}))
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len()
            == 2
    );

    let received = wait_for(|| async {
        let rows = b.handle(json!({"op":"handoffs"})).await?;
        (rows.as_array().unwrap().len() == 2)
            .then_some(rows)
            .ok_or_else(|| "deliveries pending".into())
    })
    .await;
    let bundle_row = received
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"] == "dev.abra.bundle")
        .unwrap();
    assert_eq!(
        bundle_row["last_unread_receive"]["id"],
        bundle["snapshot_id"]
    );
    assert_eq!(
        bundle_row["last_unread_receive"]["from"],
        a_peer.to_string()
    );
    assert!(bundle_row["last_read_receive"].is_null());

    b.handle(json!({"op":"accept","id":bundle["snapshot_id"],"to":b_root.path().join("read")}))
        .await
        .unwrap();
    let after = b
        .handle(json!({"op":"handoffs","kind":"dev.abra.bundle"}))
        .await
        .unwrap();
    assert!(after[0]["last_unread_receive"].is_null());
    assert_eq!(after[0]["last_read_receive"]["id"], bundle["snapshot_id"]);
    assert!(after[0]["capsule"].is_null());

    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn flag_and_env_adapter_directories_join_discovery_without_persisting() {
    let root = private_root();
    let parent = root.path().join("bundled");
    shell_adapter(
        &parent.join("first"),
        "test.first",
        "com.test.first",
        &["export"],
        "exit 0",
    );
    shell_adapter(
        &parent.join("second"),
        "test.second",
        "com.test.second",
        &["export"],
        "exit 0",
    );
    let single = shell_adapter(
        &root.path().join("single"),
        "test.single",
        "com.test.single",
        &["export"],
        "exit 0",
    );

    let network = LoopbackNetwork::default();
    let mut daemon = Daemon::loopback(root.path(), &network, true).unwrap();
    daemon.set_adapter_sources(vec![
        cadabra::adapters::ExtraAdapterDir::flag(&parent),
        cadabra::adapters::ExtraAdapterDir::env(&single),
    ]);
    let daemon = Arc::new(daemon);
    let listed = daemon.handle(json!({"op":"adapters-list"})).await.unwrap();
    let sources = listed["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["manifest"]["name"].as_str().unwrap().to_owned(),
                row["source"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        sources,
        [
            ("test.first".to_owned(), "flag".to_owned()),
            ("test.second".to_owned(), "flag".to_owned()),
            ("test.single".to_owned(), "env".to_owned()),
        ]
    );
    assert!(listed["errors"].as_array().unwrap().is_empty());
    // Nothing was written to the persisted registry.
    assert!(!root.path().join("adapters/registry.json").exists());

    // A plain daemon on the same root sees none of them.
    let plain = Arc::new(Daemon::loopback(root.path(), &network, true).unwrap());
    let listed = plain.handle(json!({"op":"adapters-list"})).await.unwrap();
    assert!(listed["adapters"].as_array().unwrap().is_empty());
}

/// Give `receiver` a capsule of its own kind by sending it a workspace
/// snapshot and accepting it, so control has something to route.
async fn share_workspace(
    sender: &Arc<Daemon>,
    receiver: &Arc<Daemon>,
    workspace: &Path,
    accept_into: &Path,
) -> (String, String) {
    fs::create_dir_all(workspace).unwrap();
    fs::write(workspace.join("value"), "first").unwrap();
    let capsule = sender
        .handle(json!({"op":"capsule-create","path":workspace}))
        .await
        .unwrap()["capsule_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let snapshot = sender
        .handle(json!({"op":"snapshot","path":workspace}))
        .await
        .unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    sender
        .handle(json!({"op":"send","peer":receiver.peer_id().await,"snapshot_id":snapshot}))
        .await
        .unwrap();
    wait_for(|| async {
        let log = receiver
            .handle(json!({"op":"log","capsule":capsule}))
            .await?;
        (!log.as_array().unwrap().is_empty())
            .then_some(log)
            .ok_or_else(|| "capsule pending".into())
    })
    .await;
    receiver
        .handle(json!({"op":"accept","id":snapshot,"to":accept_into}))
        .await
        .unwrap();
    (capsule, snapshot)
}

fn reference_folder_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/reference-folder")
}

#[tokio::test]
async fn control_reaches_the_adapter_that_claims_the_capsule_kind() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    b.handle(json!({"op":"adapters-add","dir":reference_folder_dir()}))
        .await
        .unwrap();
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;
    let restored = b_root.path().join("restored");
    let (capsule, _) = share_workspace(&a, &b, &a_root.path().join("workspace"), &restored).await;

    let ack = a
        .handle(json!({
            "op":"control",
            "peer":b.peer_id().await,
            "capsule":capsule,
            "control_op":"instruct",
            "text":"run the tests"
        }))
        .await
        .unwrap();
    assert_eq!(ack["ok"], json!(true));
    assert_eq!(
        ack["result"],
        json!({"op":"instruct","text":"run the tests","workspace":restored})
    );
    let handled = wait_for(|| async {
        let events = b.handle(json!({"op":"events"})).await?;
        events
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["event"] == "control-handled")
            .cloned()
            .ok_or_else(|| "control event pending".into())
    })
    .await;
    assert_eq!(handled["op"], json!("instruct"));
    assert_eq!(handled["ok"], json!(true));
    assert_eq!(handled["adapter"], json!("dev.abra.reference-folder"));
    assert_eq!(handled["capsule_id"], json!(capsule));
    assert!(handled["at"].is_string());
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn slow_inbound_control_does_not_block_local_status() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let adapter = shell_adapter(
        &b_root.path().join("slow-control-adapter"),
        "slow-control",
        "dev.abra.workspace",
        &["control"],
        r#"read line
id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
sleep 3
printf '{"request_id":"%s","ok":true,"result":{}}\n' "$id""#,
    );
    b.handle(json!({"op":"adapters-add","dir":adapter}))
        .await
        .unwrap();
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;
    let (capsule, _) = share_workspace(
        &a,
        &b,
        &a_root.path().join("slow-workspace"),
        &b_root.path().join("slow-restored"),
    )
    .await;
    let control = {
        let a = Arc::clone(&a);
        let peer = b.peer_id().await;
        tokio::spawn(async move {
            a.handle(json!({
                "op":"control",
                "peer":peer,
                "capsule":capsule,
                "control_op":"instruct",
                "text":"sleep"
            }))
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let status = tokio::time::timeout(Duration::from_secs(2), a.handle(json!({"op":"status"})))
        .await
        .expect("status was blocked by the slow peer")
        .unwrap();
    assert_eq!(status["running"], true);
    control.await.unwrap().unwrap();
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn control_without_an_adapter_refuses_instruct_and_records_pause() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;
    let (capsule, _) = share_workspace(
        &a,
        &b,
        &a_root.path().join("workspace"),
        &b_root.path().join("restored"),
    )
    .await;

    let refused = a
        .handle(json!({
            "op":"control",
            "peer":b.peer_id().await,
            "capsule":capsule,
            "control_op":"instruct",
            "text":"run the tests"
        }))
        .await
        .unwrap();
    assert_eq!(refused["ok"], json!(false));
    assert!(refused["error"]
        .as_str()
        .unwrap()
        .contains("no adapter handles control for dev.abra.workspace"));
    let paused = a
        .handle(json!({
            "op":"control",
            "peer":b.peer_id().await,
            "capsule":capsule,
            "control_op":"pause"
        }))
        .await
        .unwrap();
    assert_eq!(paused["ok"], json!(true));
    assert_eq!(paused["result"], json!({"recorded":true}));
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn auto_accept_runs_the_importer_and_forwards_to_the_next_peer() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let c_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    let c = Arc::new(Daemon::loopback(c_root.path(), &network, true).unwrap());
    let capture = b_root.path().join("import-request.json");
    b.handle(json!({
        "op":"adapters-add",
        "dir":shell_adapter(
            &b_root.path().join("bundle-importer"),
            "bundle-importer",
            "dev.abra.bundle",
            &["import"],
            &import_body(&capture),
        )
    }))
    .await
    .unwrap();
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    let c_run = c.start().await.unwrap();
    pair_daemons(&a, &b).await;
    pair_daemons(&b, &c).await;
    // The forwarding peer must already trust the original author: a receiver
    // refuses a manifest whose origin it does not know.
    pair_daemons(&a, &c).await;

    let destination = b_root.path().join("granted");
    b.handle(json!({
        "op":"policy-grant",
        "peer":a.peer_id().await,
        "kind":"dev.abra.bundle",
        "auto_accept":true,
        "to":destination,
        "forward":c.peer_id().await
    }))
    .await
    .unwrap();
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("value"), "payload").unwrap();
    let sent = a
        .handle(json!({"op":"send","peer":b.peer_id().await,"path":source.path()}))
        .await
        .unwrap();

    wait_for(|| async {
        capture
            .is_file()
            .then_some(json!({"imported":true}))
            .ok_or_else(|| "importer has not run".into())
    })
    .await;
    let request: Value = serde_json::from_slice(&fs::read(&capture).unwrap()).unwrap();
    assert_eq!(request["verb"], json!("import"));
    // The importer runs before the entry is marked read; wait for that step.
    wait_for(|| async {
        let inbox = b.handle(json!({"op":"inbox"})).await?;
        (inbox[0]["read"] == json!(true))
            .then_some(inbox)
            .ok_or_else(|| "entry not yet marked read".into())
    })
    .await;
    let received = wait_for(|| async {
        let inbox = c.handle(json!({"op":"inbox"})).await?;
        (!inbox.as_array().unwrap().is_empty())
            .then_some(inbox)
            .ok_or_else(|| "forward pending".into())
    })
    .await;
    assert_eq!(received[0]["id"], sent["snapshot_id"]);
    let events = b.handle(json!({"op":"events"})).await.unwrap();
    let named = |name: &str| {
        events
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["event"] == name)
            .cloned()
            .unwrap_or(Value::Null)
    };
    assert_eq!(named("auto-accepted")["kind"], json!("dev.abra.bundle"));
    assert_eq!(named("auto-forwarded")["peer"], json!(c.peer_id().await));
    let grant = b.handle(json!({"op":"policy-list"})).await.unwrap();
    assert_eq!(
        grant.as_object().unwrap().values().next().unwrap()["forward"],
        json!(c.peer_id().await)
    );
    c_run.shutdown().await;
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn a_blocking_inspect_refuses_the_send_until_it_is_forced() {
    let network = LoopbackNetwork::default();
    let a_root = private_root();
    let b_root = private_root();
    let a = Arc::new(Daemon::loopback(a_root.path(), &network, true).unwrap());
    let b = Arc::new(Daemon::loopback(b_root.path(), &network, true).unwrap());
    a.handle(json!({"op":"adapters-add","dir":reference_folder_dir()}))
        .await
        .unwrap();
    let a_run = a.start().await.unwrap();
    let b_run = b.start().await.unwrap();
    pair_daemons(&a, &b).await;
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join(".env"), "TOKEN=secret").unwrap();
    fs::write(source.path().join("big.bin"), vec![7u8; 1024 * 1024 + 1]).unwrap();

    let refused = a
        .handle(json!({
            "op":"send",
            "peer":b.peer_id().await,
            "kind":"dev.abra.folder",
            "source":source.path()
        }))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("blocked this send"), "{refused}");
    assert!(refused.contains("dotenv"), "{refused}");

    let forced = a
        .handle(json!({
            "op":"send",
            "peer":b.peer_id().await,
            "kind":"dev.abra.folder",
            "source":source.path(),
            "force":true
        }))
        .await
        .unwrap();
    assert_eq!(forced["warnings"][0]["code"], json!("large-file"));
    assert_eq!(forced["warnings"][0]["item"], json!("big.bin"));
    assert_eq!(forced["blocked"][0]["code"], json!("dotenv"));
    assert!(forced["summary"].is_string());
    b_run.shutdown().await;
    a_run.shutdown().await;
}

#[tokio::test]
async fn inspect_runs_the_verb_on_its_own() {
    let network = LoopbackNetwork::default();
    let root = private_root();
    let daemon = Arc::new(Daemon::loopback(root.path(), &network, true).unwrap());
    daemon
        .handle(json!({"op":"adapters-add","dir":reference_folder_dir()}))
        .await
        .unwrap();
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("notes.txt"), "small").unwrap();
    let clean = daemon
        .handle(json!({"op":"inspect","kind":"dev.abra.folder","source":source.path()}))
        .await
        .unwrap();
    assert_eq!(clean["warnings"], json!([]));
    assert_eq!(clean["blocked"], json!([]));
    assert_eq!(clean["summary"], json!("1 files"));

    fs::write(source.path().join(".env"), "TOKEN=secret").unwrap();
    let blocked = daemon
        .handle(json!({"op":"inspect","kind":"dev.abra.folder","source":source.path()}))
        .await
        .unwrap();
    assert_eq!(blocked["blocked"][0]["item"], json!(".env"));
    let events = daemon.handle(json!({"op":"events"})).await.unwrap();
    assert!(events
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["event"] == "adapter-inspect" && event["blocked"] == json!(1)));
}
