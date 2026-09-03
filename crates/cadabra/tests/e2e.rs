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
async fn relay_add_accepts_first_failure_and_five_second_polling() {
    let network = LoopbackNetwork::default();
    let root = tempfile::tempdir().unwrap();
    let daemon = Daemon::loopback(root.path(), &network, true).unwrap();
    daemon
        .handle(json!({"op":"relay-add","url":"http://127.0.0.1:1","relay_after_attempts":0,"poll_seconds":5}))
        .await
        .unwrap();
    let config = cadabra::relay::RelayConfig::load(root.path()).unwrap();
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
async fn capsule_round_trip_and_into_replace_workspace() {
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
        .handle(json!({"op":"accept","id":third["snapshot_id"],"to":b_workspace,"into":true}))
        .await
        .unwrap_err();
    assert!(mismatch.to_string().contains("different capsule"));
    assert_eq!(
        fs::read_to_string(b_workspace.join("stale")).unwrap(),
        "remove me"
    );
    fs::write(b_workspace.join(".abra/capsule_id"), correct_capsule).unwrap();
    b.handle(json!({"op":"accept","id":third["snapshot_id"],"to":b_workspace,"into":true}))
        .await
        .unwrap();
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
    b.handle(json!({"op":"policy-grant","peer":a.peer_id().await,"kind":"dev.abra.workspace","capsule":capsule,"auto_accept":true,"auto_run_recipes":false,"to":destination_root})).await.unwrap();
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
    assert!(b
        .handle(json!({"op":"events"}))
        .await
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["type"] == "auto-accepted-full"));
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
    c.handle(json!({"op":"policy-grant","peer":a.peer_id().await,"kind":"dev.abra.workspace","capsule":capsule,"auto_accept":true,"auto_run_recipes":false,"to":destination_root})).await.unwrap();
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
        &json!({"op":"accept","id":sent["snapshot_id"],"to":b_root.path().join("into"),"into":true}),
    )
    .await
    .unwrap_err();
    assert!(into_error
        .to_string()
        .contains("--into requires a full capsule snapshot"));

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
        "auto_run_recipes":false,
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
