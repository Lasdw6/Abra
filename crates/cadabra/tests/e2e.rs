#![cfg(unix)]

use abra_net::LoopbackNetwork;
use cadabra::Daemon;
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
