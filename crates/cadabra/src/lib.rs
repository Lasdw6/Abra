//! Library-first Abra daemon and its newline-delimited JSON control API.
#![forbid(unsafe_code)]

use abra_core::{
    capsule::{random_capsule_id, Genesis, LabelOp, LeaseMode, LeaseRecord},
    cas::{materialize, snapshot_dir, EntryMode, Hash, Tree, TreeEntry},
    identity::{PeerId, Signature},
    manifest::{Manifest, Origin, RawManifest, Scope},
    now_ms,
};
use abra_net::{
    dial_handshake, format_time, read_frame, write_frame, DeliveryNode, EnrollmentToken, Intro,
    LoopbackNetwork, LoopbackTransport, PairAccept, PairRequest, PairTicket, Scopes, Transport,
};
use rand::Rng;
use serde_json::{json, Map, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{watch, Mutex},
    task::JoinHandle,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// A running daemon owns exactly one durable network/store node.
pub struct Daemon {
    root: PathBuf,
    node: Arc<Mutex<DeliveryNode>>,
    transport: Arc<dyn Transport>,
    shutdown: watch::Sender<bool>,
}

pub struct RunningDaemon {
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningDaemon {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

impl Daemon {
    pub fn new(root: impl AsRef<Path>, transport: Arc<dyn Transport>, yes: bool) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let mut node = DeliveryNode::open(&root)?;
        if transport.local_peer_id() != node.peer_id() {
            return Err("transport identity differs from store identity".into());
        }
        node.auto_confirm_pairs = yes;
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            root,
            node: Arc::new(Mutex::new(node)),
            transport,
            shutdown,
        })
    }

    pub fn loopback(root: impl AsRef<Path>, network: &LoopbackNetwork, yes: bool) -> Result<Self> {
        let node = DeliveryNode::open(root.as_ref())?;
        let transport = Arc::new(LoopbackTransport::bind(network, node.peer_id()));
        drop(node);
        Self::new(root, transport, yes)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn peer_id(&self) -> PeerId {
        self.node.lock().await.peer_id()
    }

    pub async fn start(self: &Arc<Self>) -> Result<RunningDaemon> {
        let socket = self.root.join("cadabra.sock");
        match fs::remove_file(&socket) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&socket)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        }
        let mut tasks = Vec::new();
        let daemon = Arc::clone(self);
        let mut stop = self.shutdown.subscribe();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            let daemon = Arc::clone(&daemon);
                            tokio::spawn(async move { let _ = daemon.serve_client(stream).await; });
                        }
                        Err(_) => break,
                    }
                }
            }
        }));
        let daemon = Arc::clone(self);
        let mut stop = self.shutdown.subscribe();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    incoming = daemon.transport.accept() => if let Ok(mut connection) = incoming {
                        let node = Arc::clone(&daemon.node);
                        tokio::spawn(async move {
                            let _ = node.lock().await.handle_connection(&mut connection, now_ms()).await;
                        });
                    }
                }
            }
        }));
        let daemon = Arc::clone(self);
        let mut stop = self.shutdown.subscribe();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => daemon.work_outbox().await,
                }
            }
        }));
        Ok(RunningDaemon {
            shutdown: self.shutdown.clone(),
            tasks,
        })
    }

    async fn work_outbox(&self) {
        let pending = self.node.lock().await.outbox.pending_ids(now_ms());
        for id in pending {
            let peer = match self.node.lock().await.outbox.get(&id) {
                Some(entry) => entry.peer_id,
                None => continue,
            };
            match self.transport.dial(peer).await {
                Ok(mut connection) => {
                    let _ = self
                        .node
                        .lock()
                        .await
                        .send_offer(&id, &mut connection, now_ms())
                        .await;
                }
                Err(error) => {
                    let _ = self.node.lock().await.outbox.fail_attempt(
                        &id,
                        error.to_string(),
                        now_ms(),
                    );
                }
            }
        }
    }

    async fn serve_client(&self, stream: UnixStream) -> Result<()> {
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        while let Some(line) = lines.next_line().await? {
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(request) => match self.handle(request).await {
                    Ok(value) => json!({"ok":true,"result":value}),
                    Err(error) => json!({"ok":false,"error":error.to_string()}),
                },
                Err(error) => json!({"ok":false,"error":format!("invalid request: {error}")}),
            };
            write
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            write.write_all(b"\n").await?;
        }
        Ok(())
    }

    /// Execute one control request. This is also the in-process test API.
    pub async fn handle(&self, request: Value) -> Result<Value> {
        let op = request
            .get("op")
            .and_then(Value::as_str)
            .ok_or("request lacks op")?;
        match op {
            "status" => {
                let node = self.node.lock().await;
                Ok(
                    json!({"running":true,"peer_id":node.peer_id(),"root":self.root,"peers":node.trust.peers().len(),"outbox_pending":node.outbox.entries().filter(|e| !e.state.terminal()).count()}),
                )
            }
            "pair-ticket" => {
                let mut node = self.node.lock().await;
                let ticket = PairTicket::mint(
                    string_or(&request, "name", "device"),
                    node.store.keys.x25519_public(),
                    None,
                    vec![],
                    now_ms(),
                    600_000,
                    &node.store.keys.identity,
                )?;
                node.trust.register_ticket(ticket.clone())?;
                Ok(json!({"ticket":ticket.encode()?}))
            }
            "pair-add" => self.pair_add(required_str(&request, "ticket")?).await,
            "pair-confirm" => {
                let peer: PeerId = required_str(&request, "id")?.parse()?;
                self.node.lock().await.approved_pair_requests.insert(peer);
                Ok(json!({"confirmed":peer,"instruction":"retry pair add with the same ticket"}))
            }
            "pending-pairs" => {
                let node = self.node.lock().await;
                Ok(serde_json::to_value(
                    node.pending_pair_requests.values().collect::<Vec<_>>(),
                )?)
            }
            "peers" => {
                let node = self.node.lock().await;
                Ok(serde_json::to_value(
                    node.trust.peers().values().collect::<Vec<_>>(),
                )?)
            }
            "capsule-create" => {
                self.capsule_create(Path::new(required_str(&request, "path")?))
                    .await
            }
            "snapshot" => self.snapshot(&request).await,
            "send" => self.send(&request).await,
            "inbox" => self.inbox().await,
            "accept" => self.accept(&request).await,
            "log" => self.log(&request).await,
            "enroll-mint" => self.enroll(&request).await,
            "outbox" => {
                let node = self.node.lock().await;
                Ok(serde_json::to_value(
                    node.outbox.entries().collect::<Vec<_>>(),
                )?)
            }
            "cancel" => {
                self.node
                    .lock()
                    .await
                    .outbox
                    .cancel(required_str(&request, "id")?, now_ms())?;
                Ok(json!({"cancelled":required_str(&request, "id")?}))
            }
            _ => Err(format!("unknown operation: {op}").into()),
        }
    }

    async fn pair_add(&self, encoded: &str) -> Result<Value> {
        let ticket = PairTicket::parse(encoded, now_ms())?;
        let mut connection = self.transport.dial(ticket.peer_id).await?;
        dial_handshake(&mut connection, self.peer_id().await, "abra".into()).await?;
        let (request, nonce) = {
            let node = self.node.lock().await;
            let nonce = rand::thread_rng().gen::<[u8; 16]>();
            let request = PairRequest::sign(
                ticket.ticket_id.clone(),
                "device".into(),
                node.store.keys.x25519_public(),
                None,
                nonce,
                &node.store.keys.identity,
            )?;
            (request, hex::encode(nonce))
        };
        let (send, recv) = connection.control_mut();
        write_frame(send, &request).await?;
        let accept: PairAccept = read_frame(recv).await?;
        let confirm = self
            .node
            .lock()
            .await
            .trust
            .complete_pair_as_joiner(&ticket, &accept, &nonce)?;
        let (send, _) = connection.control_mut();
        write_frame(send, &confirm).await?;
        Ok(json!({"peer_id":ticket.peer_id}))
    }

    async fn capsule_create(&self, path: &Path) -> Result<Value> {
        if !path.is_dir() {
            return Err("capsule path must be a directory".into());
        }
        let title = path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("workspace")
            .to_string();
        let mut node = self.node.lock().await;
        let id = random_capsule_id();
        let at = format_time(now_ms());
        let genesis = Genesis::new(
            id,
            at.clone(),
            "dev.abra.workspace".into(),
            title,
            &node.store.keys.identity,
        )?;
        let grant = LeaseRecord::new(
            id,
            node.peer_id(),
            1,
            LeaseMode::Grant,
            at,
            format_time(now_ms() + 86_400_000),
            genesis.hash()?,
            &node.store.keys.identity,
        )?;
        node.store.add_capsule(genesis, grant)?;
        fs::create_dir_all(path.join(".abra"))?;
        fs::write(path.join(".abra/capsule_id"), id.to_hex())?;
        Ok(json!({"capsule_id":id}))
    }

    async fn snapshot(&self, request: &Value) -> Result<Value> {
        let path = PathBuf::from(required_str(request, "path")?);
        let capsule = read_capsule_id(&path)?;
        let mut node = self.node.lock().await;
        let files = snapshot_dir(&node.store.cas, &path)?;
        let cap = node.store.capsules.get(&capsule).ok_or("unknown capsule")?;
        let parents = cap
            .label("main")
            .map(|x| vec![x.snapshot_id])
            .unwrap_or_default();
        let mut payload = Map::new();
        payload.insert("schema".into(), json!("dev.abra.workspace/1"));
        payload.insert(
            "name".into(),
            json!(path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("workspace")),
        );
        payload.insert("default_cwd".into(), json!("."));
        let mut manifest = base_manifest(
            &node,
            Scope::Full,
            "dev.abra.workspace",
            path.file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("workspace"),
        );
        manifest.capsule_id = Some(capsule);
        manifest.parents = Some(parents);
        manifest.files = Some(files);
        manifest.payload = payload;
        if let Some(label) = request.get("label").and_then(Value::as_str) {
            manifest.labels = Some(vec![abra_core::manifest::Label {
                name: "checkpoint".into(),
                value: Some(label.into()),
            }]);
        }
        manifest.sign(&node.store.keys.identity)?;
        let raw = RawManifest::parse(manifest.to_canonical_bytes()?)?;
        let result = node
            .store
            .receive_full(raw, format_time(now_ms()), now_ms(), None)?;
        let lease = node.store.capsules[&capsule]
            .winning_lease()
            .ok_or("capsule lacks lease")?;
        let seq = node.store.capsules[&capsule]
            .label("main")
            .map_or(1, |x| x.seq + 1);
        let op = LabelOp::new(
            capsule,
            seq,
            "main".into(),
            result.snapshot_id,
            lease.epoch,
            format_time(now_ms()),
            &node.store.keys.identity,
        )?;
        let caller = node.peer_id();
        node.store.apply_label(op, caller, now_ms())?;
        Ok(json!({"capsule_id":capsule,"snapshot_id":result.snapshot_id,"forked":result.forked}))
    }

    async fn send(&self, request: &Value) -> Result<Value> {
        let peer: PeerId = required_str(request, "peer")?.parse()?;
        let mut node = self.node.lock().await;
        let raw = if let Some(id) = request.get("snapshot_id").and_then(Value::as_str) {
            find_snapshot_or_capsule_head(&node, id)?
        } else if let Some(link) = request.get("link").and_then(Value::as_str) {
            let title = request.get("title").and_then(Value::as_str).unwrap_or(link);
            let mut manifest = base_manifest(&node, Scope::Partial, "dev.abra.handoff.v1", title);
            manifest.link = Some(link.into());
            manifest.payload.insert("url".into(), json!(link));
            if let Some(note) = request.get("note").and_then(Value::as_str) {
                manifest.payload.insert("note".into(), json!(note));
            }
            manifest.sign(&node.store.keys.identity)?;
            RawManifest::parse(manifest.to_canonical_bytes()?)?
        } else {
            let path = Path::new(required_str(request, "path")?);
            let files = capture_path(&node.store.cas, path)?;
            let mut manifest = base_manifest(
                &node,
                Scope::Partial,
                "dev.abra.bundle",
                path.file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or("handoff"),
            );
            manifest.files = Some(files);
            manifest.sign(&node.store.keys.identity)?;
            RawManifest::parse(manifest.to_canonical_bytes()?)?
        };
        let id = node.enqueue(peer, &raw, now_ms())?;
        Ok(json!({"outbox_id":id,"snapshot_id":raw.snapshot_id()}))
    }

    async fn inbox(&self) -> Result<Value> {
        let node = self.node.lock().await;
        let mut rows = Vec::new();
        for entry in node.store.inbox.values() {
            let raw = RawManifest::parse(entry.manifest.clone())?;
            let m = raw.manifest();
            rows.push(json!({"id":entry.snapshot_id,"from":entry.from,"received_at":entry.received_at,"read":entry.read,"kind":m.kind,"title":m.title,"origin":m.origin,"created_at":m.created_at,"link":m.link}));
        }
        Ok(Value::Array(rows))
    }

    async fn accept(&self, request: &Value) -> Result<Value> {
        let id: Hash = required_str(request, "id")?.parse()?;
        let destination = Path::new(required_str(request, "to")?);
        let mut node = self.node.lock().await;
        if let Some(entry) = node.store.inbox.get(&id).cloned() {
            let raw = RawManifest::parse(entry.manifest)?;
            if let Some(files) = raw.manifest().files {
                materialize(&node.store.cas, &files, destination)?;
            }
            node.store.mark_inbox_read(id)?;
        } else {
            let raw = find_snapshot(&node, &id.to_hex())?;
            if let Some(files) = raw.manifest().files {
                materialize(&node.store.cas, &files, destination)?;
            }
        }
        Ok(json!({"accepted":id,"to":destination}))
    }

    async fn log(&self, request: &Value) -> Result<Value> {
        let node = self.node.lock().await;
        let capsule = match request.get("capsule").and_then(Value::as_str) {
            Some(x) => x.parse()?,
            None if node.store.capsules.len() == 1 => *node.store.capsules.keys().next().unwrap(),
            None => {
                return Err("capsule is required when store has zero or multiple capsules".into())
            }
        };
        let cap = node.store.capsules.get(&capsule).ok_or("unknown capsule")?;
        let rows = cap.snapshots().iter().map(|(id, r)| json!({"snapshot_id":id,"received_at":r.received_at,"orphan":r.orphan,"title":r.raw.manifest().title,"parents":r.raw.manifest().parents})).collect::<Vec<_>>();
        Ok(Value::Array(rows))
    }

    async fn enroll(&self, request: &Value) -> Result<Value> {
        let node = self.node.lock().await;
        let scopes = Scopes {
            capsules: request
                .get("capsules")
                .and_then(Value::as_array)
                .map(|xs| {
                    xs.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|| vec!["*".into()]),
            kinds: request
                .get("kinds")
                .and_then(Value::as_array)
                .map(|xs| {
                    xs.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|| vec!["*".into()]),
            send: request
                .get("send")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            receive: request
                .get("receive")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            lease_acquire: false,
            lease_takeover: false,
        };
        let token = EnrollmentToken::mint(
            "agent".into(),
            vec![Intro {
                peer_id: node.peer_id(),
                name: "device".into(),
            }],
            None,
            scopes,
            now_ms(),
            request
                .get("ttl_ms")
                .and_then(Value::as_u64)
                .unwrap_or(86_400_000),
            &node.store.keys.identity,
        )?;
        Ok(json!({"token":token.encode()?}))
    }
}

fn base_manifest(node: &DeliveryNode, scope: Scope, kind: &str, title: &str) -> Manifest {
    Manifest {
        spec: abra_core::SPEC.into(),
        scope,
        kind: kind.into(),
        title: title.into(),
        origin: Origin {
            peer_id: node.peer_id(),
            name: Some("device".into()),
            adapter: None,
        },
        created_at: format_time(now_ms()),
        summary: None,
        link: None,
        thumbnail: None,
        capsule_id: None,
        parents: None,
        labels: None,
        provenance: None,
        files: None,
        recipes: None,
        native: None,
        payload: Map::new(),
        extensions: None,
        signature: Signature::from_bytes([0; 64]),
    }
}

fn find_snapshot(node: &DeliveryNode, id: &str) -> Result<RawManifest> {
    let hash: Hash = id.parse()?;
    node.store
        .capsules
        .values()
        .find_map(|c| c.snapshot(&hash))
        .map(|r| r.raw.clone())
        .ok_or_else(|| "snapshot not found".into())
}

fn find_snapshot_or_capsule_head(node: &DeliveryNode, id: &str) -> Result<RawManifest> {
    let hash: Hash = id.parse()?;
    if let Some(capsule) = node.store.capsules.get(&hash) {
        let head = capsule.label("main").ok_or("capsule has no main head")?;
        return capsule
            .snapshot(&head.snapshot_id)
            .map(|record| record.raw.clone())
            .ok_or_else(|| "capsule main snapshot not found".into());
    }
    find_snapshot(node, id)
}

fn read_capsule_id(path: &Path) -> Result<Hash> {
    Ok(fs::read_to_string(path.join(".abra/capsule_id"))?
        .trim()
        .parse()?)
}

fn capture_path(store: &abra_core::cas::BlobStore, path: &Path) -> Result<Hash> {
    if path.is_dir() {
        return Ok(snapshot_dir(store, path)?);
    }
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or("file name is not valid UTF-8")?
        .to_string();
    let (hash, size) = store.put_file(path)?;
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)?.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    let tree = Tree::new(vec![TreeEntry {
        mode: if executable {
            EntryMode::Exec
        } else {
            EntryMode::File
        },
        name,
        hash,
        size,
    }])?;
    Ok(store.put_tree(&tree)?)
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("request lacks {key}").into())
}

fn string_or(value: &Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

/// Send one NDJSON request to a daemon socket.
pub async fn control_call(root: impl AsRef<Path>, request: &Value) -> Result<Value> {
    let stream = UnixStream::connect(root.as_ref().join("cadabra.sock")).await?;
    let (read, mut write) = stream.into_split();
    write
        .write_all(serde_json::to_string(request)?.as_bytes())
        .await?;
    write.write_all(b"\n").await?;
    let mut lines = BufReader::new(read).lines();
    let response: Value =
        serde_json::from_str(&lines.next_line().await?.ok_or("daemon closed connection")?)?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    } else {
        Err(response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("daemon error")
            .to_string()
            .into())
    }
}
