//! Library-first Abra daemon and its newline-delimited JSON control API.
#![forbid(unsafe_code)]
pub mod adapters;

use abra_core::{
    capsule::{random_capsule_id, Genesis, LabelOp, LeaseMode, LeaseRecord},
    cas::{materialize, snapshot_dir, EntryMode, Hash, Tree, TreeEntry},
    identity::{PeerId, Signature},
    manifest::{Manifest, Origin, RawManifest, Scope},
    now_ms,
};
#[cfg(feature = "iroh")]
use abra_net::IrohTransport;
#[cfg(feature = "tcp")]
use abra_net::TcpTransport;
use abra_net::{
    dial_handshake, format_time, read_frame, write_frame, ControlAck, ControlMessage, ControlOp,
    DeliveryNode, EnrollBind, EnrollmentToken, Intro, LocalRole, LoopbackNetwork,
    LoopbackTransport, PairAccept, PairRequest, PairTicket, Role, Scopes, Transport, TrustedPeer,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{watch, Mutex, Semaphore},
    task::JoinHandle,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const MAX_CONTROL_LINE: u64 = 1024 * 1024;
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONTROL_CLIENTS: usize = 64;
const MAX_INBOUND_SESSIONS: usize = 32;
const MAX_WATCHERS: usize = 8;
const MAX_EVENT_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// A running daemon owns exactly one durable network/store node.
pub struct Daemon {
    root: PathBuf,
    node: Arc<Mutex<DeliveryNode>>,
    transport: Arc<dyn Transport>,
    shutdown: watch::Sender<bool>,
    yes: bool,
    watchers: Arc<Semaphore>,
}

pub struct RunningDaemon {
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    socket: PathBuf,
    _lock: File,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReceiveGrant {
    id: String,
    peer: PeerId,
    kind: String,
    auto_accept: bool,
    auto_run_recipes: bool,
    destination: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RecipeProcess {
    capsule: String,
    snapshot: Hash,
    pid: u32,
    argv: Vec<String>,
}

impl RunningDaemon {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
        let _ = fs::remove_file(&self.socket);
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
            yes,
            watchers: Arc::new(Semaphore::new(MAX_WATCHERS)),
        })
    }

    pub fn loopback(root: impl AsRef<Path>, network: &LoopbackNetwork, yes: bool) -> Result<Self> {
        let node = DeliveryNode::open(root.as_ref())?;
        let transport = Arc::new(LoopbackTransport::bind(network, node.peer_id()));
        drop(node);
        Self::new(root, transport, yes)
    }

    pub async fn tcp(root: impl AsRef<Path>, yes: bool) -> Result<Self> {
        let node = DeliveryNode::open(root.as_ref())?;
        let secret = node.store.keys.identity.secret_bytes();
        drop(node);
        let transport = Arc::new(TcpTransport::bind(secret).await?);
        Self::new(root, transport, yes)
    }

    #[cfg(feature = "iroh")]
    pub async fn iroh(root: impl AsRef<Path>, yes: bool) -> Result<Self> {
        let node = DeliveryNode::open(root.as_ref())?;
        let secret = node.store.keys.identity.secret_bytes();
        drop(node);
        let transport = Arc::new(IrohTransport::bind(secret).await?);
        Self::new(root, transport, yes)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn peer_id(&self) -> PeerId {
        self.node.lock().await.peer_id()
    }

    fn fresh_node(&self) -> Result<DeliveryNode> {
        DeliveryNode::open(&self.root).map_err(Into::into)
    }

    pub async fn join(&self, encoded: &str) -> Result<Value> {
        let token = EnrollmentToken::parse(encoded, now_ms())?;
        let intro = token
            .intro
            .iter()
            .find(|intro| intro.peer_id == token.issuer)
            .or_else(|| token.intro.first())
            .ok_or("enrollment token has no intro peer")?;
        for address in &intro.addresses {
            self.transport.add_peer_address(intro.peer_id, address)?;
        }
        let mut connection = self.transport.dial(intro.peer_id).await?;
        dial_handshake(&mut connection, self.peer_id().await, "abra".into()).await?;
        let bind = {
            let node = self.node.lock().await;
            EnrollBind::sign(
                token.clone(),
                Some("guest".into()),
                node.store.keys.x25519_public(),
                node.store.keys.relay_discovery_key,
                &node.store.keys.identity,
            )?
        };
        let (send, recv) = connection.control_mut();
        write_frame(send, &bind).await?;
        let ok: abra_net::EnrollOk = read_frame(recv).await?;
        if ok.message_type != "enroll-ok"
            || ok.certificate.guest_peer_id != self.peer_id().await
            || intro.peer_id != token.issuer
        {
            return Err("invalid enrollment response".into());
        }
        ok.certificate.verify(token.issuer)?;
        let mut node = self.node.lock().await;
        node.trust.insert(TrustedPeer {
            peer_id: intro.peer_id,
            name: intro.name.clone(),
            role: Role::Full,
            x25519_pk: intro.x25519_pk,
            token_id: None,
            scopes: None,
            expires_at: None,
        })?;
        for peer in ok.mesh {
            if peer.peer_id != node.peer_id() {
                node.trust.insert(TrustedPeer {
                    peer_id: peer.peer_id,
                    name: peer.name,
                    role: peer.role,
                    x25519_pk: peer.x25519_pk,
                    token_id: peer.token_id,
                    scopes: peer.scopes,
                    expires_at: peer.expires_at,
                })?;
            }
        }
        node.trust.set_mesh_profile(ok.mesh_profile)?;
        node.trust.set_local_role(LocalRole::Guest {
            token: Box::new(token.clone()),
        })?;
        node.allow_agent_send = token.scopes.send;
        Ok(
            json!({"joined":true,"issuer":token.issuer,"token_id":token.token_id,"scopes":token.scopes}),
        )
    }

    pub async fn start(self: &Arc<Self>) -> Result<RunningDaemon> {
        let socket = self.root.join("cadabra.sock");
        if socket.exists()
            && tokio::time::timeout(
                Duration::from_millis(500),
                control_call(&self.root, &json!({"op":"status"})),
            )
            .await
            .is_ok_and(|result| result.is_ok())
        {
            return Err(format!("daemon already running at {}", self.root.display()).into());
        }
        let lock_path = self.root.join("cadabra.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| format!("daemon already running at {}", self.root.display()))?;
        match fs::remove_file(&socket) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        #[cfg(unix)]
        let old_umask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
        let listener_result = UnixListener::bind(&socket);
        #[cfg(unix)]
        rustix::process::umask(old_umask);
        let listener = listener_result?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        }
        let mut tasks = Vec::new();
        let daemon = Arc::clone(self);
        let clients = Arc::new(Semaphore::new(MAX_CONTROL_CLIENTS));
        let mut stop = self.shutdown.subscribe();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            let daemon = Arc::clone(&daemon);
                            let clients = Arc::clone(&clients);
                            tokio::spawn(async move {
                                if let Ok(_permit) = clients.acquire_owned().await {
                                    if let Err(error) = daemon.serve_client(stream).await {
                                        eprintln!("cadabra: control client error: {error}");
                                    }
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("cadabra: control accept error: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }));
        let daemon = Arc::clone(self);
        let sessions = Arc::new(Semaphore::new(MAX_INBOUND_SESSIONS));
        let mut stop = self.shutdown.subscribe();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        if let Err(error) = daemon.renew_leases().await {
                            eprintln!("cadabra: lease renewal error: {error}");
                        }
                    }
                }
            }
        }));
        // Multiple accept workers ensure transport wrapping/authentication never
        // serializes the listener. Each handshake already has a transport-level
        // timeout, and the session semaphore bounds total work.
        for _ in 0..4 {
            let daemon = Arc::clone(self);
            let sessions = Arc::clone(&sessions);
            let mut stop = self.shutdown.subscribe();
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop.changed() => break,
                        incoming = daemon.transport.accept() => if let Ok(mut connection) = incoming {
                            let Ok(_permit) = sessions.clone().acquire_owned().await else { break; };
                            match DeliveryNode::open(&daemon.root) {
                                Ok(mut node) => {
                                    node.auto_confirm_pairs = daemon.yes;
                                    if let Err(error) = node.handle_connection(&mut connection, now_ms()).await {
                                        eprintln!("cadabra: incoming session error: {error}");
                                    } else if let Err(error) = daemon.apply_receive_grants().await {
                                        eprintln!("cadabra: receive policy error: {error}");
                                    }
                                }
                                Err(error) => eprintln!("cadabra: session store error: {error}"),
                            }
                        }
                    }
                }
            }));
        }
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
            socket,
            _lock: lock,
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
                    let mut session = self.node.lock().await.outgoing_session();
                    let result = session.send_offer(&id, &mut connection, now_ms()).await;
                    if let Err(error) = &result {
                        eprintln!("cadabra: outgoing session error: {error}");
                    }
                    if let Err(error) = self
                        .node
                        .lock()
                        .await
                        .outbox
                        .sync_entry_from(&session.outbox, &id)
                    {
                        eprintln!("cadabra: outbox session merge error: {error}");
                    }
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
        #[cfg(unix)]
        {
            let peer = stream.peer_cred()?;
            if peer.uid() != rustix::process::geteuid().as_raw() {
                return Err("control client uid differs from daemon uid".into());
            }
        }
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        loop {
            let mut bytes = Vec::new();
            let read = tokio::time::timeout(
                CONTROL_IDLE_TIMEOUT,
                (&mut reader)
                    .take(MAX_CONTROL_LINE + 1)
                    .read_until(b'\n', &mut bytes),
            )
            .await
            .map_err(|_| "control client idle timeout")??;
            if read == 0 {
                break;
            }
            if bytes.len() as u64 <= MAX_CONTROL_LINE && bytes.ends_with(b"\n") {
                if let Ok(request) = serde_json::from_slice::<Value>(&bytes[..bytes.len() - 1]) {
                    if request.get("op").and_then(Value::as_str) == Some("watch") {
                        let _watcher = self
                            .watchers
                            .clone()
                            .try_acquire_owned()
                            .map_err(|_| "too many concurrent watchers")?;
                        write
                            .write_all(b"{\"ok\":true,\"result\":{\"watching\":true}}\n")
                            .await?;
                        self.serve_watch(&mut write).await?;
                        return Ok(());
                    }
                }
            }
            let response = if bytes.len() as u64 > MAX_CONTROL_LINE || !bytes.ends_with(b"\n") {
                json!({"ok":false,"error":"request too large"})
            } else if let Ok(line) = std::str::from_utf8(&bytes[..bytes.len() - 1]) {
                match serde_json::from_str::<Value>(line) {
                    Ok(request) => match self.handle(request).await {
                        Ok(value) => json!({"ok":true,"result":value}),
                        Err(error) => json!({"ok":false,"error":error.to_string()}),
                    },
                    Err(error) => json!({"ok":false,"error":format!("invalid request: {error}")}),
                }
            } else {
                json!({"ok":false,"error":"invalid request: request is not UTF-8"})
            };
            write
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            write.write_all(b"\n").await?;
            if bytes.len() as u64 > MAX_CONTROL_LINE || !bytes.ends_with(b"\n") {
                break;
            }
        }
        Ok(())
    }

    async fn serve_watch(&self, write: &mut tokio::net::unix::OwnedWriteHalf) -> Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let path = self.root.join("net/events.ndjson");
        let mut sent = 0u64;
        let mut shutdown = self.shutdown.subscribe();
        loop {
            let mut bytes = Vec::new();
            if let Ok(mut file) = File::open(&path) {
                let len = file.metadata()?.len();
                if len < sent {
                    sent = len;
                }
                file.seek(SeekFrom::Start(sent))?;
                file.read_to_end(&mut bytes)?;
            }
            if !bytes.is_empty() {
                let complete = bytes
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .map_or(0, |index| index + 1);
                if complete > 0 {
                    write.write_all(&bytes[..complete]).await?;
                    sent += complete as u64;
                }
            }
            if fs::metadata(&path).is_ok_and(|metadata| metadata.len() < sent) {
                sent = 0;
            }
            tokio::select! {
                _ = shutdown.changed() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    }

    /// Execute one control request. This is also the in-process test API.
    pub async fn handle(&self, request: Value) -> Result<Value> {
        self.node.lock().await.trust.reload()?;
        let op = request
            .get("op")
            .and_then(Value::as_str)
            .ok_or("request lacks op")?;
        if matches!(
            op,
            "pair-ticket"
                | "pair-add"
                | "pair-confirm"
                | "enroll-mint"
                | "revoke"
                | "policy-grant"
                | "policy-revoke"
                | "control"
                | "lease-take"
                | "mesh-profile"
        ) && !matches!(self.node.lock().await.trust.local_role(), LocalRole::Full)
        {
            return Err("operation requires a full device; this daemon is a guest".into());
        }
        match op {
            "status" => {
                let node = self.fresh_node()?;
                let outbox_errors = node
                    .outbox
                    .entries()
                    .filter_map(|entry| {
                        entry
                            .last_error
                            .as_ref()
                            .map(|error| json!({"id":entry.id,"error":error}))
                    })
                    .collect::<Vec<_>>();
                let grant_errors = load_grant_errors(&self.root)?;
                Ok(
                    json!({"running":true,"peer_id":node.peer_id(),"root":self.root,"peers":node.trust.peers().len(),"outbox_pending":node.outbox.entries().filter(|e| !e.state.terminal()).count(),"outbox_errors":outbox_errors,"grant_errors":grant_errors}),
                )
            }
            "pair-ticket" => {
                let mut node = self.node.lock().await;
                let ticket = PairTicket::mint(
                    string_or(&request, "name", "device"),
                    node.store.keys.x25519_public(),
                    Some(node.store.keys.relay_discovery_key),
                    self.transport.local_addresses(),
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
                self.node.lock().await.approve_pair(peer)?;
                Ok(json!({"confirmed":peer}))
            }
            "pending-pairs" => {
                let node = self.node.lock().await;
                Ok(serde_json::to_value(node.durable_pending_pairs()?)?)
            }
            "peers" => {
                let node = self.fresh_node()?;
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
            "adapters-list" => {
                let registry = adapters::AdapterRegistry::discover(&self.root)?;
                Ok(serde_json::to_value(registry.list())?)
            }
            "adapters-add" => {
                adapters::AdapterRegistry::add(
                    &self.root,
                    Path::new(required_str(&request, "dir")?),
                )?;
                Ok(json!({"added":required_str(&request, "dir")?}))
            }
            "adapters-remove" => {
                adapters::AdapterRegistry::remove(&self.root, required_str(&request, "name")?)?;
                Ok(json!({"removed":required_str(&request, "name")?}))
            }
            "inbox" => self.inbox().await,
            "accept" => self.accept(&request).await,
            "log" => self.log(&request).await,
            "capsules" => self.capsules().await,
            "mesh-profile" => {
                let mut node = self.node.lock().await;
                if let Some(profile) = request.get("profile").and_then(Value::as_str) {
                    let profile = match profile {
                        "personal" => abra_net::MeshProfile::Personal,
                        "fleet" => abra_net::MeshProfile::Fleet,
                        _ => return Err("mesh profile must be personal or fleet".into()),
                    };
                    node.trust.set_mesh_profile(profile)?;
                }
                Ok(json!({"profile":node.trust.mesh_profile()}))
            }
            "enroll-mint" => self.enroll(&request).await,
            "enroll-join" => self.join(required_str(&request, "token")?).await,
            "revoke" => {
                let token_id = required_str(&request, "token_id")?;
                self.node.lock().await.trust.revoke_token(token_id)?;
                Ok(json!({"revoked":token_id}))
            }
            "policy-grant" => self.policy_grant(&request).await,
            "policy-list" => Ok(serde_json::to_value(self.load_grants()?)?),
            "policy-revoke" => {
                let id = required_str(&request, "id")?;
                let mut grants = self.load_grants()?;
                if grants.remove(id).is_none() {
                    return Err("unknown policy grant".into());
                }
                self.save_grants(&grants)?;
                Ok(json!({"revoked":id}))
            }
            "ps" => Ok(serde_json::to_value(self.load_processes()?)?),
            "stop-recipes" => self.stop_recipes(required_str(&request, "capsule")?),
            "events" => self.events(),
            "control" => self.send_control(&request).await,
            "lease-status" => self.lease_status(&request).await,
            "lease-take" => self.lease_take(&request).await,
            "outbox" => {
                let node = self.fresh_node()?;
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
        for address in &ticket.addresses {
            self.transport.add_peer_address(ticket.peer_id, address)?;
        }
        let mut connection = self.transport.dial(ticket.peer_id).await?;
        dial_handshake(&mut connection, self.peer_id().await, "abra".into()).await?;
        let (request, nonce) = {
            let node = self.node.lock().await;
            let nonce = rand::thread_rng().gen::<[u8; 16]>();
            let request = PairRequest::sign(
                ticket.ticket_id.clone(),
                "device".into(),
                node.store.keys.x25519_public(),
                Some(node.store.keys.relay_discovery_key),
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
        if !path.is_absolute() {
            return Err("capsule path must be absolute".into());
        }
        fs::create_dir_all(path)?;
        if !path.is_dir() {
            return Err("capsule path must be a directory".into());
        }
        let title = path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("workspace")
            .to_string();
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
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
        if !path.is_absolute() {
            return Err("snapshot path must be absolute".into());
        }
        let capsule = read_capsule_id(&path)?;
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
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
        let adapter_export = if let Some(kind) = request.get("kind").and_then(Value::as_str) {
            Some((
                kind.to_owned(),
                adapters::AdapterRegistry::discover(&self.root)?
                    .export(kind, required_str(request, "source")?, &self.root, None)
                    .await?,
            ))
        } else {
            None
        };
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
        let raw = if let Some((kind, export)) = adapter_export {
            let floor = export.floor;
            let title = floor
                .as_ref()
                .and_then(|value| value.title.clone())
                .unwrap_or_else(|| kind.clone());
            let mut manifest = base_manifest(&node, Scope::Partial, &kind, &title);
            manifest.payload = export
                .payload
                .as_object()
                .cloned()
                .ok_or("adapter payload must be an object")?;
            manifest.summary = floor.as_ref().and_then(|value| value.summary.clone());
            manifest.link = floor.and_then(|value| value.link);
            if let Some(path) = export.files_path {
                manifest.files = Some(snapshot_dir(&node.store.cas, &path)?);
            }
            manifest.origin.adapter = Some(kind.clone());
            manifest.sign(&node.store.keys.identity)?;
            RawManifest::parse(manifest.to_canonical_bytes()?)?
        } else if let Some(id) = request.get("snapshot_id").and_then(Value::as_str) {
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
        let node = self.fresh_node()?;
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
        validate_destination(destination)?;
        let mut node = self.fresh_node()?;
        if let Some(entry) = node.store.inbox.get(&id).cloned() {
            let raw = RawManifest::parse(entry.manifest)?;
            if let Some(files) = raw.manifest().files {
                materialize(&node.store.cas, &files, destination)?;
            }
            materialize_recipes(destination, raw.manifest().recipes.as_ref())?;
            let registry = adapters::AdapterRegistry::discover(&self.root)?;
            if registry
                .for_kind(&raw.manifest().kind)
                .is_some_and(|adapter| adapter.manifest.verbs.iter().any(|verb| verb == "import"))
            {
                registry
                    .import(
                        &raw.manifest().kind,
                        Value::Object(raw.manifest().payload.clone()),
                        raw.manifest().files.map(|_| destination),
                        destination,
                        None,
                    )
                    .await?;
            }
            node.store.mark_inbox_read(id)?;
        } else {
            let raw = find_snapshot(&node, &id.to_hex())?;
            if let Some(capsule_id) = raw.manifest().capsule_id {
                let identity_path = destination.join(".abra/capsule_id");
                if identity_path.exists() && read_capsule_id(destination)? != capsule_id {
                    return Err("destination belongs to a different capsule".into());
                }
            }
            if let Some(files) = raw.manifest().files {
                materialize(&node.store.cas, &files, destination)?;
            }
            materialize_recipes(destination, raw.manifest().recipes.as_ref())?;
            if let Some(capsule_id) = raw.manifest().capsule_id {
                let metadata = destination.join(".abra");
                fs::create_dir_all(&metadata)?;
                fs::write(metadata.join("capsule_id"), capsule_id.to_hex())?;
            }
        }
        Ok(json!({"accepted":id,"to":destination}))
    }

    async fn log(&self, request: &Value) -> Result<Value> {
        let node = self.fresh_node()?;
        let capsule = match request.get("capsule").and_then(Value::as_str) {
            Some(x) => x.parse()?,
            None if node.store.capsules.len() == 1 => *node.store.capsules.keys().next().unwrap(),
            None if node.store.capsules.is_empty() => return Ok(Value::Array(Vec::new())),
            None => return Err("capsule is required when store has multiple capsules".into()),
        };
        let cap = node.store.capsules.get(&capsule).ok_or("unknown capsule")?;
        let mut pending = cap.snapshots().iter().collect::<BTreeMap<_, _>>();
        let mut ordered = Vec::with_capacity(pending.len());
        while !pending.is_empty() {
            let ready = pending
                .iter()
                .filter(|(_, record)| {
                    record
                        .raw
                        .manifest()
                        .parents
                        .as_ref()
                        .is_none_or(|parents| {
                            parents.iter().all(|parent| !pending.contains_key(parent))
                        })
                })
                .map(|(id, _)| **id)
                .collect::<Vec<_>>();
            if ready.is_empty() {
                return Err("capsule history contains a cycle".into());
            }
            for id in ready {
                let record = pending.remove(&id).expect("ready snapshot is pending");
                ordered.push((id, record));
            }
        }
        let rows = ordered.into_iter().map(|(id, r)| json!({"snapshot_id":id,"received_at":r.received_at,"orphan":r.orphan,"title":r.raw.manifest().title,"parents":r.raw.manifest().parents})).collect::<Vec<_>>();
        Ok(Value::Array(rows))
    }

    async fn capsules(&self) -> Result<Value> {
        let node = self.fresh_node()?;
        Ok(Value::Array(node.store.capsules.iter().map(|(id, capsule)| {
            let heads = capsule.labels().values().filter(|label| label.name == "main" || label.name.starts_with("fork/")).map(|label| label.snapshot_id).collect::<Vec<_>>();
            json!({"capsule_id":id,"kind":capsule.genesis.kind,"title":capsule.genesis.title,"heads":heads})
        }).collect()))
    }

    async fn enroll(&self, request: &Value) -> Result<Value> {
        let node = self.node.lock().await;
        let required_scope = |key: &str| -> Result<Vec<String>> {
            let values = request
                .get(key)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("request lacks {key}"))?;
            let values = values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("{key} must contain strings"))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if values.is_empty() {
                return Err(format!("{key} must not be empty").into());
            }
            Ok(values)
        };
        let scopes = Scopes {
            capsules: required_scope("capsules")?,
            kinds: required_scope("kinds")?,
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
                x25519_pk: node.store.keys.x25519_public(),
                relay_discovery_key: node.store.keys.relay_discovery_key,
                addresses: self.transport.local_addresses(),
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

    fn grants_path(&self) -> PathBuf {
        self.root.join("policy/grants.json")
    }
    fn processes_path(&self) -> PathBuf {
        self.root.join("policy/processes.json")
    }
    fn load_grants(&self) -> Result<BTreeMap<String, ReceiveGrant>> {
        match fs::read(self.grants_path()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(error.into()),
        }
    }
    fn save_grants(&self, grants: &BTreeMap<String, ReceiveGrant>) -> Result<()> {
        let path = self.grants_path();
        fs::create_dir_all(path.parent().expect("policy parent"))?;
        fs::write(path, serde_json::to_vec(grants)?)?;
        Ok(())
    }
    async fn policy_grant(&self, request: &Value) -> Result<Value> {
        let peer: PeerId = required_str(request, "peer")?.parse()?;
        let kind = required_str(request, "kind")?.to_owned();
        let auto_accept = request
            .get("auto_accept")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let auto_run_recipes = request
            .get("auto_run_recipes")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if auto_run_recipes && !auto_accept {
            return Err("auto-run-recipes requires auto-accept".into());
        }
        if auto_run_recipes {
            return Err("auto-run-recipes is unimplemented: Abra carries recipes as data and never executes peer-supplied code".into());
        }
        let destination = request.get("to").and_then(Value::as_str).map(PathBuf::from);
        if auto_accept {
            validate_destination(destination.as_deref().ok_or("auto-accept requires --to")?)?;
        }
        let id = format!("{}:{}", peer, kind);
        let grant = ReceiveGrant {
            id: id.clone(),
            peer,
            kind,
            auto_accept,
            auto_run_recipes,
            destination,
        };
        let mut grants = self.load_grants()?;
        grants.insert(id.clone(), grant.clone());
        self.save_grants(&grants)?;
        Ok(serde_json::to_value(grant)?)
    }
    async fn apply_receive_grants(&self) -> Result<()> {
        let grants = self.load_grants()?;
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
        if grants.is_empty() {
            return Ok(());
        }
        let unread = node
            .store
            .inbox
            .values()
            .filter(|entry| !entry.read)
            .cloned()
            .collect::<Vec<_>>();
        for entry in unread {
            let raw = RawManifest::parse(entry.manifest.clone())?;
            let from: PeerId = entry.from.parse()?;
            let Some(grant) = grants
                .values()
                .find(|g| g.peer == from && g.kind == raw.manifest().kind)
            else {
                continue;
            };
            if !grant.auto_accept {
                continue;
            }
            let destination_root = grant
                .destination
                .as_deref()
                .ok_or("grant lacks destination")?;
            validate_destination(destination_root)?;
            let destination = destination_root.join(entry.snapshot_id.to_hex());
            validate_destination(&destination)?;
            if let Some(files) = raw.manifest().files {
                if let Err(error) = materialize(&node.store.cas, &files, &destination) {
                    record_grant_error(&self.root, entry.snapshot_id, &error.to_string())?;
                    continue;
                }
            }
            node.store.mark_inbox_read(entry.snapshot_id)?;
        }
        Ok(())
    }
    fn load_processes(&self) -> Result<Vec<RecipeProcess>> {
        match fs::read(self.processes_path()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }
    fn stop_recipes(&self, capsule: &str) -> Result<Value> {
        Err(format!(
            "recipe execution is disabled; no Abra-managed recipes exist for capsule {capsule}"
        )
        .into())
    }
    fn events(&self) -> Result<Value> {
        let path = self.root.join("net/events.ndjson");
        let text = fs::read_to_string(path).unwrap_or_default();
        Ok(Value::Array(
            text.lines()
                .map(serde_json::from_str)
                .collect::<std::result::Result<Vec<_>, _>>()?,
        ))
    }
    async fn lease_status(&self, request: &Value) -> Result<Value> {
        let capsule: Hash = required_str(request, "capsule")?.parse()?;
        let node = self.fresh_node()?;
        let cap = node.store.capsules.get(&capsule).ok_or("unknown capsule")?;
        Ok(
            json!({"capsule":capsule,"winning":cap.winning_lease(),"active":cap.active_lease(now_ms()).is_some()}),
        )
    }
    async fn lease_take(&self, request: &Value) -> Result<Value> {
        let capsule: Hash = required_str(request, "capsule")?.parse()?;
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
        let previous = node
            .store
            .capsules
            .get(&capsule)
            .ok_or("unknown capsule")?
            .winning_lease()
            .cloned()
            .ok_or("capsule lacks lease")?;
        let local = node.peer_id();
        if !matches!(node.trust.local_role(), LocalRole::Full) {
            node.trust.authorize_lease(local, true, now_ms())?;
        }
        let now = now_ms();
        let record = LeaseRecord::new(
            capsule,
            local,
            previous.epoch + 1,
            LeaseMode::Takeover,
            format_time(now),
            format_time(now + 86_400_000),
            previous.hash()?,
            &node.store.keys.identity,
        )?;
        node.store
            .accept_lease(capsule, record.clone(), &|peer, _| peer == local)?;
        record_event_file(
            &self.root,
            &json!({"event":"lease-change","capsule":capsule,"lease":record}),
        )?;
        Ok(serde_json::to_value(record)?)
    }
    async fn renew_leases(&self) -> Result<()> {
        let mut node = DeliveryNode::open(&self.root)?;
        let local = node.peer_id();
        let now = now_ms();
        let candidates = node
            .store
            .capsules
            .iter()
            .filter_map(|(id, cap)| {
                let lease = cap.winning_lease()?;
                let expires = abra_net::parse_time(&lease.expires_at).ok()?;
                (lease.holder == local && expires <= now + 300_000).then_some((*id, lease.clone()))
            })
            .collect::<Vec<_>>();
        for (capsule, previous) in candidates {
            let record = LeaseRecord::new(
                capsule,
                local,
                previous.epoch + 1,
                LeaseMode::Refresh,
                format_time(now),
                format_time(now + 86_400_000),
                previous.hash()?,
                &node.store.keys.identity,
            )?;
            node.store
                .accept_lease(capsule, record.clone(), &|peer, _| peer == local)?;
            record_event_file(
                &self.root,
                &json!({"event":"lease-change","capsule":capsule,"lease":record}),
            )?;
        }
        Ok(())
    }
    async fn send_control(&self, request: &Value) -> Result<Value> {
        let peer: PeerId = required_str(request, "peer")?.parse()?;
        let capsule: Hash = required_str(request, "capsule")?.parse()?;
        let op = match required_str(request, "control_op")? {
            "pause" => ControlOp::Pause,
            "stop" => ControlOp::Stop,
            "instruct" => ControlOp::Instruct,
            _ => return Err("control op must be pause, stop, or instruct".into()),
        };
        let text = request
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let message = {
            let node = self.fresh_node()?;
            if !node.store.capsules.contains_key(&capsule) {
                return Err("unknown capsule".into());
            }
            ControlMessage::new(
                capsule,
                op,
                text,
                now_ms(),
                rand::thread_rng().gen(),
                &node.store.keys.identity,
            )?
        };
        let mut connection = self.transport.dial(peer).await?;
        dial_handshake(&mut connection, self.peer_id().await, "abra".into()).await?;
        let (send, recv) = connection.control_mut();
        write_frame(send, &message).await?;
        let ack: ControlAck = read_frame(recv).await?;
        if !ack.ok {
            return Err(ack
                .error
                .unwrap_or_else(|| "control rejected".into())
                .into());
        }
        Ok(serde_json::to_value(ack)?)
    }
}

fn validate_destination(destination: &Path) -> Result<()> {
    if !destination.is_absolute() {
        return Err("destination must be absolute".into());
    }
    if fs::symlink_metadata(destination).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("destination is a symlink".into());
    }
    Ok(())
}

fn materialize_recipes(
    destination: &Path,
    recipes: Option<&Vec<abra_core::manifest::Recipe>>,
) -> Result<()> {
    let Some(recipes) = recipes else {
        return Ok(());
    };
    let metadata = destination.join(".abra");
    fs::create_dir_all(&metadata)?;
    fs::write(metadata.join("recipes.json"), serde_json::to_vec(recipes)?)?;
    Ok(())
}

fn grant_errors_path(root: &Path) -> PathBuf {
    root.join("policy/grant-errors.json")
}

fn load_grant_errors(root: &Path) -> Result<BTreeMap<String, String>> {
    match fs::read(grant_errors_path(root)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error.into()),
    }
}

fn record_grant_error(root: &Path, snapshot: Hash, error: &str) -> Result<()> {
    let mut errors = load_grant_errors(root)?;
    errors.insert(snapshot.to_hex(), error.to_owned());
    let path = grant_errors_path(root);
    fs::create_dir_all(path.parent().expect("policy parent"))?;
    fs::write(path, serde_json::to_vec(&errors)?)?;
    Ok(())
}

fn record_event_file(root: &Path, value: &Value) -> Result<()> {
    use std::io::Write;
    let path = root.join("net/events.ndjson");
    fs::create_dir_all(path.parent().expect("event parent"))?;
    if fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= MAX_EVENT_LOG_BYTES) {
        fs::write(&path, [])?;
    }
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&bytes)?;
    Ok(())
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
