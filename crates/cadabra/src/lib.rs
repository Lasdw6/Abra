//! Library-first Abra daemon and its newline-delimited JSON control API.
#![forbid(unsafe_code)]
pub mod adapters;
pub mod relay;

use abra_core::{
    capsule::{random_capsule_id, Genesis, LabelOp, LeaseMode, LeaseRecord},
    cas::{materialize, snapshot_dir, EntryMode, Hash, Tree, TreeEntry},
    identity::{PeerId, Signature},
    manifest::{Fingerprint, Manifest, NativeBlobRef, Origin, RawManifest, Recipe, Scope},
    now_ms,
};
#[cfg(feature = "tcp")]
use abra_net::TcpTransport;
use abra_net::{
    dial_handshake, dial_handshake_with_trust, format_time, read_frame, write_frame, ControlAck,
    ControlMessage, ControlOp, DeliveryNode, EnrollBind, EnrollmentToken, Intro, LocalRole,
    LoopbackNetwork, LoopbackTransport, PairAccept, PairRequest, PairTicket, Role, Scopes,
    Transport, TrustedPeer,
};
#[cfg(feature = "iroh")]
use abra_net::{IrohRelayMode, IrohTransport};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub iroh_relay: String,
    pub skip_native: bool,
    pub offer_budget: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            iroh_relay: "n0".into(),
            skip_native: false,
            offer_budget: abra_net::DEFAULT_OFFER_BUDGET,
        }
    }
}

impl DaemonConfig {
    fn path(root: &Path) -> PathBuf {
        root.join("config/daemon.json")
    }

    pub fn load(root: &Path) -> Result<Self> {
        match fs::read(Self::path(root)) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let path = Self::path(root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}
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
    #[serde(default)]
    capsule: Option<Hash>,
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
        let config = DaemonConfig::load(&root)?;
        node.skip_native = config.skip_native;
        node.offer_budget = config.offer_budget;
        if transport.local_peer_id() != node.peer_id() {
            return Err("transport identity differs from store identity".into());
        }
        node.auto_confirm_pairs = yes;
        for peer in node.trust.peers().values() {
            for address in &peer.addresses {
                if let Err(error) = transport.add_peer_address(peer.peer_id, address) {
                    eprintln!(
                        "cadabra: ignoring invalid stored address for {}: {address}: {error}",
                        peer.peer_id
                    );
                }
            }
        }
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
        let root = root.as_ref();
        let node = DeliveryNode::open(root)?;
        let secret = node.store.keys.identity.secret_bytes();
        drop(node);
        let port_path = root.join("net/tcp-port");
        let port = read_port(&port_path)?;
        let transport = match TcpTransport::bind_port(secret, port).await {
            Err(abra_net::Error::Io(error))
                if port != 0 && error.kind() == std::io::ErrorKind::AddrInUse =>
            {
                TcpTransport::bind_port(secret, 0).await?
            }
            result => result?,
        };
        persist_port(&port_path, transport.bound_port())?;
        let transport = Arc::new(transport);
        Self::new(root, transport, yes)
    }

    #[cfg(feature = "iroh")]
    pub async fn iroh(root: impl AsRef<Path>, yes: bool) -> Result<Self> {
        let config = DaemonConfig::load(root.as_ref())?;
        let relay = config.iroh_relay.parse::<IrohRelayMode>()?;
        Self::iroh_configured(root, yes, relay).await
    }

    #[cfg(feature = "iroh")]
    pub async fn iroh_with_relay(
        root: impl AsRef<Path>,
        yes: bool,
        relay: IrohRelayMode,
    ) -> Result<Self> {
        let root = root.as_ref();
        DaemonConfig {
            iroh_relay: relay.to_string(),
            ..DaemonConfig::load(root)?
        }
        .save(root)?;
        Self::iroh_configured(root, yes, relay).await
    }

    #[cfg(feature = "iroh")]
    async fn iroh_configured(
        root: impl AsRef<Path>,
        yes: bool,
        relay: IrohRelayMode,
    ) -> Result<Self> {
        let root = root.as_ref();
        let node = DeliveryNode::open(root)?;
        let secret = node.store.keys.identity.secret_bytes();
        drop(node);
        let port_path = root.join("net/iroh-port");
        let port = read_port(&port_path)?;
        let mut transport =
            match IrohTransport::bind_port_with_relay(secret, port, relay.clone()).await {
                Err(error) if port != 0 && is_addr_in_use(&error) => {
                    IrohTransport::bind_port_with_relay(secret, 0, relay.clone()).await?
                }
                result => result?,
            };
        if transport.bound_port().is_none() {
            eprintln!(
                "cadabra: WARNING: iroh did not report a bound port; retrying with an ephemeral port"
            );
            transport = IrohTransport::bind_port_with_relay(secret, 0, relay).await?;
        }
        let bound_port = transport.bound_port().unwrap_or_else(|| {
            eprintln!(
                "cadabra: WARNING: iroh still did not report a bound port; the next start will choose a new port"
            );
            0
        });
        persist_port(&port_path, bound_port)?;
        if port != 0 && transport.bound_port() != Some(port) {
            eprintln!(
                "cadabra: WARNING: iroh port {port} was busy; rebound to {}. Stored peer hints may be stale",
                transport.bound_port().unwrap_or_default()
            );
        }
        let transport = Arc::new(transport);
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
        let local_addresses = self.transport.wait_local_addresses().await?;
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
                local_addresses,
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
            relay_key: Some(intro.relay_discovery_key),
            token_id: None,
            scopes: None,
            expires_at: None,
            addresses: intro.addresses.clone(),
        })?;
        for peer in ok.mesh {
            if peer.peer_id != node.peer_id() {
                node.trust.insert(TrustedPeer {
                    peer_id: peer.peer_id,
                    name: peer.name,
                    role: peer.role,
                    x25519_pk: peer.x25519_pk,
                    relay_key: None,
                    token_id: peer.token_id,
                    scopes: peer.scopes,
                    expires_at: peer.expires_at,
                    addresses: Vec::new(),
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
        DeliveryNode::sweep_abandoned_partials(&self.root)?;
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
        if let Err(error) = self.poll_relays().await {
            eprintln!("cadabra: startup relay poll error: {error}");
        }
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
        let mut stop = self.shutdown.subscribe();
        tasks.push(tokio::spawn(async move {
            let mut last_poll = tokio::time::Instant::now();
            loop {
                let seconds = relay::RelayConfig::load(&daemon.root)
                    .map_or(60, |c| c.relay_poll_seconds.max(5));
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        if last_poll.elapsed() >= Duration::from_secs(seconds) {
                            if let Err(error) = daemon.poll_relays().await {
                                eprintln!("cadabra: relay poll error: {error}");
                            }
                            last_poll = tokio::time::Instant::now();
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
                            let peer = connection.peer_id();
                            let addresses = connection.observed_addresses().to_vec();
                            let Ok(_permit) = sessions.clone().acquire_owned().await else { break; };
                            match DeliveryNode::open(&daemon.root) {
                                Ok(mut node) => {
                                    node.auto_confirm_pairs = daemon.yes;
                                    let heads_before = main_heads(&node);
                                    if let Err(error) = node.handle_connection(&mut connection, now_ms()).await {
                                        eprintln!("cadabra: incoming session error: {error}");
                                    } else {
                                        let changed_heads = main_heads(&node)
                                            .difference(&heads_before)
                                            .copied()
                                            .collect::<std::collections::BTreeSet<_>>();
                                        if let Err(error) = node.trust.update_addresses(peer, addresses) {
                                            eprintln!("cadabra: peer address persistence error: {error}");
                                        }
                                        if let Err(error) = daemon.apply_receive_grants(peer, &changed_heads).await {
                                            eprintln!("cadabra: receive policy error: {error}");
                                        }
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
            let peer = {
                let mut node = self.node.lock().await;
                let Some(peer) = node.outbox.get(&id).map(|entry| entry.peer_id) else {
                    continue;
                };
                let now = now_ms();
                if node.trust.get(&peer).is_none() || node.trust.is_revoked_guest(&peer, now) {
                    let _ =
                        node.outbox
                            .fail_attempt(&id, "recipient trust was revoked".into(), now);
                    continue;
                }
                peer
            };
            match self.transport.dial(peer).await {
                Ok(mut connection) => {
                    let addresses = connection.observed_addresses().to_vec();
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
                    if let Err(error) = self
                        .node
                        .lock()
                        .await
                        .trust
                        .update_addresses(peer, addresses)
                    {
                        eprintln!("cadabra: peer address persistence error: {error}");
                    }
                    if result.is_err() {
                        if let Err(relay_error) = self.deposit_if_due(&id).await {
                            eprintln!("cadabra: relay deposit error: {relay_error}");
                        }
                    }
                }
                Err(error) => {
                    let _ = self.node.lock().await.outbox.fail_attempt(
                        &id,
                        error.to_string(),
                        now_ms(),
                    );
                    if let Err(relay_error) = self.deposit_if_due(&id).await {
                        eprintln!("cadabra: relay deposit error: {relay_error}");
                    }
                }
            }
        }
    }

    async fn deposit_if_due(&self, id: &str) -> Result<()> {
        let mut config = relay::RelayConfig::load(&self.root)?;
        let node = self.node.lock().await;
        let entry = node.outbox.get(id).cloned().ok_or("unknown outbox id")?;
        if entry.attempts < config.relay_after_attempts || config.relays.is_empty() {
            return Ok(());
        }
        let peer = node
            .trust
            .get(&entry.peer_id)
            .cloned()
            .ok_or("relay recipient is not trusted")?;
        let discovery = peer
            .relay_key
            .ok_or("relay recipient lacks discovery key")?;
        let payload = node.relay_delivery(id, now_ms())?;
        drop(node);
        let mut deposited = false;
        let mut last_error = None;
        for endpoint in config.relays.clone() {
            if config.deposited(id, &endpoint.url) {
                deposited = true;
                continue;
            }
            match relay::enqueue(
                &endpoint,
                abra_net::day_tag(&discovery, (now_ms() / 86_400_000) as i64),
                peer.x25519_pk,
                &payload,
                now_ms(),
            )
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
            config.mark_deposited(id, &endpoint.url);
            config.save(&self.root)?;
            deposited = true;
        }
        if deposited {
            self.node
                .lock()
                .await
                .outbox
                .mark_relay_deposited(id, now_ms())?;
        }
        if !deposited {
            if let Some(error) = last_error {
                return Err(error);
            }
        }
        Ok(())
    }

    async fn poll_relays(&self) -> Result<usize> {
        let config = relay::RelayConfig::load(&self.root)?;
        let mut count = 0;
        for endpoint in config.relays {
            let mut node = self.node.lock().await;
            let heads_before = main_heads(&node);
            let (handled, senders) =
                relay::poll(&self.root, &mut node, &endpoint, now_ms()).await?;
            let changed_heads = main_heads(&node)
                .difference(&heads_before)
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            count += handled;
            drop(node);
            for sender in senders {
                self.apply_receive_grants(sender, &changed_heads).await?;
            }
        }
        Ok(count)
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
                        let _ = self.poll_relays().await;
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
                | "policy-clear"
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
                let addresses = self.transport.wait_local_addresses().await?;
                warn_if_lan_only(
                    "ticket",
                    self.transport.requires_relay_for_wide_area(),
                    &addresses,
                );
                let mut node = self.node.lock().await;
                let ticket = PairTicket::mint(
                    string_or(&request, "name", "device"),
                    node.store.keys.x25519_public(),
                    Some(node.store.keys.relay_discovery_key),
                    addresses,
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
            "native-attach" => self.native_attach(&request).await,
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
            "inbox" => {
                self.poll_relays().await?;
                self.inbox().await
            }
            "relay-list" => {
                let config = relay::RelayConfig::load(&self.root)?;
                Ok(Value::Array(
                    config
                        .relays
                        .iter()
                        .map(|r| json!({"url":r.url,"secret_configured":!r.secret.is_empty()}))
                        .collect(),
                ))
            }
            "relay-add" => {
                let url = required_str(&request, "url")?
                    .trim_end_matches('/')
                    .to_owned();
                let secret = request
                    .get("secret")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let mut config = relay::RelayConfig::load(&self.root)?;
                if let Some(n) = request.get("relay_after_attempts").and_then(Value::as_u64) {
                    config.relay_after_attempts =
                        u32::try_from(n).map_err(|_| "relay_after_attempts is too large")?;
                }
                if let Some(n) = request.get("poll_seconds").and_then(Value::as_u64) {
                    config.relay_poll_seconds = n.max(5);
                }
                if let Some(existing) = config.relays.iter_mut().find(|r| r.url == url) {
                    existing.secret = secret;
                } else {
                    config.relays.push(relay::RelayEndpoint {
                        url: url.clone(),
                        secret,
                    });
                }
                config.save(&self.root)?;
                if let Err(error) = self.poll_relays().await {
                    eprintln!("cadabra: relay poll after add error: {error}");
                }
                Ok(
                    json!({"url":url,"secret_configured":!config.relays.iter().find(|r| r.url == url).expect("just inserted").secret.is_empty()}),
                )
            }
            "relay-remove" => {
                let url = required_str(&request, "url")?.trim_end_matches('/');
                let mut config = relay::RelayConfig::load(&self.root)?;
                let before = config.relays.len();
                config.relays.retain(|r| r.url != url);
                config.save(&self.root)?;
                Ok(json!({"removed":before != config.relays.len(),"url":url}))
            }
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
                let mut node = self.node.lock().await;
                let identity = node.store.keys.identity.clone();
                node.trust.revoke_token(token_id, now_ms(), &identity)?;
                Ok(json!({"revoked":token_id}))
            }
            "policy-grant" => self.policy_grant(&request).await,
            "policy-list" => Ok(serde_json::to_value(self.load_grants()?)?),
            "policy-clear" => {
                clear_grant_errors(&self.root)?;
                Ok(json!({"cleared":true}))
            }
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
        let local_addresses = self.transport.wait_local_addresses().await?;
        for address in &ticket.addresses {
            self.transport.add_peer_address(ticket.peer_id, address)?;
        }
        let mut connection = self.transport.dial(ticket.peer_id).await?;
        {
            let mut node = self.node.lock().await;
            let peer_id = node.peer_id();
            dial_handshake_with_trust(
                &mut connection,
                peer_id,
                "abra".into(),
                &mut node.trust,
                now_ms(),
            )
            .await?;
        }
        let (request, nonce) = {
            let node = self.node.lock().await;
            let nonce = rand::thread_rng().gen::<[u8; 16]>();
            let request = PairRequest::sign(
                ticket.ticket_id.clone(),
                "device".into(),
                node.store.keys.x25519_public(),
                Some(node.store.keys.relay_discovery_key),
                local_addresses,
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
        let recipes_path = path.join(".abra/recipes.json");
        if recipes_path.is_file() {
            let recipes: Vec<Recipe> = serde_json::from_slice(&fs::read(&recipes_path)?)?;
            manifest.recipes = Some(recipes);
        }
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
        if result.forked {
            let identity = node.store.keys.identity.clone();
            node.store.record_fork_label(
                capsule,
                result.snapshot_id,
                format_time(now_ms()),
                &identity,
                now_ms(),
            )?;
        } else {
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
        }
        Ok(json!({"capsule_id":capsule,"snapshot_id":result.snapshot_id,"forked":result.forked}))
    }

    async fn native_attach(&self, request: &Value) -> Result<Value> {
        let capsule: Hash = required_str(request, "capsule")?.parse()?;
        let head: Hash = required_str(request, "parent_snapshot")?.parse()?;
        if required_str(request, "snapshot_type")? != "Full" {
            return Err("native-attach only accepts standalone Full snapshots".into());
        }
        let artifact_root = fs::canonicalize(required_str(request, "artifact_root")?)?;
        let fingerprint: Fingerprint = serde_json::from_value(
            request
                .get("fingerprint")
                .cloned()
                .ok_or("request lacks fingerprint")?,
        )?;
        let artifacts = request
            .get("artifacts")
            .and_then(Value::as_array)
            .ok_or("request lacks artifacts")?;
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
        if node
            .store
            .capsules
            .get(&capsule)
            .and_then(|cap| cap.snapshot(&head))
            .is_none()
        {
            return Err("explicit portable parent is not present in capsule".into());
        }
        let mut manifest = node.store.capsules[&capsule]
            .snapshot(&head)
            .ok_or("head snapshot missing")?
            .raw
            .manifest()
            .clone();
        let mut native = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for artifact in artifacts {
            let role = artifact
                .get("role")
                .and_then(Value::as_str)
                .ok_or("artifact lacks role")?;
            let path = artifact
                .get("path")
                .and_then(Value::as_str)
                .ok_or("artifact lacks path")?;
            if !matches!(role, "vmstate" | "memory" | "disk") || !seen.insert(role) {
                return Err(format!("invalid or duplicate native artifact role: {role}").into());
            }
            let path = fs::canonicalize(path)?;
            if !path.starts_with(&artifact_root) || !path.is_file() {
                return Err("native artifact path escapes the declared slot directory".into());
            }
            let (blob, bytes) = node.store.cas.put_file(path)?;
            native.push(NativeBlobRef {
                role: role.into(),
                blob,
                bytes,
                fingerprint: fingerprint.clone(),
            });
        }
        if seen.len() != 3 {
            return Err("native artifacts must contain exactly vmstate, memory, and disk".into());
        }
        manifest.parents = Some(vec![head]);
        manifest.created_at = format_time(now_ms());
        manifest.origin.peer_id = node.peer_id();
        manifest.origin.name = Some("device".into());
        manifest.origin.adapter = Some("firecracker".into());
        manifest.labels = None;
        manifest.native = Some(native.clone());
        manifest.sign(&node.store.keys.identity)?;
        let raw = RawManifest::parse(manifest.to_canonical_bytes()?)?;
        let result = node
            .store
            .receive_full(raw, format_time(now_ms()), now_ms(), None)?;
        if result.forked {
            let identity = node.store.keys.identity.clone();
            node.store.record_fork_label(
                capsule,
                result.snapshot_id,
                format_time(now_ms()),
                &identity,
                now_ms(),
            )?;
        } else {
            let cap = &node.store.capsules[&capsule];
            let lease = cap.winning_lease().ok_or("capsule lacks lease")?;
            let seq = cap.label("main").map_or(1, |label| label.seq + 1);
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
        }
        Ok(json!({"capsule_id":capsule,"snapshot_id":result.snapshot_id,"native":native}))
    }

    async fn send(&self, request: &Value) -> Result<Value> {
        let peer: PeerId = required_str(request, "peer")?.parse()?;
        let adapter_export = if let Some(kind) = request.get("kind").and_then(Value::as_str) {
            let source = json_object_or_string(required_str(request, "source")?);
            let options = adapter_options(request)?;
            Some((
                kind.to_owned(),
                adapters::AdapterRegistry::discover(&self.root)?
                    .export(kind, source, &options, &self.root, None)
                    .await?,
            ))
        } else {
            None
        };
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
        let raw = if let Some((kind, export)) = adapter_export {
            let adapters::ExportResult {
                payload,
                files_path,
                floor,
                staging,
            } = export;
            let title = floor
                .as_ref()
                .and_then(|value| value.title.clone())
                .unwrap_or_else(|| kind.clone());
            let mut manifest = base_manifest(&node, Scope::Partial, &kind, &title);
            manifest.payload = payload
                .as_object()
                .cloned()
                .ok_or("adapter payload must be an object")?;
            manifest.summary = floor.as_ref().and_then(|value| value.summary.clone());
            manifest.link = floor.and_then(|value| value.link);
            if let Some(path) = files_path {
                manifest.files = Some(snapshot_dir(&node.store.cas, &path)?);
            }
            if let Some(staging) = staging {
                if let Err(error) = staging.close() {
                    eprintln!("cadabra: adapter staging cleanup error: {error}");
                }
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
            if request
                .get("into")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err("--into requires a full capsule snapshot".into());
            }
            if let Some(files) = raw.manifest().files {
                materialize(&node.store.cas, &files, destination)?;
            }
            materialize_recipes(destination, raw.manifest().recipes.as_ref())?;
            let registry = adapters::AdapterRegistry::discover(&self.root)?;
            if registry
                .for_kind(&raw.manifest().kind)
                .is_some_and(|adapter| adapter.manifest.verbs.iter().any(|verb| verb == "import"))
            {
                secure_adapter_tree(destination)?;
                let options = adapter_options(request)?;
                let destination_value = request
                    .get("destination")
                    .and_then(Value::as_str)
                    .map(json_object_or_string)
                    .unwrap_or_else(|| json!(destination));
                if let Err(error) = registry
                    .import(
                        &raw.manifest().kind,
                        Value::Object(raw.manifest().payload.clone()),
                        raw.manifest().files.map(|_| destination),
                        destination_value,
                        &options,
                        None,
                    )
                    .await
                {
                    return Err(format!(
                        "adapter import failed; inbox entry remains unread; files_materialized_at={}: {error}",
                        destination.display()
                    )
                    .into());
                }
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
                if request
                    .get("into")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    replace_workspace(
                        &node.store.cas,
                        files,
                        destination,
                        raw.manifest()
                            .capsule_id
                            .ok_or("snapshot has no capsule id")?,
                    )?;
                } else {
                    materialize(&node.store.cas, &files, destination)?;
                }
            }
            materialize_recipes(destination, raw.manifest().recipes.as_ref())?;
            if let Some(capsule_id) = raw.manifest().capsule_id {
                write_workspace_metadata(destination, capsule_id, id)?;
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
        let addresses = self.transport.wait_local_addresses().await?;
        warn_if_lan_only(
            "enrollment",
            self.transport.requires_relay_for_wide_area(),
            &addresses,
        );
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
                addresses,
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
        let capsule = request
            .get("capsule")
            .and_then(Value::as_str)
            .map(str::parse)
            .transpose()?;
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
        let id = format!(
            "{}:{}:{}",
            peer,
            kind,
            capsule.map_or_else(|| "*".into(), |c: Hash| c.to_hex())
        );
        let grant = ReceiveGrant {
            id: id.clone(),
            peer,
            kind,
            capsule,
            auto_accept,
            auto_run_recipes,
            destination,
        };
        let mut grants = self.load_grants()?;
        grants.insert(id.clone(), grant.clone());
        self.save_grants(&grants)?;
        Ok(serde_json::to_value(grant)?)
    }
    async fn apply_receive_grants(
        &self,
        delivering_peer: PeerId,
        changed_heads: &std::collections::BTreeSet<Hash>,
    ) -> Result<()> {
        let grants = self.load_grants()?;
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
        if grants.is_empty() {
            return Ok(());
        }
        let failed_grants = load_grant_errors(&self.root)?;
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
            if from != delivering_peer {
                continue;
            }
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
        for (capsule_id, capsule) in &node.store.capsules {
            let Some(head) = capsule.label("main").map(|label| label.snapshot_id) else {
                continue;
            };
            if !changed_heads.contains(&head) {
                continue;
            }
            let Some(record) = capsule.snapshot(&head) else {
                continue;
            };
            if failed_grants.contains_key(&head.to_hex()) {
                continue;
            }
            let raw = &record.raw;
            let Some(grant) = grants.values().find(|grant| {
                grant.auto_accept
                    && grant.peer == delivering_peer
                    && grant.kind == raw.manifest().kind
                    && grant.capsule.is_none_or(|allowed| allowed == *capsule_id)
            }) else {
                continue;
            };
            let destination = grant
                .destination
                .as_deref()
                .ok_or("grant lacks destination")?
                .join(capsule_id.to_hex());
            validate_destination(
                grant
                    .destination
                    .as_deref()
                    .ok_or("grant lacks destination")?,
            )?;
            validate_destination(&destination)?;
            if fs::read_to_string(destination.join(".abra/snapshot_id"))
                .is_ok_and(|current| current == head.to_hex())
            {
                continue;
            }
            if let Some(files) = raw.manifest().files {
                let result = if destination.join(".abra/capsule_id").exists() {
                    replace_workspace(&node.store.cas, files, &destination, *capsule_id)
                } else {
                    materialize(&node.store.cas, &files, &destination).map_err(Into::into)
                };
                if let Err(error) = result {
                    record_grant_error(&self.root, head, &error.to_string())?;
                    continue;
                }
                if let Err(error) = write_workspace_metadata(&destination, *capsule_id, head) {
                    record_grant_error(&self.root, head, &error.to_string())?;
                    continue;
                }
                record_event_file(
                    &self.root,
                    &json!({"type":"auto-accepted-full","capsule_id":capsule_id,"snapshot_id":head,"to":destination}),
                )?;
            }
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
        {
            let mut node = self.node.lock().await;
            let peer_id = node.peer_id();
            dial_handshake_with_trust(
                &mut connection,
                peer_id,
                "abra".into(),
                &mut node.trust,
                now_ms(),
            )
            .await?;
        }
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

fn relay_ready_for_mint(requires_relay: bool, addresses: &[String]) -> bool {
    !requires_relay
        || addresses
            .iter()
            .any(|address| abra_net::peer_address_has_relay_hint(address))
}

// A relay mode that has not reached its relay yet still mints usable
// LAN-only credentials; the operator is told so instead of being blocked.
fn warn_if_lan_only(what: &str, requires_relay: bool, addresses: &[String]) {
    if !relay_ready_for_mint(requires_relay, addresses) {
        eprintln!(
            "cadabra: iroh relay is not ready; this {what} carries direct addresses only and will not cross NATs"
        );
    }
}

fn main_heads(node: &DeliveryNode) -> std::collections::BTreeSet<Hash> {
    node.store
        .capsules
        .values()
        .filter_map(|capsule| capsule.label("main").map(|label| label.snapshot_id))
        .collect()
}

fn validate_destination(destination: &Path) -> Result<()> {
    if !destination.is_absolute() {
        return Err("destination must be absolute".into());
    }
    if fs::symlink_metadata(destination).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("destination is a symlink".into());
    }
    let metadata = destination.join(".abra");
    if fs::symlink_metadata(&metadata).is_ok_and(|entry| entry.file_type().is_symlink()) {
        return Err("destination .abra is a symlink".into());
    }
    let capsule_id = metadata.join("capsule_id");
    if fs::symlink_metadata(capsule_id).is_ok_and(|entry| entry.file_type().is_symlink()) {
        return Err("destination capsule_id is a symlink".into());
    }
    Ok(())
}

fn read_port(path: &Path) -> Result<u16> {
    match fs::read_to_string(path) {
        Ok(value) => match value.trim().parse() {
            Ok(port) => Ok(port),
            Err(error) => {
                eprintln!(
                    "cadabra: WARNING: ignoring invalid port file {}: {error}",
                    path.display()
                );
                Ok(0)
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn persist_port(path: &Path, port: u16) -> Result<()> {
    fs::create_dir_all(path.parent().expect("port path parent"))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, port.to_string())?;
    File::open(&tmp)?.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(feature = "iroh")]
fn is_addr_in_use(error: &abra_net::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("address already in use")
        || message.contains("addrinuse")
        || message.contains("os error 48")
        || message.contains("os error 98")
}

fn json_object_or_string(value: &str) -> Value {
    serde_json::from_str(value)
        .ok()
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::String(value.to_owned()))
}

fn adapter_options(request: &Value) -> Result<BTreeMap<String, String>> {
    request
        .get("options")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map(|options| options.unwrap_or_default())
        .map_err(Into::into)
}

fn materialize_recipes(
    destination: &Path,
    recipes: Option<&Vec<abra_core::manifest::Recipe>>,
) -> Result<()> {
    let Some(recipes) = recipes else {
        return Ok(());
    };
    write_metadata_file(destination, "recipes.json", &serde_json::to_vec(recipes)?)?;
    Ok(())
}

fn replace_workspace(
    store: &abra_core::cas::BlobStore,
    files: Hash,
    destination: &Path,
    capsule: Hash,
) -> Result<()> {
    validate_destination(destination)?;
    if read_capsule_id(destination)? != capsule {
        return Err("--into workspace belongs to a different capsule".into());
    }
    let parent = destination
        .parent()
        .ok_or("workspace has no parent directory")?;
    cleanup_workspace_staging(parent)?;
    let staged = tempfile::Builder::new()
        .prefix(".abra-into-")
        .tempdir_in(parent)?;
    let tree = staged.path().join("tree");
    materialize(store, &files, &tree)?;
    let backup = staged.path().join("backup");
    fs::create_dir(&backup)?;
    let mut old_entries = Vec::new();
    for entry in fs::read_dir(destination)? {
        let entry = entry?;
        if entry.file_name() == ".abra" {
            continue;
        }
        let name = entry.file_name();
        if let Err(error) = fs::rename(entry.path(), backup.join(&name)) {
            let mut rollback_errors = Vec::new();
            for restored in old_entries.iter().rev() {
                if let Err(rollback) = fs::rename(backup.join(restored), destination.join(restored))
                {
                    rollback_errors.push(rollback.to_string());
                }
            }
            if !rollback_errors.is_empty() {
                let retained = retain_workspace_backup(staged);
                return Err(format!(
                    "{error}; rollback failed ({}); backup retained at {}",
                    rollback_errors.join("; "),
                    retained.display()
                )
                .into());
            }
            return Err(error.into());
        }
        old_entries.push(name);
    }
    let mut new_entries = Vec::new();
    for entry in fs::read_dir(&tree)? {
        let entry = entry?;
        if entry.file_name() == ".abra" {
            continue;
        }
        let name = entry.file_name();
        if let Err(error) = fs::rename(entry.path(), destination.join(&name)) {
            let mut rollback_errors = Vec::new();
            for added in new_entries.iter().rev() {
                let path = destination.join(added);
                if let Err(rollback) =
                    if fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                        fs::remove_dir_all(path)
                    } else {
                        fs::remove_file(path)
                    }
                {
                    rollback_errors.push(rollback.to_string());
                }
            }
            for restored in old_entries.iter().rev() {
                if let Err(rollback) = fs::rename(backup.join(restored), destination.join(restored))
                {
                    rollback_errors.push(rollback.to_string());
                }
            }
            if !rollback_errors.is_empty() {
                let retained = retain_workspace_backup(staged);
                return Err(format!(
                    "{error}; rollback failed ({}); backup retained at {}",
                    rollback_errors.join("; "),
                    retained.display()
                )
                .into());
            }
            return Err(error.into());
        }
        new_entries.push(name);
    }
    Ok(())
}

fn cleanup_workspace_staging(parent: &Path) -> Result<()> {
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".abra-into-"))
            && entry.file_type()?.is_dir()
        {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

fn retain_workspace_backup(staged: tempfile::TempDir) -> PathBuf {
    let retained = staged.keep();
    let Some(name) = retained.file_name().and_then(|name| name.to_str()) else {
        return retained;
    };
    let recovery = retained.with_file_name(name.replacen(".abra-into-", ".abra-recovery-", 1));
    if fs::rename(&retained, &recovery).is_ok() {
        recovery
    } else {
        retained
    }
}

fn write_workspace_metadata(destination: &Path, capsule: Hash, snapshot: Hash) -> Result<()> {
    write_metadata_file(destination, "capsule_id", capsule.to_hex().as_bytes())?;
    if let Err(error) =
        write_metadata_file(destination, "snapshot_id", snapshot.to_hex().as_bytes())
    {
        let _ = fs::remove_file(destination.join(".abra/snapshot_id"));
        return Err(error);
    }
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

fn clear_grant_errors(root: &Path) -> Result<()> {
    let path = grant_errors_path(root);
    fs::create_dir_all(path.parent().expect("policy parent"))?;
    fs::write(path, b"{}")?;
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
    let mut value = String::new();
    open_metadata_file(path, "capsule_id")?.read_to_string(&mut value)?;
    Ok(value.trim().parse()?)
}

#[cfg(unix)]
fn open_metadata_dir(destination: &Path, create: bool) -> Result<std::os::fd::OwnedFd> {
    use rustix::fs::{mkdirat, open, openat, Mode, OFlags};
    let directory = open(
        destination,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if create {
        match mkdirat(&directory, ".abra", Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(openat(
        &directory,
        ".abra",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

#[cfg(unix)]
fn open_metadata_file(destination: &Path, name: &str) -> Result<File> {
    use rustix::fs::{openat, Mode, OFlags};
    let directory = open_metadata_dir(destination, false)?;
    Ok(File::from(openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

#[cfg(unix)]
fn write_metadata_file(destination: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    use rustix::fs::{openat, Mode, OFlags};
    let directory = open_metadata_dir(destination, true)?;
    let mut file = File::from(openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn open_metadata_file(destination: &Path, name: &str) -> Result<File> {
    validate_destination(destination)?;
    Ok(File::open(destination.join(".abra").join(name))?)
}

#[cfg(not(unix))]
fn write_metadata_file(destination: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    validate_destination(destination)?;
    fs::create_dir_all(destination.join(".abra"))?;
    fs::write(destination.join(".abra").join(name), bytes)?;
    Ok(())
}

#[cfg(unix)]
fn secure_adapter_tree(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            secure_adapter_tree(&entry?.path())?;
        }
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_adapter_tree(_path: &Path) -> Result<()> {
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use abra_core::cas::{BlobStore, EntryMode, Tree, TreeEntry};

    #[test]
    fn daemon_config_defaults_to_n0_and_persists_relay_mode() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(DaemonConfig::load(root.path()).unwrap().iroh_relay, "n0");
        DaemonConfig {
            iroh_relay: "none".into(),
            ..DaemonConfig::default()
        }
        .save(root.path())
        .unwrap();
        assert_eq!(DaemonConfig::load(root.path()).unwrap().iroh_relay, "none");
    }

    #[test]
    fn relay_modes_mint_lan_only_credentials_with_a_warning() {
        let direct = "tcp://127.0.0.1:4242".to_owned();
        assert!(!relay_ready_for_mint(true, std::slice::from_ref(&direct)));
        assert!(relay_ready_for_mint(false, &[direct]));
    }

    #[tokio::test]
    async fn daemon_config_applies_delivery_policy() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        DaemonConfig {
            skip_native: true,
            offer_budget: 1234,
            ..DaemonConfig::default()
        }
        .save(root.path())
        .unwrap();
        let network = LoopbackNetwork::default();
        let daemon = Daemon::loopback(root.path(), &network, false).unwrap();
        let node = daemon.node.lock().await;
        assert!(node.skip_native);
        assert_eq!(node.offer_budget, 1234);
    }

    #[test]
    fn corrupt_port_file_falls_back_and_persist_replaces_it() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("net/tcp-port");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "not-a-port").unwrap();
        assert_eq!(read_port(&path).unwrap(), 0);
        persist_port(&path, 4242).unwrap();
        assert_eq!(read_port(&path).unwrap(), 4242);
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn policy_clear_removes_recorded_grant_errors() {
        let root = tempfile::tempdir().unwrap();
        record_grant_error(root.path(), Hash::from_bytes([3; 32]), "disk full").unwrap();
        assert_eq!(load_grant_errors(root.path()).unwrap().len(), 1);
        clear_grant_errors(root.path()).unwrap();
        assert!(load_grant_errors(root.path()).unwrap().is_empty());
    }

    #[test]
    fn replace_workspace_ignores_sender_abra_metadata() {
        let root = tempfile::tempdir().unwrap();
        let store = BlobStore::open(root.path().join("store")).unwrap();
        let destination = root.path().join("workspace");
        let capsule = Hash::from_bytes([7; 32]);
        fs::create_dir_all(destination.join(".abra")).unwrap();
        fs::write(destination.join(".abra/capsule_id"), capsule.to_hex()).unwrap();
        fs::write(destination.join("old"), "old").unwrap();

        let new_blob = store.put(b"new").unwrap();
        let hostile_blob = store.put(b"hostile").unwrap();
        let hostile_metadata = store
            .put_tree(
                &Tree::new(vec![TreeEntry {
                    name: "capsule_id".into(),
                    mode: EntryMode::File,
                    hash: hostile_blob,
                    size: 7,
                }])
                .unwrap(),
            )
            .unwrap();
        let files = store
            .put_tree(
                &Tree::new(vec![
                    TreeEntry {
                        name: ".abra".into(),
                        mode: EntryMode::Tree,
                        hash: hostile_metadata,
                        size: 0,
                    },
                    TreeEntry {
                        name: "new".into(),
                        mode: EntryMode::File,
                        hash: new_blob,
                        size: 3,
                    },
                ])
                .unwrap(),
            )
            .unwrap();

        replace_workspace(&store, files, &destination, capsule).unwrap();
        assert!(!destination.join("old").exists());
        assert_eq!(fs::read_to_string(destination.join("new")).unwrap(), "new");
        assert_eq!(
            fs::read_to_string(destination.join(".abra/capsule_id")).unwrap(),
            capsule.to_hex()
        );
    }

    #[test]
    fn replace_workspace_removes_interrupted_staging_directory() {
        let root = tempfile::tempdir().unwrap();
        let store = BlobStore::open(root.path().join("store")).unwrap();
        let destination = root.path().join("workspace");
        let capsule = Hash::from_bytes([7; 32]);
        fs::create_dir_all(destination.join(".abra")).unwrap();
        fs::write(destination.join(".abra/capsule_id"), capsule.to_hex()).unwrap();
        let residue = root.path().join(".abra-into-interrupted");
        fs::create_dir(&residue).unwrap();
        fs::write(residue.join("recoverable"), "old").unwrap();
        let files = store.put_tree(&Tree::new(Vec::new()).unwrap()).unwrap();

        replace_workspace(&store, files, &destination, capsule).unwrap();
        assert!(!residue.exists());
    }

    #[cfg(unix)]
    #[test]
    fn workspace_metadata_refuses_symlinked_abra_and_capsule_id() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, workspace.join(".abra")).unwrap();
        let capsule = Hash::from_bytes([8; 32]);
        let snapshot = Hash::from_bytes([9; 32]);
        assert!(write_workspace_metadata(&workspace, capsule, snapshot).is_err());
        assert!(!outside.join("capsule_id").exists());

        fs::remove_file(workspace.join(".abra")).unwrap();
        fs::create_dir(workspace.join(".abra")).unwrap();
        let outside_file = outside.join("identity");
        fs::write(&outside_file, "unchanged").unwrap();
        symlink(&outside_file, workspace.join(".abra/capsule_id")).unwrap();
        assert!(write_workspace_metadata(&workspace, capsule, snapshot).is_err());
        assert_eq!(fs::read_to_string(outside_file).unwrap(), "unchanged");

        fs::remove_file(workspace.join(".abra/capsule_id")).unwrap();
        fs::write(workspace.join(".abra/capsule_id"), capsule.to_hex()).unwrap();
        let outside_snapshot = outside.join("snapshot");
        fs::write(&outside_snapshot, "old-head").unwrap();
        symlink(&outside_snapshot, workspace.join(".abra/snapshot_id")).unwrap();
        assert!(write_workspace_metadata(&workspace, capsule, snapshot).is_err());
        assert_eq!(fs::read_to_string(outside_snapshot).unwrap(), "old-head");
        assert!(!workspace.join(".abra/snapshot_id").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replace_workspace_refuses_existing_symlinked_abra() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let store = BlobStore::open(root.path().join("store")).unwrap();
        let destination = root.path().join("workspace");
        let outside = root.path().join("outside");
        fs::create_dir_all(&destination).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, destination.join(".abra")).unwrap();
        let files = store.put_tree(&Tree::new(Vec::new()).unwrap()).unwrap();

        let error =
            replace_workspace(&store, files, &destination, Hash::from_bytes([1; 32])).unwrap_err();
        assert_eq!(error.to_string(), "destination .abra is a symlink");
    }

    #[cfg(unix)]
    #[test]
    fn adapter_materialized_tree_is_private_before_import() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("payload/nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("cookies.json"), "secret").unwrap();
        fs::set_permissions(
            root.path().join("payload"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            nested.join("cookies.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        secure_adapter_tree(&root.path().join("payload")).unwrap();
        assert_eq!(
            fs::metadata(root.path().join("payload"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(nested.join("cookies.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
