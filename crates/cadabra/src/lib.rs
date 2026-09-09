//! Library-first Abra daemon and its newline-delimited JSON control API.
#![forbid(unsafe_code)]
pub mod adapters;
pub mod background;
pub mod relay;

use abra_core::{
    capsule::{random_capsule_id, Genesis, LabelOp, LeaseMode, LeaseRecord},
    cas::{materialize, snapshot_dir, EntryMode, Hash, Tree, TreeEntry},
    identity::{PeerId, Signature},
    manifest::{
        Fingerprint, Manifest, NativeBlobRef, Origin, Provenance, RawManifest, Recipe, Scope,
        Thumbnail,
    },
    now_ms,
};
#[cfg(feature = "tcp")]
use abra_net::TcpTransport;
use abra_net::{
    dial_handshake, dial_handshake_with_trust, format_time, write_frame, ControlAck,
    ControlMessage, ControlOp, DeliveryNode, EnrollBind, EnrollmentToken, Intro, LocalRole,
    LoopbackNetwork, LoopbackTransport, OutboxEntry, OutboxState, PairAccept, PairRequest,
    PairTicket, Role, Scopes, Transport, TrustedPeer,
};
#[cfg(feature = "iroh")]
use abra_net::{IrohRelayMode, IrohTransport};
use rand::Rng;
use serde::de::DeserializeOwned;
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
const MAX_OBSERVED_READ: u64 = 1024 * 1024;
const MAX_OBSERVED_EXTENSION: usize = 256 * 1024;
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
/// Default for `send --wait`, `inbox --wait`, and `accept --workspace`.
const DEFAULT_WAIT_MS: u64 = 120_000;
/// Waiting polls durable state instead of holding the node mutex.
const WAIT_POLL: Duration = Duration::from_millis(100);
/// Inbox waiting also drives a relay poll, so it ticks slower.
const INBOX_POLL: Duration = Duration::from_millis(250);

/// A running daemon owns exactly one durable network/store node.
pub struct Daemon {
    root: PathBuf,
    config: DaemonConfig,
    node: Arc<Mutex<DeliveryNode>>,
    transport: Arc<dyn Transport>,
    shutdown: watch::Sender<bool>,
    yes: bool,
    watchers: Arc<Semaphore>,
    adapter_sources: Vec<adapters::ExtraAdapterDir>,
    /// Outbox ids whose ack already produced a `send-acked` event, so the
    /// waiter and the outbox worker record it exactly once.
    acked_events: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
}

pub struct RunningDaemon {
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    socket: PathBuf,
    _lock: File,
}

/// Unknown fields are ignored on purpose: grants written before recipe
/// auto-run was removed still carry `auto_run_recipes`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReceiveGrant {
    id: String,
    peer: PeerId,
    kind: String,
    #[serde(default)]
    capsule: Option<Hash>,
    auto_accept: bool,
    destination: Option<PathBuf>,
    /// Re-deliver every auto-accepted snapshot to this peer.
    #[serde(default)]
    forward: Option<PeerId>,
}

/// Where this device last put a capsule. Written by every materializing path so
/// a control message can tell an adapter which directory to act in.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WorkspaceRecord {
    path: PathBuf,
    snapshot_id: Option<Hash>,
    at: String,
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
            config,
            node: Arc::new(Mutex::new(node)),
            transport,
            shutdown,
            yes,
            watchers: Arc::new(Semaphore::new(MAX_WATCHERS)),
            adapter_sources: Vec::new(),
            acked_events: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new())),
        })
    }

    /// Extra adapter discovery directories for this process only; nothing is
    /// persisted. Call before starting the daemon.
    pub fn set_adapter_sources(&mut self, sources: Vec<adapters::ExtraAdapterDir>) {
        self.adapter_sources = sources;
    }

    fn registry(&self) -> Result<adapters::AdapterRegistry> {
        adapters::AdapterRegistry::discover_with(&self.root, &self.adapter_sources)
    }

    fn detached_node(&self) -> Result<DeliveryNode> {
        let mut node = DeliveryNode::open(&self.root)?;
        node.skip_native = self.config.skip_native;
        node.offer_budget = self.config.offer_budget;
        node.auto_confirm_pairs = self.yes;
        if let LocalRole::Guest { token } = node.trust.local_role() {
            node.allow_agent_send = token.scopes.send;
        }
        node.control_handler = Some(Arc::new(ControlRouter {
            root: self.root.clone(),
            adapter_sources: self.adapter_sources.clone(),
        }));
        Ok(node)
    }

    pub fn loopback(root: impl AsRef<Path>, network: &LoopbackNetwork, yes: bool) -> Result<Self> {
        let node = DeliveryNode::open(root.as_ref())?;
        let transport = Arc::new(LoopbackTransport::bind(network, node.peer_id()));
        drop(node);
        Self::new(root, transport, yes)
    }

    #[cfg(feature = "tcp")]
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
        self.locked_node()
            .await
            .expect("daemon node refresh")
            .peer_id()
    }

    /// Lock the daemon's single node after refreshing the durable state that
    /// detached network sessions may have written since the last use. Never
    /// hold this guard across network, relay, adapter, or subprocess awaits.
    async fn locked_node(&self) -> Result<tokio::sync::MutexGuard<'_, DeliveryNode>> {
        let mut node = self.node.lock().await;
        node.store = abra_core::store::AbraStore::open(&self.root)?;
        node.trust.reload()?;
        node.outbox = abra_net::Outbox::open(&self.root)?;
        Ok(node)
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
            let node = self.locked_node().await?;
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
        let ok: abra_net::EnrollOk = abra_net::read_frame_timeout(recv, Duration::from_secs(630))
            .await
            .map_err(|error| match error {
                abra_net::Error::Timeout => "enrollment timed out".into(),
                error => Box::new(error) as Box<dyn std::error::Error + Send + Sync>,
            })?;
        if ok.message_type != "enroll-ok"
            || ok.certificate.guest_peer_id != self.peer_id().await
            || intro.peer_id != token.issuer
        {
            return Err("invalid enrollment response".into());
        }
        ok.certificate.verify(token.issuer)?;
        let mut node = self.locked_node().await?;
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
        let (socket, listener, lock) = self.bind_control_socket().await?;
        background::clear_stale_pid_file(&self.root);
        if let Err(error) = self.poll_relays().await {
            eprintln!("cadabra: startup relay poll error: {error}");
        }
        let mut tasks = vec![
            self.spawn_control_server(listener),
            self.spawn_relay_poller(),
            self.spawn_lease_renewer(),
        ];
        tasks.extend(self.spawn_inbound_workers());
        tasks.push(self.spawn_outbox_worker());
        Ok(RunningDaemon {
            shutdown: self.shutdown.clone(),
            tasks,
            socket,
            _lock: lock,
        })
    }

    async fn bind_control_socket(&self) -> Result<(PathBuf, UnixListener, File)> {
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
        Ok((socket, listener, lock))
    }

    fn spawn_control_server(self: &Arc<Self>, listener: UnixListener) -> JoinHandle<()> {
        let daemon = Arc::clone(self);
        let clients = Arc::new(Semaphore::new(MAX_CONTROL_CLIENTS));
        let mut stop = self.shutdown.subscribe();
        tokio::spawn(async move {
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
        })
    }

    fn spawn_relay_poller(self: &Arc<Self>) -> JoinHandle<()> {
        let daemon = Arc::clone(self);
        let mut stop = self.shutdown.subscribe();
        tokio::spawn(async move {
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
        })
    }

    fn spawn_lease_renewer(self: &Arc<Self>) -> JoinHandle<()> {
        let daemon = Arc::clone(self);
        let mut stop = self.shutdown.subscribe();
        tokio::spawn(async move {
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
        })
    }

    // Multiple accept workers ensure transport wrapping/authentication never
    // serializes the listener. Each handshake already has a transport-level
    // timeout, and the session semaphore bounds total work.
    fn spawn_inbound_workers(self: &Arc<Self>) -> Vec<JoinHandle<()>> {
        let sessions = Arc::new(Semaphore::new(MAX_INBOUND_SESSIONS));
        (0..4)
            .map(|_| {
                let daemon = Arc::clone(self);
                let sessions = Arc::clone(&sessions);
                let mut stop = self.shutdown.subscribe();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = stop.changed() => break,
                            incoming = daemon.transport.accept() => if let Ok(mut connection) = incoming {
                                let peer = connection.peer_id();
                                let addresses = connection.observed_addresses().to_vec();
                                let Ok(_permit) = sessions.clone().acquire_owned().await else { break; };
                                match daemon.detached_node() {
                                    Ok(mut node) => {
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
                })
            })
            .collect()
    }

    fn spawn_outbox_worker(self: &Arc<Self>) -> JoinHandle<()> {
        let daemon = Arc::clone(self);
        let mut stop = self.shutdown.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => daemon.work_outbox().await,
                }
            }
        })
    }

    async fn work_outbox(&self) {
        // Refresh once for this worker tick, then detach each network session.
        let pending = match self.locked_node().await {
            Ok(mut node) => {
                let mut pending = Vec::new();
                for id in node.outbox.pending_ids(now_ms()) {
                    let Some(peer) = node.outbox.get(&id).map(|entry| entry.peer_id) else {
                        continue;
                    };
                    let now = now_ms();
                    if node.trust.get(&peer).is_none() || node.trust.is_revoked_guest(&peer, now) {
                        let _ = node.outbox.fail_attempt(
                            &id,
                            "recipient trust was revoked".into(),
                            now,
                        );
                        continue;
                    }
                    pending.push((id, peer, node.outgoing_session()));
                }
                pending
            }
            Err(error) => {
                eprintln!("cadabra: outbox reload error: {error}");
                return;
            }
        };
        for (id, peer, mut session) in pending {
            match self.transport.dial(peer).await {
                Ok(mut connection) => {
                    let addresses = connection.observed_addresses().to_vec();
                    let result = session.send_offer(&id, &mut connection, now_ms()).await;
                    if let Err(error) = &result {
                        eprintln!("cadabra: outgoing session error: {error}");
                    }
                    {
                        let mut node = match self.locked_node().await {
                            Ok(node) => node,
                            Err(error) => {
                                eprintln!("cadabra: node refresh after send error: {error}");
                                continue;
                            }
                        };
                        if let Err(error) = node.outbox.sync_entry_from(&session.outbox, &id) {
                            eprintln!("cadabra: outbox session merge error: {error}");
                        }
                        if let Some(entry) = node
                            .outbox
                            .get(&id)
                            .filter(|entry| entry.state == OutboxState::Acked)
                        {
                            if let Err(error) = self.record_send_acked(entry) {
                                eprintln!("cadabra: send-acked event error: {error}");
                            }
                        }
                    }
                    if let Err(error) = self.locked_node().await.and_then(|mut node| {
                        node.trust
                            .update_addresses(peer, addresses)
                            .map_err(Into::into)
                    }) {
                        eprintln!("cadabra: peer address persistence error: {error}");
                    }
                    if result.is_err() {
                        if let Err(relay_error) = self.deposit_if_due(&id).await {
                            eprintln!("cadabra: relay deposit error: {relay_error}");
                        }
                    }
                }
                Err(error) => {
                    if let Ok(mut node) = self.locked_node().await {
                        let _ = node.outbox.fail_attempt(&id, error.to_string(), now_ms());
                    }
                    if let Err(relay_error) = self.deposit_if_due(&id).await {
                        eprintln!("cadabra: relay deposit error: {relay_error}");
                    }
                }
            }
        }
    }

    async fn deposit_if_due(&self, id: &str) -> Result<()> {
        let mut config = relay::RelayConfig::load(&self.root)?;
        let node = self.locked_node().await?;
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
            self.locked_node()
                .await?
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
            let mut node = self.locked_node().await?.outgoing_session();
            let heads_before = main_heads(&node);
            let (handled, senders) =
                relay::poll(&self.root, &mut node, &endpoint, now_ms()).await?;
            let mut refreshed = self.locked_node().await?;
            // Acks fetched from the relay landed in the detached outbox copy;
            // carry them into the durable one.
            for entry in node.outbox.entries() {
                if entry.state == OutboxState::Acked {
                    refreshed.outbox.sync_entry_from(&node.outbox, &entry.id)?;
                }
            }
            drop(node);
            let changed_heads = main_heads(&refreshed)
                .difference(&heads_before)
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            count += handled;
            drop(refreshed);
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
        let op = request
            .get("op")
            .and_then(Value::as_str)
            .ok_or("request lacks op")?;
        // One refresh per request; every op below then uses the locked node.
        drop(self.locked_node().await?);
        self.authorize_op(op).await?;
        match op {
            "status" => self.status().await,
            "events" => self.events(),
            "control" => self.send_control(&request).await,
            "pair-ticket" | "pair-add" | "pair-confirm" | "pair-remove" | "pending-pairs"
            | "peers" | "enroll-mint" | "enroll-join" | "revoke" => {
                self.handle_pairing(op, &request).await
            }
            "adapters-list" | "adapters-add" | "adapters-remove" | "inspect" => {
                self.handle_adapters(op, &request).await
            }
            "relay-list" | "relay-add" | "relay-remove" => self.handle_relays(op, &request).await,
            "policy-grant" | "policy-list" | "policy-clear" | "policy-revoke" => {
                self.handle_policy(op, &request).await
            }
            "capsule-create" | "capsules" | "log" | "snapshot" | "native-attach"
            | "restore-plan" | "lease-status" | "lease-take" => {
                self.handle_capsules(op, &request).await
            }
            "send" | "inbox" | "accept" | "outbox" | "cancel" | "handoffs" => {
                self.handle_delivery(op, &request).await
            }
            _ => Err(format!("unknown operation: {op}").into()),
        }
    }

    /// Mesh-wide authority stays on full devices; guests may only move data.
    async fn authorize_op(&self, op: &str) -> Result<()> {
        if matches!(
            op,
            "pair-ticket"
                | "pair-add"
                | "pair-confirm"
                | "pair-remove"
                | "enroll-mint"
                | "revoke"
                | "policy-grant"
                | "policy-revoke"
                | "policy-clear"
                | "control"
        ) && !matches!(
            self.locked_node().await?.trust.local_role(),
            LocalRole::Full
        ) {
            return Err("operation requires a full device; this daemon is a guest".into());
        }
        Ok(())
    }

    async fn status(&self) -> Result<Value> {
        let node = self.locked_node().await?;
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

    async fn handle_pairing(&self, op: &str, request: &Value) -> Result<Value> {
        match op {
            "pair-ticket" => {
                let addresses = self.transport.wait_local_addresses().await?;
                warn_if_lan_only(
                    "ticket",
                    self.transport.requires_relay_for_wide_area(),
                    &addresses,
                );
                let mut node = self.locked_node().await?;
                let ticket = PairTicket::mint(
                    string_or(request, "name", "device"),
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
            "pair-add" => self.pair_add(required_str(request, "ticket")?).await,
            "pair-confirm" => {
                let peer: PeerId = required_str(request, "id")?.parse()?;
                self.locked_node().await?.approve_pair(peer)?;
                Ok(json!({"confirmed":peer}))
            }
            "pair-remove" => {
                let peer: PeerId = required_str(request, "id")?.parse()?;
                let mut node = self.locked_node().await?;
                if peer == node.peer_id() {
                    return Err("cannot remove this device".into());
                }
                let removed = node.trust.remove_peer(peer)?;
                Ok(json!({"peer_id":peer,"removed":removed}))
            }
            "pending-pairs" => {
                let node = self.locked_node().await?;
                Ok(serde_json::to_value(node.durable_pending_pairs()?)?)
            }
            "peers" => {
                let node = self.locked_node().await?;
                Ok(serde_json::to_value(
                    node.trust.peers().values().collect::<Vec<_>>(),
                )?)
            }
            "enroll-mint" => self.enroll(request).await,
            "enroll-join" => self.join(required_str(request, "token")?).await,
            "revoke" => {
                let token_id = required_str(request, "token_id")?;
                let mut node = self.locked_node().await?;
                let identity = node.store.keys.identity.clone();
                node.trust.revoke_token(token_id, now_ms(), &identity)?;
                Ok(json!({"revoked":token_id}))
            }
            _ => Err(format!("unknown operation: {op}").into()),
        }
    }

    async fn handle_adapters(&self, op: &str, request: &Value) -> Result<Value> {
        match op {
            "adapters-list" => {
                let registry = self.registry()?;
                Ok(serde_json::to_value(registry.list())?)
            }
            "adapters-add" => {
                adapters::AdapterRegistry::add(
                    &self.root,
                    Path::new(required_str(request, "dir")?),
                    &self.adapter_sources,
                )?;
                Ok(json!({"added":required_str(request, "dir")?}))
            }
            "adapters-remove" => {
                adapters::AdapterRegistry::remove(&self.root, required_str(request, "name")?)?;
                Ok(json!({"removed":required_str(request, "name")?}))
            }
            "inspect" => {
                let kind = required_str(request, "kind")?;
                let source = json_object_or_string(required_str(request, "source")?);
                let options = adapter_options(request)?;
                self.inspect_source(kind, source, &options).await
            }
            _ => Err(format!("unknown operation: {op}").into()),
        }
    }

    /// Run only an adapter's `inspect` verb and report what it found.
    async fn inspect_source(
        &self,
        kind: &str,
        source: Value,
        options: &BTreeMap<String, String>,
    ) -> Result<Value> {
        let report = self
            .registry()?
            .inspect(kind, source, options, None)
            .await?;
        let parsed: adapters::InspectResult = serde_json::from_value(report.clone())?;
        record_event(
            &self.root,
            "adapter-inspect",
            json!({"kind":kind,"warnings":parsed.warnings.len(),"blocked":parsed.blocked.len()}),
        )?;
        Ok(report)
    }

    async fn handle_relays(&self, op: &str, request: &Value) -> Result<Value> {
        match op {
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
                let url = required_str(request, "url")?
                    .trim_end_matches('/')
                    .to_owned();
                let secret = request
                    .get("secret")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                relay::RelayEndpoint {
                    url: url.clone(),
                    secret: secret.clone(),
                }
                .validate()?;
                let mut config = relay::RelayConfig::load(&self.root)?;
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
                let url = required_str(request, "url")?.trim_end_matches('/');
                let mut config = relay::RelayConfig::load(&self.root)?;
                let before = config.relays.len();
                config.relays.retain(|r| r.url != url);
                config.save(&self.root)?;
                Ok(json!({"removed":before != config.relays.len(),"url":url}))
            }
            _ => Err(format!("unknown operation: {op}").into()),
        }
    }

    async fn handle_policy(&self, op: &str, request: &Value) -> Result<Value> {
        match op {
            "policy-grant" => self.policy_grant(request).await,
            "policy-list" => Ok(serde_json::to_value(self.load_grants()?)?),
            "policy-clear" => {
                clear_grant_errors(&self.root)?;
                Ok(json!({"cleared":true}))
            }
            "policy-revoke" => {
                let id = required_str(request, "id")?;
                let removed = update_json_file(
                    &self.grants_path(),
                    |grants: &mut BTreeMap<String, ReceiveGrant>| Ok(grants.remove(id).is_some()),
                )?;
                if !removed {
                    return Err("unknown policy grant".into());
                }
                Ok(json!({"revoked":id}))
            }
            _ => Err(format!("unknown operation: {op}").into()),
        }
    }

    async fn handle_capsules(&self, op: &str, request: &Value) -> Result<Value> {
        match op {
            "capsule-create" => {
                self.capsule_create(Path::new(required_str(request, "path")?))
                    .await
            }
            "capsules" => self.capsules().await,
            "log" => self.log(request).await,
            "snapshot" => self.snapshot(request).await,
            "native-attach" => self.native_attach(request).await,
            "restore-plan" => self.restore_plan(request).await,
            "lease-status" => self.lease_status(request).await,
            "lease-take" => self.lease_take(request).await,
            _ => Err(format!("unknown operation: {op}").into()),
        }
    }

    async fn handle_delivery(&self, op: &str, request: &Value) -> Result<Value> {
        match op {
            "send" => self.send(request).await,
            "inbox" => self.inbox(request).await,
            "accept" => self.accept(request).await,
            "handoffs" => self.handoffs(request).await,
            "outbox" => {
                let node = self.locked_node().await?;
                Ok(serde_json::to_value(
                    node.outbox.entries().collect::<Vec<_>>(),
                )?)
            }
            "cancel" => {
                self.locked_node()
                    .await?
                    .outbox
                    .cancel(required_str(request, "id")?, now_ms())?;
                Ok(json!({"cancelled":required_str(request, "id")?}))
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
            let mut session = self.locked_node().await?.outgoing_session();
            let peer_id = session.peer_id();
            dial_handshake_with_trust(
                &mut connection,
                peer_id,
                "abra".into(),
                &mut session.trust,
                now_ms(),
            )
            .await?;
        }
        let (request, nonce) = {
            let node = self.locked_node().await?;
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
        let accept: PairAccept = abra_net::read_frame_timeout(recv, Duration::from_secs(630))
            .await
            .map_err(|error| match error {
                abra_net::Error::Timeout => "pairing confirmation timed out".into(),
                error => Box::new(error) as Box<dyn std::error::Error + Send + Sync>,
            })?;
        let confirm = self
            .locked_node()
            .await?
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
        let mut node = self.locked_node().await?;
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
        record_workspace(&self.root, id, path, None)?;
        Ok(json!({"capsule_id":id}))
    }

    async fn snapshot(&self, request: &Value) -> Result<Value> {
        let path = PathBuf::from(required_str(request, "path")?);
        let label = request.get("label").and_then(Value::as_str);
        let no_lease = flag(request, "no_lease");
        let barrier = request
            .get("observation_barrier")
            .filter(|value| !value.is_null())
            .map(|value| value.as_str().ok_or("observation_barrier must be a string"))
            .transpose()?;
        let snapshot = self
            .snapshot_workspace(
                &path,
                label,
                no_lease,
                false,
                barrier,
                request
                    .get("observation_host")
                    .filter(|value| !value.is_null()),
            )
            .await?;
        Ok(
            json!({"capsule_id":snapshot.capsule_id,"snapshot_id":snapshot.snapshot_id,"forked":snapshot.forked,"observation_barrier":request.get("observation_barrier")}),
        )
    }

    /// Snapshot a workspace directory. With `initialize`, a directory that has
    /// no `.abra/capsule_id` becomes a capsule first, exactly as `abra init`
    /// would. Unless `no_lease`, a device that may drive the capsule takes the
    /// lease first so the new snapshot extends `main` instead of forking.
    async fn snapshot_workspace(
        &self,
        path: &Path,
        label: Option<&str>,
        no_lease: bool,
        initialize: bool,
        observation_barrier: Option<&str>,
        observation_host: Option<&Value>,
    ) -> Result<WorkspaceSnapshot> {
        if !path.is_absolute() {
            return Err("snapshot path must be absolute".into());
        }
        if initialize && !path.join(".abra/capsule_id").exists() {
            self.capsule_create(path).await?;
        }
        let capsule = read_capsule_id(path)?;
        let mut node = self.locked_node().await?;
        if !no_lease {
            ensure_lease(&mut node, &self.root, capsule)?;
        }
        // Read the selected ledger before walking a potentially large file tree.
        let mut observation =
            base_manifest(&node, Scope::Full, "dev.abra.workspace", "observation");
        load_workspace_observation(
            path,
            &mut observation,
            observation_barrier,
            observation_host,
        )?;
        let files = snapshot_dir(&node.store.cas, path)?;
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
        manifest.recipes = observation.recipes;
        manifest.extensions = observation.extensions;
        manifest.payload = payload;
        if let Some(label) = label {
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
        record_workspace(&self.root, capsule, path, Some(result.snapshot_id))?;
        Ok(WorkspaceSnapshot {
            capsule_id: capsule,
            snapshot_id: result.snapshot_id,
            forked: result.forked,
        })
    }

    async fn restore_plan(&self, request: &Value) -> Result<Value> {
        let id: Hash = required_str(request, "id")?.parse()?;
        let target: Option<Fingerprint> = request
            .get("fingerprint")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .flatten();
        let roles: Vec<String> = request
            .get("native_roles")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        let (cas, raw) = {
            let node = self.locked_node().await?;
            (
                node.store.cas.clone(),
                abra_core::link::find_snapshot(&node.store, id)?,
            )
        };
        // Large native objects are streamed and verified outside the daemon lock.
        let plan = tokio::task::spawn_blocking(move || {
            let roles: Vec<_> = roles.iter().map(String::as_str).collect();
            abra_core::restore::plan_restore(&cas, &raw, target.as_ref(), &roles)
        })
        .await??;
        Ok(serde_json::to_value(plan)?)
    }

    async fn native_attach(&self, request: &Value) -> Result<Value> {
        let capsule: Hash = required_str(request, "capsule")?.parse()?;
        let head: Hash = required_str(request, "parent_snapshot")?.parse()?;
        if required_str(request, "snapshot_type")? != "Full" {
            return Err("native-attach only accepts standalone full snapshots".into());
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
        let mut node = self.locked_node().await?;
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
        let wait = flag(request, "wait");
        let timeout = wait_timeout(request);
        let no_lease = flag(request, "no_lease");
        let kind = request
            .get("kind")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let workspace = request
            .get("workspace")
            .and_then(Value::as_str)
            .map(PathBuf::from);
        if workspace.is_some() && kind.is_none() {
            return Err("--workspace links a workspace to an adapter --kind send".into());
        }
        // The adapter runs unlocked: an export may take minutes.
        let mut inspection = None;
        let adapter_export = match &kind {
            Some(kind) => {
                let source = json_object_or_string(required_str(request, "source")?);
                let options = adapter_options(request)?;
                let registry = self.registry()?;
                if registry
                    .for_kind(kind)
                    .is_some_and(|adapter| adapter.supports("inspect"))
                {
                    let report = self.inspect_source(kind, source.clone(), &options).await?;
                    let parsed: adapters::InspectResult = serde_json::from_value(report)?;
                    if !parsed.blocked.is_empty() && !flag(request, "force") {
                        return Err(format!(
                            "adapter inspect blocked this send: {}; pass --force to send anyway",
                            Value::Array(parsed.blocked.clone())
                        )
                        .into());
                    }
                    inspection = Some(parsed);
                }
                Some((
                    kind.clone(),
                    registry
                        .export(kind, source, &options, &self.root, None)
                        .await?,
                ))
            }
            None => None,
        };
        // A linked handoff carries the workspace it came out of. Snapshot it
        // first so the receiver can resolve the partial's provenance.
        let linked = match &workspace {
            Some(dir) => Some(
                self.snapshot_workspace(dir, Some("handoff"), no_lease, true, None, None)
                    .await?,
            ),
            None => None,
        };
        // `--path` on an initialized workspace sends the capsule snapshot.
        let path_workspace = match request.get("path").and_then(Value::as_str) {
            Some(path) if is_workspace_dir(Path::new(path)) => Some(
                self.snapshot_workspace(Path::new(path), None, no_lease, false, None, None)
                    .await?,
            ),
            _ => None,
        };

        let mut node = self.locked_node().await?;
        let mut extra = Map::new();
        let mut ids = Vec::new();
        let provenance = if let Some(snapshot) = &linked {
            Some(Provenance {
                capsule_id: snapshot.capsule_id,
                snapshot_id: snapshot.snapshot_id,
                turn: None,
            })
        } else if let Some(id) = request.get("provenance").and_then(Value::as_str) {
            let raw = find_snapshot(&node, id)
                .map_err(|_| "provenance names a snapshot this device does not have")?;
            Some(Provenance {
                capsule_id: raw
                    .manifest()
                    .capsule_id
                    .ok_or("provenance snapshot has no capsule id")?,
                snapshot_id: raw.snapshot_id(),
                turn: None,
            })
        } else {
            adapter_export
                .as_ref()
                .and_then(|(_, export)| export.provenance)
                .map(|value| Provenance {
                    capsule_id: value.capsule_id,
                    snapshot_id: value.snapshot_id,
                    turn: None,
                })
        };
        if let Some(provenance) = &provenance {
            let raw = find_snapshot(&node, &provenance.snapshot_id.to_hex())
                .map_err(|_| "provenance names a snapshot this device does not have")?;
            if raw.manifest().scope != Scope::Full
                || raw.manifest().capsule_id != Some(provenance.capsule_id)
            {
                return Err("provenance names a snapshot this device does not have".into());
            }
            let id = node.enqueue(peer, &raw, now_ms())?;
            ids.push(id.clone());
            extra.insert("provenance_outbox_id".into(), json!(id.clone()));
            extra.insert(
                "provenance_snapshot_id".into(),
                json!(provenance.snapshot_id),
            );
            if linked.is_some() {
                extra.insert("workspace_outbox_id".into(), json!(id));
                extra.insert(
                    "workspace_snapshot_id".into(),
                    json!(provenance.snapshot_id),
                );
                extra.insert("capsule_id".into(), json!(provenance.capsule_id));
            }
        }
        let raw = if let Some((kind, export)) = adapter_export {
            let adapters::ExportResult {
                payload,
                files_path,
                floor,
                staging,
                ..
            } = export;
            let title = floor
                .as_ref()
                .and_then(|value| value.title.clone())
                .unwrap_or_else(|| kind.clone());
            let thumbnail_path = floor
                .as_ref()
                .and_then(|value| value.thumbnail_path.clone());
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
            if let Some(path) = thumbnail_path {
                manifest.thumbnail = Some(ingest_thumbnail(&node.store.cas, &path)?);
            }
            if let Some(staging) = staging {
                if let Err(error) = staging.close() {
                    eprintln!("cadabra: adapter staging cleanup error: {error}");
                }
            }
            manifest.provenance = provenance;
            manifest.origin.adapter = Some(kind.clone());
            manifest.sign(&node.store.keys.identity)?;
            RawManifest::parse(manifest.to_canonical_bytes()?)?
        } else if let Some(id) = request.get("snapshot_id").and_then(Value::as_str) {
            if provenance.is_some() {
                return Err("provenance applies only to a partial send".into());
            }
            find_snapshot_or_capsule_head(&node, id)?
        } else if let Some(link) = request.get("link").and_then(Value::as_str) {
            let title = request.get("title").and_then(Value::as_str).unwrap_or(link);
            let mut manifest = base_manifest(&node, Scope::Partial, "dev.abra.handoff.v1", title);
            manifest.link = Some(link.into());
            manifest.payload.insert("url".into(), json!(link));
            if let Some(note) = request.get("note").and_then(Value::as_str) {
                manifest.payload.insert("note".into(), json!(note));
            }
            manifest.provenance = provenance;
            manifest.sign(&node.store.keys.identity)?;
            RawManifest::parse(manifest.to_canonical_bytes()?)?
        } else if let Some(snapshot) = path_workspace {
            if provenance.is_some() {
                return Err("provenance applies only to a partial send".into());
            }
            extra.insert("capsule_id".into(), json!(snapshot.capsule_id));
            extra.insert("workspace_detected".into(), json!(true));
            find_snapshot(&node, &snapshot.snapshot_id.to_hex())?
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
            manifest.provenance = provenance;
            manifest.sign(&node.store.keys.identity)?;
            RawManifest::parse(manifest.to_canonical_bytes()?)?
        };
        let id = node.enqueue(peer, &raw, now_ms())?;
        ids.push(id.clone());
        drop(node);
        let mut result = json!({"outbox_id":id,"snapshot_id":raw.snapshot_id()});
        let object = result.as_object_mut().expect("send result is an object");
        object.append(&mut extra);
        if let Some(inspection) = inspection {
            object.insert("summary".into(), json!(inspection.summary));
            object.insert("warnings".into(), Value::Array(inspection.warnings));
            object.insert("blocked".into(), Value::Array(inspection.blocked));
        }
        if wait {
            let mut entries = self.wait_for_acks(&ids, timeout).await?;
            object.insert(
                "entry".into(),
                entries.last().cloned().unwrap_or(Value::Null),
            );
            object.insert("entries".into(), Value::Array(std::mem::take(&mut entries)));
        }
        Ok(result)
    }

    /// One `send-acked` line per outbox entry, whoever notices the ack first.
    fn record_send_acked(&self, entry: &OutboxEntry) -> Result<()> {
        {
            let mut seen = self.acked_events.lock().expect("ack event set");
            if !seen.insert(entry.id.clone()) {
                return Ok(());
            }
        }
        record_event(
            &self.root,
            "send-acked",
            json!({"outbox_id":entry.id,"snapshot_id":entry.snapshot_id,"peer":entry.peer_id}),
        )
    }

    /// Watch durable outbox state until every entry is acked. The node mutex is
    /// only held for each poll, never across the sleep.
    async fn wait_for_acks(&self, ids: &[String], timeout: Duration) -> Result<Vec<Value>> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut acked: BTreeMap<String, Value> = BTreeMap::new();
        loop {
            let mut unfinished = None;
            {
                let node = self.locked_node().await?;
                for id in ids {
                    if acked.contains_key(id) {
                        continue;
                    }
                    let entry = node.outbox.get(id).ok_or("unknown outbox id")?;
                    match entry.state {
                        OutboxState::Acked => {
                            self.record_send_acked(entry)?;
                            acked.insert(id.clone(), outbox_summary(entry));
                        }
                        OutboxState::Failed | OutboxState::Cancelled | OutboxState::Expired => {
                            return Err(format!(
                                "delivery {id} ended as {}: {}",
                                state_name(entry.state),
                                entry.last_error.as_deref().unwrap_or("no detail")
                            )
                            .into());
                        }
                        _ => {
                            unfinished.get_or_insert_with(|| {
                                (
                                    id.clone(),
                                    state_name(entry.state),
                                    entry.last_error.clone(),
                                )
                            });
                        }
                    }
                }
            }
            let Some((id, state, last_error)) = unfinished else {
                return Ok(ids.iter().map(|id| acked[id].clone()).collect());
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "delivery {id} was not acknowledged within {}ms; state {state}: {}",
                    timeout.as_millis(),
                    last_error.as_deref().unwrap_or("no detail")
                )
                .into());
            }
            tokio::time::sleep(WAIT_POLL).await;
        }
    }

    async fn inbox(&self, request: &Value) -> Result<Value> {
        let kind = request.get("kind").and_then(Value::as_str);
        let from = request.get("from").and_then(Value::as_str);
        let wait = flag(request, "wait");
        let timeout = wait_timeout(request);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            self.poll_relays().await?;
            let rows = self.inbox_rows(kind, from).await?;
            if !wait || rows.iter().any(|row| row["read"] == json!(false)) {
                return Ok(Value::Array(rows));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "no unread {} delivery arrived within {}ms",
                    kind.unwrap_or("inbox"),
                    timeout.as_millis()
                )
                .into());
            }
            tokio::time::sleep(INBOX_POLL).await;
        }
    }

    async fn inbox_rows(&self, kind: Option<&str>, from: Option<&str>) -> Result<Vec<Value>> {
        let node = self.locked_node().await?;
        let mut rows = Vec::new();
        for entry in node.store.inbox.values() {
            let raw = RawManifest::parse(entry.manifest.clone())?;
            let m = raw.manifest();
            if kind.is_some_and(|kind| kind != m.kind)
                || from.is_some_and(|from| from != entry.from)
            {
                continue;
            }
            rows.push(json!({"id":entry.snapshot_id,"from":entry.from,"received_at":entry.received_at,"read":entry.read,"kind":m.kind,"title":m.title,"origin":m.origin,"created_at":m.created_at,"link":m.link,"provenance":m.provenance}));
        }
        Ok(rows)
    }

    /// The single delivery of a kind waiting to be taken, the way an integrator
    /// picking up a handoff means it. Unread inbox partials first; when a kind
    /// has none, a capsule head that arrived from a peer. Zero or several is an
    /// error, never a guess.
    async fn latest_unread(&self, kind: &str, from: Option<&str>) -> Result<Hash> {
        let node = self.locked_node().await?;
        let mut matches = Vec::new();
        for entry in node.store.inbox.values() {
            if entry.read || from.is_some_and(|from| from != entry.from) {
                continue;
            }
            if RawManifest::parse(entry.manifest.clone())?.manifest().kind != kind {
                continue;
            }
            matches.push((entry.received_at.clone(), entry.snapshot_id));
        }
        if matches.is_empty() {
            let local = node.peer_id();
            for capsule in node.store.capsules.values() {
                let Some(record) = capsule
                    .label("main")
                    .and_then(|label| capsule.snapshot(&label.snapshot_id))
                else {
                    continue;
                };
                let origin = record.raw.manifest().origin.peer_id;
                if record.raw.manifest().kind != kind
                    || origin == local
                    || from.is_some_and(|from| from != origin.to_hex())
                {
                    continue;
                }
                matches.push((record.received_at.clone(), record.raw.snapshot_id()));
            }
        }
        matches.sort_by(|left, right| right.0.cmp(&left.0));
        match matches.len() {
            0 => Err(format!("no unread {kind} delivery found").into()),
            1 => Ok(matches[0].1),
            _ => Err(format!(
                "multiple unread {kind} deliveries match; pass one id: {}",
                matches
                    .iter()
                    .map(|(_, id)| id.to_hex())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into()),
        }
    }

    /// One row per kind: who last acked a send of it, what send is still
    /// outstanding, what was last received, and, for a capsule kind, which
    /// device is driving it now. This is the state integrators otherwise keep
    /// in their own file.
    async fn handoffs(&self, request: &Value) -> Result<Value> {
        let kind_filter = request.get("kind").and_then(Value::as_str);
        let peer_filter = request.get("peer").and_then(Value::as_str);
        let node = self.locked_node().await?;
        let mut rows: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        let row = |rows: &mut BTreeMap<String, Map<String, Value>>, kind: &str| -> bool {
            if kind_filter.is_some_and(|filter| filter != kind) {
                return false;
            }
            rows.entry(kind.to_owned()).or_default();
            true
        };
        for entry in node.outbox.entries() {
            let Ok(raw) = RawManifest::parse(entry.manifest_raw.clone()) else {
                continue;
            };
            let kind = raw.manifest().kind.clone();
            if peer_filter.is_some_and(|peer| peer != entry.peer_id.to_hex())
                || !row(&mut rows, &kind)
            {
                continue;
            }
            let field = if entry.state == OutboxState::Acked {
                "last_acked_send"
            } else {
                "last_pending_send"
            };
            let record = outbox_summary(entry);
            let current = rows.get_mut(&kind).expect("row exists");
            if current
                .get(field)
                .and_then(|value| value["updated_at"].as_str().map(str::to_owned))
                .is_none_or(|previous| previous <= entry.updated_at)
            {
                current.insert(field.into(), record);
            }
        }
        for entry in node.store.inbox.values() {
            let Ok(raw) = RawManifest::parse(entry.manifest.clone()) else {
                continue;
            };
            let kind = raw.manifest().kind.clone();
            if peer_filter.is_some_and(|peer| peer != entry.from) || !row(&mut rows, &kind) {
                continue;
            }
            let field = if entry.read {
                "last_read_receive"
            } else {
                "last_unread_receive"
            };
            let current = rows.get_mut(&kind).expect("row exists");
            if current
                .get(field)
                .and_then(|value| value["received_at"].as_str().map(str::to_owned))
                .is_none_or(|previous| previous <= entry.received_at)
            {
                current.insert(
                    field.into(),
                    json!({"id":entry.snapshot_id,"from":entry.from,"received_at":entry.received_at,"title":raw.manifest().title}),
                );
            }
        }
        // A full capsule snapshot lands in neither queue, so the workspace half
        // of a handoff is reported from the capsule's own head and lease.
        let local = node.peer_id();
        let now = now_ms();
        let workspaces = load_workspaces(&self.root)?;
        for (capsule_id, capsule) in &node.store.capsules {
            let Some(record) = capsule
                .label("main")
                .and_then(|label| capsule.snapshot(&label.snapshot_id))
            else {
                continue;
            };
            let kind = record.raw.manifest().kind.clone();
            let origin = record.raw.manifest().origin.peer_id;
            let holder = capsule.active_lease(now).map(|lease| lease.holder);
            if peer_filter.is_some_and(|peer| {
                peer != origin.to_hex() && Some(peer) != holder.map(|id| id.to_hex()).as_deref()
            }) || !row(&mut rows, &kind)
            {
                continue;
            }
            let current = rows.get_mut(&kind).expect("row exists");
            if current
                .get("capsule")
                .and_then(|value| value["received_at"].as_str().map(str::to_owned))
                .is_none_or(|previous| previous <= record.received_at)
            {
                let workspace = workspaces.get(&capsule_id.to_hex());
                let path = workspace.map(|record| record.path.clone());
                let snapshot_id = workspace
                    .and_then(|record| record.snapshot_id)
                    .unwrap_or_else(|| record.raw.snapshot_id());
                current.insert(
                    "capsule".into(),
                    json!({"capsule_id":capsule_id,"snapshot_id":snapshot_id,"origin":origin,"received_at":record.received_at,"lease_holder":holder,"driving":holder == Some(local),"path":path}),
                );
            }
        }
        Ok(Value::Array(
            rows.into_iter()
                .map(|(kind, mut fields)| {
                    let mut object = Map::new();
                    object.insert("kind".into(), json!(kind));
                    for field in [
                        "last_acked_send",
                        "last_pending_send",
                        "last_unread_receive",
                        "last_read_receive",
                        "capsule",
                    ] {
                        let value = fields.remove(field).unwrap_or(Value::Null);
                        object.insert(field.into(), value);
                    }
                    Value::Object(object)
                })
                .collect(),
        ))
    }

    async fn accept(&self, request: &Value) -> Result<Value> {
        let id: Hash = if flag(request, "latest") {
            self.latest_unread(
                required_str(request, "kind")?,
                request.get("from").and_then(Value::as_str),
            )
            .await?
        } else {
            required_str(request, "id")?.parse()?
        };
        let destination = Path::new(required_str(request, "to")?);
        validate_destination(destination)?;
        let replace = request
            .get("replace")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| flag(request, "into"));
        let no_lease = flag(request, "no_lease");
        let discard_local = flag(request, "discard_local");
        let allow_divergence = flag(request, "allow_divergence");
        let workspace = request
            .get("workspace")
            .and_then(Value::as_str)
            .map(PathBuf::from);
        let inbox_entry = self.locked_node().await?.store.inbox.get(&id).cloned();
        let mut linked_capsule = None;
        let mut remote_peer = None;
        let mut imported = None;
        if let Some(entry) = inbox_entry {
            remote_peer = Some(entry.from.parse::<PeerId>()?);
            let raw = RawManifest::parse(entry.manifest)?;
            if replace {
                return Err("--replace requires a full capsule snapshot".into());
            }
            // A linked handoff restores its workspace before the adapter runs,
            // so the importer sees the tree the sender exported against.
            let restore = match &workspace {
                Some(dir) => {
                    let provenance = raw.manifest().provenance.clone().ok_or(
                        "--workspace requires a delivery whose manifest carries provenance",
                    )?;
                    linked_capsule = Some(provenance.capsule_id);
                    Some(
                        self.materialize_provenance(
                            &provenance,
                            dir,
                            wait_timeout(request),
                            no_lease,
                            discard_local,
                            allow_divergence,
                        )
                        .await?,
                    )
                }
                None => None,
            };
            match self
                .import_partial(&raw, destination, workspace.as_deref(), request)
                .await
            {
                Ok(import) => imported = import,
                Err(error) => {
                    if let Some(restore) = restore {
                        let node = self.locked_node().await?;
                        if let Err(rollback) = restore.apply(&self.root, &node.store.cas) {
                            return Err(
                                format!("{error}; workspace rollback failed: {rollback}").into()
                            );
                        }
                        return Err(format!("{error}; workspace was restored").into());
                    }
                    return Err(error);
                }
            }
            self.locked_node().await?.store.mark_inbox_read(id)?;
        } else {
            if workspace.is_some() {
                return Err("--workspace applies to a partial delivery".into());
            }
            let mut node = self.locked_node().await?;
            let raw = find_snapshot(&node, &id.to_hex())?;
            if let Some(capsule_id) = raw.manifest().capsule_id {
                let identity_path = destination.join(".abra/capsule_id");
                if identity_path.exists() && read_capsule_id(destination)? != capsule_id {
                    return Err("destination belongs to a different capsule".into());
                }
                if replace {
                    replacement_guards(
                        &node,
                        destination,
                        id,
                        capsule_id,
                        discard_local,
                        allow_divergence,
                    )?;
                    if !no_lease {
                        ensure_lease(&mut node, &self.root, capsule_id)?;
                    }
                }
            }
            if let Some(files) = raw.manifest().files {
                if replace {
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
            materialize_recipes(destination, raw.manifest())?;
            if let Some(capsule_id) = raw.manifest().capsule_id {
                write_workspace_metadata(destination, capsule_id, id)?;
                record_workspace(&self.root, capsule_id, destination, Some(id))?;
            }
        }
        let mut result = json!({"accepted":id,"to":destination,"replace":replace});
        if let Some(import) = imported {
            result["import"] = import;
        }
        if let Some(dir) = workspace {
            record_event(
                &self.root,
                "linked-accept",
                json!({"snapshot_id":id,"capsule_id":linked_capsule,"workspace":dir,"peer":remote_peer}),
            )?;
            result["workspace"] = json!(dir);
        }
        Ok(result)
    }

    /// Materialize a partial's files and hand them to a registered importer.
    /// Returns the adapter's `{result, deep_link?}` reply when one ran.
    async fn import_partial(
        &self,
        raw: &RawManifest,
        destination: &Path,
        workspace: Option<&Path>,
        request: &Value,
    ) -> Result<Option<Value>> {
        if let Some(files) = raw.manifest().files {
            let node = self.locked_node().await?;
            materialize(&node.store.cas, &files, destination)?;
        }
        materialize_recipes(destination, raw.manifest())?;
        // `--no-import` leaves the files for another tool to consume, such as
        // the sandbox coordinator pushing a browser bundle into a remote browser.
        if flag(request, "no_import") {
            return Ok(None);
        }
        let registry = self.registry()?;
        // The adapter runs unlocked: an import may take minutes.
        if !registry
            .for_kind(&raw.manifest().kind)
            .is_some_and(|adapter| adapter.supports("import"))
        {
            return Ok(None);
        }
        secure_adapter_tree(destination)?;
        let options = adapter_options(request)?;
        let mut destination_value = request
            .get("destination")
            .and_then(Value::as_str)
            .map(json_object_or_string)
            .unwrap_or_else(|| json!(destination));
        // An adapter such as codex-session finds the restored tree here.
        if let (Some(workspace), Some(object)) = (workspace, destination_value.as_object_mut()) {
            object.insert("workspace".into(), json!(workspace));
        }
        let import = registry
            .import_with_workspace(
                &raw.manifest().kind,
                Value::Object(raw.manifest().payload.clone()),
                raw.manifest().files.map(|_| destination),
                destination_value,
                workspace,
                &options,
                None,
            )
            .await
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                format!(
                    "adapter import failed; inbox entry remains unread; files_materialized_at={}: {error}",
                    destination.display()
                )
                .into()
            })?;
        Ok(Some(import))
    }

    /// Wait for the referenced full snapshot, then put that workspace on disk.
    /// Deliveries are independent, so the companion usually but not always
    /// arrives first.
    async fn materialize_provenance(
        &self,
        provenance: &Provenance,
        workspace: &Path,
        timeout: Duration,
        no_lease: bool,
        discard_local: bool,
        allow_divergence: bool,
    ) -> Result<WorkspaceRestore> {
        validate_destination(workspace)?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self
                .locked_node()
                .await?
                .store
                .capsules
                .get(&provenance.capsule_id)
                .is_some_and(|capsule| capsule.snapshot(&provenance.snapshot_id).is_some())
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "workspace snapshot {} did not arrive within {}ms",
                    provenance.snapshot_id,
                    timeout.as_millis()
                )
                .into());
            }
            tokio::time::sleep(WAIT_POLL).await;
        }
        let mut node = self.locked_node().await?;
        let raw = find_snapshot(&node, &provenance.snapshot_id.to_hex())?;
        let files = raw
            .manifest()
            .files
            .ok_or("workspace snapshot has no files")?;
        let existing = workspace.join(".abra/capsule_id").exists();
        let previous_record = load_workspaces(&self.root)?
            .get(&provenance.capsule_id.to_hex())
            .cloned();
        let restore = if existing {
            if read_capsule_id(workspace)? != provenance.capsule_id {
                return Err("workspace belongs to a different capsule".into());
            }
            replacement_guards(
                &node,
                workspace,
                provenance.snapshot_id,
                provenance.capsule_id,
                discard_local,
                allow_divergence,
            )?;
            WorkspaceRestore::Replace {
                path: workspace.to_path_buf(),
                capsule: provenance.capsule_id,
                files: snapshot_dir(&node.store.cas, workspace)?,
                snapshot: fs::read_to_string(workspace.join(".abra/snapshot_id"))
                    .ok()
                    .and_then(|value| value.trim().parse().ok()),
                previous_record,
            }
        } else {
            WorkspaceRestore::Remove {
                path: workspace.to_path_buf(),
                capsule: provenance.capsule_id,
                previous_record,
            }
        };
        if existing {
            replace_workspace(&node.store.cas, files, workspace, provenance.capsule_id)?;
        } else {
            materialize(&node.store.cas, &files, workspace)?;
        }
        materialize_recipes(workspace, raw.manifest())?;
        write_workspace_metadata(workspace, provenance.capsule_id, provenance.snapshot_id)?;
        record_workspace(
            &self.root,
            provenance.capsule_id,
            workspace,
            Some(provenance.snapshot_id),
        )?;
        if !no_lease {
            ensure_lease(&mut node, &self.root, provenance.capsule_id)?;
        }
        Ok(restore)
    }

    async fn log(&self, request: &Value) -> Result<Value> {
        let node = self.locked_node().await?;
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
        let node = self.locked_node().await?;
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
        let node = self.locked_node().await?;
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
            lease_acquire: flag(request, "lease_acquire"),
            lease_takeover: flag(request, "lease_takeover"),
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
    fn load_grants(&self) -> Result<BTreeMap<String, ReceiveGrant>> {
        match fs::read(self.grants_path()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(error.into()),
        }
    }
    fn save_grants(&self, grant: ReceiveGrant) -> Result<()> {
        update_json_file(
            &self.grants_path(),
            |grants: &mut BTreeMap<String, ReceiveGrant>| {
                grants.insert(grant.id.clone(), grant);
                Ok(())
            },
        )
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
        let destination = request.get("to").and_then(Value::as_str).map(PathBuf::from);
        let forward: Option<PeerId> = request
            .get("forward")
            .and_then(Value::as_str)
            .map(str::parse)
            .transpose()?;
        if auto_accept {
            validate_destination(destination.as_deref().ok_or("auto-accept requires --to")?)?;
        }
        if forward.is_some() && !auto_accept {
            return Err("--forward requires --auto-accept".into());
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
            destination,
            forward,
        };
        self.save_grants(grant.clone())?;
        Ok(serde_json::to_value(grant)?)
    }
    async fn apply_receive_grants(
        &self,
        delivering_peer: PeerId,
        changed_heads: &std::collections::BTreeSet<Hash>,
    ) -> Result<()> {
        let grants = self.load_grants()?;
        if grants.is_empty() {
            return Ok(());
        }
        let failed_grants = load_grant_errors(&self.root)?;
        let unread = {
            let node = self.locked_node().await?;
            node.store
                .inbox
                .values()
                .filter(|entry| !entry.read)
                .cloned()
                .collect::<Vec<_>>()
        };
        for entry in unread {
            let raw = RawManifest::parse(entry.manifest.clone())?;
            let from: PeerId = entry.from.parse()?;
            if from != delivering_peer || failed_grants.contains_key(&entry.snapshot_id.to_hex()) {
                continue;
            }
            let Some(grant) = grants.values().find(|grant| {
                grant.auto_accept && grant.peer == from && grant.kind == raw.manifest().kind
            }) else {
                continue;
            };
            let destination_root = grant
                .destination
                .as_deref()
                .ok_or("grant lacks destination")?;
            validate_destination(destination_root)?;
            let destination = destination_root.join(entry.snapshot_id.to_hex());
            validate_destination(&destination)?;
            // The same materialize-then-import path `accept` runs, so a grant
            // leaves the adapter's work done rather than only files on disk.
            let import = match self
                .import_partial(&raw, &destination, None, &json!({}))
                .await
            {
                Ok(import) => import,
                Err(error) => {
                    record_grant_error(&self.root, entry.snapshot_id, &error.to_string())?;
                    continue;
                }
            };
            self.locked_node()
                .await?
                .store
                .mark_inbox_read(entry.snapshot_id)?;
            let mut accepted = json!({"snapshot_id":entry.snapshot_id,"kind":raw.manifest().kind,"to":destination,"peer":from});
            if let Some(import) = import {
                accepted["import"] = import;
            }
            record_event(&self.root, "auto-accepted", accepted)?;
            self.forward_grant(grant, &raw, from).await?;
        }
        // Capsule heads are collected first: materializing and forwarding both
        // need the node, and the store cannot stay borrowed across them.
        let mut heads = Vec::new();
        {
            let node = self.locked_node().await?;
            for (capsule_id, capsule) in &node.store.capsules {
                let Some(head) = capsule.label("main").map(|label| label.snapshot_id) else {
                    continue;
                };
                if !changed_heads.contains(&head) || failed_grants.contains_key(&head.to_hex()) {
                    continue;
                }
                let Some(record) = capsule.snapshot(&head) else {
                    continue;
                };
                let raw = &record.raw;
                let Some(grant) = grants.values().find(|grant| {
                    grant.auto_accept
                        && grant.peer == delivering_peer
                        && grant.kind == raw.manifest().kind
                        && grant.capsule.is_none_or(|allowed| allowed == *capsule_id)
                }) else {
                    continue;
                };
                let destination_root = grant
                    .destination
                    .as_deref()
                    .ok_or("grant lacks destination")?;
                validate_destination(destination_root)?;
                let destination = destination_root.join(capsule_id.to_hex());
                validate_destination(&destination)?;
                if fs::read_to_string(destination.join(".abra/snapshot_id"))
                    .is_ok_and(|current| current == head.to_hex())
                {
                    continue;
                }
                heads.push((*capsule_id, head, raw.clone(), grant.clone(), destination));
            }
        }
        for (capsule_id, head, raw, grant, destination) in heads {
            let Some(files) = raw.manifest().files else {
                continue;
            };
            let result = {
                let node = self.locked_node().await?;
                if destination.join(".abra/capsule_id").exists() {
                    replacement_guards(&node, &destination, head, capsule_id, false, false)
                        .and_then(|()| {
                            replace_workspace(&node.store.cas, files, &destination, capsule_id)
                        })
                } else {
                    materialize(&node.store.cas, &files, &destination).map_err(Into::into)
                }
            };
            if let Err(error) = result {
                record_grant_error(&self.root, head, &error.to_string())?;
                continue;
            }
            if let Err(error) = write_workspace_metadata(&destination, capsule_id, head) {
                record_grant_error(&self.root, head, &error.to_string())?;
                continue;
            }
            record_workspace(&self.root, capsule_id, &destination, Some(head))?;
            // A mirror never takes the lease: the delivering peer keeps
            // driving, and its next snapshot must not land here as a fork.
            record_event(
                &self.root,
                "auto-accepted-full",
                json!({"capsule_id":capsule_id,"snapshot_id":head,"to":destination,"peer":delivering_peer}),
            )?;
            record_event(
                &self.root,
                "auto-accepted",
                json!({"capsule_id":capsule_id,"snapshot_id":head,"kind":raw.manifest().kind,"to":destination,"peer":delivering_peer}),
            )?;
            self.forward_grant(&grant, &raw, delivering_peer).await?;
        }
        Ok(())
    }
    /// "Receive, process, pass it on": a grant may re-deliver what it accepted
    /// to one more peer, so a filtering middleman needs no separate send.
    async fn forward_grant(
        &self,
        grant: &ReceiveGrant,
        raw: &RawManifest,
        delivering_peer: PeerId,
    ) -> Result<()> {
        let Some(peer) = grant.forward else {
            return Ok(());
        };
        let reason = if peer == delivering_peer {
            Some("delivering-peer")
        } else if peer == raw.manifest().origin.peer_id {
            Some("manifest-origin")
        } else {
            None
        };
        if let Some(reason) = reason {
            record_event(
                &self.root,
                "auto-forward-skipped",
                json!({"snapshot_id":raw.snapshot_id(),"peer":peer,"reason":reason}),
            )?;
            return Ok(());
        }
        let key = format!("{}:{peer}", raw.snapshot_id());
        let inserted = update_json_file(
            &self.root.join("policy/forwarded.json"),
            |forwarded: &mut std::collections::BTreeSet<String>| Ok(forwarded.insert(key.clone())),
        )?;
        if !inserted {
            record_event(
                &self.root,
                "auto-forward-skipped",
                json!({"snapshot_id":raw.snapshot_id(),"peer":peer,"reason":"already-forwarded"}),
            )?;
            return Ok(());
        }
        let id = match self.locked_node().await?.enqueue(peer, raw, now_ms()) {
            Ok(id) => id,
            Err(error) => {
                update_json_file(
                    &self.root.join("policy/forwarded.json"),
                    |forwarded: &mut std::collections::BTreeSet<String>| {
                        forwarded.remove(&key);
                        Ok(())
                    },
                )?;
                return Err(error.into());
            }
        };
        record_event(
            &self.root,
            "auto-forwarded",
            json!({"capsule_id":raw.manifest().capsule_id,"snapshot_id":raw.snapshot_id(),"peer":peer,"outbox_id":id}),
        )?;
        Ok(())
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
        let node = self.locked_node().await?;
        let cap = node.store.capsules.get(&capsule).ok_or("unknown capsule")?;
        Ok(
            json!({"capsule":capsule,"winning":cap.winning_lease(),"active":cap.active_lease(now_ms()).is_some()}),
        )
    }
    async fn lease_take(&self, request: &Value) -> Result<Value> {
        let capsule: Hash = required_str(request, "capsule")?.parse()?;
        let mut node = self.locked_node().await?;
        local_lease_allowed(&node.trust, true, now_ms())?;
        let record = take_lease(&mut node, &self.root, capsule)?;
        Ok(serde_json::to_value(record)?)
    }
    async fn renew_leases(&self) -> Result<()> {
        let mut node = self.detached_node()?;
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
                &json!({"event":"lease-change","at":format_time(now_ms()),"capsule_id":capsule,"lease":record}),
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
            let node = self.locked_node().await?;
            if node.trust.get(&peer).is_none() {
                return Err("unknown or untrusted control recipient".into());
            }
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
            let mut session = self.locked_node().await?.outgoing_session();
            let peer_id = session.peer_id();
            dial_handshake_with_trust(
                &mut connection,
                peer_id,
                "abra".into(),
                &mut session.trust,
                now_ms(),
            )
            .await?;
        }
        drop(self.locked_node().await?);
        let (send, recv) = connection.control_mut();
        write_frame(send, &message).await?;
        // A refused control is an answer, not a transport failure: the caller
        // wants the peer's `error` and any `result` it managed to produce.
        let ack: ControlAck = abra_net::read_frame_timeout(
            recv,
            abra_net::CONTROL_HANDLER_TIMEOUT + Duration::from_secs(30),
        )
        .await
        .map_err(|error| match error {
            abra_net::Error::Timeout => "control ack timed out".into(),
            error => Box::new(error) as Box<dyn std::error::Error + Send + Sync>,
        })?;
        Ok(serde_json::to_value(ack)?)
    }
}

/// Receiver-side routing of verified control messages to adapters. Everything
/// it needs is durable state, so each message reads the store and the registry
/// fresh instead of borrowing the daemon's node.
struct ControlRouter {
    root: PathBuf,
    adapter_sources: Vec<adapters::ExtraAdapterDir>,
}

#[async_trait::async_trait]
impl abra_net::ControlHandler for ControlRouter {
    async fn handle(&self, from: PeerId, message: &ControlMessage) -> abra_net::Result<Value> {
        self.route(from, message)
            .await
            .map_err(|error| abra_net::Error::Protocol(error.to_string()))
    }
}

impl ControlRouter {
    async fn route(&self, from: PeerId, message: &ControlMessage) -> Result<Value> {
        let op = match message.op {
            ControlOp::Pause => "pause",
            ControlOp::Stop => "stop",
            ControlOp::Instruct => "instruct",
        };
        let kind = abra_core::store::AbraStore::open(&self.root)?
            .capsules
            .get(&message.capsule_id)
            .map(|capsule| capsule.genesis.kind.clone());
        let registry = adapters::AdapterRegistry::discover_with(&self.root, &self.adapter_sources)?;
        let adapter = kind
            .as_deref()
            .and_then(|kind| registry.for_control(kind))
            .map(|adapter| adapter.manifest.name.clone());
        let outcome = match (&kind, &adapter) {
            (Some(kind), Some(_)) => {
                let key = message.capsule_id.to_hex();
                let workspace = update_json_file(
                    &workspaces_path(&self.root),
                    |workspaces: &mut BTreeMap<String, WorkspaceRecord>| {
                        let workspace = workspaces.get(&key).and_then(|record| {
                            (record.path.is_dir()
                                && read_capsule_id(&record.path).ok() == Some(message.capsule_id))
                            .then(|| record.path.clone())
                        });
                        if workspace.is_none() {
                            workspaces.remove(&key);
                        }
                        Ok(workspace)
                    },
                )?;
                registry
                    .control(
                        &adapters::ControlRequest {
                            kind: kind.clone(),
                            capsule_id: message.capsule_id,
                            op: op.into(),
                            text: message.text.clone(),
                            workspace,
                            options: BTreeMap::new(),
                        },
                        None,
                    )
                    .await
            }
            // No adapter: the built-in behaviour is that the message is now on
            // record, which is all `pause` and `stop` ever promised.
            _ if matches!(message.op, ControlOp::Pause | ControlOp::Stop) => {
                Ok(json!({"recorded":true}))
            }
            _ => Err(format!(
                "no adapter handles control for {}",
                kind.as_deref().unwrap_or("unknown capsule")
            )
            .into()),
        };
        record_event(
            &self.root,
            "control-handled",
            json!({"capsule_id":message.capsule_id,"op":op,"ok":outcome.is_ok(),"adapter":adapter,"peer":from}),
        )?;
        outcome
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

/// What one workspace snapshot produced.
struct WorkspaceSnapshot {
    capsule_id: Hash,
    snapshot_id: Hash,
    forked: bool,
}

/// How to undo a workspace materialization when a later step fails.
enum WorkspaceRestore {
    /// The directory did not exist before.
    Remove {
        path: PathBuf,
        capsule: Hash,
        previous_record: Option<WorkspaceRecord>,
    },
    /// The previous contents, captured in CAS before they were replaced.
    Replace {
        path: PathBuf,
        capsule: Hash,
        files: Hash,
        snapshot: Option<Hash>,
        previous_record: Option<WorkspaceRecord>,
    },
}

impl WorkspaceRestore {
    fn apply(self, root: &Path, store: &abra_core::cas::BlobStore) -> Result<()> {
        match self {
            Self::Remove {
                path,
                capsule,
                previous_record,
            } => {
                fs::remove_dir_all(path)?;
                restore_workspace_record(root, capsule, previous_record)
            }
            Self::Replace {
                path,
                capsule,
                files,
                snapshot,
                previous_record,
            } => {
                replace_workspace(store, files, &path, capsule)?;
                match snapshot {
                    Some(snapshot) => write_workspace_metadata(&path, capsule, snapshot),
                    None => {
                        let _ = fs::remove_file(path.join(".abra/snapshot_id"));
                        Ok(())
                    }
                }?;
                restore_workspace_record(root, capsule, previous_record)
            }
        }
    }
}

fn flag(request: &Value, key: &str) -> bool {
    request.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn wait_timeout(request: &Value) -> Duration {
    Duration::from_millis(
        request
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_WAIT_MS),
    )
}

fn is_workspace_dir(path: &Path) -> bool {
    path.is_dir() && path.join(".abra/capsule_id").is_file()
}

fn state_name(state: OutboxState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn outbox_summary(entry: &OutboxEntry) -> Value {
    json!({
        "id": entry.id,
        "peer_id": entry.peer_id,
        "snapshot_id": entry.snapshot_id,
        "state": entry.state,
        "attempts": entry.attempts,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
        "acked_at": (entry.state == OutboxState::Acked).then(|| entry.updated_at.clone()),
        "ack_sig": entry.ack_sig,
        "last_error": entry.last_error,
    })
}

/// Sign a takeover of `capsule` for the local device and record it.
fn take_lease(node: &mut DeliveryNode, root: &Path, capsule: Hash) -> Result<LeaseRecord> {
    let previous = node
        .store
        .capsules
        .get(&capsule)
        .ok_or("unknown capsule")?
        .winning_lease()
        .cloned()
        .ok_or("capsule lacks lease")?;
    let local = node.peer_id();
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
        root,
        &json!({"event":"lease-change","at":format_time(now_ms()),"capsule_id":capsule,"lease":record}),
    )?;
    Ok(record)
}

/// Take the lease before authoring so an ordinary handoff produces a new head
/// rather than a fork. A guest that its issuer did not authorize keeps the old
/// forking behaviour instead of failing.
fn ensure_lease(
    node: &mut DeliveryNode,
    root: &Path,
    capsule: Hash,
) -> Result<Option<LeaseRecord>> {
    let local = node.peer_id();
    let now = now_ms();
    let held = node
        .store
        .capsules
        .get(&capsule)
        .ok_or("unknown capsule")?
        .active_lease(now)
        .is_some_and(|lease| lease.holder == local);
    if held {
        return Ok(None);
    }
    if local_lease_allowed(&node.trust, true, now).is_err() {
        return Ok(None);
    }
    take_lease(node, root, capsule).map(Some)
}

fn local_lease_allowed(trust: &abra_net::TrustStore, takeover: bool, now: u64) -> Result<()> {
    let LocalRole::Guest { token } = trust.local_role() else {
        return Ok(());
    };
    token.verify(now)?;
    let allowed = if takeover {
        token.scopes.lease_takeover
    } else {
        token.scopes.lease_acquire
    };
    if allowed {
        Ok(())
    } else {
        Err(format!(
            "local guest token does not allow lease {}",
            if takeover { "takeover" } else { "acquire" }
        )
        .into())
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

#[cfg(any(test, feature = "iroh", feature = "tcp"))]
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

#[cfg(any(test, feature = "iroh", feature = "tcp"))]
fn persist_port(path: &Path, port: u16) -> Result<()> {
    abra_core::atomic_write(path, port.to_string().as_bytes())?;
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

fn valid_observation_barrier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn load_workspace_observation(
    path: &Path,
    manifest: &mut Manifest,
    barrier: Option<&str>,
    host: Option<&Value>,
) -> Result<()> {
    if host.is_some() && barrier.is_none() {
        return Err("observation_host requires observation_barrier".into());
    }
    let filename = match barrier {
        Some(id) if valid_observation_barrier(id) => format!("observed-{id}.json"),
        Some(_) => return Err("invalid observation barrier: use 1 to 64 ASCII letters, digits, underscores or hyphens".into()),
        None => "observed.json".into(),
    };
    let observed_path = path.join(".abra").join(&filename);
    if barrier.is_some() || fs::symlink_metadata(&observed_path).is_ok() {
        let mut bytes = Vec::new();
        open_metadata_file(path, &filename)?
            .take(MAX_OBSERVED_READ + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_OBSERVED_READ {
            return Err("observed.json exceeds 1 MiB".into());
        }
        let mut observed = serde_json::from_slice::<Value>(&bytes)?
            .as_object()
            .cloned()
            .ok_or("observed.json must be a JSON object")?;
        if let Some(id) = barrier {
            if observed.get("schema").and_then(Value::as_str) != Some("dev.abra.observed/3")
                || observed
                    .get("observer")
                    .and_then(|o| o.get("version"))
                    .and_then(Value::as_u64)
                    != Some(3)
                || observed["observer"]["mode"].as_str() != Some("once")
                || observed["observer"]["barrier"].as_str() != Some(id)
            {
                return Err("observer capture schema, mode or barrier mismatch".into());
            }
            let start = observed["observer"]["capture_started_at"]
                .as_str()
                .ok_or("observer capture lacks start time")?;
            let end = observed["observer"]["capture_finished_at"]
                .as_str()
                .ok_or("observer capture lacks finish time")?;
            if abra_net::parse_time(start)? > abra_net::parse_time(end)? {
                return Err("observer capture ends before it starts".into());
            }
        }
        if let Some(host) = host {
            if !host.is_object() || serde_json::to_vec(host)?.len() > 16 * 1024 {
                return Err("observation_host must be an object of at most 16 KiB".into());
            }
            observed.insert(
                "host".into(),
                json!({"source":"host-adapter", "facts":host}),
            );
        }
        let recipes: Vec<Recipe> = serde_json::from_value(
            observed
                .remove("recipes")
                .unwrap_or_else(|| Value::Array(Vec::new())),
        )?;
        if !recipes.is_empty() {
            manifest.recipes = Some(recipes);
        }
        if serde_json::to_vec(&observed)?.len() <= MAX_OBSERVED_EXTENSION {
            manifest
                .extensions
                .get_or_insert_with(Map::new)
                .insert("dev.abra.observed".into(), Value::Object(observed));
        } else if barrier.is_some() {
            return Err("checkpoint observation exceeds 256 KiB".into());
        } else {
            eprintln!(
                "cadabra: WARNING: observed.json ledger exceeds 256 KiB; embedding recipes only"
            );
        }
        return Ok(());
    }

    let recipes_path = path.join(".abra/recipes.json");
    if recipes_path.is_file() {
        let recipes: Vec<Recipe> = serde_json::from_slice(&fs::read(&recipes_path)?)?;
        manifest.recipes = Some(recipes);
    }
    Ok(())
}

fn materialize_recipes(destination: &Path, manifest: &Manifest) -> Result<()> {
    if let Some(recipes) = &manifest.recipes {
        write_metadata_file(destination, "recipes.json", &serde_json::to_vec(recipes)?)?;
    } else if manifest
        .extensions
        .as_ref()
        .is_some_and(|extensions| extensions.contains_key("dev.abra.observed"))
    {
        // A capture with no complete recipe must not leave a previous recipe runnable.
        write_metadata_file(destination, "recipes.json", b"[]")?;
    }
    if let Some(observed) = manifest
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get("dev.abra.observed"))
    {
        write_metadata_file(
            destination,
            "received-observed.json",
            &serde_json::to_vec(observed)?,
        )?;
    }
    Ok(())
}

fn replacement_guards(
    node: &DeliveryNode,
    destination: &Path,
    incoming: Hash,
    capsule: Hash,
    discard_local: bool,
    allow_divergence: bool,
) -> Result<()> {
    let recorded = match fs::read_to_string(destination.join(".abra/snapshot_id")) {
        Ok(value) => value.trim().parse::<Hash>()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let Some(cap) = node.store.capsules.get(&capsule) else {
        return Ok(());
    };
    if !discard_local {
        // Skip when the recorded snapshot is not in the local store: nothing
        // to compare against.
        if let Some(files) = cap
            .snapshot(&recorded)
            .and_then(|record| record.raw.manifest().files)
        {
            if snapshot_dir(&node.store.cas, destination)? != files {
                return Err(format!(
                    "workspace has local changes since snapshot {recorded}; pass --discard-local to overwrite them"
                )
                .into());
            }
        }
    }
    if !allow_divergence && !cap.descends_from(incoming, recorded) {
        return Err(format!(
            "snapshot {incoming} does not descend from workspace snapshot {recorded}; pass --allow-divergence to replace anyway"
        )
        .into());
    }
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
        return Err("--replace workspace belongs to a different capsule".into());
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
    update_json_file(
        &grant_errors_path(root),
        |errors: &mut BTreeMap<String, String>| {
            errors.insert(snapshot.to_hex(), error.to_owned());
            Ok(())
        },
    )
}

fn clear_grant_errors(root: &Path) -> Result<()> {
    update_json_file(
        &grant_errors_path(root),
        |errors: &mut BTreeMap<String, String>| {
            errors.clear();
            Ok(())
        },
    )
}

fn workspaces_path(root: &Path) -> PathBuf {
    root.join("policy/workspaces.json")
}

fn load_workspaces(root: &Path) -> Result<BTreeMap<String, WorkspaceRecord>> {
    match fs::read(workspaces_path(root)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error.into()),
    }
}

/// Remember where a capsule now lives on this device. Every path that puts a
/// capsule on disk calls this, so `control` can name the directory.
fn record_workspace(root: &Path, capsule: Hash, path: &Path, snapshot: Option<Hash>) -> Result<()> {
    update_json_file(
        &workspaces_path(root),
        |workspaces: &mut BTreeMap<String, WorkspaceRecord>| {
            workspaces.insert(
                capsule.to_hex(),
                WorkspaceRecord {
                    path: path.to_path_buf(),
                    snapshot_id: snapshot,
                    at: format_time(now_ms()),
                },
            );
            Ok(())
        },
    )
}

fn restore_workspace_record(
    root: &Path,
    capsule: Hash,
    previous: Option<WorkspaceRecord>,
) -> Result<()> {
    update_json_file(
        &workspaces_path(root),
        |workspaces: &mut BTreeMap<String, WorkspaceRecord>| {
            match previous {
                Some(record) => {
                    workspaces.insert(capsule.to_hex(), record);
                }
                None => {
                    workspaces.remove(&capsule.to_hex());
                }
            }
            Ok(())
        },
    )
}

fn update_json_file<T, R>(path: &Path, update: impl FnOnce(&mut T) -> Result<R>) -> Result<R>
where
    T: Serialize + DeserializeOwned + Default,
{
    fs::create_dir_all(path.parent().expect("json file parent"))?;
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let mut value = match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => T::default(),
        Err(error) => return Err(error.into()),
    };
    let result = update(&mut value)?;
    abra_core::atomic_write(path, &serde_json::to_vec(&value)?)?;
    fs2::FileExt::unlock(&lock)?;
    Ok(result)
}

/// Append one `{"event":...,"at":...}` line. Names are stable API: `watch`
/// consumers match on them.
fn record_event(root: &Path, event: &str, fields: Value) -> Result<()> {
    let mut object = Map::new();
    object.insert("event".into(), json!(event));
    object.insert("at".into(), json!(format_time(now_ms())));
    if let Value::Object(extra) = fields {
        object.extend(extra);
    }
    record_event_file(root, &Value::Object(object))
}

fn record_event_file(root: &Path, value: &Value) -> Result<()> {
    abra_net::append_event(root, value).map_err(Into::into)
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
    use std::os::unix::fs::PermissionsExt;
    let directory = open_metadata_dir(destination, true)?;
    let mut file = File::from(openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
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

fn ingest_thumbnail(store: &abra_core::cas::BlobStore, path: &Path) -> Result<Thumbnail> {
    let data = fs::read(path)?;
    if data.is_empty() || data.len() > 512 * 1024 {
        return Err("adapter thumbnail must be 1 to 512 KiB".into());
    }
    let media_type = if data.starts_with(&[0x89, b'P', b'N', b'G']) {
        "image/png"
    } else if data.len() >= 2 && data[0] == 0xff && data[1] == 0xd8 {
        "image/jpeg"
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        "image/webp"
    } else {
        return Err("adapter thumbnail must be jpeg, png, or webp".into());
    };
    let (blob, bytes) = store.put_file(path)?;
    Ok(Thumbnail {
        blob,
        media_type: media_type.into(),
        bytes,
    })
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

    fn observation_manifest(root: &Path) -> Manifest {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let node = DeliveryNode::open(root).unwrap();
        base_manifest(&node, Scope::Full, "dev.abra.workspace", "workspace")
    }

    fn recipe_json() -> Value {
        json!({"argv":["python3","-m","http.server","8123"],"cwd":".","ports":[8123]})
    }

    fn checkpoint_ledger(barrier: &str) -> Value {
        json!({"schema":"dev.abra.observed/3", "observer":{
            "version":3, "mode":"once", "barrier":barrier,
            "capture_started_at":"2026-09-04T00:00:00.000Z",
            "capture_finished_at":"2026-09-04T00:00:01.000Z"
        }, "service_candidates":[{"restartability":"blocked"}], "recipes":[]})
    }

    #[test]
    fn checkpoint_uses_selected_capture_despite_periodic_updates() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".abra")).unwrap();
        fs::write(
            root.path().join(".abra/observed-chosen.json"),
            serde_json::to_vec(&checkpoint_ledger("chosen")).unwrap(),
        )
        .unwrap();
        fs::write(
            root.path().join(".abra/observed.json"),
            b"invalid live data",
        )
        .unwrap();
        let mut manifest = observation_manifest(root.path());
        let host = json!({"configured_resources":{"cpus":2}});
        load_workspace_observation(root.path(), &mut manifest, Some("chosen"), Some(&host))
            .unwrap();
        let observed = &manifest.extensions.as_ref().unwrap()["dev.abra.observed"];
        assert_eq!(observed["observer"]["barrier"], "chosen");
        assert_eq!(observed["host"]["facts"], host);
        assert_eq!(
            observed["service_candidates"][0]["restartability"],
            "blocked"
        );
        assert!(manifest.recipes.is_none());
    }

    #[test]
    fn checkpoint_rejects_missing_mismatched_and_invalid_captures() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".abra")).unwrap();
        fs::write(
            root.path().join(".abra/observed.json"),
            serde_json::to_vec(&checkpoint_ledger("chosen")).unwrap(),
        )
        .unwrap();
        let mut manifest = observation_manifest(root.path());
        for id in ["chosen", "../observed", "", "é", "invalid/name"] {
            assert!(
                load_workspace_observation(root.path(), &mut manifest, Some(id), None).is_err()
            );
        }
        let path = root.path().join(".abra/observed-chosen.json");
        for (field, value) in [
            ("barrier", json!("wrong")),
            ("mode", json!("periodic")),
            ("version", json!(2)),
            ("capture_finished_at", json!("2025-01-01T00:00:00.000Z")),
        ] {
            let mut ledger = checkpoint_ledger("chosen");
            ledger["observer"][field] = value;
            fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
            assert!(
                load_workspace_observation(root.path(), &mut manifest, Some("chosen"), None)
                    .is_err()
            );
        }
        let mut ledger = checkpoint_ledger("chosen");
        ledger["padding"] = json!("x".repeat(MAX_OBSERVED_EXTENSION));
        fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
        assert!(
            load_workspace_observation(root.path(), &mut manifest, Some("chosen"), None).is_err()
        );
    }

    #[test]
    fn checkpoint_refuses_symlink_and_clears_stale_received_recipes() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".abra")).unwrap();
        let mut manifest = observation_manifest(root.path());
        #[cfg(unix)]
        {
            let target = root.path().join("ledger.json");
            fs::write(
                &target,
                serde_json::to_vec(&checkpoint_ledger("chosen")).unwrap(),
            )
            .unwrap();
            std::os::unix::fs::symlink(&target, root.path().join(".abra/observed-chosen.json"))
                .unwrap();
            assert!(
                load_workspace_observation(root.path(), &mut manifest, Some("chosen"), None)
                    .is_err()
            );
        }
        manifest.extensions = Some(Map::from_iter([(
            "dev.abra.observed".into(),
            checkpoint_ledger("chosen"),
        )]));
        fs::write(
            root.path().join(".abra/recipes.json"),
            serde_json::to_vec(&json!([recipe_json()])).unwrap(),
        )
        .unwrap();
        materialize_recipes(root.path(), &manifest).unwrap();
        assert_eq!(
            fs::read(root.path().join(".abra/recipes.json")).unwrap(),
            b"[]"
        );
    }

    #[test]
    fn observed_json_adds_recipes_and_ledger_extension() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".abra")).unwrap();
        fs::write(
            root.path().join(".abra/observed.json"),
            serde_json::to_vec(&json!({
                "observer":{"version":2},
                "platform":{"arch":"x86_64"},
                "recipes":[recipe_json()]
            }))
            .unwrap(),
        )
        .unwrap();
        let mut manifest = observation_manifest(root.path());

        load_workspace_observation(root.path(), &mut manifest, None, None).unwrap();

        assert_eq!(manifest.recipes.as_ref().unwrap()[0].ports, vec![8123]);
        let observed = &manifest.extensions.as_ref().unwrap()["dev.abra.observed"];
        assert_eq!(observed["observer"]["version"], 2);
        assert!(observed.get("recipes").is_none());

        let node = DeliveryNode::open(root.path()).unwrap();
        manifest.capsule_id = Some(Hash::from_bytes([1; 32]));
        manifest.parents = Some(Vec::new());
        manifest.files = Some(
            node.store
                .cas
                .put_tree(&Tree::new(Vec::new()).unwrap())
                .unwrap(),
        );
        manifest.sign(&node.store.keys.identity).unwrap();
        let raw = RawManifest::parse(manifest.to_canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            raw.manifest().extensions.as_ref().unwrap()["dev.abra.observed"]["platform"]["arch"],
            "x86_64"
        );
    }

    #[test]
    fn recipes_json_is_the_observer_fallback() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".abra")).unwrap();
        fs::write(
            root.path().join(".abra/recipes.json"),
            serde_json::to_vec(&json!([recipe_json()])).unwrap(),
        )
        .unwrap();
        let mut manifest = observation_manifest(root.path());

        load_workspace_observation(root.path(), &mut manifest, None, None).unwrap();

        assert_eq!(manifest.recipes.unwrap()[0].ports, vec![8123]);
        assert!(manifest.extensions.is_none());
    }

    #[test]
    fn oversized_observed_ledger_keeps_recipes_only() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".abra")).unwrap();
        fs::write(
            root.path().join(".abra/observed.json"),
            serde_json::to_vec(&json!({
                "platform":{"padding":"x".repeat(MAX_OBSERVED_EXTENSION + 1)},
                "recipes":[recipe_json()]
            }))
            .unwrap(),
        )
        .unwrap();
        let mut manifest = observation_manifest(root.path());

        load_workspace_observation(root.path(), &mut manifest, None, None).unwrap();

        assert_eq!(manifest.recipes.unwrap()[0].ports, vec![8123]);
        assert!(manifest.extensions.is_none());
    }

    #[test]
    fn materialize_writes_received_recipes_and_observation() {
        let root = tempfile::tempdir().unwrap();
        let mut manifest = observation_manifest(root.path());
        manifest.recipes = Some(vec![serde_json::from_value(recipe_json()).unwrap()]);
        manifest.extensions = Some(Map::from_iter([(
            "dev.abra.observed".into(),
            json!({"platform":{"arch":"x86_64"}}),
        )]));

        materialize_recipes(root.path(), &manifest).unwrap();

        assert!(root.path().join(".abra/recipes.json").is_file());
        assert!(root.path().join(".abra/received-observed.json").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.path().join(".abra/recipes.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(root.path().join(".abra/received-observed.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

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
        drop(node);
        let detached = daemon.detached_node().unwrap();
        assert!(detached.skip_native);
        assert_eq!(detached.offer_budget, 1234);
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
    fn grants_written_before_recipe_auto_run_was_removed_still_load() {
        let peer = "ab".repeat(32);
        let json = format!(
            r#"{{"one":{{"id":"one","peer":"{peer}","kind":"dev.abra.bundle","auto_accept":true,"auto_run_recipes":false,"destination":"/tmp/inbox"}}}}"#
        );
        let grants: BTreeMap<String, ReceiveGrant> = serde_json::from_str(&json).unwrap();
        assert!(grants["one"].auto_accept);
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
    fn local_guest_lease_scope_is_checked_without_remote_peer_lookup() {
        let root = tempfile::tempdir().unwrap();
        let mut node = DeliveryNode::open(root.path()).unwrap();
        let now = now_ms();
        let token = EnrollmentToken::mint(
            "guest".into(),
            Vec::new(),
            None,
            Scopes {
                capsules: vec!["*".into()],
                kinds: vec!["*".into()],
                send: false,
                receive: false,
                lease_acquire: false,
                lease_takeover: true,
            },
            now,
            60_000,
            &node.store.keys.identity,
        )
        .unwrap();
        node.trust
            .set_local_role(LocalRole::Guest {
                token: Box::new(token),
            })
            .unwrap();
        assert!(local_lease_allowed(&node.trust, true, now).is_ok());
        assert_eq!(
            local_lease_allowed(&node.trust, false, now)
                .unwrap_err()
                .to_string(),
            "local guest token does not allow lease acquire"
        );
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
