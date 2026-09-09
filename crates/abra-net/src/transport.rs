use crate::{Error, Result};
use abra_core::identity::PeerId;
#[cfg(feature = "tcp")]
use abra_core::identity::{Identity, Signature};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
#[cfg(feature = "tcp")]
use std::{
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(feature = "tcp")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "tcp")]
use tokio::io::{AsyncReadExt, ReadBuf};
#[cfg(feature = "tcp")]
use tokio::net::{TcpListener, TcpStream};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, Mutex as AsyncMutex},
};

pub type ControlSend = Box<dyn AsyncWrite + Send + Sync + Unpin>;
pub type ControlRecv = Box<dyn AsyncRead + Send + Sync + Unpin>;

enum Streams {
    Loopback {
        uni_send: mpsc::Sender<Vec<u8>>,
        uni_recv: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    },
    #[cfg(feature = "tcp")]
    Tcp { send: SharedWrite, recv: SharedRead },
    #[cfg(feature = "iroh")]
    Iroh(iroh::endpoint::Connection),
}

pub struct Connection {
    peer_id: PeerId,
    control_send: ControlSend,
    control_recv: ControlRecv,
    streams: Streams,
    observed_addresses: Vec<String>,
}

impl Connection {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn observed_addresses(&self) -> &[String] {
        &self.observed_addresses
    }
    pub fn control_mut(&mut self) -> (&mut ControlSend, &mut ControlRecv) {
        (&mut self.control_send, &mut self.control_recv)
    }
    pub async fn open_uni(&self, bytes: Vec<u8>) -> Result<()> {
        match &self.streams {
            Streams::Loopback { uni_send, .. } => uni_send
                .send(bytes)
                .await
                .map_err(|_| Error::Transport("connection closed".into())),
            #[cfg(feature = "tcp")]
            Streams::Tcp { send, .. } => {
                let mut send = send.clone();
                send.write_all(&(bytes.len() as u64).to_be_bytes()).await?;
                send.write_all(&bytes).await?;
                send.flush().await?;
                Ok(())
            }
            #[cfg(feature = "iroh")]
            Streams::Iroh(conn) => {
                let mut stream = conn
                    .open_uni()
                    .await
                    .map_err(|e| Error::Transport(e.to_string()))?;
                stream
                    .write_all(&bytes)
                    .await
                    .map_err(|e| Error::Transport(e.to_string()))?;
                stream
                    .finish()
                    .map_err(|e| Error::Transport(e.to_string()))?;
                Ok(())
            }
        }
    }
    pub async fn accept_uni_bounded(&self, max: usize) -> Result<Vec<u8>> {
        match &self.streams {
            Streams::Loopback { uni_recv, .. } => {
                let bytes = uni_recv
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| Error::Transport("connection closed".into()))?;
                if bytes.len() > max {
                    return Err(Error::protocol("object stream exceeds quota"));
                }
                Ok(bytes)
            }
            #[cfg(feature = "tcp")]
            Streams::Tcp { recv, .. } => {
                let mut recv = recv.clone();
                let len = recv.read_u64().await?;
                if len > max as u64 {
                    return Err(Error::protocol("object stream exceeds quota"));
                }
                let mut bytes = vec![0; len as usize];
                recv.read_exact(&mut bytes).await?;
                Ok(bytes)
            }
            #[cfg(feature = "iroh")]
            Streams::Iroh(conn) => {
                let mut stream = conn
                    .accept_uni()
                    .await
                    .map_err(|e| Error::Transport(e.to_string()))?;
                stream
                    .read_to_end(max)
                    .await
                    .map_err(|e| Error::Transport(e.to_string()))
            }
        }
    }
}

#[derive(Clone)]
#[cfg(feature = "tcp")]
struct SharedRead(Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>);
#[cfg(feature = "tcp")]
impl AsyncRead for SharedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0.lock().expect("tcp read lock")).poll_read(cx, buf)
    }
}
#[derive(Clone)]
#[cfg(feature = "tcp")]
struct SharedWrite(Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>);
#[cfg(feature = "tcp")]
impl AsyncWrite for SharedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.0.lock().expect("tcp write lock")).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0.lock().expect("tcp write lock")).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0.lock().expect("tcp write lock")).poll_shutdown(cx)
    }
}

#[cfg(feature = "tcp")]
pub struct TcpTransport {
    identity: Identity,
    listener: TcpListener,
    address: std::net::SocketAddr,
    addresses: Mutex<BTreeMap<PeerId, std::net::SocketAddr>>,
}

#[cfg(feature = "tcp")]
impl TcpTransport {
    pub async fn bind(secret: [u8; 32]) -> Result<Self> {
        Self::bind_port(secret, 0).await
    }
    pub async fn bind_port(secret: [u8; 32], port: u16) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        let address = listener.local_addr()?;
        Ok(Self {
            identity: Identity::from_secret_bytes(&secret),
            listener,
            address,
            addresses: Mutex::new(BTreeMap::new()),
        })
    }
    pub fn bound_port(&self) -> u16 {
        self.address.port()
    }
    async fn authenticate(&self, mut stream: TcpStream) -> Result<Connection> {
        let nonce = rand::random::<[u8; 32]>();
        let local_address = self.address.to_string();
        stream.write_all(self.identity.peer_id().as_bytes()).await?;
        stream.write_all(&nonce).await?;
        stream.write_u16(local_address.len() as u16).await?;
        stream.write_all(local_address.as_bytes()).await?;
        stream.flush().await?;
        let mut peer_bytes = [0; 32];
        let mut peer_nonce = [0; 32];
        stream.read_exact(&mut peer_bytes).await?;
        stream.read_exact(&mut peer_nonce).await?;
        let peer_address_len = stream.read_u16().await? as usize;
        if peer_address_len > 128 {
            return Err(Error::Transport("TCP advertised address too long".into()));
        }
        let mut peer_address = vec![0; peer_address_len];
        stream.read_exact(&mut peer_address).await?;
        let peer_address: std::net::SocketAddr = std::str::from_utf8(&peer_address)
            .map_err(|_| Error::Transport("invalid TCP advertised address".into()))?
            .parse()
            .map_err(|_| Error::Transport("invalid TCP advertised address".into()))?;
        let peer = PeerId::from_bytes(peer_bytes);
        let mut proof = nonce.to_vec();
        proof.extend_from_slice(&peer_nonce);
        proof.extend_from_slice(local_address.as_bytes());
        let signature = self.identity.sign("tcp-transport", &proof);
        stream.write_all(signature.as_bytes()).await?;
        stream.flush().await?;
        let mut peer_signature = [0; 64];
        stream.read_exact(&mut peer_signature).await?;
        let mut peer_proof = peer_nonce.to_vec();
        peer_proof.extend_from_slice(&nonce);
        peer_proof.extend_from_slice(peer_address.to_string().as_bytes());
        peer.verify(
            "tcp-transport",
            &peer_proof,
            &Signature::from_bytes(peer_signature),
        )?;
        self.addresses
            .lock()
            .expect("tcp address lock")
            .insert(peer, peer_address);
        let (read, write) = stream.into_split();
        let recv = SharedRead(Arc::new(Mutex::new(read)));
        let send = SharedWrite(Arc::new(Mutex::new(write)));
        Ok(Connection {
            peer_id: peer,
            control_send: Box::new(send.clone()),
            control_recv: Box::new(recv.clone()),
            streams: Streams::Tcp { send, recv },
            // The peer advertises this address itself. Keep it session-local;
            // it is not proof that the peer owns a durable dial target.
            observed_addresses: Vec::new(),
        })
    }
}

#[async_trait]
#[cfg(feature = "tcp")]
impl Transport for TcpTransport {
    fn local_peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }
    fn local_addresses(&self) -> Vec<String> {
        vec![format!("tcp://{}", self.address)]
    }
    fn add_peer_address(&self, peer: PeerId, address: &str) -> Result<()> {
        let address = parse_tcp_address(address)?;
        self.addresses
            .lock()
            .expect("tcp address lock")
            .insert(peer, address);
        Ok(())
    }
    async fn dial(&self, peer: PeerId) -> Result<Connection> {
        let address = self
            .addresses
            .lock()
            .expect("tcp address lock")
            .get(&peer)
            .copied()
            .ok_or_else(|| Error::Transport("peer has no TCP dial address".into()))?;
        let connection = self
            .authenticate(TcpStream::connect(address).await?)
            .await?;
        if connection.peer_id() != peer {
            return Err(Error::Authentication(
                "TCP peer identity differs from ticket".into(),
            ));
        }
        Ok(connection)
    }
    async fn accept(&self) -> Result<Connection> {
        let (stream, _) = self.listener.accept().await?;
        tokio::time::timeout(std::time::Duration::from_secs(1), self.authenticate(stream))
            .await
            .map_err(|_| Error::Timeout)?
    }
}

#[async_trait]
pub trait Transport: Send + Sync {
    fn local_peer_id(&self) -> PeerId;
    fn local_addresses(&self) -> Vec<String> {
        Vec::new()
    }
    fn add_peer_address(&self, _peer: PeerId, _address: &str) -> Result<()> {
        Ok(())
    }
    async fn wait_local_addresses(&self) -> Result<Vec<String>> {
        Ok(self.local_addresses())
    }
    fn requires_relay_for_wide_area(&self) -> bool {
        false
    }
    async fn dial(&self, peer: PeerId) -> Result<Connection>;
    async fn accept(&self) -> Result<Connection>;
}

type Incoming = mpsc::Sender<Connection>;

#[derive(Clone, Default)]
pub struct LoopbackNetwork {
    peers: Arc<Mutex<BTreeMap<PeerId, Incoming>>>,
}

pub struct LoopbackTransport {
    peer: PeerId,
    network: LoopbackNetwork,
    incoming: AsyncMutex<mpsc::Receiver<Connection>>,
}

impl LoopbackTransport {
    pub fn bind(network: &LoopbackNetwork, peer: PeerId) -> Self {
        let (tx, rx) = mpsc::channel(16);
        network
            .peers
            .lock()
            .expect("loopback lock")
            .insert(peer, tx);
        Self {
            peer,
            network: network.clone(),
            incoming: AsyncMutex::new(rx),
        }
    }
}

#[async_trait]
impl Transport for LoopbackTransport {
    fn local_peer_id(&self) -> PeerId {
        self.peer
    }
    async fn dial(&self, peer: PeerId) -> Result<Connection> {
        let target = self
            .network
            .peers
            .lock()
            .expect("loopback lock")
            .get(&peer)
            .cloned()
            .ok_or_else(|| Error::Transport("peer unavailable".into()))?;
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let (a_tx, b_rx) = mpsc::channel(8);
        let (b_tx, a_rx) = mpsc::channel(8);
        let local = Connection {
            peer_id: peer,
            control_send: Box::new(aw),
            control_recv: Box::new(ar),
            streams: Streams::Loopback {
                uni_send: a_tx,
                uni_recv: AsyncMutex::new(a_rx),
            },
            observed_addresses: Vec::new(),
        };
        let remote = Connection {
            peer_id: self.peer,
            control_send: Box::new(bw),
            control_recv: Box::new(br),
            streams: Streams::Loopback {
                uni_send: b_tx,
                uni_recv: AsyncMutex::new(b_rx),
            },
            observed_addresses: Vec::new(),
        };
        target
            .send(remote)
            .await
            .map_err(|_| Error::Transport("peer unavailable".into()))?;
        Ok(local)
    }
    async fn accept(&self) -> Result<Connection> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::Transport("transport closed".into()))
    }
}

#[cfg(feature = "iroh")]
pub struct IrohTransport {
    endpoint: iroh::Endpoint,
    addresses: Mutex<BTreeMap<PeerId, iroh::EndpointAddr>>,
    relay: IrohRelayMode,
}
#[cfg(feature = "iroh")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum IrohRelayMode {
    #[default]
    N0,
    None,
    Custom(iroh::RelayUrl),
}
#[cfg(feature = "iroh")]
impl std::fmt::Display for IrohRelayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::N0 => f.write_str("n0"),
            Self::None => f.write_str("none"),
            Self::Custom(url) => url.fmt(f),
        }
    }
}
#[cfg(feature = "iroh")]
impl std::str::FromStr for IrohRelayMode {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "n0" => Ok(Self::N0),
            "none" => Ok(Self::None),
            url => {
                let url: iroh::RelayUrl = url.parse().map_err(|error| {
                    Error::Transport(format!("invalid iroh relay URL: {error}"))
                })?;
                if url.scheme() != "https" {
                    return Err(Error::Transport(
                        "custom iroh relay URL must use https".into(),
                    ));
                }
                Ok(Self::Custom(url))
            }
        }
    }
}
#[cfg(feature = "iroh")]
impl IrohTransport {
    pub async fn bind(secret: [u8; 32]) -> Result<Self> {
        Self::bind_port_with_relay(secret, 0, IrohRelayMode::default()).await
    }
    pub async fn bind_port(secret: [u8; 32], port: u16) -> Result<Self> {
        Self::bind_port_with_relay(secret, port, IrohRelayMode::default()).await
    }
    pub async fn bind_port_with_relay(
        secret: [u8; 32],
        port: u16,
        relay: IrohRelayMode,
    ) -> Result<Self> {
        use iroh::endpoint::presets::Preset;

        let builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal);
        let builder = match &relay {
            IrohRelayMode::None => builder,
            IrohRelayMode::N0 => iroh::endpoint::presets::N0.apply(builder),
            IrohRelayMode::Custom(url) => iroh::endpoint::presets::N0
                .apply(builder)
                .relay_mode(iroh::RelayMode::custom([url.clone()])),
        };
        let endpoint = builder
            .bind_addr((std::net::Ipv4Addr::UNSPECIFIED, port))
            .map_err(|e| Error::Transport(e.to_string()))?
            .bind_addr((std::net::Ipv6Addr::UNSPECIFIED, port))
            .map_err(|e| Error::Transport(e.to_string()))?
            .secret_key(iroh::SecretKey::from_bytes(&secret))
            .alpns(vec![crate::ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Self {
            endpoint,
            addresses: Mutex::new(BTreeMap::new()),
            relay,
        })
    }
    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        self.endpoint.addr()
    }
    pub fn relay_mode(&self) -> &IrohRelayMode {
        &self.relay
    }
    pub fn bound_port(&self) -> Option<u16> {
        self.endpoint
            .bound_sockets()
            .first()
            .map(std::net::SocketAddr::port)
    }
    pub fn add_peer_addr(&self, peer: PeerId, addr: iroh::EndpointAddr) {
        let mut addresses = self.addresses.lock().expect("iroh address lock");
        addresses
            .entry(peer)
            .and_modify(|known| merge_endpoint_addr(known, &addr))
            .or_insert(addr);
    }
    async fn wrap(
        conn: iroh::endpoint::Connection,
        outgoing: bool,
        observed_addresses: Vec<String>,
    ) -> Result<Connection> {
        let peer_id = PeerId::from_bytes(*conn.remote_id().as_bytes());
        let (send, recv) = if outgoing {
            conn.open_bi().await
        } else {
            conn.accept_bi().await
        }
        .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Connection {
            peer_id,
            control_send: Box::new(send),
            control_recv: Box::new(recv),
            streams: Streams::Iroh(conn),
            observed_addresses,
        })
    }
}

#[cfg(feature = "iroh")]
fn merge_endpoint_addr(known: &mut iroh::EndpointAddr, observed: &iroh::EndpointAddr) {
    known.addrs.extend(observed.addrs.iter().cloned());
}
#[cfg(feature = "iroh")]
#[async_trait]
impl Transport for IrohTransport {
    fn local_peer_id(&self) -> PeerId {
        PeerId::from_bytes(*self.endpoint.id().as_bytes())
    }
    fn local_addresses(&self) -> Vec<String> {
        serde_json::to_string(&self.endpoint_addr())
            .map(|address| vec![address])
            .unwrap_or_default()
    }
    fn requires_relay_for_wide_area(&self) -> bool {
        !matches!(self.relay, IrohRelayMode::None)
    }
    fn add_peer_address(&self, peer: PeerId, address: &str) -> Result<()> {
        let address = parse_iroh_address(address)?;
        validate_iroh_relay_policy(&address, &self.relay)?;
        self.add_peer_addr(peer, address);
        Ok(())
    }
    async fn wait_local_addresses(&self) -> Result<Vec<String>> {
        wait_for_dialable_address(std::time::Duration::from_secs(3), || {
            let address = self.endpoint_addr();
            let ready = iroh_address_is_dialable(&address);
            if ready {
                serde_json::to_string(&address)
                    .map(|address| vec![address])
                    .map(Some)
                    .map_err(|error| Error::Transport(error.to_string()))
            } else {
                Ok(None)
            }
        })
        .await
    }
    async fn dial(&self, peer: PeerId) -> Result<Connection> {
        let addr = self
            .addresses
            .lock()
            .expect("iroh address lock")
            .get(&peer)
            .cloned()
            .unwrap_or(iroh::EndpointAddr::from(
                iroh::EndpointId::from_bytes(peer.as_bytes())
                    .map_err(|e| Error::Transport(e.to_string()))?,
            ));
        let observed_addresses = serde_json::to_string(&addr)
            .map(|address| vec![address])
            .map_err(|error| Error::Transport(error.to_string()))?;
        let conn = self
            .endpoint
            .connect(addr, crate::ALPN)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Self::wrap(conn, true, observed_addresses).await
    }
    async fn accept(&self) -> Result<Connection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::Transport("endpoint closed".into()))?;
        let incoming_addr = incoming.remote_addr();
        let conn = incoming
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let remote_addr = iroh::EndpointAddr::from_parts(
            conn.remote_id(),
            [iroh::TransportAddr::from(incoming_addr)],
        );
        let observed_addresses = serde_json::to_string(&remote_addr)
            .map(|address| vec![address])
            .map_err(|error| Error::Transport(error.to_string()))?;
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            Self::wrap(conn, false, observed_addresses),
        )
        .await
        .map_err(|_| Error::Timeout)?
    }
}

#[cfg(feature = "iroh")]
fn iroh_address_is_dialable(address: &iroh::EndpointAddr) -> bool {
    address.relay_urls().next().is_some() || address.ip_addrs().next().is_some()
}

#[cfg(feature = "tcp")]
fn parse_tcp_address(address: &str) -> Result<std::net::SocketAddr> {
    address
        .strip_prefix("tcp://")
        .ok_or_else(|| Error::Transport("unsupported dial address".into()))?
        .parse()
        .map_err(|_| Error::Transport("invalid TCP dial address".into()))
}

#[cfg(feature = "iroh")]
fn parse_iroh_address(address: &str) -> Result<iroh::EndpointAddr> {
    let address: iroh::EndpointAddr = serde_json::from_str(address)
        .map_err(|error| Error::Transport(format!("invalid iroh address: {error}")))?;
    for relay in address.relay_urls() {
        if relay.scheme() != "https" {
            return Err(Error::Transport("iroh relay URL must use https".into()));
        }
    }
    Ok(address)
}

#[cfg(feature = "iroh")]
fn validate_iroh_relay_policy(address: &iroh::EndpointAddr, mode: &IrohRelayMode) -> Result<()> {
    let allowed = |relay: &iroh::RelayUrl| match mode {
        IrohRelayMode::None => false,
        IrohRelayMode::N0 => iroh::defaults::prod::default_relay_map().contains(relay),
        IrohRelayMode::Custom(expected) => relay == expected,
    };
    if address.relay_urls().any(|relay| !allowed(relay)) {
        return Err(Error::Transport(
            "peer address uses a relay outside the configured policy".into(),
        ));
    }
    Ok(())
}

/// True when a persisted hint contains a direct network address.
pub fn peer_address_has_direct_hint(_address: &str) -> bool {
    #[cfg(feature = "tcp")]
    if _address.starts_with("tcp://") {
        return true;
    }
    #[cfg(feature = "iroh")]
    if let Ok(address) = parse_iroh_address(_address) {
        return address.ip_addrs().next().is_some();
    }
    false
}

/// True when a serialized iroh hint names a relay.
pub fn peer_address_has_relay_hint(_address: &str) -> bool {
    #[cfg(feature = "iroh")]
    if let Ok(address) = parse_iroh_address(_address) {
        return address.relay_urls().next().is_some();
    }
    false
}

/// Merge two serialized iroh hints for the same endpoint.
pub fn merge_peer_address_hints(existing: &str, observed: &str) -> Option<String> {
    #[cfg(feature = "iroh")]
    {
        let mut existing = parse_iroh_address(existing).ok()?;
        let observed = parse_iroh_address(observed).ok()?;
        if existing.id != observed.id {
            return None;
        }
        merge_endpoint_addr(&mut existing, &observed);
        serde_json::to_string(&existing).ok()
    }
    #[cfg(not(feature = "iroh"))]
    {
        let _ = (existing, observed);
        None
    }
}

/// Validate a persisted dial hint with the same parser used by a transport.
pub fn validate_peer_address(_address: &str) -> Result<()> {
    #[cfg(feature = "tcp")]
    if _address.starts_with("tcp://") {
        return parse_tcp_address(_address).map(drop);
    }
    #[cfg(feature = "iroh")]
    {
        parse_iroh_address(_address).map(drop)
    }
    #[cfg(not(feature = "iroh"))]
    {
        Err(Error::Transport("unsupported peer address".into()))
    }
}

#[cfg(feature = "iroh")]
async fn wait_for_dialable_address(
    timeout: std::time::Duration,
    mut snapshot: impl FnMut() -> Result<Option<Vec<String>>>,
) -> Result<Vec<String>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(addresses) = snapshot()? {
            return Ok(addresses);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Transport(format!(
                "iroh endpoint has no direct or relay address after {} seconds",
                timeout.as_secs()
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(all(test, feature = "iroh"))]
mod iroh_tests {
    use super::*;

    #[tokio::test]
    async fn waiting_for_dialable_addresses_times_out() {
        let error = wait_for_dialable_address(std::time::Duration::ZERO, || Ok(None))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no direct or relay address"));
    }

    #[test]
    fn iroh_relay_mode_parsing() {
        assert_eq!("n0".parse::<IrohRelayMode>().unwrap(), IrohRelayMode::N0);
        assert_eq!(
            "none".parse::<IrohRelayMode>().unwrap(),
            IrohRelayMode::None
        );
        assert!(matches!(
            "https://relay.example.test"
                .parse::<IrohRelayMode>()
                .unwrap(),
            IrohRelayMode::Custom(_)
        ));
        assert!("http://relay.example.test"
            .parse::<IrohRelayMode>()
            .is_err());
    }

    #[tokio::test]
    async fn bound_relay_modes_expose_the_configured_relay_set() {
        let none = match IrohTransport::bind_port_with_relay([31; 32], 0, IrohRelayMode::None).await
        {
            Ok(transport) => transport,
            Err(Error::Transport(message)) if message.contains("netmon monitor") => {
                eprintln!("skipping iroh bind test: sandbox denied network monitor access");
                return;
            }
            Err(error) => panic!("iroh none bind failed: {error}"),
        };
        assert!(none.endpoint_addr().relay_urls().next().is_none());

        // A relay URL only appears in the live endpoint address once the
        // relay connection is up, so an unreachable custom relay is checked
        // through the configured mode rather than the address.
        let relay: iroh::RelayUrl = "https://relay.example.test".parse().unwrap();
        let custom =
            IrohTransport::bind_port_with_relay([32; 32], 0, IrohRelayMode::Custom(relay.clone()))
                .await
                .unwrap();
        assert_eq!(custom.relay_mode(), &IrohRelayMode::Custom(relay));
        assert_ne!(none.relay_mode(), custom.relay_mode());

        let n0 = IrohTransport::bind_port_with_relay([33; 32], 0, IrohRelayMode::N0)
            .await
            .unwrap();
        assert_eq!(n0.relay_mode(), &IrohRelayMode::N0);
        // With Internet access n0 assigns a home relay within a few seconds;
        // without it the address simply stays direct-only.
        for _ in 0..50 {
            if n0.endpoint_addr().relay_urls().next().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    #[test]
    fn endpoint_address_json_preserves_relay_url() {
        let id = iroh::SecretKey::from_bytes(&[23; 32]).public();
        let relay: iroh::RelayUrl = "https://relay.example.test".parse().unwrap();
        let address = iroh::EndpointAddr::new(id).with_relay_url(relay.clone());
        let encoded = serde_json::to_string(&address).unwrap();
        let decoded = parse_iroh_address(&encoded).unwrap();

        assert_eq!(decoded.relay_urls().next(), Some(&relay));
    }

    #[test]
    fn direct_address_is_dialable_without_a_relay_url() {
        let id = iroh::SecretKey::from_bytes(&[26; 32]).public();
        let address = iroh::EndpointAddr::new(id).with_ip_addr("127.0.0.1:4242".parse().unwrap());
        assert!(iroh_address_is_dialable(&address));
        assert!(address.relay_urls().next().is_none());
    }

    #[test]
    fn peer_relay_hints_require_https_and_respect_custom_pin() {
        let id = iroh::SecretKey::from_bytes(&[24; 32]).public();
        let insecure: iroh::RelayUrl = "http://relay.example.test".parse().unwrap();
        let encoded =
            serde_json::to_string(&iroh::EndpointAddr::new(id).with_relay_url(insecure)).unwrap();
        assert!(parse_iroh_address(&encoded).is_err());

        let configured: iroh::RelayUrl = "https://one.example.test".parse().unwrap();
        let other: iroh::RelayUrl = "https://two.example.test".parse().unwrap();
        let address = iroh::EndpointAddr::new(id).with_relay_url(other);
        assert!(validate_iroh_relay_policy(&address, &IrohRelayMode::Custom(configured)).is_err());
        assert!(validate_iroh_relay_policy(&address, &IrohRelayMode::None).is_err());
        assert!(validate_iroh_relay_policy(&address, &IrohRelayMode::N0).is_err());

        let n0 = iroh::defaults::prod::default_relay_map()
            .urls::<Vec<_>>()
            .pop()
            .unwrap();
        let address = iroh::EndpointAddr::new(id).with_relay_url(n0);
        assert!(validate_iroh_relay_policy(&address, &IrohRelayMode::N0).is_ok());
    }

    #[test]
    fn repeated_peer_addresses_keep_relay_and_direct_hints() {
        let id = iroh::SecretKey::from_bytes(&[28; 32]).public();
        let relay = iroh::defaults::prod::default_relay_map()
            .urls::<Vec<_>>()
            .pop()
            .unwrap();
        let mut known = iroh::EndpointAddr::new(id).with_relay_url(relay.clone());
        let observed = iroh::EndpointAddr::new(id).with_ip_addr("127.0.0.1:4242".parse().unwrap());
        merge_endpoint_addr(&mut known, &observed);
        assert_eq!(known.relay_urls().next(), Some(&relay));
        assert_eq!(known.ip_addrs().count(), 1);
    }

    #[tokio::test]
    async fn iroh_binds_ipv4_and_ipv6_when_available() {
        let ipv6_available = std::net::UdpSocket::bind("[::1]:0").is_ok();
        let transport = match IrohTransport::bind([7; 32]).await {
            Ok(transport) => transport,
            Err(Error::Transport(message)) if message.contains("netmon monitor") => {
                eprintln!("skipping iroh bind test: sandbox denied network monitor access");
                return;
            }
            Err(error) => panic!("iroh bind failed: {error}"),
        };
        let sockets = transport.endpoint.bound_sockets();
        assert!(sockets.iter().any(std::net::SocketAddr::is_ipv4));
        if ipv6_available {
            assert!(sockets.iter().any(std::net::SocketAddr::is_ipv6));
        }
    }
}
