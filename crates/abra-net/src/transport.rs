use crate::{Error, Result};
use abra_core::identity::{Identity, PeerId, Signature};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex as AsyncMutex},
};

pub type ControlSend = Box<dyn AsyncWrite + Send + Sync + Unpin>;
pub type ControlRecv = Box<dyn AsyncRead + Send + Sync + Unpin>;

enum Streams {
    Loopback {
        uni_send: mpsc::Sender<Vec<u8>>,
        uni_recv: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    },
    Tcp {
        send: SharedWrite,
        recv: SharedRead,
    },
    #[cfg(feature = "iroh")]
    Iroh(iroh::endpoint::Connection),
}

pub struct Connection {
    peer_id: PeerId,
    control_send: ControlSend,
    control_recv: ControlRecv,
    streams: Streams,
}

impl Connection {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
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
struct SharedRead(Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>);
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
struct SharedWrite(Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>);
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

pub struct TcpTransport {
    identity: Identity,
    listener: TcpListener,
    address: std::net::SocketAddr,
    addresses: Mutex<BTreeMap<PeerId, std::net::SocketAddr>>,
}

impl TcpTransport {
    pub async fn bind(secret: [u8; 32]) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        Ok(Self {
            identity: Identity::from_secret_bytes(&secret),
            listener,
            address,
            addresses: Mutex::new(BTreeMap::new()),
        })
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
        })
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn local_peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }
    fn local_addresses(&self) -> Vec<String> {
        vec![format!("tcp://{}", self.address)]
    }
    fn add_peer_address(&self, peer: PeerId, address: &str) -> Result<()> {
        let address = address
            .strip_prefix("tcp://")
            .ok_or_else(|| Error::Transport("unsupported dial address".into()))?;
        let address = address
            .parse()
            .map_err(|_| Error::Transport("invalid TCP dial address".into()))?;
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
        self.authenticate(stream).await
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
        };
        let remote = Connection {
            peer_id: self.peer,
            control_send: Box::new(bw),
            control_recv: Box::new(br),
            streams: Streams::Loopback {
                uni_send: b_tx,
                uni_recv: AsyncMutex::new(b_rx),
            },
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
}
#[cfg(feature = "iroh")]
impl IrohTransport {
    pub async fn bind(secret: [u8; 32]) -> Result<Self> {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(iroh::SecretKey::from_bytes(&secret))
            .alpns(vec![crate::ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Self {
            endpoint,
            addresses: Mutex::new(BTreeMap::new()),
        })
    }
    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        self.endpoint.addr()
    }
    pub fn add_peer_addr(&self, peer: PeerId, addr: iroh::EndpointAddr) {
        self.addresses
            .lock()
            .expect("iroh address lock")
            .insert(peer, addr);
    }
    async fn wrap(conn: iroh::endpoint::Connection, outgoing: bool) -> Result<Connection> {
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
        })
    }
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
    fn add_peer_address(&self, peer: PeerId, address: &str) -> Result<()> {
        let address = serde_json::from_str(address)
            .map_err(|error| Error::Transport(format!("invalid iroh address: {error}")))?;
        self.add_peer_addr(peer, address);
        Ok(())
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
        let conn = self
            .endpoint
            .connect(addr, crate::ALPN)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Self::wrap(conn, true).await
    }
    async fn accept(&self) -> Result<Connection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::Transport("endpoint closed".into()))?;
        let conn = incoming
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Self::wrap(conn, false).await
    }
}
