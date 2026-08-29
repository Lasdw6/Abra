use crate::{Error, Result};
use abra_core::identity::PeerId;
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, Mutex as AsyncMutex},
};

pub type ControlSend = Box<dyn AsyncWrite + Send + Unpin>;
pub type ControlRecv = Box<dyn AsyncRead + Send + Unpin>;

enum Streams {
    Loopback {
        uni_send: mpsc::Sender<Vec<u8>>,
        uni_recv: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
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

#[async_trait]
pub trait Transport: Send + Sync {
    fn local_peer_id(&self) -> PeerId;
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
