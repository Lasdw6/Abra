use crate::Result;
use abra_net::{day_tag, open, polling_tags, seal, Ack, DeliveryNode, RelayPayload};
use abra_relay::OpaqueEnvelope;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub const MAX_RELAY_ENVELOPE: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub url: String,
    #[serde(default)]
    pub secret: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    pub relays: Vec<RelayEndpoint>,
    pub relay_after_attempts: u32,
    pub relay_poll_seconds: u64,
    deposits: BTreeSet<String>,
}
impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            relay_after_attempts: 3,
            relay_poll_seconds: 60,
            deposits: BTreeSet::new(),
        }
    }
}
impl RelayConfig {
    fn path(root: &Path) -> PathBuf {
        root.join("config/relays.json")
    }
    pub fn load(root: &Path) -> Result<Self> {
        match fs::read(Self::path(root)) {
            Ok(b) => Ok(serde_json::from_slice(&b)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn save(&self, root: &Path) -> Result<()> {
        let path = Self::path(root);
        fs::create_dir_all(path.parent().expect("config parent"))?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, abra_core::canonical::to_vec(self)?)?;
        fs::rename(tmp, path)?;
        Ok(())
    }
    pub fn deposited(&self, id: &str, url: &str) -> bool {
        self.deposits.contains(&format!("{id}\0{url}"))
    }
    pub fn mark_deposited(&mut self, id: &str, url: &str) {
        self.deposits.insert(format!("{id}\0{url}"));
    }
}

fn parse_http(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("relay URL must use http:// (put TLS in a reverse proxy)")?;
    let (authority, base) = rest
        .split_once('/')
        .map_or((rest, String::new()), |(a, p)| (a, format!("/{p}")));
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, 80), |(h, p)| (h, p.parse().unwrap_or(0)));
    if host.is_empty() || port == 0 {
        return Err("invalid relay URL".into());
    }
    Ok((host.into(), port, base.trim_end_matches('/').into()))
}
async fn request(endpoint: &RelayEndpoint, method: &str, path: &str, body: &[u8]) -> Result<Value> {
    let (host, port, base) = parse_http(&endpoint.url)?;
    let mut stream = TcpStream::connect((host.as_str(), port)).await?;
    let request = format!("{method} {base}{path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", endpoint.secret, body.len());
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let split = bytes
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or("invalid relay HTTP response")?;
    let header = std::str::from_utf8(&bytes[..split])?;
    if !header
        .lines()
        .next()
        .is_some_and(|line| line.contains(" 200 "))
    {
        return Err(format!(
            "relay request failed: {}",
            header.lines().next().unwrap_or("invalid response")
        )
        .into());
    }
    Ok(serde_json::from_slice(&bytes[split + 4..])?)
}
pub async fn enqueue(
    endpoint: &RelayEndpoint,
    tag: [u8; 32],
    recipient: [u8; 32],
    payload: &RelayPayload,
    now: u64,
) -> Result<()> {
    let plaintext = abra_core::canonical::to_vec(payload)?;
    let sealed = seal(recipient, &plaintext)?;
    let env = OpaqueEnvelope {
        version: 1,
        tag: hex::encode(tag),
        expires_at: now + 72 * 3_600_000,
        sealed: BASE64URL_NOPAD.encode(&sealed),
    };
    let bytes = abra_core::canonical::to_vec(&env)?;
    if bytes.len() > MAX_RELAY_ENVELOPE {
        return Err(format!(
            "relay envelope exceeds 16 MiB limit ({} bytes); split the snapshot before sending",
            bytes.len()
        )
        .into());
    }
    request(endpoint, "POST", "/v1/enqueue", &bytes).await?;
    Ok(())
}
pub async fn poll(
    root: &Path,
    node: &mut DeliveryNode,
    endpoint: &RelayEndpoint,
    now: u64,
) -> Result<(usize, Vec<abra_core::identity::PeerId>)> {
    let tags = polling_tags(&node.store.keys.relay_discovery_key, now).map(hex::encode);
    let response = request(
        endpoint,
        "POST",
        "/v1/poll",
        &serde_json::to_vec(&json!({"tags":tags,"delete_on_fetch":false}))?,
    )
    .await?;
    let mut handled = 0;
    let mut delivery_senders = Vec::new();
    for item in response["items"]
        .as_array()
        .ok_or("invalid relay poll response")?
    {
        let id = item["id"].as_str().ok_or("relay item lacks id")?;
        let bytes: Vec<u8> = serde_json::from_value(item["envelope"].clone())?;
        let env: OpaqueEnvelope = serde_json::from_slice(&bytes)?;
        let sealed = BASE64URL_NOPAD
            .decode(env.sealed.as_bytes())
            .map_err(|_| "bad relay sealed base64")?;
        let plaintext = open(node.store.keys.x25519_secret, &sealed)?;
        let payload: RelayPayload = serde_json::from_slice(&plaintext)?;
        match payload {
            RelayPayload::Delivery { .. } => {
                let (sender, ack) = node.receive_relay_delivery(payload, now)?;
                delivery_senders.push(sender);
                let peer = node
                    .trust
                    .get(&sender)
                    .ok_or("relay sender is not trusted")?;
                let key = peer.relay_key.ok_or("relay sender lacks discovery key")?;
                enqueue(
                    endpoint,
                    day_tag(&key, (now / 86_400_000) as i64),
                    peer.x25519_pk,
                    &RelayPayload::Ack {
                        sender: node.peer_id(),
                        ack,
                    },
                    now,
                )
                .await?;
            }
            RelayPayload::Ack { sender, ack } => apply_ack(node, sender, &ack, now)?,
        }
        request(endpoint, "DELETE", &format!("/v1/item/{id}"), b"").await?;
        handled += 1;
    }
    let _ = root;
    Ok((handled, delivery_senders))
}
fn apply_ack(
    node: &mut DeliveryNode,
    sender: abra_core::identity::PeerId,
    ack: &Ack,
    now: u64,
) -> Result<()> {
    let id = node
        .outbox
        .entries()
        .find(|e| e.offer_id == ack.offer_id && e.peer_id == sender)
        .map(|e| e.id.clone());
    if let Some(id) = id {
        node.outbox.apply_ack(&id, ack, node.peer_id(), now)?;
    }
    Ok(())
}
