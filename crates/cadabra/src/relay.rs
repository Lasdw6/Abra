use crate::Result;
use abra_net::{day_tag, open, polling_tags, seal, Ack, DeliveryNode, RelayPayload};
use abra_relay::OpaqueEnvelope;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

pub const MAX_RELAY_ENVELOPE: usize = 16 * 1024 * 1024;
const MAX_RELAY_RESPONSE_BYTES: usize = 80 * 1024 * 1024;
const MAX_RELAY_POLL_ITEMS: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub url: String,
    #[serde(default)]
    pub secret: String,
}

impl RelayEndpoint {
    pub fn validate(&self) -> Result<()> {
        request_url(self, "/v1/poll").map(|_| ())
    }
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

fn request_url(endpoint: &RelayEndpoint, path: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(&endpoint.url).map_err(|_| "invalid relay URL")?;
    let host = url.host_str().ok_or("relay URL must include a host")?;
    if url.port() == Some(0) {
        return Err("invalid relay URL".into());
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        "http" => return Err("insecure relay URL is only allowed for loopback hosts".into()),
        _ => return Err("relay URL must use https:// (http:// is allowed on loopback)".into()),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("relay URL must not contain credentials".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("relay URL must not contain a query or fragment".into());
    }
    let base = url.path().trim_end_matches('/');
    url.set_path(&format!("{base}{path}"));
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn relay_client() -> Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<std::result::Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()
                .map_err(|error| format!("cannot create relay HTTP client: {error}"))
        })
        .as_ref()
        .map_err(|error| error.clone().into())
}

async fn request(endpoint: &RelayEndpoint, method: &str, path: &str, body: &[u8]) -> Result<Value> {
    let url = request_url(endpoint, path)?;
    let method = reqwest::Method::from_bytes(method.as_bytes())?;
    let mut response = relay_client()?
        .request(method, url)
        .bearer_auth(&endpoint.secret)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec())
        .send()
        .await?;
    let status = response.status();
    let bytes = read_response_bytes(&mut response, MAX_RELAY_RESPONSE_BYTES).await?;
    if !status.is_success() {
        let detail = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| value["error"].as_str().map(str::to_owned));
        return Err(match detail {
            Some(detail) => format!("relay request failed ({status}): {detail}"),
            None => format!("relay request failed ({status})"),
        }
        .into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn read_response_bytes(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(format!("relay response exceeds {max_bytes} byte limit").into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
            return Err(format!("relay response exceeds {max_bytes} byte limit").into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
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
        &serde_json::to_vec(&json!({
            "tags": tags,
            "delete_on_fetch": false,
            "max_items": MAX_RELAY_POLL_ITEMS,
            "max_bytes": MAX_RELAY_ENVELOPE,
        }))?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn endpoint(url: &str) -> RelayEndpoint {
        RelayEndpoint {
            url: url.into(),
            secret: "never-put-this-in-the-url".into(),
        }
    }

    #[test]
    fn https_relay_url_keeps_base_path() {
        let url = request_url(&endpoint("https://relay.example/abra/"), "/v1/poll").unwrap();
        assert_eq!(url.as_str(), "https://relay.example/abra/v1/poll");
        assert!(!url.as_str().contains("never-put-this-in-the-url"));
    }

    #[test]
    fn plain_http_is_limited_to_loopback() {
        assert!(request_url(&endpoint("http://127.0.0.1:8787"), "/v1/poll").is_ok());
        assert!(request_url(&endpoint("http://[::1]:8787"), "/v1/poll").is_ok());
        let error = request_url(&endpoint("http://relay.example"), "/v1/poll").unwrap_err();
        assert_eq!(
            error.to_string(),
            "insecure relay URL is only allowed for loopback hosts"
        );
    }

    #[test]
    fn relay_url_rejects_credentials_query_and_non_http_schemes() {
        for url in [
            "https://user:pass@relay.example",
            "https://relay.example?secret=bad",
            "https://relay.example:0",
            "file:///tmp/relay",
        ] {
            assert!(request_url(&endpoint(url), "/v1/poll").is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn loopback_request_sends_bearer_auth_and_parses_json() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
                )
                .await
                .unwrap();
            String::from_utf8(request).unwrap()
        });
        let endpoint = RelayEndpoint {
            url: format!("http://{address}"),
            secret: "test-secret".into(),
        };
        assert_eq!(
            request(&endpoint, "POST", "/v1/poll", b"{}").await.unwrap(),
            json!({"ok":true})
        );
        let request = server.await.unwrap();
        assert!(request.contains("authorization: Bearer test-secret\r\n"));
    }

    #[tokio::test]
    async fn response_reader_stops_at_its_byte_limit() {
        for wire in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nhello world\r\n0\r\n\r\n"
                .as_slice(),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                stream.write_all(wire).await.unwrap();
            });
            let mut response = relay_client()
                .unwrap()
                .get(format!("http://{address}"))
                .send()
                .await
                .unwrap();
            let error = read_response_bytes(&mut response, 10).await.unwrap_err();
            assert_eq!(error.to_string(), "relay response exceeds 10 byte limit");
            server.await.unwrap();
        }
    }
}
