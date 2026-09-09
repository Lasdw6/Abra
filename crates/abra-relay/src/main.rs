use abra_relay::{now_ms, RelayStore, DEFAULT_MAX_ENVELOPE, DEFAULT_MAX_STORAGE_BYTES};
use clap::Parser;
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
};

const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const MAX_POLL_ITEMS: usize = 64;
const MAX_POLL_BYTES: usize = DEFAULT_MAX_ENVELOPE;
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 32;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    #[arg(long, env = "ABRA_RELAY_SECRET")]
    secret: String,
    #[arg(long, default_value_t = DEFAULT_MAX_ENVELOPE)]
    max_bytes: usize,
    /// Total queued envelope bytes accepted before new unique items are rejected.
    #[arg(long, default_value_t = DEFAULT_MAX_STORAGE_BYTES)]
    max_storage_bytes: usize,
    /// Durable queue directory. Keep this directory across relay restarts.
    #[arg(long, env = "ABRA_RELAY_DATA_DIR", default_value = ".abra-relay")]
    data_dir: PathBuf,
    /// Maximum number of requests being read or handled at once.
    #[arg(long, default_value_t = DEFAULT_MAX_CONCURRENT_REQUESTS)]
    max_concurrent_requests: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.max_concurrent_requests == 0 {
        return Err("max concurrent requests must be at least 1".into());
    }
    validate_max_envelope(args.max_bytes).map_err(std::io::Error::other)?;
    let store = RelayStore::open(
        args.secret.as_bytes().to_vec(),
        args.max_bytes,
        args.max_storage_bytes,
        &args.data_dir,
        now_ms(),
    )
    .map_err(std::io::Error::other)?;
    let listener = TcpListener::bind(&args.listen).await?;
    let store = Arc::new(Mutex::new(store));
    let permits = Arc::new(Semaphore::new(args.max_concurrent_requests));
    let max_body_bytes = args.max_bytes;
    loop {
        let permit = permits.clone().acquire_owned().await?;
        let (stream, _) = listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                serve_request(stream, store, max_body_bytes),
            )
            .await;
            if let Ok(Err(error)) = result {
                eprintln!("abra-relay: request error: {error}");
            }
        });
    }
}

fn validate_max_envelope(max_bytes: usize) -> Result<(), String> {
    if max_bytes > MAX_POLL_BYTES {
        return Err(format!(
            "max envelope size cannot exceed the {MAX_POLL_BYTES} byte relay protocol limit"
        ));
    }
    Ok(())
}

async fn serve_request(
    mut stream: TcpStream,
    store: Arc<Mutex<RelayStore>>,
    max_body_bytes: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let remaining = (MAX_REQUEST_HEADER_BYTES + 1).saturating_sub(bytes.len());
        let read_size = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_size]).await?;
        if read == 0 {
            return Err("incomplete request".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(found) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            if found + 4 > MAX_REQUEST_HEADER_BYTES {
                write_json_response(
                    &mut stream,
                    "431 Request Header Fields Too Large",
                    &json!({"error":"request headers exceed 16 KiB limit"}),
                )
                .await?;
                return Ok(());
            }
            break found;
        }
        if bytes.len() > MAX_REQUEST_HEADER_BYTES {
            write_json_response(
                &mut stream,
                "431 Request Header Fields Too Large",
                &json!({"error":"request headers exceed 16 KiB limit"}),
            )
            .await?;
            return Ok(());
        }
    };
    let header = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
    let content_length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_| "invalid content length")?;
    let first = header.lines().next().ok_or("bad request")?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let supplied = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.eq_ignore_ascii_case("authorization") {
                return None;
            }
            value.trim().strip_prefix("Bearer ")
        })
        .unwrap_or("");

    if let Err(error) = store.lock().await.authenticate(supplied.as_bytes()) {
        write_json_response(
            &mut stream,
            status_for_error(&error),
            &json!({"error":error}),
        )
        .await?;
        return Ok(());
    }
    if content_length > max_body_bytes {
        write_json_response(
            &mut stream,
            "413 Content Too Large",
            &json!({"error":"request body exceeds relay size cap"}),
        )
        .await?;
        return Ok(());
    }
    let known_route = matches!(
        (method, path),
        ("POST", "/v1/enqueue") | ("POST", "/v1/poll")
    ) || (method == "DELETE" && path.starts_with("/v1/item/"));
    if !known_route {
        write_json_response(&mut stream, "404 Not Found", &json!({"error":"not found"})).await?;
        return Ok(());
    }

    let needed = header_end
        .checked_add(4)
        .and_then(|size| size.checked_add(content_length))
        .ok_or("request too large")?;
    while bytes.len() < needed {
        let remaining = needed - bytes.len();
        let read_size = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_size]).await?;
        if read == 0 {
            return Err("incomplete body".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let body = &bytes[header_end + 4..needed];

    let mut relay = store.lock().await;
    let response: Result<Value, String> = match (method, path) {
        ("POST", "/v1/enqueue") => relay
            .enqueue(supplied.as_bytes(), body.to_vec(), now_ms())
            .map(|id| json!({"id":id})),
        ("POST", "/v1/poll") => serde_json::from_slice::<Value>(body)
            .map_err(|_| "bad poll".into())
            .and_then(|value| {
                let tags = value["tags"]
                    .as_array()
                    .ok_or("tags required")?
                    .iter()
                    .map(|tag| tag.as_str().map(str::to_owned).ok_or("bad tag"))
                    .collect::<Result<Vec<_>, _>>()?;
                let max_items = value["max_items"]
                    .as_u64()
                    .and_then(|limit| usize::try_from(limit).ok())
                    .unwrap_or(MAX_POLL_ITEMS)
                    .min(MAX_POLL_ITEMS);
                let max_bytes = value["max_bytes"]
                    .as_u64()
                    .and_then(|limit| usize::try_from(limit).ok())
                    .unwrap_or(MAX_POLL_BYTES)
                    .min(MAX_POLL_BYTES);
                relay
                    .poll_bounded(
                        supplied.as_bytes(),
                        &tags,
                        now_ms(),
                        value["delete_on_fetch"].as_bool().unwrap_or(true),
                        max_items,
                        max_bytes,
                    )
                    .map(|items| {
                        json!({"items":items.into_iter().map(|(id,envelope)|json!({"id":id,"envelope":envelope})).collect::<Vec<_>>()})
                    })
            }),
        _ if method == "DELETE" && path.starts_with("/v1/item/") => relay
            .delete(supplied.as_bytes(), &path[9..])
            .map(|deleted| json!({"deleted":deleted})),
        _ => Err("not found".into()),
    };
    drop(relay);

    let (status, payload) = match response {
        Ok(value) => ("200 OK", value),
        Err(error) => {
            let status = status_for_error(&error);
            (status, json!({"error":error}))
        }
    };
    write_json_response(&mut stream, status, &payload).await
}

fn status_for_error(error: &str) -> &'static str {
    match error {
        "unauthorized" => "401 Unauthorized",
        "not found" => "404 Not Found",
        value if value.starts_with("relay storage cap reached") => "507 Insufficient Storage",
        value if value.starts_with("cannot ") => "500 Internal Server Error",
        _ => "400 Bad Request",
    }
}

async fn write_json_response(
    stream: &mut TcpStream,
    status: &str,
    payload: &Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = serde_json::to_vec(payload)?;
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(&body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run_request(request: &[u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(Mutex::new(RelayStore::new(b"secret", 1024)));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_request(stream, store, 1024).await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = vec![0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
            .await
            .expect("server waited for a request body")
            .unwrap();
        server.await.unwrap();
        response.truncate(read);
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn rejects_unauthorized_request_before_reading_large_body() {
        let response = run_request(
            b"POST /v1/enqueue HTTP/1.1\r\nAuthorization: Bearer wrong\r\nContent-Length: 1024\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    }

    #[tokio::test]
    async fn rejects_headers_over_16_kib() {
        let request = format!(
            "POST /v1/poll HTTP/1.1\r\nX-Fill: {}",
            "x".repeat(MAX_REQUEST_HEADER_BYTES)
        );
        let response = run_request(request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
    }

    #[test]
    fn refuses_envelopes_larger_than_bounded_poll_can_return() {
        assert!(validate_max_envelope(DEFAULT_MAX_ENVELOPE).is_ok());
        assert_eq!(
            validate_max_envelope(DEFAULT_MAX_ENVELOPE + 1).unwrap_err(),
            "max envelope size cannot exceed the 16777216 byte relay protocol limit"
        );
    }
}
