use abra_relay::{now_ms, RelayStore, DEFAULT_MAX_ENVELOPE};
use clap::Parser;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    #[arg(long, env = "ABRA_RELAY_SECRET")]
    secret: String,
    #[arg(long, default_value_t=DEFAULT_MAX_ENVELOPE)]
    max_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let listener = TcpListener::bind(&args.listen).await?;
    let store = Arc::new(Mutex::new(RelayStore::new(
        args.secret.as_bytes().to_vec(),
        args.max_bytes,
    )));
    loop {
        let (mut stream, _) = listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(10), async move {
                let mut bytes = Vec::new(); let mut chunk = [0u8; 8192]; let split;
                loop { let n=stream.read(&mut chunk).await?; if n==0{return Err("incomplete request".into())} bytes.extend_from_slice(&chunk[..n]); if bytes.len()>DEFAULT_MAX_ENVELOPE+16*1024{return Err("request too large".into())}
                    if let Some(found)=bytes.windows(4).position(|w|w==b"\r\n\r\n"){split=found;break}
                }
                let header=String::from_utf8_lossy(&bytes[..split]).into_owned(); let content_length=header.lines().find_map(|line|line.to_ascii_lowercase().strip_prefix("content-length:").map(str::trim).map(str::to_owned)).and_then(|x|x.parse::<usize>().ok()).unwrap_or(0); let needed=split+4+content_length; while bytes.len()<needed { let n=stream.read(&mut chunk).await?; if n==0{return Err("incomplete body".into())} bytes.extend_from_slice(&chunk[..n]); }
                let first=header.lines().next().ok_or("bad request")?; let mut parts=first.split_whitespace(); let method=parts.next().unwrap_or(""); let path=parts.next().unwrap_or(""); let body=&bytes[split+4..needed]; let supplied=header.lines().find_map(|l|l.strip_prefix("Authorization: Bearer ")).unwrap_or(""); let mut relay=store.lock().await;
                let response:Result<Value,String>=match(method,path){("POST","/v1/enqueue")=>relay.enqueue(supplied.as_bytes(),body.to_vec(),now_ms()).map(|id|json!({"id":id})),("POST","/v1/poll")=>serde_json::from_slice::<Value>(body).map_err(|_|"bad poll".into()).and_then(|v|{let tags=v["tags"].as_array().ok_or("tags required")?.iter().map(|x|x.as_str().map(str::to_owned).ok_or("bad tag")).collect::<Result<Vec<_>,_>>()?;relay.poll(supplied.as_bytes(),&tags,now_ms(),v["delete_on_fetch"].as_bool().unwrap_or(true)).map(|items|json!({"items":items.into_iter().map(|(id,envelope)|json!({"id":id,"envelope":envelope})).collect::<Vec<_>>() }))}),_ if method=="DELETE"&&path.starts_with("/v1/item/")=>relay.delete(supplied.as_bytes(),&path[9..]).map(|deleted|json!({"deleted":deleted})),_=>Err("not found".into())}; let(status,payload)=match response{Ok(v)=>("200 OK",v),Err(e)=>("400 Bad Request",json!({"error":e}))};let body=serde_json::to_vec(&payload)?;stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await?;stream.write_all(&body).await?;Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
            }).await;
        });
    }
}
