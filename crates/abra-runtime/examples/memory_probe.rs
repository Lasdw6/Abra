//! Live-checkpoint fixture. All progress stays in RAM; it has no checkpoint API.
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args
        .get(2)
        .ok_or("usage: memory_probe serve|query PORT [COMMAND]")?
        .parse()?;
    let address = ("127.0.0.1", port);
    if args[1] == "query" {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        writeln!(
            stream,
            "{}",
            args.get(3).map(String::as_str).unwrap_or("status")
        )?;
        let mut response = String::new();
        BufReader::new(stream)
            .take(65536)
            .read_line(&mut response)?;
        print!("{response}");
        return Ok(());
    }
    if args[1] != "serve" {
        return Err("expected serve or query".into());
    }
    let mut nonce = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut results = Vec::<String>::new();
    let listener = TcpListener::bind(address)?;
    for connection in listener.incoming() {
        let mut stream = connection?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut request = String::new();
        BufReader::new(&mut stream)
            .take(1024)
            .read_line(&mut request)?;
        if let Some(count) = request.trim().strip_prefix("advance ") {
            let count: usize = count.parse()?;
            if results.len() + count > 1000 {
                return Err("fixture task limit exceeded".into());
            }
            for task in results.len() + 1..=results.len() + count {
                results.push(format!("{nonce}:task-{task}"));
            }
        }
        let digest = blake3::hash(results.join("\n").as_bytes());
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "nonce": nonce, "completed": results.len(), "digest": digest.to_hex().to_string(),
                "pid": std::process::id(), "state_storage": "memory-only"
            })
        )?;
    }
    Ok(())
}
