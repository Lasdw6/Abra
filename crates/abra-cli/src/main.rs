use cadabra::{control_call, Daemon, DaemonConfig};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::Arc,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Parser)]
#[command(name = "abra", version, about = "Teleport workspaces and handoffs")]
struct Cli {
    #[arg(long, env = "ABRA_ROOT", global = true)]
    root: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status,
    Daemon {
        #[arg(long)]
        yes: bool,
        #[arg(long, value_enum, default_value_t = TransportKind::Iroh)]
        transport: TransportKind,
        #[arg(long)]
        token: Option<String>,
        /// n0, none, or a custom https relay URL.
        #[arg(long)]
        iroh_relay: Option<String>,
        /// Accept portable content without optional native cache blobs.
        #[arg(long)]
        skip_native: bool,
        /// Maximum bytes accepted for one direct offer.
        #[arg(long)]
        offer_budget: Option<u64>,
    },
    Pair {
        #[command(subcommand)]
        command: PairCommand,
    },
    Peers,
    Init {
        path: PathBuf,
    },
    Snapshot {
        #[arg(short = 'm')]
        label: Option<String>,
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Send(SendArgs),
    Inbox,
    Accept {
        id: String,
        #[arg(long, required_unless_present = "into", conflicts_with = "into")]
        to: Option<PathBuf>,
        #[arg(long, required_unless_present = "to", conflicts_with = "to")]
        into: Option<PathBuf>,
        #[arg(long)]
        destination: Option<String>,
        #[arg(long = "adapter-option", value_parser = parse_adapter_option)]
        adapter_options: Vec<(String, String)>,
    },
    Log {
        #[arg(long)]
        capsule: Option<String>,
    },
    Capsules,
    Outbox,
    Cancel {
        id: String,
    },
    Enroll(EnrollArgs),
    Join {
        token: String,
    },
    Revoke {
        token_id: String,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Ps,
    StopRecipes {
        capsule: String,
    },
    Lease {
        #[command(subcommand)]
        command: LeaseCommand,
    },
    Control(ControlArgs),
    Watch,
    Mesh {
        #[command(subcommand)]
        command: MeshCommand,
    },
    Link {
        #[command(subcommand)]
        command: LinkCommand,
    },
    Adapters {
        #[command(subcommand)]
        command: AdapterCommand,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
}

#[derive(Subcommand)]
enum RelayCommand {
    Add {
        url: String,
        #[arg(long)]
        secret: Option<String>,
        #[arg(long)]
        relay_after_attempts: Option<u32>,
        #[arg(long)]
        poll_seconds: Option<u64>,
    },
    List,
    Remove {
        url: String,
    },
}

#[derive(Subcommand)]
enum AdapterCommand {
    List,
    Add { dir: PathBuf },
    Remove { name: String },
}

#[derive(Subcommand)]
enum LinkCommand {
    Mint {
        snapshot: String,
        #[arg(long, value_parser = parse_duration, default_value = "7d")]
        ttl: u64,
        #[arg(long, conflicts_with = "full")]
        floor_only: bool,
        #[arg(long)]
        full: bool,
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Public ciphertext URL after upload (defaults to the local file URL).
        #[arg(long)]
        url: Option<String>,
        /// Shell command template with {file}, {hash}, and {url} placeholders.
        #[arg(long)]
        upload_command: Option<String>,
        /// Required companion hook for remotely uploaded ciphertext. Receives
        /// the same {file}, {hash}, and {url} placeholders at revoke time.
        #[arg(long, requires = "upload_command")]
        revoke_command: Option<String>,
        /// Static viewer origin. When set, emits the fragment-only viewer form.
        #[arg(long)]
        viewer: Option<String>,
    },
    List,
    Revoke {
        id: String,
    },
    Open {
        url: String,
        #[arg(long, default_value = ".")]
        to: PathBuf,
    },
    Serve {
        dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
    },
}

#[derive(Subcommand)]
enum MeshCommand {
    Profile { profile: Option<String> },
}

#[derive(Subcommand)]
enum PolicyCommand {
    Grant {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        capsule: Option<String>,
        #[arg(long)]
        auto_accept: bool,
        #[arg(long)]
        auto_run_recipes: bool,
        #[arg(long)]
        to: Option<PathBuf>,
    },
    List,
    Clear,
    Revoke {
        id: String,
    },
}

#[derive(Subcommand)]
enum LeaseCommand {
    Status { capsule: String },
    Take { capsule: String },
}

#[derive(Args)]
struct ControlArgs {
    peer: String,
    #[arg(long)]
    capsule: String,
    #[arg(value_parser = ["pause", "stop", "instruct"])]
    op: String,
    text: Option<String>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum TransportKind {
    Iroh,
    Tcp,
}

#[derive(Subcommand)]
enum PairCommand {
    Ticket,
    Add { ticket: String },
    Confirm { id: String },
    Pending,
}

#[derive(Args)]
struct SendArgs {
    peer: String,
    #[arg(long)]
    link: Option<String>,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    note: Option<String>,
    #[arg(long)]
    path: Option<PathBuf>,
    #[arg(long)]
    capsule: Option<String>,
    #[arg(long, requires = "source")]
    kind: Option<String>,
    #[arg(long, requires = "kind")]
    source: Option<String>,
    #[arg(long = "adapter-option", value_parser = parse_adapter_option)]
    adapter_options: Vec<(String, String)>,
}

fn parse_adapter_option(value: &str) -> Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "adapter option must be k=v".to_owned())?;
    if key.is_empty() {
        return Err("adapter option key must not be empty".into());
    }
    Ok((key.to_owned(), value.to_owned()))
}

#[derive(Args)]
struct EnrollArgs {
    #[arg(long = "capsule", required = true)]
    capsules: Vec<String>,
    #[arg(long = "kind", required = true)]
    kinds: Vec<String>,
    #[arg(long, value_parser = parse_duration)]
    ttl: u64,
    #[arg(long)]
    send: bool,
    #[arg(long)]
    receive: bool,
}

fn parse_duration(s: &str) -> Result<u64, String> {
    let (number, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = number.parse().map_err(|_| "invalid duration".to_string())?;
    let multiplier = match unit {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err("duration needs ms/s/m/h/d suffix".into()),
    };
    n.checked_mul(multiplier)
        .ok_or_else(|| "duration too large".into())
}

fn default_root() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".abra")
}

#[tokio::main]
async fn main() -> cadabra::Result<()> {
    let cli = Cli::parse();
    let root = cli.root.unwrap_or_else(default_root);
    if let Command::Link { command } = cli.command {
        return run_link(&root, command, cli.json).await;
    }
    if let Command::Daemon {
        yes,
        transport,
        token,
        iroh_relay,
        skip_native,
        offer_budget,
    } = cli.command
    {
        let mut config = DaemonConfig::load(&root)?;
        let config_changed = iroh_relay.is_some() || skip_native || offer_budget.is_some();
        if let Some(relay) = &iroh_relay {
            relay.parse::<abra_net::IrohRelayMode>()?;
            config.iroh_relay = relay.clone();
        }
        if skip_native {
            config.skip_native = true;
        }
        if let Some(bytes) = offer_budget {
            config.offer_budget = bytes;
        }
        if config_changed {
            config.save(&root)?;
        }
        let daemon = Arc::new(match transport {
            #[cfg(feature = "iroh")]
            TransportKind::Iroh => Daemon::iroh(&root, yes).await?,
            #[cfg(not(feature = "iroh"))]
            TransportKind::Iroh => return Err("binary built without iroh transport".into()),
            #[cfg(feature = "tcp")]
            TransportKind::Tcp => Daemon::tcp(&root, yes).await?,
            #[cfg(not(feature = "tcp"))]
            TransportKind::Tcp => return Err("binary built without TCP transport".into()),
        });
        if let Some(token) = token {
            daemon.join(&token).await?;
        }
        let running = daemon.start().await?;
        wait_for_shutdown().await?;
        running.shutdown().await;
        return Ok(());
    }
    if matches!(cli.command, Command::Watch) {
        let stream = UnixStream::connect(root.join("cadabra.sock")).await?;
        let (read, mut write) = stream.into_split();
        write.write_all(b"{\"op\":\"watch\"}\n").await?;
        let mut lines = BufReader::new(read).lines();
        while let Some(line) = lines.next_line().await? {
            println!("{line}");
        }
        return Ok(());
    }
    let request = match cli.command {
        Command::Status => json!({"op":"status"}),
        Command::Pair { command } => match command {
            PairCommand::Ticket => json!({"op":"pair-ticket"}),
            PairCommand::Add { ticket } => json!({"op":"pair-add","ticket":ticket}),
            PairCommand::Confirm { id } => json!({"op":"pair-confirm","id":id}),
            PairCommand::Pending => json!({"op":"pending-pairs"}),
        },
        Command::Peers => json!({"op":"peers"}),
        Command::Init { path } => {
            std::fs::create_dir_all(&path)?;
            json!({"op":"capsule-create","path":std::fs::canonicalize(path)?})
        }
        Command::Snapshot { label, path } => {
            json!({"op":"snapshot","path":std::fs::canonicalize(path)?,"label":label})
        }
        Command::Send(args) => {
            let path = args.path.map(std::fs::canonicalize).transpose()?;
            let options = args
                .adapter_options
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>();
            json!({"op":"send","peer":args.peer,"link":args.link,"title":args.title,"note":args.note,"path":path,"snapshot_id":args.capsule,"kind":args.kind,"source":args.source,"options":options})
        }
        Command::Inbox => json!({"op":"inbox"}),
        Command::Accept {
            id,
            to,
            into,
            destination,
            adapter_options,
        } => {
            let path = to.or(into.clone()).expect("clap requires a destination");
            let absolute = if into.is_some() {
                std::fs::canonicalize(&path)?
            } else if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            };
            let options = adapter_options
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>();
            json!({"op":"accept","id":id,"to":absolute,"into":into.is_some(),"destination":destination,"options":options})
        }
        Command::Log { capsule } => json!({"op":"log","capsule":capsule}),
        Command::Capsules => json!({"op":"capsules"}),
        Command::Outbox => json!({"op":"outbox"}),
        Command::Cancel { id } => json!({"op":"cancel","id":id}),
        Command::Enroll(args) => {
            json!({"op":"enroll-mint","capsules":args.capsules,"kinds":args.kinds,"ttl_ms":args.ttl,"send":args.send,"receive":args.receive})
        }
        Command::Join { token } => json!({"op":"enroll-join","token":token}),
        Command::Revoke { token_id } => json!({"op":"revoke","token_id":token_id}),
        Command::Policy { command } => match command {
            PolicyCommand::Grant {
                peer,
                kind,
                capsule,
                auto_accept,
                auto_run_recipes,
                to,
            } => {
                let to = to.map(|path| {
                    if path.is_absolute() {
                        path
                    } else {
                        std::env::current_dir().unwrap().join(path)
                    }
                });
                json!({"op":"policy-grant","peer":peer,"kind":kind,"capsule":capsule,"auto_accept":auto_accept,"auto_run_recipes":auto_run_recipes,"to":to})
            }
            PolicyCommand::List => json!({"op":"policy-list"}),
            PolicyCommand::Clear => json!({"op":"policy-clear"}),
            PolicyCommand::Revoke { id } => json!({"op":"policy-revoke","id":id}),
        },
        Command::Ps => json!({"op":"ps"}),
        Command::StopRecipes { capsule } => json!({"op":"stop-recipes","capsule":capsule}),
        Command::Lease { command } => match command {
            LeaseCommand::Status { capsule } => json!({"op":"lease-status","capsule":capsule}),
            LeaseCommand::Take { capsule } => json!({"op":"lease-take","capsule":capsule}),
        },
        Command::Control(args) => {
            json!({"op":"control","peer":args.peer,"capsule":args.capsule,"control_op":args.op,"text":args.text})
        }
        Command::Mesh {
            command: MeshCommand::Profile { profile },
        } => json!({"op":"mesh-profile","profile":profile}),
        Command::Adapters { command } => match command {
            AdapterCommand::List => json!({"op":"adapters-list"}),
            AdapterCommand::Add { dir } => {
                json!({"op":"adapters-add","dir":fs::canonicalize(dir)?})
            }
            AdapterCommand::Remove { name } => json!({"op":"adapters-remove","name":name}),
        },
        Command::Relay { command } => match command {
            RelayCommand::Add {
                url,
                secret,
                relay_after_attempts,
                poll_seconds,
            } => {
                json!({"op":"relay-add","url":url,"secret":secret,"relay_after_attempts":relay_after_attempts,"poll_seconds":poll_seconds})
            }
            RelayCommand::List => json!({"op":"relay-list"}),
            RelayCommand::Remove { url } => json!({"op":"relay-remove","url":url}),
        },
        Command::Watch => unreachable!(),
        Command::Link { .. } => unreachable!(),
        Command::Daemon { .. } => unreachable!(),
    };
    let result = control_call(root, &request).await?;
    if cli.json {
        println!("{}", serde_json::to_string(&result)?);
    } else if matches!(
        request.get("op").and_then(Value::as_str),
        Some("pair-ticket")
    ) {
        println!(
            "{}",
            result
                .get("ticket")
                .and_then(Value::as_str)
                .ok_or("daemon returned no ticket")?
        );
    } else if request.get("op").and_then(Value::as_str) == Some("enroll-mint") {
        let token = result
            .get("token")
            .and_then(Value::as_str)
            .ok_or("daemon returned no enrollment token")?;
        println!("{token}");
        println!("abra://join/{token}");
    } else {
        print_human(&result);
    }
    Ok(())
}

async fn run_link(root: &Path, command: LinkCommand, json_output: bool) -> cadabra::Result<()> {
    use abra_core::{
        cas::Hash,
        link::{self, LinkMode},
    };
    use data_encoding::BASE64URL_NOPAD;
    if matches!(
        &command,
        LinkCommand::Mint { .. } | LinkCommand::Serve { .. }
    ) {
        let trust = abra_net::TrustStore::open(root)?;
        if !matches!(trust.local_role(), abra_net::LocalRole::Full) {
            return Err("guest devices may not mint or host capability links".into());
        }
    }
    match command {
        LinkCommand::Mint {
            snapshot,
            ttl,
            floor_only: _,
            full,
            out,
            url,
            upload_command,
            revoke_command,
            viewer,
        } => {
            let store = abra_core::store::AbraStore::open(root)?;
            let id: Hash = snapshot.parse()?;
            let raw = link::find_snapshot(&store, id)?;
            fs::create_dir_all(&out)?;
            let expires_ms = abra_core::now_ms()
                .checked_add(ttl)
                .ok_or("expiry overflow")?;
            if ttl > 30 * 86_400_000 {
                return Err("link TTL exceeds 30 days".into());
            }
            let provisional = out.join(format!("{id}.abracap"));
            let absolute = if provisional.is_absolute() {
                provisional.clone()
            } else {
                std::env::current_dir()?.join(&provisional)
            };
            let public_url = url.unwrap_or_else(|| format!("file://{}", absolute.display()));
            if !public_url.starts_with("file://") && revoke_command.is_none() {
                return Err("remote uploads require --revoke-command so revocation can tombstone the hosted blob".into());
            }
            let minted = link::mint(
                &store,
                &raw,
                expires_ms,
                abra_net::format_time(expires_ms),
                if full {
                    LinkMode::Full
                } else {
                    LinkMode::Floor
                },
                public_url.clone(),
            )?;
            let blob_hash = Hash::of(&minted.blob);
            let blob_path = out.join(format!("{blob_hash}.abracap"));
            fs::write(&blob_path, &minted.blob)?;
            let actual_url = capability_public_url(&minted.record.url, blob_hash, &blob_path)?;
            if let Some(template) = upload_command {
                let command = template
                    .replace("{file}", &blob_path.to_string_lossy())
                    .replace("{hash}", &blob_hash.to_hex())
                    .replace("{url}", &actual_url);
                let status = ProcessCommand::new("sh").arg("-c").arg(command).status()?;
                if !status.success() {
                    return Err("uploader command failed".into());
                }
            }
            let mut record = minted.record;
            record.url = actual_url.clone();
            record.ciphertext_hash = Some(blob_hash);
            record.local_path = Some(blob_path.to_string_lossy().into_owned());
            record.revoke_command = revoke_command;
            record.resign(&store.keys.identity)?;
            link::save_record(&store, &record)?;
            let key = BASE64URL_NOPAD.encode(&minted.key);
            let share_url = if let Some(viewer) = viewer {
                format!(
                    "{}#v=1&u={}&k={}",
                    viewer.trim_end_matches('#'),
                    BASE64URL_NOPAD.encode(actual_url.as_bytes()),
                    key
                )
            } else {
                format!("{actual_url}#{key}")
            };
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string(
                        &json!({"link_id":record.link_id,"url":share_url,"expires_at":record.expires_at,"mode":record.mode})
                    )?
                );
            } else {
                println!("{share_url}");
            }
        }
        LinkCommand::List => {
            let store = abra_core::store::AbraStore::open(root)?;
            let records = link::list_records(&store)?;
            if json_output {
                println!("{}", serde_json::to_string(&records)?);
            } else {
                for record in records {
                    println!(
                        "{}\t{}\t{:?}\t{}\t{}",
                        record.link_id,
                        record.snapshot_id,
                        record.mode,
                        record.expires_at,
                        if record.revoked { "revoked" } else { "active" }
                    );
                }
            }
        }
        LinkCommand::Revoke { id } => {
            let store = abra_core::store::AbraStore::open(root)?;
            let record = link::revoke_record(&store, &id)?;
            if !record.url.starts_with("file://") {
                let template = record.revoke_command.as_deref().ok_or(
                    "remote capability has no revoke hook; hosted ciphertext was not revoked",
                )?;
                let file = record.local_path.as_deref().unwrap_or("");
                let hash = record
                    .ciphertext_hash
                    .map(|h| h.to_hex())
                    .unwrap_or_default();
                let command = template
                    .replace("{file}", file)
                    .replace("{hash}", &hash)
                    .replace("{url}", &record.url);
                let status = ProcessCommand::new("sh").arg("-c").arg(command).status()?;
                if !status.success() {
                    return Err("remote revoke command failed".into());
                }
            }
            if json_output {
                println!("{}", serde_json::to_string(&record)?);
            } else {
                println!("revoked {}", record.link_id);
            }
        }
        LinkCommand::Open { url, to } => {
            let (ciphertext_url, key) = parse_capability_url(&url)?;
            let blob = fetch_capability(&ciphertext_url).await?;
            let pack = link::open(&blob, &key, abra_core::now_ms())?;
            let store = abra_core::store::AbraStore::open(root)?;
            let raw = link::import(&pack, &store, &to)?;
            println!(
                "{}",
                if json_output {
                    serde_json::to_string(&json!({"snapshot_id":raw.snapshot_id(),"to":to}))?
                } else {
                    format!("opened {} into {}", raw.snapshot_id(), to.display())
                }
            );
        }
        LinkCommand::Serve { dir, listen } => serve_links(&dir, &listen).await?,
    }
    Ok(())
}

fn parse_capability_url(url: &str) -> cadabra::Result<(String, [u8; 32])> {
    use data_encoding::BASE64URL_NOPAD;
    let (base, fragment) = url
        .split_once('#')
        .ok_or("capability URL lacks key fragment")?;
    let (ciphertext_url, encoded_key) =
        if fragment.starts_with("v=1&") || fragment.starts_with("u=") {
            let fields = fragment
                .split('&')
                .filter_map(|field| field.split_once('='))
                .collect::<std::collections::BTreeMap<_, _>>();
            let encoded_url = fields.get("u").ok_or("viewer URL lacks u fragment")?;
            let decoded_url = BASE64URL_NOPAD
                .decode(encoded_url.as_bytes())
                .map_err(|_| "invalid ciphertext URL encoding")?;
            (
                String::from_utf8(decoded_url)?,
                *fields.get("k").ok_or("viewer URL lacks k fragment")?,
            )
        } else {
            (base.to_owned(), fragment)
        };
    let decoded = BASE64URL_NOPAD
        .decode(encoded_key.as_bytes())
        .map_err(|_| "invalid capability key")?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "capability key must be 32 bytes")?;
    Ok((ciphertext_url, key))
}

async fn fetch_capability(url: &str) -> cadabra::Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        return Ok(tokio::fs::read(path).await?);
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("capability ciphertext URL must use file, http, or https".into());
    }
    let output = tokio::process::Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--location", url])
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!(
            "ciphertext fetch failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

async fn serve_links(dir: &Path, listen: &str) -> cadabra::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let root = fs::canonicalize(dir)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "serving {} on http://{}",
        root.display(),
        listener.local_addr()?
    );
    loop {
        let (mut stream, _) = listener.accept().await?;
        let root = root.clone();
        tokio::spawn(async move {
            let mut request = vec![0; 8192];
            let Ok(count) = stream.read(&mut request).await else {
                return;
            };
            let first = String::from_utf8_lossy(&request[..count])
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            let path = first
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .trim_start_matches('/');
            if path.contains("..") || path.contains('\\') {
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return;
            }
            let file = if path.is_empty() {
                root.join("index.html")
            } else {
                root.join(path)
            };
            let resolved = resolve_served_path(&file).await;
            if resolved.as_ref().is_ok_and(|p| !p.starts_with(&root)) {
                let _ = stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return;
            }
            let Ok(file) = resolved else {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 0\r\n\r\n").await;
                return;
            };
            match tokio::fs::read(&file).await {
                Ok(bytes) => {
                    let content_type = if file.extension().and_then(|x| x.to_str()) == Some("html")
                    {
                        "text/html; charset=utf-8"
                    } else if file.extension().and_then(|x| x.to_str()) == Some("js") {
                        "text/javascript; charset=utf-8"
                    } else {
                        "application/octet-stream"
                    };
                    let header = format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nX-Content-Type-Options: nosniff\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len());
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&bytes).await;
                }
                Err(_) => {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\n\r\n").await;
                }
            }
        });
    }
}

fn capability_public_url(
    configured: &str,
    hash: abra_core::cas::Hash,
    blob_path: &Path,
) -> cadabra::Result<String> {
    if configured.starts_with("file://") {
        let path = if blob_path.is_absolute() {
            blob_path.to_owned()
        } else {
            std::env::current_dir()?.join(blob_path)
        };
        Ok(format!("file://{}", path.display()))
    } else {
        Ok(configured.replace("{hash}", &hash.to_hex()))
    }
}

async fn resolve_served_path(path: &Path) -> std::io::Result<PathBuf> {
    match tokio::fs::canonicalize(path).await {
        Ok(path) if path.is_dir() => tokio::fs::canonicalize(path.join("index.html")).await,
        other => other,
    }
}

async fn wait_for_shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = term.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

fn print_human(value: &Value) {
    match value {
        Value::String(s) => println!("{s}"),
        Value::Array(items) => {
            for item in items {
                println!("{}", serde_json::to_string_pretty(item).unwrap());
            }
        }
        _ => println!("{}", serde_json::to_string_pretty(value).unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_url_substitutes_ciphertext_hash() {
        let hash = abra_core::cas::Hash::of(b"ciphertext");
        assert_eq!(
            capability_public_url(
                "http://127.0.0.1:8080/{hash}.abracap",
                hash,
                Path::new("unused"),
            )
            .unwrap(),
            format!("http://127.0.0.1:8080/{hash}.abracap")
        );
    }

    #[test]
    fn accept_requires_exactly_one_materialization_mode() {
        assert!(Cli::try_parse_from(["abra", "accept", "id"]).is_err());
        assert!(
            Cli::try_parse_from(["abra", "accept", "id", "--to", "new", "--into", "existing"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["abra", "accept", "id", "--to", "new"]).is_ok());
        assert!(Cli::try_parse_from(["abra", "accept", "id", "--into", "existing"]).is_ok());
    }

    #[test]
    fn policy_clear_is_a_valid_command() {
        assert!(Cli::try_parse_from(["abra", "policy", "clear"]).is_ok());
    }

    #[tokio::test]
    async fn directory_routes_resolve_to_their_index() {
        let root = tempfile::tempdir().unwrap();
        let viewer = root.path().join("viewer");
        fs::create_dir(&viewer).unwrap();
        fs::write(viewer.join("index.html"), "viewer").unwrap();
        assert_eq!(
            resolve_served_path(&viewer).await.unwrap(),
            fs::canonicalize(viewer.join("index.html")).unwrap()
        );
    }
}
