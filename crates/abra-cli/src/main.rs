#[cfg(any(feature = "iroh", feature = "tcp"))]
use cadabra::{adapters::ExtraAdapterDir, Daemon};
use cadabra::{background, control_call, relay::RelayConfig, DaemonConfig};
use clap::{ArgGroup, Args, Parser, Subcommand};
use serde_json::{json, Value};
#[cfg(any(feature = "iroh", feature = "tcp"))]
use std::{ffi::OsString, process::Stdio, sync::Arc, time::Duration};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
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
    /// Collect process and environment observations inside a sandbox.
    Observe(abra_runtime::observe::ObserveArgs),
    /// Check, capture, and restore live Linux processes with CRIU.
    Process(abra_runtime::process::ProcessArgs),
    /// Internal file transfer and process helpers for sandbox coordinators.
    #[command(hide = true)]
    SandboxHelper(abra_runtime::sandbox::SandboxArgs),
    Status,
    Daemon {
        #[arg(long)]
        yes: bool,
        /// Loopback-only test transport; the default iroh transport is the
        /// only inter-device one.
        #[arg(long, value_enum, default_value_t = TransportKind::Iroh, hide = true)]
        transport: TransportKind,
        #[arg(long)]
        token: Option<String>,
        /// Re-execute detached, logging to <root>/daemon.log, and print the
        /// peer id once the daemon answers.
        #[arg(long)]
        background: bool,
        /// Extra adapter directory, or a parent of adapter directories. Not
        /// persisted; repeatable. `ABRA_ADAPTERS` is the colon-separated form.
        #[arg(long = "adapters")]
        adapters: Vec<PathBuf>,
    },
    /// Terminate the daemon recorded by `daemon --background`.
    Stop,
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
        /// Do not take the capsule lease before snapshotting.
        #[arg(long)]
        no_lease: bool,
        /// Read the immutable observer capture with this barrier ID.
        #[arg(long)]
        observation_barrier: Option<String>,
        /// Host-supplied environment facts as JSON, attached to that capture.
        #[arg(long, requires = "observation_barrier")]
        observation_host: Option<String>,
    },
    Send(SendArgs),
    Inbox(InboxArgs),
    Accept(AcceptArgs),
    /// Verify local snapshot objects and report native or portable restore options.
    RestorePlan {
        id: String,
        /// Receiver fingerprint as JSON; never use the captured host's fingerprint.
        #[arg(long)]
        fingerprint: Option<String>,
        /// Native artifact role required by the receiver's adapter; repeatable.
        #[arg(long = "native-role", requires = "fingerprint")]
        native_roles: Vec<String>,
    },
    /// Per-kind summary of who last had each handoff.
    Handoffs {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        peer: Option<String>,
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
    Lease {
        #[command(subcommand)]
        command: LeaseCommand,
    },
    Control(ControlArgs),
    /// Run only an adapter's inspect verb on a source.
    Inspect(InspectArgs),
    Watch,
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
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print one key, or every key when none is named.
    Get {
        key: Option<String>,
    },
    Set {
        key: String,
        value: String,
    },
    /// Restore a key to its default.
    Unset {
        key: String,
    },
}

#[derive(Subcommand)]
enum RelayCommand {
    Add {
        url: String,
        #[arg(long)]
        secret: Option<String>,
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
        to: Option<PathBuf>,
        /// Re-deliver every auto-accepted snapshot to this peer.
        #[arg(long, requires = "auto_accept")]
        forward: Option<String>,
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

#[derive(Args)]
struct InspectArgs {
    #[arg(long)]
    kind: String,
    #[arg(long)]
    source: String,
    #[arg(long = "adapter-option", value_parser = parse_adapter_option)]
    adapter_options: Vec<(String, String)>,
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
    Remove { id: String },
    Pending,
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("payload")
        .required(true)
        .multiple(false)
        .args(["link", "path", "snapshot", "kind"])
))]
#[command(group(
    ArgGroup::new("back_reference")
        .multiple(false)
        .args(["workspace", "provenance"])
))]
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
    /// Snapshot id, or a capsule id resolved to its main head.
    #[arg(long, alias = "capsule")]
    snapshot: Option<String>,
    #[arg(long, requires = "source")]
    kind: Option<String>,
    #[arg(long, requires = "kind")]
    source: Option<String>,
    /// Snapshot this workspace, send it, and set the adapter partial's
    /// provenance to it. Initializes the directory when it is not a capsule.
    #[arg(long, requires = "kind")]
    workspace: Option<PathBuf>,
    /// Existing local snapshot id to record as the partial's provenance.
    #[arg(long)]
    provenance: Option<String>,
    /// Return only once every enqueued delivery is acknowledged.
    #[arg(long)]
    wait: bool,
    #[arg(long, value_parser = parse_duration, default_value = "120s")]
    timeout: u64,
    /// Do not take the capsule lease before snapshotting a workspace.
    #[arg(long)]
    no_lease: bool,
    /// Send even when the adapter's inspect verb blocked this source.
    #[arg(long)]
    force: bool,
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
struct InboxArgs {
    #[arg(long)]
    kind: Option<String>,
    #[arg(long)]
    from: Option<String>,
    /// Block until an unread matching delivery exists.
    #[arg(long)]
    wait: bool,
    #[arg(long, value_parser = parse_duration, default_value = "120s")]
    timeout: u64,
}

// `id` is optional with `--latest`, so the last positional stays the path.
#[derive(Args)]
#[command(allow_missing_positional = true)]
struct AcceptArgs {
    #[arg(required_unless_present = "latest")]
    id: Option<String>,
    path: PathBuf,
    /// Accept the newest unread delivery of `--kind`, or another peer's
    /// capsule main head of that kind when the inbox has none.
    #[arg(long, requires = "kind")]
    latest: bool,
    #[arg(long)]
    kind: Option<String>,
    #[arg(long)]
    from: Option<String>,
    /// Replace the files of an existing workspace for the same capsule,
    /// preserving its .abra directory. Local edits since the recorded snapshot
    /// require --discard-local; a snapshot that does not descend from it
    /// requires --allow-divergence.
    #[arg(long)]
    replace: bool,
    /// Restore the workspace this delivery's provenance names into <dir>
    /// before the adapter import runs.
    #[arg(long)]
    workspace: Option<PathBuf>,
    #[arg(long, value_parser = parse_duration, default_value = "120s")]
    timeout: u64,
    /// Do not take the capsule lease while materializing a workspace.
    #[arg(long)]
    no_lease: bool,
    /// Overwrite local workspace files that differ from the recorded snapshot.
    #[arg(long)]
    discard_local: bool,
    /// Replace even when the incoming snapshot does not descend from the recorded one.
    #[arg(long)]
    allow_divergence: bool,
    /// Materialize the files and mark the delivery read without running the
    /// registered importer.
    #[arg(long)]
    no_import: bool,
    #[arg(long)]
    destination: Option<String>,
    #[arg(long = "adapter-option", value_parser = parse_adapter_option)]
    adapter_options: Vec<(String, String)>,
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
    /// Let the guest acquire an expired or unheld capsule lease.
    #[arg(long)]
    lease_acquire: bool,
    /// Let the guest take over a capsule lease another peer holds.
    #[arg(long)]
    lease_takeover: bool,
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
    // These commands operate inside a sandbox and do not need a daemon or identity.
    if let Command::Observe(args) = cli.command {
        return print_runtime_result(abra_runtime::observe::run(args), true);
    }
    if let Command::Process(args) = cli.command {
        return print_runtime_result(abra_runtime::process::run(args), cli.json);
    }
    if let Command::SandboxHelper(args) = cli.command {
        return print_runtime_result(abra_runtime::sandbox::run(args), true);
    }
    let root = cli.root.unwrap_or_else(default_root);
    if let Command::Link { command } = cli.command {
        return run_link(&root, command, cli.json).await;
    }
    if let Command::Config { command } = cli.command {
        return run_config(&root, command, cli.json);
    }
    if matches!(cli.command, Command::Stop) {
        let result = background::stop(&root).await?;
        if cli.json {
            println!("{}", serde_json::to_string(&result)?);
        } else {
            print_human(&result);
        }
        return Ok(());
    }
    if let Command::Daemon {
        yes,
        transport,
        token,
        background: detached,
        adapters,
    } = cli.command
    {
        #[cfg(not(any(feature = "iroh", feature = "tcp")))]
        {
            let _ = (yes, transport, token, detached, adapters);
            return Err("binary built without a network transport".into());
        }
        #[cfg(any(feature = "iroh", feature = "tcp"))]
        {
            if detached {
                return start_background_daemon(&root, cli.json).await;
            }
            background::detach_from_terminal();
            let mut daemon = match transport {
                #[cfg(feature = "iroh")]
                TransportKind::Iroh => Daemon::iroh(&root, yes).await?,
                #[cfg(not(feature = "iroh"))]
                TransportKind::Iroh => return Err("binary built without iroh transport".into()),
                #[cfg(feature = "tcp")]
                TransportKind::Tcp => Daemon::tcp(&root, yes).await?,
                #[cfg(not(feature = "tcp"))]
                TransportKind::Tcp => return Err("binary built without TCP transport".into()),
            };
            daemon.set_adapter_sources(adapter_sources(adapters)?);
            let daemon = Arc::new(daemon);
            if let Some(token) = token {
                daemon.join(&token).await?;
            }
            let running = daemon.start().await?;
            wait_for_shutdown().await?;
            running.shutdown().await;
            background::release_pid_file(&root);
            return Ok(());
        }
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
            PairCommand::Remove { id } => json!({"op":"pair-remove","id":id}),
            PairCommand::Pending => json!({"op":"pending-pairs"}),
        },
        Command::Peers => json!({"op":"peers"}),
        Command::RestorePlan {
            id,
            fingerprint,
            native_roles,
        } => {
            let fingerprint = fingerprint
                .map(|value| serde_json::from_str::<Value>(&value))
                .transpose()?;
            json!({"op":"restore-plan","id":id,"fingerprint":fingerprint,"native_roles":native_roles})
        }
        Command::Init { path } => {
            std::fs::create_dir_all(&path)?;
            json!({"op":"capsule-create","path":std::fs::canonicalize(path)?})
        }
        Command::Snapshot {
            label,
            path,
            no_lease,
            observation_barrier,
            observation_host,
        } => {
            let observation_host = observation_host
                .map(|value| serde_json::from_str::<Value>(&value))
                .transpose()?;
            json!({"op":"snapshot","path":std::fs::canonicalize(path)?,"label":label,"no_lease":no_lease,"observation_barrier":observation_barrier,"observation_host":observation_host})
        }
        Command::Send(args) => {
            let path = args.path.map(std::fs::canonicalize).transpose()?;
            let workspace = args
                .workspace
                .map(|path| {
                    std::fs::create_dir_all(&path)?;
                    std::fs::canonicalize(path)
                })
                .transpose()?;
            let options = args
                .adapter_options
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>();
            json!({"op":"send","peer":args.peer,"link":args.link,"title":args.title,"note":args.note,"path":path,"snapshot_id":args.snapshot,"kind":args.kind,"source":args.source,"workspace":workspace,"provenance":args.provenance,"wait":args.wait,"timeout_ms":args.timeout,"no_lease":args.no_lease,"force":args.force,"options":options})
        }
        Command::Inbox(args) => {
            json!({"op":"inbox","kind":args.kind,"from":args.from,"wait":args.wait,"timeout_ms":args.timeout})
        }
        Command::Accept(args) => {
            let absolute = if args.replace {
                std::fs::canonicalize(&args.path)?
            } else if args.path.is_absolute() {
                args.path
            } else {
                std::env::current_dir()?.join(args.path)
            };
            let workspace = args
                .workspace
                .map(|path| {
                    if path.is_absolute() {
                        Ok(path)
                    } else {
                        std::env::current_dir().map(|cwd| cwd.join(path))
                    }
                })
                .transpose()?;
            let options = args
                .adapter_options
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>();
            json!({"op":"accept","id":args.id,"to":absolute,"replace":args.replace,"latest":args.latest,"kind":args.kind,"from":args.from,"workspace":workspace,"timeout_ms":args.timeout,"no_lease":args.no_lease,"discard_local":args.discard_local,"allow_divergence":args.allow_divergence,"no_import":args.no_import,"destination":args.destination,"options":options})
        }
        Command::Handoffs { kind, peer } => json!({"op":"handoffs","kind":kind,"peer":peer}),
        Command::Log { capsule } => json!({"op":"log","capsule":capsule}),
        Command::Capsules => json!({"op":"capsules"}),
        Command::Outbox => json!({"op":"outbox"}),
        Command::Cancel { id } => json!({"op":"cancel","id":id}),
        Command::Enroll(args) => {
            json!({"op":"enroll-mint","capsules":args.capsules,"kinds":args.kinds,"ttl_ms":args.ttl,"send":args.send,"receive":args.receive,"lease_acquire":args.lease_acquire,"lease_takeover":args.lease_takeover})
        }
        Command::Join { token } => json!({"op":"enroll-join","token":token}),
        Command::Revoke { token_id } => json!({"op":"revoke","token_id":token_id}),
        Command::Policy { command } => match command {
            PolicyCommand::Grant {
                peer,
                kind,
                capsule,
                auto_accept,
                to,
                forward,
            } => {
                let to = to.map(|path| {
                    if path.is_absolute() {
                        path
                    } else {
                        std::env::current_dir().unwrap().join(path)
                    }
                });
                json!({"op":"policy-grant","peer":peer,"kind":kind,"capsule":capsule,"auto_accept":auto_accept,"to":to,"forward":forward})
            }
            PolicyCommand::List => json!({"op":"policy-list"}),
            PolicyCommand::Clear => json!({"op":"policy-clear"}),
            PolicyCommand::Revoke { id } => json!({"op":"policy-revoke","id":id}),
        },
        Command::Lease { command } => match command {
            LeaseCommand::Status { capsule } => json!({"op":"lease-status","capsule":capsule}),
            LeaseCommand::Take { capsule } => json!({"op":"lease-take","capsule":capsule}),
        },
        Command::Control(args) => {
            json!({"op":"control","peer":args.peer,"capsule":args.capsule,"control_op":args.op,"text":args.text})
        }
        Command::Inspect(args) => {
            let options = args
                .adapter_options
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>();
            json!({"op":"inspect","kind":args.kind,"source":args.source,"options":options})
        }
        Command::Adapters { command } => match command {
            AdapterCommand::List => json!({"op":"adapters-list"}),
            AdapterCommand::Add { dir } => {
                json!({"op":"adapters-add","dir":fs::canonicalize(dir)?})
            }
            AdapterCommand::Remove { name } => json!({"op":"adapters-remove","name":name}),
        },
        Command::Relay { command } => match command {
            RelayCommand::Add { url, secret } => {
                json!({"op":"relay-add","url":url,"secret":secret})
            }
            RelayCommand::List => json!({"op":"relay-list"}),
            RelayCommand::Remove { url } => json!({"op":"relay-remove","url":url}),
        },
        Command::Watch => unreachable!(),
        Command::Link { .. } => unreachable!(),
        Command::Daemon { .. } | Command::Stop => unreachable!(),
        Command::Config { .. } => unreachable!(),
        Command::Observe(_) | Command::Process(_) | Command::SandboxHelper(_) => unreachable!(),
    };
    let result = call_with_pairing_hint(&root, &request, !cli.json).await?;
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
    } else {
        if result.get("workspace_detected") == Some(&Value::Bool(true)) {
            eprintln!(
                "workspace detected: sent capsule snapshot {}",
                result
                    .get("snapshot_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            );
        }
        print_human(&result);
        // A control ack is a result, not a transport error; human mode still
        // exits non-zero when the peer refused it.
        if request.get("op").and_then(Value::as_str) == Some("control")
            && result.get("ok") == Some(&Value::Bool(false))
        {
            return Err(result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("control was refused")
                .to_owned()
                .into());
        }
    }
    Ok(())
}

fn print_runtime_result(
    result: Result<Value, Box<dyn std::error::Error>>,
    json_output: bool,
) -> cadabra::Result<()> {
    let result = result.map_err(|error| error.to_string())?;
    if json_output {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        print_human(&result);
    }
    if result.get("ok") == Some(&Value::Bool(false)) {
        return Err("runtime check reported blockers; see the result above".into());
    }
    Ok(())
}

/// `--adapters` first, then `ABRA_ADAPTERS`, so an explicit flag wins.
#[cfg(any(feature = "iroh", feature = "tcp"))]
fn adapter_sources(flags: Vec<PathBuf>) -> cadabra::Result<Vec<ExtraAdapterDir>> {
    let mut sources = Vec::new();
    for path in flags {
        sources.push(ExtraAdapterDir::flag(absolute(path)?));
    }
    sources.extend(ExtraAdapterDir::from_env());
    Ok(sources)
}

#[cfg(any(feature = "iroh", feature = "tcp"))]
fn absolute(path: PathBuf) -> cadabra::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Re-execute this binary without `--background`, detached, and wait for the
/// child to answer on the control socket.
#[cfg(any(feature = "iroh", feature = "tcp"))]
async fn start_background_daemon(root: &Path, json_output: bool) -> cadabra::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if !root.exists() {
        builder.create(root)?;
    }
    let launch_lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("daemon.launch.lock"))?;
    fs2::FileExt::lock_exclusive(&launch_lock)?;
    if control_call(root, &json!({"op":"status"})).await.is_ok() {
        return Err(format!("daemon already running at {}", root.display()).into());
    }
    let binary = std::env::current_exe()?;
    let args = std::env::args_os()
        .skip(1)
        .filter(|argument| argument != "--background")
        .collect::<Vec<OsString>>();
    let log_path = background::log_path(root);
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let log = options.open(&log_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))?;
    }
    let child = ProcessCommand::new(&binary)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .env("ABRA_DAEMON_DETACH", "1")
        .spawn()?;
    let pid = child.id() as i32;
    background::PidFile {
        pid,
        started_at: background::process_identity(pid).map(|(started, _)| started),
        binary: binary.display().to_string(),
        root: root.to_path_buf(),
    }
    .save(root)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(status) = control_call(root, &json!({"op":"status"})).await {
            let peer = status
                .get("peer_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string(
                        &json!({"peer_id":peer,"pid":pid,"root":root,"log":log_path})
                    )?
                );
            } else {
                println!("{peer}");
            }
            return Ok(());
        }
        if !background::is_alive(pid) {
            remove_pid_file_if_matches(root, pid);
            return Err(format!("daemon exited during startup; see {}", log_path.display()).into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "daemon did not answer within 60 seconds; see {}",
                log_path.display()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(any(feature = "iroh", feature = "tcp"))]
fn remove_pid_file_if_matches(root: &Path, pid: i32) {
    if background::PidFile::load(root)
        .is_ok_and(|record| record.is_some_and(|record| record.pid == pid))
    {
        let _ = background::PidFile::remove(root);
    }
}

/// Daemon and relay settings are plain JSON files, so `config` edits them
/// directly and works before the first daemon start.
fn run_config(root: &Path, command: ConfigCommand, json_output: bool) -> cadabra::Result<()> {
    match command {
        ConfigCommand::Get { key } => {
            let daemon = DaemonConfig::load(root)?;
            let relays = RelayConfig::load(root)?;
            let all = json!({
                "iroh_relay": daemon.iroh_relay,
                "skip_native": daemon.skip_native,
                "offer_budget": daemon.offer_budget,
                "relay_after_attempts": relays.relay_after_attempts,
                "relay_poll_seconds": relays.relay_poll_seconds,
            });
            let value = match &key {
                Some(key) => all
                    .get(key.as_str())
                    .cloned()
                    .ok_or_else(|| format!("unknown config key: {key}"))?,
                None => all,
            };
            if json_output {
                println!("{}", serde_json::to_string(&value)?);
            } else if let Some(object) = value.as_object() {
                for (key, value) in object {
                    println!("{key}={}", plain_value(value));
                }
            } else {
                println!("{}", plain_value(&value));
            }
        }
        ConfigCommand::Set { key, value } => {
            apply_config(root, &key, Some(&value))?;
            if json_output {
                println!("{}", serde_json::to_string(&json!({"key":key}))?);
            } else {
                println!("{key} set{}", restart_note(&key));
            }
        }
        ConfigCommand::Unset { key } => {
            apply_config(root, &key, None)?;
            if json_output {
                println!("{}", serde_json::to_string(&json!({"key":key}))?);
            } else {
                println!("{key} reset to its default{}", restart_note(&key));
            }
        }
    }
    Ok(())
}

/// Relay tuning is reread while the daemon runs; daemon settings are not.
fn restart_note(key: &str) -> &'static str {
    match key {
        "relay_after_attempts" | "relay_poll_seconds" => "",
        _ => "; restart the daemon to apply it",
    }
}

fn plain_value(value: &Value) -> String {
    match value.as_str() {
        Some(text) => text.to_owned(),
        None => value.to_string(),
    }
}

/// `None` restores the key's default.
fn apply_config(root: &Path, key: &str, value: Option<&str>) -> cadabra::Result<()> {
    match key {
        "iroh_relay" | "skip_native" | "offer_budget" => {
            let mut config = DaemonConfig::load(root)?;
            let default = DaemonConfig::default();
            match (key, value) {
                ("iroh_relay", Some(value)) => {
                    #[cfg(feature = "iroh")]
                    {
                        value.parse::<abra_net::IrohRelayMode>()?;
                        config.iroh_relay = value.to_owned();
                    }
                    #[cfg(not(feature = "iroh"))]
                    {
                        let _ = value;
                        return Err("binary built without iroh transport".into());
                    }
                }
                ("iroh_relay", None) => config.iroh_relay = default.iroh_relay,
                ("skip_native", Some(value)) => {
                    config.skip_native = value
                        .parse()
                        .map_err(|_| "skip_native must be true or false")?;
                }
                ("skip_native", None) => config.skip_native = default.skip_native,
                (_, Some(value)) => {
                    config.offer_budget =
                        value.parse().map_err(|_| "offer_budget must be bytes")?;
                }
                (_, None) => config.offer_budget = default.offer_budget,
            }
            config.save(root)?;
        }
        "relay_after_attempts" | "relay_poll_seconds" => {
            let mut config = RelayConfig::load(root)?;
            let default = RelayConfig::default();
            match (key, value) {
                ("relay_after_attempts", Some(value)) => {
                    config.relay_after_attempts = value
                        .parse()
                        .map_err(|_| "relay_after_attempts must be a count")?;
                }
                ("relay_after_attempts", None) => {
                    config.relay_after_attempts = default.relay_after_attempts;
                }
                (_, Some(value)) => {
                    let seconds: u64 = value
                        .parse()
                        .map_err(|_| "relay_poll_seconds must be seconds")?;
                    if seconds < 5 {
                        return Err("relay_poll_seconds minimum is 5".into());
                    }
                    config.relay_poll_seconds = seconds;
                }
                (_, None) => config.relay_poll_seconds = default.relay_poll_seconds,
            }
            config.save(root)?;
        }
        _ => return Err(format!("unknown config key: {key}").into()),
    }
    Ok(())
}

/// Pairing blocks until the ticket issuer confirms, so tell the operator where
/// to confirm when the wait is real.
async fn call_with_pairing_hint(
    root: &Path,
    request: &Value,
    human: bool,
) -> cadabra::Result<Value> {
    let hint = if human && request.get("op").and_then(Value::as_str) == Some("pair-add") {
        pairing_hint(root, request).await
    } else {
        None
    };
    let call = control_call(root, request);
    tokio::pin!(call);
    if let Some(hint) = hint {
        tokio::select! {
            result = &mut call => return result,
            _ = tokio::time::sleep(std::time::Duration::from_millis(1500)) => eprintln!("{hint}"),
        }
    }
    call.await
}

async fn pairing_hint(root: &Path, request: &Value) -> Option<String> {
    let ticket = request.get("ticket").and_then(Value::as_str)?;
    let issuer = abra_net::PairTicket::parse(ticket, abra_core::now_ms())
        .ok()?
        .peer_id;
    let local = control_call(root, &json!({"op":"status"}))
        .await
        .ok()?
        .get("peer_id")
        .and_then(Value::as_str)?
        .to_owned();
    Some(format!(
        "waiting for confirmation on {}: run `abra pair confirm {local}` there",
        issuer.short()
    ))
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

#[cfg(any(feature = "iroh", feature = "tcp"))]
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
    fn snapshot_host_facts_require_a_capture_barrier() {
        assert!(
            Cli::try_parse_from(["abra", "snapshot", ".", "--observation-host", "{}"]).is_err()
        );
        let parsed = Cli::try_parse_from([
            "abra",
            "snapshot",
            ".",
            "--observation-barrier",
            "capture_1",
            "--observation-host",
            "{}",
        ])
        .unwrap();
        let Command::Snapshot {
            observation_barrier,
            observation_host,
            ..
        } = parsed.command
        else {
            panic!("expected snapshot")
        };
        assert_eq!(observation_barrier.as_deref(), Some("capture_1"));
        assert_eq!(observation_host.as_deref(), Some("{}"));
    }

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
    fn accept_takes_one_path_and_an_optional_replace() {
        assert!(Cli::try_parse_from(["abra", "accept", "id"]).is_err());
        assert!(Cli::try_parse_from(["abra", "accept", "id", "new"]).is_ok());
        assert!(Cli::try_parse_from(["abra", "accept", "id", "existing", "--replace"]).is_ok());
        let parsed = Cli::try_parse_from([
            "abra",
            "accept",
            "id",
            "existing",
            "--replace",
            "--discard-local",
            "--allow-divergence",
            "--no-import",
        ])
        .unwrap();
        let Command::Accept(args) = parsed.command else {
            panic!("expected accept");
        };
        assert!(args.discard_local);
        assert!(args.allow_divergence);
        assert!(args.no_import);
    }

    #[test]
    fn accept_latest_replaces_the_id_positional() {
        let parsed =
            Cli::try_parse_from(["abra", "accept", "--latest", "--kind", "k", "here"]).unwrap();
        let Command::Accept(args) = parsed.command else {
            panic!("expected accept");
        };
        assert!(args.id.is_none());
        assert_eq!(args.path, PathBuf::from("here"));
        assert!(args.latest);

        let parsed = Cli::try_parse_from(["abra", "accept", "id", "here"]).unwrap();
        let Command::Accept(args) = parsed.command else {
            panic!("expected accept");
        };
        assert_eq!(args.id.as_deref(), Some("id"));
        assert_eq!(args.path, PathBuf::from("here"));

        // Without --latest the id stays required, and --latest needs a kind.
        assert!(Cli::try_parse_from(["abra", "accept", "here"]).is_err());
        assert!(Cli::try_parse_from(["abra", "accept", "--latest", "here"]).is_err());
    }

    #[test]
    fn send_workspace_and_provenance_are_exclusive_back_references() {
        assert!(Cli::try_parse_from([
            "abra",
            "send",
            "peer",
            "--kind",
            "k",
            "--source",
            "s",
            "--workspace",
            "dir",
            "--wait"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "abra",
            "send",
            "peer",
            "--kind",
            "k",
            "--source",
            "s",
            "--workspace",
            "dir",
            "--provenance",
            "id"
        ])
        .is_err());
        // --workspace only makes sense for an adapter send.
        assert!(
            Cli::try_parse_from(["abra", "send", "peer", "--path", "dir", "--workspace", "w"])
                .is_err()
        );
    }

    #[test]
    fn daemon_takes_background_and_repeatable_adapter_dirs() {
        let parsed = Cli::try_parse_from([
            "abra",
            "daemon",
            "--background",
            "--adapters",
            "/one",
            "--adapters",
            "/two",
        ])
        .unwrap();
        let Command::Daemon {
            background,
            adapters,
            ..
        } = parsed.command
        else {
            panic!("expected daemon");
        };
        assert!(background);
        assert_eq!(adapters, [PathBuf::from("/one"), PathBuf::from("/two")]);
        assert!(Cli::try_parse_from(["abra", "stop"]).is_ok());
    }

    #[test]
    fn send_takes_exactly_one_payload_source() {
        assert!(Cli::try_parse_from(["abra", "send", "peer"]).is_err());
        assert!(Cli::try_parse_from(["abra", "send", "peer", "--snapshot", "id"]).is_ok());
        assert!(Cli::try_parse_from(["abra", "send", "peer", "--capsule", "id"]).is_ok());
        assert!(
            Cli::try_parse_from(["abra", "send", "peer", "--snapshot", "id", "--path", "dir"])
                .is_err()
        );
    }

    #[test]
    fn config_rejects_unknown_keys_and_restores_defaults() {
        let root = tempfile::tempdir().unwrap();
        assert!(apply_config(root.path(), "nope", Some("1")).is_err());
        apply_config(root.path(), "skip_native", Some("true")).unwrap();
        assert!(DaemonConfig::load(root.path()).unwrap().skip_native);
        apply_config(root.path(), "skip_native", None).unwrap();
        assert!(!DaemonConfig::load(root.path()).unwrap().skip_native);
        assert!(apply_config(root.path(), "relay_poll_seconds", Some("1")).is_err());
        apply_config(root.path(), "relay_poll_seconds", Some("30")).unwrap();
        assert_eq!(
            RelayConfig::load(root.path()).unwrap().relay_poll_seconds,
            30
        );
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
