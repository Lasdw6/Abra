use cadabra::{control_call, Daemon};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};

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
        #[arg(long)]
        to: PathBuf,
    },
    Log {
        #[arg(long)]
        capsule: Option<String>,
    },
    Outbox,
    Cancel {
        id: String,
    },
    Enroll(EnrollArgs),
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
    if let Command::Daemon { yes } = cli.command {
        let daemon = Arc::new(Daemon::tcp(&root, yes).await?);
        let running = daemon.start().await?;
        tokio::signal::ctrl_c().await?;
        running.shutdown().await;
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
            json!({"op":"send","peer":args.peer,"link":args.link,"title":args.title,"note":args.note,"path":path,"snapshot_id":args.capsule})
        }
        Command::Inbox => json!({"op":"inbox"}),
        Command::Accept { id, to } => {
            let absolute = if to.is_absolute() {
                to
            } else {
                std::env::current_dir()?.join(to)
            };
            json!({"op":"accept","id":id,"to":absolute})
        }
        Command::Log { capsule } => json!({"op":"log","capsule":capsule}),
        Command::Outbox => json!({"op":"outbox"}),
        Command::Cancel { id } => json!({"op":"cancel","id":id}),
        Command::Enroll(args) => {
            json!({"op":"enroll-mint","capsules":args.capsules,"kinds":args.kinds,"ttl_ms":args.ttl,"send":args.send,"receive":args.receive})
        }
        Command::Daemon { .. } => unreachable!(),
    };
    let result = control_call(root, &request).await?;
    if cli.json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        if matches!(
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
        } else {
            print_human(&result);
        }
    }
    Ok(())
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
