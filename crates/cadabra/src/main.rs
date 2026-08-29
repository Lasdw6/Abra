use cadabra::Daemon;
use clap::Parser;
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "ABRA_ROOT")]
    root: Option<PathBuf>,
    #[arg(long)]
    yes: bool,
}

fn default_root() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".abra")
}

#[tokio::main]
async fn main() -> cadabra::Result<()> {
    let args = Args::parse();
    let root = args.root.unwrap_or_else(default_root);
    let daemon = Arc::new(Daemon::tcp(root, args.yes).await?);
    let running = daemon.start().await?;
    tokio::signal::ctrl_c().await?;
    running.shutdown().await;
    Ok(())
}
