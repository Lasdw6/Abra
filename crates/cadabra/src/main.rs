use cadabra::Daemon;
use clap::Parser;
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "ABRA_ROOT")]
    root: Option<PathBuf>,
    #[arg(long)]
    yes: bool,
    #[arg(long, value_enum, default_value_t = TransportKind::Iroh)]
    transport: TransportKind,
    #[arg(long)]
    token: Option<String>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum TransportKind {
    Iroh,
    Tcp,
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
    let daemon = Arc::new(match args.transport {
        #[cfg(feature = "iroh")]
        TransportKind::Iroh => Daemon::iroh(root, args.yes).await?,
        #[cfg(not(feature = "iroh"))]
        TransportKind::Iroh => return Err("binary built without iroh transport".into()),
        #[cfg(feature = "tcp")]
        TransportKind::Tcp => Daemon::tcp(root, args.yes).await?,
        #[cfg(not(feature = "tcp"))]
        TransportKind::Tcp => return Err("binary built without TCP transport".into()),
    });
    if let Some(token) = args.token {
        daemon.join(&token).await?;
    }
    let running = daemon.start().await?;
    wait_for_shutdown().await?;
    running.shutdown().await;
    Ok(())
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
