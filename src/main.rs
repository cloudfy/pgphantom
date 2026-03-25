mod auth;
mod backend;
mod cluster;
mod config;
mod errors;
mod protocol;
mod proxy;
mod routing;
mod server;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

/// pgphantom — PostgreSQL 16+ edge reverse proxy
#[derive(Parser, Debug)]
#[command(name = "pgphantom", version, about)]
struct Args {
    /// Path to the configuration file (YAML or JSON).
    #[arg(short, long, default_value = "/etc/pgphantom/config.yaml")]
    config: PathBuf,

    /// Override the listen address (e.g. 0.0.0.0:5432).
    #[arg(long, value_name = "HOST:PORT")]
    bind: Option<String>,

    /// Override the log level (trace|debug|info|warn|error).
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Override the log format (text|json).
    #[arg(long, value_name = "FORMAT")]
    log_format: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // ---- Load configuration ----
    let mut cfg = config::load(&args.config)?;

    // CLI overrides.
    if let Some(bind) = &args.bind {
        if let Some((host, port_str)) = bind.rsplit_once(':') {
            cfg.listen.host = host.to_string();
            cfg.listen.port = port_str.parse().unwrap_or(cfg.listen.port);
        }
    }
    if let Some(level) = &args.log_level {
        cfg.logging.level = level.clone();
    }
    if let Some(fmt) = &args.log_format {
        cfg.logging.format = match fmt.as_str() {
            "json" => config::LogFormat::Json,
            _ => config::LogFormat::Text,
        };
    }

    // ---- Initialise logging ----
    init_logging(&cfg.logging);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %args.config.display(),
        "pgphantom starting"
    );

    let config = Arc::new(cfg);

    // ---- Start cluster manager (etcd watcher if enabled) ----
    let (cluster_manager, _cluster_task) =
        cluster::ClusterManager::start(Arc::clone(&config)).await?;

    // Subscribe to config updates from etcd peers.
    let mut config_rx = cluster_manager.subscribe();

    // ---- Build initial proxy context ----
    let ctx = server::build_context(Arc::clone(&config))?;

    // ---- Spawn the accept loop in the background ----
    let ctx_for_server = Arc::clone(&ctx);
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server::run(ctx_for_server).await {
            tracing::error!(error = %e, "server loop exited with error");
        }
    });

    // ---- Config reload: rebuild context when etcd sends an update ----
    // In a full implementation, this would atomically swap the Arc<ProxyContext>
    // and drain in-flight connections gracefully.  For now we log the change.
    let reload_handle = tokio::spawn(async move {
        loop {
            if config_rx.changed().await.is_err() {
                break;
            }
            let new_cfg = config_rx.borrow().clone();
            tracing::info!("config update received from etcd peer — reload support coming soon");
            drop(new_cfg);
        }
    });

    // ---- Wait for CTRL-C / SIGTERM ----
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received SIGINT — shutting down");
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM — shutting down");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!("received CTRL-C — shutting down");
    }

    server_handle.abort();
    reload_handle.abort();

    Ok(())
}

fn init_logging(logging: &config::LoggingConfig) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&logging.level));

    match logging.format {
        config::LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        config::LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
        }
    }
}
