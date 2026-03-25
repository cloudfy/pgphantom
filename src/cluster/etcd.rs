use crate::config::{Config, EtcdConfig};
use crate::errors::PgPhantomError;
use etcd_client::Client;
use std::sync::Arc;
use tokio::sync::watch;

/// Push the local config to etcd and start watching for config changes
/// from other nodes.  Runs until the process exits.
pub(super) async fn run_watcher(
    config: Arc<Config>,
    etcd_cfg: EtcdConfig,
    node_id: String,
    tx: watch::Sender<Arc<Config>>,
) {
    if let Err(e) = run_watcher_inner(config, etcd_cfg, node_id, tx).await {
        tracing::error!(error = %e, "etcd watcher terminated with error");
    }
}

async fn run_watcher_inner(
    config: Arc<Config>,
    etcd_cfg: EtcdConfig,
    node_id: String,
    tx: watch::Sender<Arc<Config>>,
) -> Result<(), PgPhantomError> {
    tracing::info!(node_id = %node_id, "connecting to etcd");

    let mut client = Client::connect(etcd_cfg.endpoints.clone(), None)
        .await
        .map_err(|e| {
            PgPhantomError::Backend(format!("etcd connect failed: {e}"))
        })?;

    // Publish this node's config so peers can see it.
    let local_key = format!("{}/config/{}", etcd_cfg.prefix.trim_end_matches('/'), node_id);
    let config_json = serde_json::to_string(&*config).map_err(|e| {
        PgPhantomError::Config(crate::errors::ConfigError::Json(e))
    })?;

    client
        .put(local_key.as_bytes(), config_json.as_bytes(), None)
        .await
        .map_err(|e| PgPhantomError::Backend(format!("etcd put failed: {e}")))?;

    tracing::info!(key = %local_key, "published local config to etcd");

    // Watch the cluster-wide config prefix for changes.
    let watch_prefix = format!("{}/config/", etcd_cfg.prefix.trim_end_matches('/'));
    tracing::info!(prefix = %watch_prefix, "watching etcd prefix for config updates");

    let (mut watcher, mut stream) = client
        .watch(watch_prefix.as_bytes(), Some(etcd_client::WatchOptions::new().with_prefix()))
        .await
        .map_err(|e| PgPhantomError::Backend(format!("etcd watch failed: {e}")))?;

    while let Some(resp) = stream.message().await.map_err(|e| {
        PgPhantomError::Backend(format!("etcd watch stream error: {e}"))
    })? {
        for event in resp.events() {
            use etcd_client::EventType;
            if event.event_type() == EventType::Put {
                if let Some(kv) = event.kv() {
                    let key = String::from_utf8_lossy(kv.key());
                    // Skip our own node's key to avoid feedback loops.
                    if key.ends_with(&node_id) {
                        continue;
                    }
                    let value = match std::str::from_utf8(kv.value()) {
                        Ok(s) => s,
                        Err(_) => {
                            tracing::warn!(peer_key = %key, "etcd value is not valid UTF-8 — skipping");
                            continue;
                        }
                    };
                    match crate::config::parse_str(value, "json") {
                        Ok(new_cfg) => {
                            tracing::info!(
                                peer_key = %key,
                                "received config update from peer — reloading routing rules"
                            );
                            // Merge: use our listen/auth settings but peer's routing.
                            // For now, broadcast the peer config as-is so callers can
                            // decide how to merge.  A production implementation would
                            // apply a merge strategy.
                            let _ = tx.send(Arc::new(new_cfg));
                        }
                        Err(e) => {
                            tracing::warn!(
                                peer_key = %key,
                                error = %e,
                                "failed to parse peer config from etcd — ignoring"
                            );
                        }
                    }
                }
            }
        }
    }

    watcher.cancel().await.ok();
    Ok(())
}
