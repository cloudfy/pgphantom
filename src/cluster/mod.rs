pub mod etcd;

use crate::config::{Config, EtcdConfig};
use crate::errors::PgPhantomError;
use std::sync::Arc;
use tokio::sync::watch;

/// Manages the cluster state and config distribution.
///
/// When cluster mode is disabled, this is effectively a no-op holder around
/// the static config.  When enabled, it watches etcd for changes from peer
/// nodes and emits updated configs via a `watch::Receiver`.
pub struct ClusterManager {
    /// Receives the latest `Config` whenever it changes via etcd.
    pub config_rx: watch::Receiver<Arc<Config>>,
}

impl ClusterManager {
    /// Start the cluster manager.
    ///
    /// If cluster mode is disabled, immediately returns a manager whose
    /// receiver will never update.
    pub async fn start(
        config: Arc<Config>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), PgPhantomError> {
        let (tx, rx) = watch::channel(Arc::clone(&config));

        let handle = if config.cluster.enabled {
            let etcd_cfg = config
                .cluster
                .etcd
                .clone()
                .ok_or_else(|| {
                    PgPhantomError::Config(crate::errors::ConfigError::Validation(
                        "cluster.enabled=true but no [cluster.etcd] section".into(),
                    ))
                })?;

            let node_id = config
                .cluster
                .node_id
                .clone()
                .unwrap_or_else(|| {
                    std::env::var("HOSTNAME").unwrap_or_else(|_| "default".to_string())
                });

            tokio::spawn(etcd::run_watcher(config, etcd_cfg, node_id, tx))
        } else {
            // No cluster — spawn a no-op task so the caller always gets a JoinHandle.
            tokio::spawn(async {
                tracing::debug!("cluster mode disabled — no etcd watcher");
            })
        };

        Ok((ClusterManager { config_rx: rx }, handle))
    }

    /// Returns a cloned receiver for the latest config.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Config>> {
        self.config_rx.clone()
    }
}
