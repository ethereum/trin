use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::consensus::ConsensusLightClient;
use log::{error, info, warn};
use tokio::sync::RwLock;

use ethportal_api::consensus::header::BeaconBlockHeader;
use std::path::PathBuf;
use tokio::{spawn, time::sleep};

use crate::{
    config::{client_config::Config, CheckpointFallback, Network},
    consensus::{errors::ConsensusError, rpc::ConsensusRpc},
};

use crate::{database::Database, errors::NodeError, node::Node};

use crate::rpc::Rpc;

#[derive(Default)]
pub struct ClientBuilder {
    network: Option<Network>,
    consensus_rpc: Option<String>,
    checkpoint: Option<Vec<u8>>,
    rpc_port: Option<u16>,
    data_dir: Option<PathBuf>,
    config: Option<Config>,
    fallback: Option<String>,
    load_external_fallback: bool,
    strict_checkpoint_age: bool,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    pub fn consensus_rpc(mut self, consensus_rpc: &str) -> Self {
        self.consensus_rpc = Some(consensus_rpc.to_string());
        self
    }

    pub fn checkpoint(mut self, checkpoint: &str) -> Self {
        let checkpoint = hex::decode(checkpoint.strip_prefix("0x").unwrap_or(checkpoint))
            .expect("cannot parse checkpoint");
        self.checkpoint = Some(checkpoint);
        self
    }

    pub fn rpc_port(mut self, port: u16) -> Self {
        self.rpc_port = Some(port);
        self
    }

    pub fn data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = Some(data_dir);
        self
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub fn fallback(mut self, fallback: &str) -> Self {
        self.fallback = Some(fallback.to_string());
        self
    }

    pub fn load_external_fallback(mut self) -> Self {
        self.load_external_fallback = true;
        self
    }

    pub fn strict_checkpoint_age(mut self) -> Self {
        self.strict_checkpoint_age = true;
        self
    }

    pub fn build<DB: Database, R: ConsensusRpc + 'static>(self) -> Result<Client<DB, R>> {
        let base_config = if let Some(network) = self.network {
            network.to_base_config()
        } else {
            let config = self
                .config
                .as_ref()
                .ok_or(anyhow!("missing network config"))?;
            config.to_base_config()
        };

        let consensus_rpc = self.consensus_rpc.unwrap_or_else(|| {
            self.config
                .as_ref()
                .expect("missing consensus rpc")
                .consensus_rpc
                .clone()
        });

        let checkpoint = if let Some(checkpoint) = self.checkpoint {
            Some(checkpoint)
        } else if let Some(config) = &self.config {
            config.checkpoint.clone()
        } else {
            None
        };

        let default_checkpoint = if let Some(config) = &self.config {
            config.default_checkpoint.clone()
        } else {
            base_config.default_checkpoint.clone()
        };

        let rpc_port = if self.rpc_port.is_some() {
            self.rpc_port
        } else if let Some(config) = &self.config {
            config.rpc_port
        } else {
            None
        };

        let data_dir = if self.data_dir.is_some() {
            self.data_dir
        } else if let Some(config) = &self.config {
            config.data_dir.clone()
        } else {
            None
        };

        let fallback = if self.fallback.is_some() {
            self.fallback
        } else if let Some(config) = &self.config {
            config.fallback.clone()
        } else {
            None
        };

        let load_external_fallback = if let Some(config) = &self.config {
            self.load_external_fallback || config.load_external_fallback
        } else {
            self.load_external_fallback
        };

        let strict_checkpoint_age = if let Some(config) = &self.config {
            self.strict_checkpoint_age || config.strict_checkpoint_age
        } else {
            self.strict_checkpoint_age
        };

        let config = Config {
            consensus_rpc,
            checkpoint,
            default_checkpoint,
            rpc_port,
            data_dir,
            chain: base_config.chain,
            forks: base_config.forks,
            max_checkpoint_age: base_config.max_checkpoint_age,
            fallback,
            load_external_fallback,
            strict_checkpoint_age,
        };

        Client::new(config)
    }

    pub fn build_with_rpc<DB: Database, R: ConsensusRpc + 'static>(
        self,
        portal_rpc: R,
    ) -> Result<Client<DB, R>> {
        let base_config = if let Some(network) = self.network {
            network.to_base_config()
        } else {
            let config = self
                .config
                .as_ref()
                .ok_or(anyhow!("missing network config"))?;
            config.to_base_config()
        };

        let checkpoint = if let Some(checkpoint) = self.checkpoint {
            Some(checkpoint)
        } else if let Some(config) = &self.config {
            config.checkpoint.clone()
        } else {
            None
        };

        let default_checkpoint = if let Some(config) = &self.config {
            config.default_checkpoint.clone()
        } else {
            base_config.default_checkpoint.clone()
        };

        let rpc_port = if self.rpc_port.is_some() {
            self.rpc_port
        } else if let Some(config) = &self.config {
            config.rpc_port
        } else {
            None
        };

        let data_dir = if self.data_dir.is_some() {
            self.data_dir
        } else if let Some(config) = &self.config {
            config.data_dir.clone()
        } else {
            None
        };

        let fallback = if self.fallback.is_some() {
            self.fallback
        } else if let Some(config) = &self.config {
            config.fallback.clone()
        } else {
            None
        };

        let load_external_fallback = if let Some(config) = &self.config {
            self.load_external_fallback || config.load_external_fallback
        } else {
            self.load_external_fallback
        };

        let strict_checkpoint_age = if let Some(config) = &self.config {
            self.strict_checkpoint_age || config.strict_checkpoint_age
        } else {
            self.strict_checkpoint_age
        };

        let config = Config {
            checkpoint,
            default_checkpoint,
            rpc_port,
            data_dir,
            chain: base_config.chain,
            forks: base_config.forks,
            max_checkpoint_age: base_config.max_checkpoint_age,
            fallback,
            load_external_fallback,
            strict_checkpoint_age,
            ..Default::default()
        };

        Client::with_portal(config, portal_rpc)
    }
}

#[derive(Clone)]
pub struct Client<DB: Database, R: ConsensusRpc> {
    node: Arc<RwLock<Node<R>>>,
    rpc: Option<Rpc<R>>,
    db: DB,
    fallback: Option<String>,
    load_external_fallback: bool,
}

impl<DB: Database, R: ConsensusRpc + 'static> Client<DB, R> {
    fn new(mut config: Config) -> Result<Self> {
        let db = DB::new(&config)?;
        if config.checkpoint.is_none() {
            let checkpoint = db.load_checkpoint()?;
            config.checkpoint = Some(checkpoint);
        }

        let config = Arc::new(config);
        let node = Node::new(config.clone())?;
        let node = Arc::new(RwLock::new(node));

        let rpc = config.rpc_port.map(|port| Rpc::new(node.clone(), port));

        Ok(Client {
            node,
            rpc,
            db,
            fallback: config.fallback.clone(),
            load_external_fallback: config.load_external_fallback,
        })
    }

    fn with_portal(mut config: Config, portal_rpc: R) -> Result<Self> {
        let db = DB::new(&config)?;
        if config.checkpoint.is_none() {
            let checkpoint = db.load_checkpoint()?;
            config.checkpoint = Some(checkpoint);
        }

        let config = Arc::new(config);
        let node = Node::with_portal(config.clone(), portal_rpc)?;
        let node = Arc::new(RwLock::new(node));

        let rpc = config.rpc_port.map(|port| Rpc::new(node.clone(), port));

        Ok(Client {
            node,
            rpc,
            db,
            fallback: config.fallback.clone(),
            load_external_fallback: config.load_external_fallback,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        if let Some(rpc) = &mut self.rpc {
            rpc.start().await?;
        }

        let sync_res = self.node.write().await.sync().await;

        if let Err(err) = sync_res {
            match err {
                NodeError::ConsensusSyncError(err) => match err
                    .downcast_ref()
                    .ok_or(err.to_string())
                    .map_err(|err| anyhow!(err))?
                {
                    ConsensusError::CheckpointTooOld => {
                        warn!(
                            "failed to sync consensus node with checkpoint: 0x{}",
                            hex::encode(
                                self.node
                                    .read()
                                    .await
                                    .config
                                    .checkpoint
                                    .clone()
                                    .unwrap_or_default()
                            ),
                        );

                        let fallback = self.boot_from_fallback().await;
                        if fallback.is_err() && self.load_external_fallback {
                            self.boot_from_external_fallbacks().await?
                        } else if fallback.is_err() {
                            error!("Invalid checkpoint. Please update your checkpoint too a more recent block. Alternatively, set an explicit checkpoint fallback service url with the `-f` flag or use the configured external fallback services with `-l` (NOT RECOMMENDED)");
                            return Err(err);
                        }
                    }
                    _ => return Err(err),
                },
                _ => return Err(err.into()),
            }
        }

        self.start_advance_thread();

        Ok(())
    }

    fn start_advance_thread(&self) {
        let node = self.node.clone();
        spawn(async move {
            loop {
                let res = node.write().await.advance().await;
                if let Err(err) = res {
                    warn!("consensus error: {}", err);
                }

                let next_update = node.read().await.duration_until_next_update();

                sleep(next_update).await;
            }
        });
    }

    async fn boot_from_fallback(&self) -> anyhow::Result<()> {
        if let Some(fallback) = &self.fallback {
            info!(
                "attempting to load checkpoint from fallback \"{}\"",
                fallback
            );

            let checkpoint = CheckpointFallback::fetch_checkpoint_from_api(fallback)
                .await
                .map_err(|_| {
                    anyhow!("Failed to fetch checkpoint from fallback \"{}\"", fallback)
                })?;

            info!(
                "external fallbacks responded with checkpoint 0x{:?}",
                checkpoint
            );

            // Try to sync again with the new checkpoint by reconstructing the consensus client
            // We fail fast here since the node is unrecoverable at this point
            let config = self.node.read().await.config.clone();
            let consensus = ConsensusLightClient::new(
                &config.consensus_rpc,
                checkpoint.as_slice(),
                config.clone(),
            )?;
            self.node.write().await.consensus = consensus;
            self.node.write().await.sync().await?;

            Ok(())
        } else {
            Err(anyhow!("no explicit fallback specified"))
        }
    }

    async fn boot_from_external_fallbacks(&self) -> anyhow::Result<()> {
        info!("attempting to fetch checkpoint from external fallbacks...");
        // Build the list of external checkpoint fallback services
        let list = CheckpointFallback::new()
            .build()
            .await
            .map_err(|_| anyhow!("Failed to construct external checkpoint sync fallbacks"))?;

        let checkpoint = list
            .fetch_latest_checkpoint(&Network::Mainnet)
            .await
            .map_err(|_| {
                anyhow!("Failed to fetch latest mainnet checkpoint from external fallbacks")
            })?;

        info!(
            "external fallbacks responded with checkpoint {:?}",
            checkpoint
        );

        // Try to sync again with the new checkpoint by reconstructing the consensus client
        // We fail fast here since the node is unrecoverable at this point
        let config = self.node.read().await.config.clone();
        let consensus = ConsensusLightClient::new(
            &config.consensus_rpc,
            checkpoint.as_slice(),
            config.clone(),
        )?;
        self.node.write().await.consensus = consensus;
        self.node.write().await.sync().await?;
        Ok(())
    }

    pub async fn shutdown(&self) {
        let node = self.node.read().await;
        let checkpoint = if let Some(checkpoint) = node.get_last_checkpoint() {
            checkpoint
        } else {
            return;
        };

        info!("saving last checkpoint hash");
        let res = self.db.save_checkpoint(checkpoint);
        if res.is_err() {
            warn!("checkpoint save failed");
        }
    }

    pub async fn chain_id(&self) -> u64 {
        self.node.read().await.chain_id()
    }

    pub async fn get_header(&self) -> Result<BeaconBlockHeader> {
        self.node.read().await.get_header()
    }
}
