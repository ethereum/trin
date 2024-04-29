use std::{path::PathBuf, sync::Arc};

use super::era1::get_shuffled_era1_files;
use anyhow::anyhow;
use ethportal_api::{jsonrpsee::http_client::HttpClient, StateContentKey, StateContentValue};
use surf::{Client, Config};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, error, info, warn};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::oracle::HeaderOracle;

use crate::{
    bridge::history::{EPOCH_SIZE, SERVE_BLOCK_TIMEOUT},
    gossip::gossip_state_content,
    types::{
        era1::Era1,
        mode::{BridgeMode, ModeType},
        state::{
            content::{create_content_key, create_content_value},
            execution::State,
        },
    },
};

pub struct StateBridge {
    pub mode: BridgeMode,
    pub portal_client: HttpClient,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
    pub era1_files: Vec<String>,
    pub http_client: Client,
    pub metrics: BridgeMetricsReporter,
    pub gossip_limit: usize,
}

impl StateBridge {
    pub async fn new(
        mode: BridgeMode,
        portal_client: HttpClient,
        header_oracle: HeaderOracle,
        epoch_acc_path: PathBuf,
        gossip_limit: usize,
    ) -> anyhow::Result<Self> {
        let http_client: Client = Config::new()
            .add_header("Content-Type", "application/xml")
            .expect("to be able to add header")
            .try_into()?;
        let era1_files = get_shuffled_era1_files(&http_client).await?;
        let metrics = BridgeMetricsReporter::new("state".to_string(), &format!("{mode:?}"));
        Ok(Self {
            mode,
            portal_client,
            header_oracle,
            epoch_acc_path,
            era1_files,
            http_client,
            metrics,
            gossip_limit,
        })
    }

    pub async fn launch(&self) {
        info!("Launching state bridge: {:?}", self.mode);
        match self.mode.clone() {
            BridgeMode::Single(ModeType::Block(last_block)) => {
                if last_block > 46146 {
                    panic!("State bridge only supports blocks up to 46146 for the time being.");
                }
                self.launch_state(last_block)
                    .await
                    .expect("State bridge failed");
            }
            _ => panic!("State bridge only supports State modes."),
        }
        info!("Bridge mode: {:?} complete.", self.mode);
    }

    async fn launch_state(&self, last_block: u64) -> anyhow::Result<()> {
        info!("Gossiping state data from block 0 to {last_block}");
        // We are using a semaphore to limit the amount of active gossip transfers to make sure
        // we don't overwhelm the trin client
        let gossip_send_semaphore = Arc::new(Semaphore::new(self.gossip_limit));
        let mut current_epoch_index = u64::MAX;
        let mut current_raw_era1 = vec![];
        let mut state = State::new().map_err(|e| anyhow!("unable to create genesis state: {e}"))?;
        for block_index in 0..=last_block {
            info!("Gossipping state for block at height: {block_index}");
            let epoch_index = block_index / EPOCH_SIZE;
            // make sure we have the current era1 file loaded
            if current_epoch_index != epoch_index {
                let era1_path = self
                    .era1_files
                    .iter()
                    .find(|file| file.contains(&format!("mainnet-{epoch_index:05}-")))
                    .expect("to be able to find era1 file");
                let raw_era1 = self
                    .http_client
                    .get(era1_path.clone())
                    .recv_bytes()
                    .await
                    .unwrap_or_else(|_| panic!("unable to read era1 file at path: {era1_path:?}"));
                current_epoch_index = epoch_index;
                current_raw_era1 = raw_era1;
            }

            // process block
            let block_tuple = Era1::get_tuple_by_index(&current_raw_era1, block_index % EPOCH_SIZE);
            let updated_accounts = match block_index == 0 {
                true => state.accounts.clone(),
                false => state.process_block(&block_tuple)?,
            };

            // gossip block's new state transitions
            for updated_account in updated_accounts {
                let permit = gossip_send_semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("to be able to acquire semaphore");
                let account_proof = state.get_proof(&updated_account)?;
                let content_key = create_content_key(&account_proof)?;
                let content_value =
                    create_content_value(block_tuple.header.header.hash(), &account_proof)?;
                Self::spawn_serve_state_proof(
                    self.portal_client.clone(),
                    content_key,
                    content_value,
                    permit,
                    self.metrics.clone(),
                );
            }
        }
        Ok(())
    }

    fn spawn_serve_state_proof(
        portal_client: HttpClient,
        content_key: StateContentKey,
        content_value: StateContentValue,
        permit: OwnedSemaphorePermit,
        metrics: BridgeMetricsReporter,
    ) -> JoinHandle<()> {
        info!("Spawning serve_state_proof for content key: {content_key}");
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_serve_state_proof");
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_state_proof(
                    portal_client,
                    content_key.clone(),
                    content_value,
                    metrics.clone()
                )).await
                {
                Ok(result) => match result {
                    Ok(_) => {
                        debug!("Done serving state proof: {content_key}");
                    }
                    Err(msg) => warn!("Error serving state proof: {content_key}: {msg:?}"),
                },
                Err(_) => error!("serve_state_proof() timed out on state proof {content_key}: this is an indication a bug is present")
            };
            drop(permit);
            metrics.stop_process_timer(timer);
        })
    }

    async fn serve_state_proof(
        portal_client: HttpClient,
        content_key: StateContentKey,
        content_value: StateContentValue,
        metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        let timer = metrics.start_process_timer("gossip_state_content");
        match gossip_state_content(portal_client, content_key.clone(), content_value).await {
            Ok(_) => {
                debug!("Successfully gossiped state proof: {content_key}")
            }
            Err(msg) => {
                warn!("Error gossiping state proof: {content_key} {msg}",);
            }
        }
        metrics.stop_process_timer(timer);
        Ok(())
    }
}
