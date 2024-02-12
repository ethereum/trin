use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::ensure;
use futures::future::join_all;
use rand::{seq::SliceRandom, thread_rng};
use surf::{Client, Config};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, error, info, warn};

use crate::{
    api::execution::construct_proof,
    bridge::{
        history::{GOSSIP_LIMIT, SERVE_BLOCK_TIMEOUT},
        utils::lookup_epoch_acc,
    },
    gossip::gossip_history_content,
    stats::{HistoryBlockStats, StatsReporter},
    types::{
        era1::{BlockTuple, Era1},
        mode::{BridgeMode, FourFoursMode},
    },
};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient, types::execution::accumulator::EpochAccumulator,
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
    HistoryContentValue,
};
use trin_validation::{
    accumulator::MasterAccumulator, constants::EPOCH_SIZE, oracle::HeaderOracle,
};

const ERA1_DIR_URL: &str = "https://era1.ethportal.net/";

pub struct Era1Bridge {
    pub mode: BridgeMode,
    pub portal_clients: Vec<HttpClient>,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
    pub era1_files: Vec<String>,
    pub http_client: Client,
}

// todo: validate via checksum, so we don't have to validate content on a per-value basis
impl Era1Bridge {
    pub async fn new(
        mode: BridgeMode,
        portal_clients: Vec<HttpClient>,
        header_oracle: HeaderOracle,
        epoch_acc_path: PathBuf,
    ) -> anyhow::Result<Self> {
        let http_client: Client = Config::new()
            .add_header("Content-Type", "application/xml")
            .expect("to be able to add header")
            .try_into()?;
        let directory = http_client
            .get(ERA1_DIR_URL)
            .recv_string()
            .await
            .expect("to be able to read era1 file directory");
        let xml = roxmltree::Document::parse(&directory)?;
        let mut era1_files: Vec<String> = xml
            .descendants()
            .filter(|n| n.tag_name().name() == "Key")
            .map(|n| {
                let key = n.text().expect("to be able to get text");
                format!("{ERA1_DIR_URL}{key}")
            })
            .collect();
        era1_files.shuffle(&mut thread_rng());
        Ok(Self {
            mode,
            portal_clients,
            header_oracle,
            epoch_acc_path,
            era1_files,
            http_client,
        })
    }

    pub async fn launch(&self) {
        info!("Launching era1 bridge: {:?}", self.mode);
        match self.mode.clone() {
            BridgeMode::FourFours(FourFoursMode::Random) => self.launch_random().await,
            BridgeMode::FourFours(FourFoursMode::Single(epoch)) => self.launch_single(epoch).await,
            _ => panic!("4444s bridge only supports 4444s modes."),
        }
        info!("Bridge mode: {:?} complete.", self.mode);
    }

    pub async fn launch_random(&self) {
        for era1_path in self.era1_files.clone().into_iter() {
            self.gossip_era1(era1_path).await;
        }
    }

    pub async fn launch_single(&self, epoch: u64) {
        let epoch_string = format!("{epoch}-");
        let era1_path = self
            .era1_files
            .clone()
            .into_iter()
            .find(|file| file.contains(&epoch_string));
        match era1_path {
            Some(path) => self.gossip_era1(path).await,
            None => panic!("4444s bridge couldn't find request epoch on era1 file server"),
        }
    }

    pub async fn gossip_era1(&self, era1_path: String) {
        info!("Processing era1 file at path: {era1_path:?}");
        // We are using a semaphore to limit the amount of active gossip transfers to make sure
        // we don't overwhelm the trin client
        let gossip_send_semaphore = Arc::new(Semaphore::new(GOSSIP_LIMIT));

        let raw_era1 = self
            .http_client
            .get(era1_path.clone())
            .recv_bytes()
            .await
            .unwrap_or_else(|_| panic!("unable to read era1 file at path: {era1_path:?}"));
        let era1 = Era1::deserialize(&raw_era1).expect("to be able to deserialize era1 file");
        let epoch_index = era1.block_tuples[0].header.header.number / EPOCH_SIZE as u64;
        info!("Era1 file read successfully, gossiping block tuples for epoch: {epoch_index}");
        let epoch_acc = match self.get_epoch_acc(epoch_index).await {
            Ok(epoch_acc) => epoch_acc,
            Err(e) => {
                error!("Failed to get epoch acc for epoch: {epoch_index}, error: {e}");
                return;
            }
        };
        let master_acc = Arc::new(self.header_oracle.master_acc.clone());
        let mut serve_block_tuple_handles = vec![];
        for block_tuple in era1.block_tuples {
            let permit = gossip_send_semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("to be able to acquire semaphore");
            let serve_block_tuple_handle = Self::spawn_serve_block_tuple(
                self.portal_clients.clone(),
                block_tuple,
                epoch_acc.clone(),
                master_acc.clone(),
                permit,
            );
            serve_block_tuple_handles.push(serve_block_tuple_handle);
        }
        // Wait till all block tuples are done gossiping.
        // This can't deadlock, because the tokio::spawn has a timeout.
        join_all(serve_block_tuple_handles).await;
    }

    async fn get_epoch_acc(&self, epoch_index: u64) -> anyhow::Result<Arc<EpochAccumulator>> {
        let (epoch_hash, epoch_acc) = lookup_epoch_acc(
            epoch_index,
            &self.header_oracle.master_acc,
            &self.epoch_acc_path,
        )
        .await?;
        // Gossip epoch acc to network if found locally
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash });
        let content_value = HistoryContentValue::EpochAccumulator(epoch_acc.clone());
        // create unique stats for epoch accumulator, since it's rarely gossiped
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(
            epoch_index * EPOCH_SIZE as u64,
        )));
        debug!("Built EpochAccumulator for Epoch #{epoch_index:?}: now gossiping.");
        // spawn gossip in new thread to avoid blocking
        let portal_clients = self.portal_clients.clone();
        tokio::spawn(async move {
            if let Err(msg) =
                gossip_history_content(&portal_clients, content_key, content_value, block_stats)
                    .await
            {
                warn!("Failed to gossip epoch accumulator: {msg}");
            }
        });
        Ok(Arc::new(epoch_acc))
    }

    fn spawn_serve_block_tuple(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        master_acc: Arc<MasterAccumulator>,
        permit: OwnedSemaphorePermit,
    ) -> JoinHandle<()> {
        let number = block_tuple.header.header.number;
        info!("Spawning serve_block_tuple for block at height: {number}",);
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(number)));
        tokio::spawn(async move {
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_block_tuple(
                    portal_clients,
                    block_tuple,
                    epoch_acc,
                    master_acc,
                    block_stats.clone(),
                )).await
                {
                Ok(result) => match result {
                    Ok(_) => debug!("Successfully served block: {number}"),
                    Err(msg) => warn!("Error serving block: {number}: {msg:?}"),
                },
                Err(_) => error!("serve_full_block() timed out on height {number}: this is an indication a bug is present")
            };
            drop(permit);
        })
    }

    async fn serve_block_tuple(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        master_acc: Arc<MasterAccumulator>,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        info!(
            "Serving block tuple at height: {}",
            block_tuple.header.header.number
        );
        if let Err(msg) = Self::construct_and_gossip_header(
            portal_clients.clone(),
            block_tuple.clone(),
            epoch_acc,
            master_acc,
            block_stats.clone(),
        )
        .await
        {
            warn!(
                "Error serving block tuple header at height: {:?} - {:?}",
                block_tuple.header.header.number, msg
            );
            // we actually do want to cut off the gossip for body / receipts if header fails,
            // since the header might fail validation and we don't want to serve the rest of the
            // block a future improvement would be to have a more fine-grained error
            // handling and only cut off gossip if header fails validation
            return Ok(());
        }

        if let Err(msg) = Self::construct_and_gossip_block_body(
            portal_clients.clone(),
            block_tuple.clone(),
            block_stats.clone(),
        )
        .await
        {
            warn!(
                "Error serving block tuple block body at height: {:?} - {:?}",
                block_tuple.header.header.number, msg
            );
        }

        if let Err(msg) = Self::construct_and_gossip_receipts(
            portal_clients.clone(),
            block_tuple.clone(),
            block_stats.clone(),
        )
        .await
        {
            warn!(
                "Error serving block tuple receipts at height: {:?} - {:?}",
                block_tuple.header.header.number, msg
            );
        }
        Ok(())
    }

    async fn construct_and_gossip_header(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        master_acc: Arc<MasterAccumulator>,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let header = block_tuple.header.header;
        // Fetch HeaderRecord from EpochAccumulator for validation
        let header_index = header.number % EPOCH_SIZE as u64;
        let header_record = &epoch_acc[header_index as usize];

        // Validate Header
        let actual_header_hash = header.hash();

        ensure!(
            header_record.block_hash == actual_header_hash,
            "Header hash doesn't match record in local accumulator: {:?} - {:?}",
            actual_header_hash,
            header_record.block_hash
        );

        // Construct HistoryContentKey
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: header.hash().to_fixed_bytes(),
        });
        // Construct HeaderWithProof
        let header_with_proof = construct_proof(header.clone(), &epoch_acc).await?;
        // Double check that the proof is valid
        master_acc.validate_header_with_proof(&header_with_proof)?;
        // Construct HistoryContentValue
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);

        gossip_history_content(
            // remove borrow
            &portal_clients,
            content_key,
            content_value,
            block_stats,
        )
        .await
    }

    async fn construct_and_gossip_block_body(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let header = block_tuple.header.header;
        // Construct HistoryContentKey
        let content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: header.hash().to_fixed_bytes(),
        });
        // Construct HistoryContentValue
        let content_value = HistoryContentValue::BlockBody(block_tuple.body.body);
        gossip_history_content(&portal_clients, content_key, content_value, block_stats).await
    }

    async fn construct_and_gossip_receipts(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let header = block_tuple.header.header;
        // Construct HistoryContentKey
        let content_key = HistoryContentKey::BlockReceipts(BlockReceiptsKey {
            block_hash: header.hash().to_fixed_bytes(),
        });
        // Construct HistoryContentValue
        let content_value = HistoryContentValue::Receipts(block_tuple.receipts.receipts);
        gossip_history_content(&portal_clients, content_key, content_value, block_stats).await
    }
}
