/// Downloader struct that load a data CSV file from disk with block number and block hashes
/// and do FIndContent queries in batches to download all the content from the csv file.
/// We don't save the content to disk, we just download it and drop
/// it.
use std::fs::File;
use std::{
    fmt::{Display, Formatter},
    io::{self, BufRead},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Error};
use ethportal_api::{
    jsonrpsee::http_client::{HttpClient, HttpClientBuilder},
    types::{
        distance::XorMetric,
        network::Subnetwork,
        portal_wire::{Content, OfferTrace},
    },
    utils::bytes::hex_decode,
    BlockBodyKey, BlockReceiptsKey, ContentValue, HistoryContentKey, HistoryContentValue,
    OverlayContentKey,
};
use futures::{channel::oneshot, future::join_all};
use portal_bridge::census::Census;
use portalnet::{
    constants::DEFAULT_WEB3_HTTP_ADDRESS,
    overlay::{command::OverlayCommand, protocol::OverlayProtocol},
};
use ssz_types::BitList;
use tracing::{error, info, warn};
use trin_metrics::downloader::DownloaderMetricsReporter;

use crate::{storage::HistoryStorage, validation::ChainHistoryValidator};

/// The number of blocks to download in a single batch.
const BATCH_SIZE: usize = 30;
/// Enable census  with full view of the network and peer scoring to find peers to download content
/// from.
const CENSUS: bool = true;
/// The max number of ENRs to send FindContent queries to.
const CENSUS_ENR_LIMIT: usize = 4;
/// The path to the CSV file with block numbers and block hashes.
const CSV_PATH: &str = "ethereum_blocks_14000000_merge.csv";

enum ContentType {
    BlockBody,
    BlockReceipts,
}

impl Display for ContentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::BlockBody => write!(f, "BlockBody"),
            ContentType::BlockReceipts => write!(f, "BlockReceipts"),
        }
    }
}

#[derive(Clone)]
pub struct Downloader {
    pub census: Option<Census>,
    pub overlay_arc:
        Arc<OverlayProtocol<HistoryContentKey, XorMetric, ChainHistoryValidator, HistoryStorage>>,
    pub metrics: DownloaderMetricsReporter,
}

impl Downloader {
    pub fn new(
        overlay_arc: Arc<
            OverlayProtocol<HistoryContentKey, XorMetric, ChainHistoryValidator, HistoryStorage>,
        >,
    ) -> Self {
        // Build hhtp client bound to the current node web3rpc
        let http_client: HttpClient = HttpClientBuilder::default()
            // increase default timeout to allow for trace_gossip requests that can take a long
            // time
            .request_timeout(Duration::from_secs(120))
            .build(DEFAULT_WEB3_HTTP_ADDRESS)
            .map_err(|e| e.to_string())
            .expect("Failed to build http client");

        let metrics = DownloaderMetricsReporter::new();

        let mut census = None;

        if CENSUS {
            info!("Census enabled");
            census = Some(Census::new(http_client, CENSUS_ENR_LIMIT, vec![]));
        } else {
            info!("Census disabled");
        }

        Self {
            overlay_arc,
            census,
            metrics,
        }
    }

    pub async fn start(self) -> io::Result<()> {
        // set the csv path to a file in the root trin-history directory
        info!("Opening CSV file");
        let csv_path = Path::new(CSV_PATH);
        let file = File::open(csv_path)?;
        let reader = io::BufReader::new(file);
        info!("Reading CSV file");
        let lines: Vec<_> = reader.lines().collect::<Result<_, _>>()?;
        info!("Parsing CSV file");
        // skip the header of the csv file
        let lines = &lines[1..];
        let blocks: Vec<(u64, String)> = lines.iter().map(|line| parse_line(line)).collect();
        // Initialize the census with the history subnetwork if enabled
        if let Some(mut census) = self.census.clone() {
            let _ = Some(
                census
                    .init([Subnetwork::History])
                    .await
                    .expect("Failed to initialize Census"),
            );
        }

        info!("Processing blocks");
        let batches = blocks.chunks(BATCH_SIZE);

        for batch in batches {
            self.clone().process_batches(batch.to_vec()).await;
        }

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");

        Ok(())
    }

    async fn process_batches(self, batch: Vec<(u64, String)>) {
        let mut futures = Vec::new();

        for (block_number, block_hash) in batch {
            self.metrics.report_current_block(block_number);
            let block_body_content_key = generate_block_body_content_key(block_hash.clone());
            futures.push(self.find_content(
                block_body_content_key,
                block_number,
                ContentType::BlockBody,
            ));
            let block_receipts_content_key = generate_block_receipts_content_key(block_hash);
            futures.push(self.find_content(
                block_receipts_content_key,
                block_number,
                ContentType::BlockReceipts,
            ));
        }
        join_all(futures).await;
    }

    async fn find_content(
        &self,
        content_key: HistoryContentKey,
        block_number: u64,
        content_type: ContentType,
    ) -> anyhow::Result<()> {
        if CENSUS {
            self.find_content_census(&content_key, block_number, content_type)
                .await
        } else {
            self.recursive_find_content(content_key, block_number, content_type)
                .await
        }
    }

    /// Send FindContent queries to the interested peers in the census, includes peers scoring
    async fn find_content_census(
        &self,
        content_key: &HistoryContentKey,
        block_number: u64,
        content_type: ContentType,
    ) -> Result<(), Error> {
        let census = self.census.clone().expect("census should be enabled");
        // Select interested peers from the census
        let enrs = census
            .select_peers(Subnetwork::History, &content_key.content_id())
            .expect("Failed to select peers");
        // Send FindContent query to the interested peers
        if enrs.is_empty() {
            warn!(
                block_number = block_number,
                content_type = %content_type,
                "No peers found for block. Skipping"
            );
            return Err(anyhow!("No peers found for block {block_number}"));
        };

        for (index, enr) in enrs.iter().enumerate() {
            info!(
                block_number = block_number,
                content_type = %content_type,
                peer_index = index,
                "Sending FindContent query to peer"
            );

            let result = self
                .overlay_arc
                .send_find_content(enr.clone(), content_key.to_bytes())
                .await?;
            let content = result.0;

            match content {
                Content::ConnectionId(_) => {
                    // Should not return connection ID, should always return the content
                    warn!(
                        block_number = block_number,
                        content_type = %content_type,
                        "Received ConnectionId content"
                    );
                    census.record_offer_result(
                        Subnetwork::History,
                        enr.node_id(),
                        0,
                        Duration::from_secs(0),
                        &OfferTrace::Failed,
                    );
                    continue;
                }
                Content::Content(content_bytes) => {
                    let content = HistoryContentValue::decode(content_key, &content_bytes);

                    match content {
                        Ok(_) => {
                            info!(
                                block_number = block_number,
                                content_type = %content_type,
                                "Received content from peer"
                            );
                            census.record_offer_result(
                                Subnetwork::History,
                                enr.node_id(),
                                content_bytes.len(),
                                Duration::from_secs(0),
                                &OfferTrace::Success(
                                    BitList::with_capacity(1).expect("Failed to create bitlist"),
                                ),
                            );
                            return Ok(());
                        }
                        Err(_) => {
                            warn!(
                                block_number = block_number,
                                content_type = %content_type,
                                "Failed to parse content from peer, invalid content"
                            );
                            census.record_offer_result(
                                Subnetwork::History,
                                enr.node_id(),
                                0,
                                Duration::from_secs(0),
                                &OfferTrace::Failed,
                            );
                            continue;
                        }
                    }
                }
                Content::Enrs(_) => {
                    //  Content not found
                    warn!(
                        block_number = block_number,
                        content_type = %content_type,
                        "Received Enrs content, content not found from peer"
                    );
                    census.record_offer_result(
                        Subnetwork::History,
                        enr.node_id(),
                        0,
                        Duration::from_secs(0),
                        &OfferTrace::Failed,
                    );
                    continue;
                }
            }
        }
        warn!(
            block_number = block_number,
            content_type = %content_type,
            "Failed to find content for block"
        );
        Err(anyhow!("Failed to find content for block"))
    }

    /// Send recursive FindContent queries to the overlay service
    async fn recursive_find_content(
        &self,
        content_key: HistoryContentKey,
        block_number: u64,
        content_type: ContentType,
    ) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();

        let overlay_command = OverlayCommand::FindContentQuery {
            target: content_key.clone(),
            callback: tx,
            config: Default::default(),
        };

        if let Err(err) = self.overlay_arc.command_tx.send(overlay_command) {
            warn!(
                error = %err,
                block_number = block_number,
                content_type = %content_type,
                "Error submitting FindContent query to service"
            );
        }
        match rx.await {
            Ok(result) => match result {
                Ok(result) => {
                    HistoryContentValue::decode(&content_key, &result.0)?;
                    info!(block_number = block_number, "Downloaded content for block");
                    Ok(())
                }
                Err(err) => {
                    error!(
                        block_number = block_number,
                        content_type = %content_type,
                        error = %err,
                        "Error in FindContent query"
                    );
                    Err(anyhow!("Error in FindContent query: {:?}", err))
                }
            },
            Err(err) => {
                error!(
                    block_number = block_number,
                    content_type = %content_type,
                    error = %err,
                    "Error receiving FindContent query response"
                );
                Err(err.into())
            }
        }
    }
}

fn parse_line(line: &str) -> (u64, String) {
    let parts: Vec<&str> = line.split(',').collect();
    let block_number = parts[0].parse().expect("Failed to parse block number");
    let block_hash = parts[1].to_string();
    (block_number, block_hash)
}

fn generate_block_body_content_key(block_hash: String) -> HistoryContentKey {
    HistoryContentKey::BlockBody(BlockBodyKey {
        block_hash: <[u8; 32]>::try_from(
            hex_decode(&block_hash).expect("Failed to decode block hash"),
        )
        .expect("Failed to convert block hash to byte array"),
    })
}

fn generate_block_receipts_content_key(block_hash: String) -> HistoryContentKey {
    HistoryContentKey::BlockReceipts(BlockReceiptsKey {
        block_hash: <[u8; 32]>::try_from(
            hex_decode(&block_hash).expect("Failed to decode block hash"),
        )
        .expect("Failed to convert block hash to byte array"),
    })
}
