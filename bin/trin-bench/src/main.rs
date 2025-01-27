use std::{sync::Arc, thread::sleep, time::Instant};

use clap::Parser;
use e2store::{era1::Era1, utils::get_era1_files};
use ethportal_api::{
    types::portal_wire::OfferTrace, BlockBodyLegacy, ContentValue, Discv5ApiClient, Enr,
    HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient, Receipts,
};
use futures::future::join_all;
use humanize_duration::{prelude::DurationExt, Truncate};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use portal_bridge::{
    api::execution::construct_proof,
    bridge::{history::SERVE_BLOCK_TIMEOUT, utils::lookup_epoch_acc},
};
use reqwest::Client;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, error, info, warn, Instrument};
use trin_bench::cli::TrinBenchConfig;
use trin_execution::era::utils::download_raw_era;
use trin_utils::log::init_tracing_logger;
use trin_validation::{constants::EPOCH_SIZE, oracle::HeaderOracle};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing_logger();

    // Sleep for a bit to allow the node to start up
    sleep(std::time::Duration::from_secs(10));

    let trin_bench_config = TrinBenchConfig::parse();
    let send_node_client = HttpClientBuilder::default()
        .build(trin_bench_config.web3_http_address_node_1.clone())
        .expect("Failed to build send_node_client");

    let receiver_node_client = HttpClientBuilder::default()
        .build(trin_bench_config.web3_http_address_node_2.clone())
        .expect("Failed to build receiver_node_client");

    let receiver_node_enr = match receiver_node_client.node_info().await {
        Ok(node_info) => node_info.enr,
        Err(err) => panic!("Error getting receiver_node_enr: {err:?}"),
    };

    // ping receiver node, to exchange radius's, as if we just start with offers, the other node
    // will assume a 100% radius by default
    send_node_client.ping(receiver_node_enr.clone()).await?;

    let http_client = Client::new();
    let era1_files = get_era1_files(&http_client).await?;
    let mut blocks = vec![];
    for era1_index in trin_bench_config.start_era1..=trin_bench_config.end_era1 {
        let era1_path = era1_files[&(era1_index as u64)].clone();
        let raw_era1 = download_raw_era(era1_path, http_client.clone()).await?;
        let block_tuples = Era1::deserialize(&raw_era1)?;
        blocks.extend(block_tuples.block_tuples);
    }

    info!("Beginning benchmark");
    let start_timer = Instant::now();
    let mut offer_count = 0;

    // gossip blocks to receiver node
    let gossip_semaphore = Arc::new(Semaphore::new(trin_bench_config.offer_concurrency));
    let header_oracle = HeaderOracle::default();

    let mut epoch_acc = None;
    let mut serve_full_block_handles = vec![];
    let mut current_epoch_index = u64::MAX;
    // gossip headers
    for block in blocks.clone() {
        let height = block.header.header.number;
        // Using epoch_size chunks & epoch boundaries ensures that every
        // "chunk" shares an epoch accumulator avoiding the need to
        // look up the epoch acc on a header by header basis
        if current_epoch_index != height / EPOCH_SIZE {
            current_epoch_index = height / EPOCH_SIZE;
            epoch_acc = match lookup_epoch_acc(
                current_epoch_index,
                &header_oracle.header_validator.pre_merge_acc,
                &trin_bench_config.epoch_acc_path,
            )
            .await
            {
                Ok(epoch_acc) => Some(epoch_acc),
                Err(msg) => {
                    unreachable!("Error looking up epoch acc: {msg:?}");
                }
            };
        }

        let permit = gossip_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("to be able to acquire semaphore");

        let content_key = HistoryContentKey::new_block_header_by_hash(block.header.header.hash());
        let content_value = if let Some(epoch_acc) = &epoch_acc {
            // Construct HeaderWithProof
            let header_with_proof = construct_proof(block.header.header.clone(), epoch_acc).await?;
            // Double check that the proof is valid
            header_oracle
                .header_validator
                .validate_header_with_proof(&header_with_proof)?;
            HistoryContentValue::BlockHeaderWithProof(header_with_proof)
        } else {
            unreachable!("epoch_acc should be Some(epoch_acc) at this point");
        };
        serve_full_block_handles.push(spawn_serve_history_content(
            send_node_client.clone(),
            receiver_node_enr.clone(),
            content_key,
            content_value,
            Some(permit),
        ));
        offer_count += 1;
    }

    // gossip bodies
    for block in blocks.clone() {
        let permit = gossip_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("to be able to acquire semaphore");

        let content_key = HistoryContentKey::new_block_body(block.header.header.hash());
        let content_value =
            HistoryContentValue::BlockBody(ethportal_api::BlockBody::Legacy(BlockBodyLegacy {
                txs: block.body.body.transactions().to_vec(),
                uncles: block.body.body.uncles().to_vec(),
            }));
        serve_full_block_handles.push(spawn_serve_history_content(
            send_node_client.clone(),
            receiver_node_enr.clone(),
            content_key,
            content_value,
            Some(permit),
        ));
        offer_count += 1;
    }

    // gossip receipts
    for block in blocks.clone() {
        let permit = gossip_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("to be able to acquire semaphore");

        let content_key = HistoryContentKey::new_block_receipts(block.header.header.hash());
        let content_value = HistoryContentValue::Receipts(Receipts {
            receipt_list: block.receipts.receipts.receipt_list,
        });
        serve_full_block_handles.push(spawn_serve_history_content(
            send_node_client.clone(),
            receiver_node_enr.clone(),
            content_key,
            content_value,
            Some(permit),
        ));
        offer_count += 1;
    }

    // Wait till all blocks are done gossiping.
    // This can't deadlock, because the tokio::spawn has a timeout.
    join_all(serve_full_block_handles).await;

    info!(
        "Finished gossiping blocks in {}, with {} offers",
        start_timer.elapsed().human(Truncate::Second),
        offer_count
    );

    Ok(())
}

fn spawn_serve_history_content(
    portal_client: HttpClient,
    enr: Enr,
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
    permit: Option<OwnedSemaphorePermit>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        match timeout(
            SERVE_BLOCK_TIMEOUT,
            offer_content(&portal_client, enr, content_key.clone(), content_value)
                .in_current_span(),
        )
        .await {
            Ok(result) => match result {
                Ok(_) => debug!("Successfully served block: {content_key:?}"),
                Err(msg) => warn!("Error serving block: {content_key:?}: {msg:?}"),
            },
            Err(_) => error!("serve_full_block() timed out on height {content_key:?}: this is an indication a bug is present")
        };
        if let Some(permit) = permit {
            drop(permit);
        }
    })
}

async fn offer_content(
    client: &HttpClient,
    enr: Enr,
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
) -> anyhow::Result<()> {
    let result = HistoryNetworkApiClient::trace_offer(
        client,
        enr.clone(),
        content_key.clone(),
        content_value.encode(),
    )
    .await?;
    if OfferTrace::Declined == result || OfferTrace::Failed == result {
        warn!("Error offering content: {enr:?} ||| {result:?}");
    }

    Ok(())
}
