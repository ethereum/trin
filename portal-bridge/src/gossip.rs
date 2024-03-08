use std::sync::{Arc, Mutex};

use jsonrpsee::http_client::HttpClient;
use tokio::time::{sleep, Duration};
use tracing::{debug, warn, Instrument};

use crate::stats::{BeaconSlotStats, HistoryBlockStats, StatsReporter};
use ethportal_api::{
    jsonrpsee::core::Error, types::portal::TraceGossipInfo, BeaconContentKey, BeaconContentValue,
    BeaconNetworkApiClient, HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient,
    OverlayContentKey,
};

const GOSSIP_RETRY_COUNT: u64 = 3;
const RETRY_AFTER: Duration = Duration::from_secs(15);

/// Gossip any given content key / value to the history network.
pub async fn gossip_beacon_content(
    portal_clients: Arc<Vec<HttpClient>>,
    content_key: BeaconContentKey,
    content_value: BeaconContentValue,
    slot_stats: Arc<Mutex<BeaconSlotStats>>,
) -> anyhow::Result<()> {
    let mut results: Vec<Result<(Vec<TraceGossipInfo>, u64), Error>> = vec![];
    for client in portal_clients.as_ref() {
        let client = client.clone();
        let content_key = content_key.clone();
        let content_value = content_value.clone();
        let result =
            tokio::spawn(beacon_trace_gossip(client, content_key, content_value).in_current_span())
                .await?;
        results.push(result);
    }
    if let Ok(mut data) = slot_stats.lock() {
        data.update(content_key, results.into());
    } else {
        warn!("Error updating beacon gossip stats. Unable to acquire lock.");
    }
    Ok(())
}

async fn beacon_trace_gossip(
    client: HttpClient,
    content_key: BeaconContentKey,
    content_value: BeaconContentValue,
) -> Result<(Vec<TraceGossipInfo>, u64), Error> {
    let mut retry_count = 0;
    let mut traces = vec![];
    while retry_count < GOSSIP_RETRY_COUNT {
        let result = BeaconNetworkApiClient::trace_gossip(
            &client,
            content_key.clone(),
            content_value.clone(),
        )
        .await;
        // check if content was successfully transferred to at least one peer on network
        if let Ok(trace) = result {
            traces.push(trace.clone());
            if !trace.transferred.is_empty() {
                return Ok((traces, retry_count));
            }
        }
        // if not, make rfc request to see if data is available on network
        let result =
            BeaconNetworkApiClient::recursive_find_content(&client, content_key.clone()).await;
        if let Ok(ethportal_api::types::beacon::ContentInfo::Content { .. }) = result {
            debug!("Found content on network, after failing to gossip, aborting gossip. content key={:?}", content_key.to_hex());
            return Ok((traces, retry_count));
        }
        retry_count += 1;
        debug!("Unable to locate content on network, after failing to gossip, retrying in {:?} seconds. content key={:?}", RETRY_AFTER, content_key.to_hex());
        sleep(RETRY_AFTER).await;
    }
    warn!(
        "Failed to gossip beacon content, without successfully locating data on network, after {} attempts: content key={:?}",
        GOSSIP_RETRY_COUNT,
        content_key.to_hex(),
    );
    Ok((traces, retry_count))
}

/// Gossip any given content key / value to the history network.
pub async fn gossip_history_content(
    portal_clients: &Vec<HttpClient>,
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
    block_stats: Arc<Mutex<HistoryBlockStats>>,
) -> anyhow::Result<()> {
    let mut results: Vec<Result<(Vec<TraceGossipInfo>, u64), Error>> = vec![];
    for client in portal_clients {
        let client = client.clone();
        let content_key = content_key.clone();
        let content_value = content_value.clone();
        let result = tokio::spawn(
            history_trace_gossip(client, content_key, content_value).in_current_span(),
        )
        .await?;
        results.push(result);
    }
    if let Ok(mut data) = block_stats.lock() {
        data.update(content_key, results.into());
    } else {
        warn!("Error updating history gossip stats. Unable to acquire lock.");
    }
    Ok(())
}

async fn history_trace_gossip(
    client: HttpClient,
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
) -> Result<(Vec<TraceGossipInfo>, u64), Error> {
    let mut retry_count = 0;
    let mut traces = vec![];
    while retry_count < GOSSIP_RETRY_COUNT {
        let result = HistoryNetworkApiClient::trace_gossip(
            &client,
            content_key.clone(),
            content_value.clone(),
        )
        .await;
        // check if content was successfully transferred to at least one peer on network
        if let Ok(trace) = result {
            traces.push(trace.clone());
            if !trace.transferred.is_empty() {
                return Ok((traces, retry_count));
            }
        }
        // if not, make rfc request to see if data is available on network
        let result =
            HistoryNetworkApiClient::recursive_find_content(&client, content_key.clone()).await;
        if let Ok(ethportal_api::types::history::ContentInfo::Content { .. }) = result {
            debug!("Found content on network, after failing to gossip, aborting gossip. content key={:?}", content_key.to_hex());
            return Ok((traces, retry_count));
        }
        retry_count += 1;
        debug!("Unable to locate content on network, after failing to gossip, retrying in {:?} seconds. content key={:?}", RETRY_AFTER, content_key.to_hex());
        sleep(RETRY_AFTER).await;
    }
    warn!(
        "Failed to gossip history content, without successfully locating data on network, after {} attempts: content key={:?}",
        GOSSIP_RETRY_COUNT,
        content_key.to_hex(),
    );
    Ok((traces, retry_count))
}
