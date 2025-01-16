use std::sync::{Arc, Mutex};

use ethportal_api::{
    types::portal::TracePutContentInfo, BeaconContentKey, BeaconContentValue,
    BeaconNetworkApiClient, ContentValue, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient, OverlayContentKey,
};
use jsonrpsee::http_client::HttpClient;
use tokio::time::{sleep, Duration};
use tracing::{debug, warn, Instrument};

use crate::stats::{BeaconSlotStats, HistoryBlockStats, StatsReporter};

const GOSSIP_RETRY_COUNT: u64 = 3;
const RETRY_AFTER: Duration = Duration::from_secs(15);

/// Gossip any given content key / value to the beacon network.
pub async fn put_content_beacon_content(
    portal_client: HttpClient,
    content_key: BeaconContentKey,
    content_value: BeaconContentValue,
    slot_stats: Arc<Mutex<BeaconSlotStats>>,
) -> anyhow::Result<()> {
    let result = tokio::spawn(
        beacon_trace_put_content(portal_client, content_key.clone(), content_value)
            .in_current_span(),
    )
    .await?;
    if let Ok(mut data) = slot_stats.lock() {
        data.update(content_key, result.into());
    } else {
        warn!("Error updating beacon put content stats. Unable to acquire lock.");
    }
    Ok(())
}

async fn beacon_trace_put_content(
    client: HttpClient,
    content_key: BeaconContentKey,
    content_value: BeaconContentValue,
) -> PutContentReport {
    let mut retries = 0;
    let mut traces = vec![];
    let mut found = false;
    while retries < GOSSIP_RETRY_COUNT {
        let result = BeaconNetworkApiClient::trace_put_content(
            &client,
            content_key.clone(),
            content_value.encode(),
        )
        .await;
        // check if content was successfully transferred to at least one peer on network
        if let Ok(trace) = result {
            traces.push(trace.clone());
            if !trace.transferred.is_empty() {
                return PutContentReport {
                    traces,
                    retries,
                    found,
                };
            }
        }
        // if not, make rfc request to see if data is available on network
        let result = BeaconNetworkApiClient::get_content(&client, content_key.clone()).await;
        if result.is_ok() {
            debug!("Found content on network, after failing to put content, aborting put content. content key={:?}", content_key.to_hex());
            found = true;
            return PutContentReport {
                traces,
                retries,
                found,
            };
        }
        retries += 1;
        debug!("Unable to locate content on network, after failing to put content, retrying in {:?} seconds. content key={:?}", RETRY_AFTER, content_key.to_hex());
        sleep(RETRY_AFTER).await;
    }
    warn!(
        "Failed to gossip beacon content, without successfully locating data on network, after {} attempts: content key={:?}",
        GOSSIP_RETRY_COUNT,
        content_key.to_hex(),
    );
    PutContentReport {
        traces,
        retries,
        found,
    }
}

/// Gossip any given content key / value to the history network.
pub async fn gossip_history_content(
    portal_client: HttpClient,
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
    block_stats: Arc<Mutex<HistoryBlockStats>>,
) -> anyhow::Result<()> {
    let result = tokio::spawn(
        history_trace_gossip(portal_client, content_key.clone(), content_value).in_current_span(),
    )
    .await?;
    if let Ok(mut data) = block_stats.lock() {
        data.update(content_key, result.into());
    } else {
        warn!("Error updating history gossip stats. Unable to acquire lock.");
    }
    Ok(())
}

async fn history_trace_gossip(
    client: HttpClient,
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
) -> PutContentReport {
    let mut retries = 0;
    let mut traces = vec![];
    let mut found = false;
    while retries < GOSSIP_RETRY_COUNT {
        let result = HistoryNetworkApiClient::trace_put_content(
            &client,
            content_key.clone(),
            content_value.encode(),
        )
        .await;
        // check if content was successfully transferred to at least one peer on network
        if let Ok(trace) = result {
            traces.push(trace.clone());
            if !trace.transferred.is_empty() {
                return PutContentReport {
                    traces,
                    retries,
                    found,
                };
            }
        }
        // if not, make rfc request to see if data is available on network
        let result = HistoryNetworkApiClient::get_content(&client, content_key.clone()).await;
        if result.is_ok() {
            debug!("Found content on network, after failing to gossip, aborting gossip. content key={:?}", content_key.to_hex());
            found = true;
            return PutContentReport {
                traces,
                retries,
                found,
            };
        }
        retries += 1;
        debug!("Unable to locate content on network, after failing to gossip, retrying in {:?} seconds. content key={:?}", RETRY_AFTER, content_key.to_hex());
        sleep(RETRY_AFTER).await;
    }
    warn!(
        "Failed to gossip history content, without successfully locating data on network, after {} attempts: content key={:?}",
        GOSSIP_RETRY_COUNT,
        content_key.to_hex(),
    );
    PutContentReport {
        traces,
        retries,
        found,
    }
}

pub struct PutContentReport {
    pub traces: Vec<TracePutContentInfo>,
    pub retries: u64,
    pub found: bool,
}
