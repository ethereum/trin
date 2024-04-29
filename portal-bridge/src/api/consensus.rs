use std::fmt::Display;

use anyhow::anyhow;
use surf::Client;
use tokio::time::sleep;
use tracing::{debug, warn};
use url::Url;

use crate::{cli::url_to_client, constants::FALLBACK_RETRY_AFTER};

/// Implements endpoints from the Beacon API to access data from the consensus layer.
#[derive(Clone, Debug)]
pub struct ConsensusApi {
    primary: Url,
    fallback: Url,
}

impl ConsensusApi {
    pub async fn new(primary: Url, fallback: Url) -> Result<Self, surf::Error> {
        debug!(
            "Starting ConsensusApi with primary provider: {} and fallback provider: {}",
            primary, fallback
        );
        let client = url_to_client(primary.clone()).map_err(|err| {
            anyhow!("Unable to create primary client for consensus data provider: {err:?}")
        })?;
        if let Err(err) = check_provider(&client).await {
            warn!("Primary consensus data provider may be offline: {err:?}");
        }
        Ok(Self { primary, fallback })
    }

    /// Requests the `LightClientBootstrap` structure corresponding to a given post-Altair beacon
    /// block root.
    pub async fn get_lc_bootstrap<S: AsRef<str> + Display>(
        &self,
        block_root: S,
    ) -> anyhow::Result<String> {
        let endpoint = format!("/eth/v1/beacon/light_client/bootstrap/{block_root}");
        self.request(endpoint).await
    }

    /// Retrieves hashTreeRoot of `BeaconBlock/BeaconBlockHeader`
    /// Block identifier can be one of: "head" (canonical head in node's view),
    /// "genesis", "finalized", <slot>, <hex encoded blockRoot with 0x prefix>.
    pub async fn get_beacon_block_root<S: AsRef<str> + Display>(
        &self,
        block_id: S,
    ) -> anyhow::Result<String> {
        let endpoint = format!("/eth/v1/beacon/blocks/{block_id}/root");
        self.request(endpoint).await
    }

    /// Requests the LightClientUpdate instances in the sync committee period range
    /// [start_period, start_period + count), leading up to the current head sync committee period
    /// as selected by fork choice.
    pub async fn get_lc_updates(&self, start_period: u64, count: u64) -> anyhow::Result<String> {
        let endpoint = format!(
            "/eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}"
        );
        self.request(endpoint).await
    }

    /// Requests the latest `LightClientOptimisticUpdate` known by the server.
    pub async fn get_lc_optimistic_update(&self) -> anyhow::Result<String> {
        let endpoint = "/eth/v1/beacon/light_client/optimistic_update".to_string();
        self.request(endpoint).await
    }

    /// Requests the latest `LightClientFinalityUpdate` known by the server.
    pub async fn get_lc_finality_update(&self) -> anyhow::Result<String> {
        let endpoint = "/eth/v1/beacon/light_client/finality_update".to_string();
        self.request(endpoint).await
    }

    /// Make a request to the cl provider.
    async fn request(&self, endpoint: String) -> anyhow::Result<String> {
        let client = url_to_client(self.primary.clone()).map_err(|err| {
            anyhow!("Unable to create client for primary consensus data provider: {err:?}")
        })?;
        match client.get(&endpoint).recv_string().await {
            Ok(response) => Ok(response),
            Err(err) => {
                warn!("Error requesting consensus data from provider, retrying with fallback provider: {err:?}");
                sleep(FALLBACK_RETRY_AFTER).await;
                let client = url_to_client(self.fallback.clone()).map_err(|err| {
                    anyhow!("Unable to create client for fallback consensus data provider: {err:?}")
                })?;
                client.get(endpoint).recv_string().await.map_err(|err| {
                    anyhow!("Unable to request consensus data from fallback provider: {err:?}")
                })
            }
        }
    }
}

/// Check that provider is valid and accessible.
async fn check_provider(client: &Client) -> anyhow::Result<()> {
    let endpoint = "/eth/v1/node/version".to_string();
    match client.get(endpoint).recv_string().await {
        Ok(_) => Ok(()),
        Err(err) => Err(anyhow!(
            "Unable to request consensus data from provider: {err:?}"
        )),
    }
}
