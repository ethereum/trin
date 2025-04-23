pub mod rpc_types;

use std::fmt::Display;

use alloy::primitives::B256;
use anyhow::{anyhow, bail};
use ethportal_api::{
    consensus::beacon_state::BeaconStateDeneb,
    light_client::{
        bootstrap::LightClientBootstrapDeneb, finality_update::LightClientFinalityUpdateDeneb,
        optimistic_update::LightClientOptimisticUpdateDeneb, update::LightClientUpdateDeneb,
    },
};
use reqwest::header::CONTENT_TYPE;
use rpc_types::{RootResponse, VersionedDataResponse, VersionedDataResult};
use serde::de::DeserializeOwned;
use ssz::Decode;
use tracing::{debug, warn};
use url::Url;

use super::utils::{ClientWithBaseUrl, ContentType, JSON_CONTENT_TYPE, SSZ_CONTENT_TYPE};
use crate::api::utils::url_to_client;

/// Implements endpoints from the Beacon API to access data from the consensus layer.
#[derive(Clone, Debug)]
pub struct ConsensusApi {
    primary: Url,
    fallback: Url,
    request_timeout: u64,
}

impl ConsensusApi {
    pub async fn new(
        primary: Url,
        fallback: Url,
        request_timeout: u64,
    ) -> Result<Self, reqwest_middleware::Error> {
        debug!(
            "Starting ConsensusApi with primary provider: {primary} and fallback provider: {fallback}",
        );
        let client =
            url_to_client(primary.clone(), request_timeout, ContentType::Json).map_err(|err| {
                anyhow!("Unable to create primary client for consensus data provider: {err:?}")
            })?;
        if let Err(err) = check_provider(&client).await {
            warn!("Primary consensus data provider may be offline: {err:?}");
        }
        Ok(Self {
            primary,
            fallback,
            request_timeout,
        })
    }

    /// Request the finalized root of the beacon state.
    pub async fn get_beacon_state_finalized_root(&self) -> anyhow::Result<RootResponse> {
        let endpoint = "/eth/v1/beacon/states/finalized/root".to_string();
        Ok(self.request(endpoint).await?.data)
    }

    /// Requests the `LightClientBootstrap` structure corresponding to a given post-Altair beacon
    /// block root.
    pub async fn get_light_client_bootstrap(
        &self,
        block_root: B256,
    ) -> anyhow::Result<LightClientBootstrapDeneb> {
        let endpoint = format!("/eth/v1/beacon/light_client/bootstrap/{block_root}");
        Ok(self.request(endpoint).await?.data)
    }

    /// Retrieves hashTreeRoot of `BeaconBlock/BeaconBlockHeader`
    /// Block identifier can be one of: "head" (canonical head in node's view),
    /// "genesis", "finalized", <slot>, <hex encoded blockRoot with 0x prefix>.
    pub async fn get_beacon_block_root<S: AsRef<str> + Display>(
        &self,
        block_id: S,
    ) -> anyhow::Result<RootResponse> {
        let endpoint = format!("/eth/v1/beacon/blocks/{block_id}/root");
        Ok(self.request(endpoint).await?.data)
    }

    /// Requests the LightClientUpdate instances in the sync committee period range
    /// [start_period, start_period + count), leading up to the current head sync committee period
    /// as selected by fork choice.
    pub async fn get_light_client_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> anyhow::Result<Vec<LightClientUpdateDeneb>> {
        let endpoint = format!(
            "/eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}"
        );
        Ok(self.request(endpoint).await?.data)
    }

    /// Requests the latest `LightClientOptimisticUpdate` known by the server.
    pub async fn get_light_client_optimistic_update(
        &self,
    ) -> anyhow::Result<LightClientOptimisticUpdateDeneb> {
        let endpoint = "/eth/v1/beacon/light_client/optimistic_update".to_string();
        Ok(self.request(endpoint).await?.data)
    }

    /// Requests the latest `LightClientFinalityUpdate` known by the server.
    pub async fn get_light_client_finality_update(
        &self,
    ) -> anyhow::Result<LightClientFinalityUpdateDeneb> {
        let endpoint = "/eth/v1/beacon/light_client/finality_update".to_string();
        Ok(self.request(endpoint).await?.data)
    }

    /// Requests the `BeaconState` structure corresponding to the current head of the beacon chain.
    pub async fn get_beacon_state(&self) -> anyhow::Result<BeaconStateDeneb> {
        let endpoint = "/eth/v2/debug/beacon/states/finalized".to_string();
        Ok(self.request(endpoint).await?.data)
    }

    /// Make a request to the cl provider. If the primary provider fails, it will retry with the
    /// fallback.
    async fn request<T>(&self, endpoint: String) -> anyhow::Result<VersionedDataResponse<T>>
    where
        T: Decode + DeserializeOwned,
    {
        match self
            .request_no_fallback(endpoint.clone(), self.primary.clone())
            .await
        {
            Ok(response) => Ok(response),
            Err(err) => {
                warn!("Error requesting consensus data from provider, retrying with fallback provider: {err:?}");
                self.request_no_fallback(endpoint, self.fallback.clone())
                    .await
                    .map_err(|err| {
                        anyhow!("Unable to request consensus data from fallback provider: {err:?}")
                    })
            }
        }
    }

    /// request() should be used instead of this function.
    async fn request_no_fallback<T>(
        &self,
        endpoint: String,
        url: Url,
    ) -> anyhow::Result<VersionedDataResponse<T>>
    where
        T: Decode + DeserializeOwned,
    {
        let client = url_to_client(url, self.request_timeout, ContentType::Ssz).map_err(|err| {
            anyhow!("Unable to create client for primary consensus data provider: {err:?}")
        })?;
        let response = client.get(&endpoint)?.send().await?;
        let content_type = response.headers().get(CONTENT_TYPE);
        let Some(content_type) = content_type else {
            return Err(anyhow!("No content type found in response"));
        };
        let content_type = content_type
            .to_str()
            .map_err(|_| anyhow!("Unable to convert content type to string: {content_type:?}"))?;

        Ok(match content_type {
            SSZ_CONTENT_TYPE => {
                let eth_consensus_version = response.headers().get("Eth-Consensus-Version");
                let version = eth_consensus_version
                    .map(|header_value| {
                        header_value.to_str().map(String::from).map_err(|err| {
                            anyhow!("Unable to convert Eth-Consensus-Version to string {err:?}")
                        })
                    })
                    .transpose()?;
                VersionedDataResponse::new(
                    T::from_ssz_bytes(&response.bytes().await?)
                        .map_err(|err| anyhow!("Failed to decode {err:?}"))?,
                    version,
                )
            }
            JSON_CONTENT_TYPE => response
                .json::<VersionedDataResult<T>>()
                .await?
                .to_result()?,
            _ => bail!("Unexpected content type: {content_type:?} {response:?}"),
        })
    }
}

/// Check that provider is valid and accessible.
async fn check_provider(client: &ClientWithBaseUrl) -> anyhow::Result<()> {
    let endpoint = "/eth/v1/node/version".to_string();
    match client.get(endpoint)?.send().await?.text().await {
        Ok(_) => Ok(()),
        Err(err) => Err(anyhow!(
            "Unable to request consensus data from provider: {err:?}"
        )),
    }
}
