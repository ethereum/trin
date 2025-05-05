pub mod constants;
pub mod rpc_types;

use std::{fmt::Display, time::Duration};

use alloy::primitives::B256;
use anyhow::{anyhow, bail};
use constants::DEFAULT_BEACON_STATE_REQUEST_TIMEOUT;
use ethportal_api::{
    consensus::beacon_state::BeaconStateElectra,
    light_client::{
        bootstrap::LightClientBootstrapDeneb, finality_update::LightClientFinalityUpdateDeneb,
        optimistic_update::LightClientOptimisticUpdateDeneb, update::LightClientUpdateDeneb,
    },
};
use reqwest::{
    header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE},
    Response,
};
use rpc_types::{RootResponse, VersionResponse, VersionedDataResponse, VersionedDataResult};
use serde::de::DeserializeOwned;
use ssz::Decode;
use tracing::{debug, warn};
use url::Url;

use super::http_client::{
    ClientWithBaseUrl, ContentType, JSON_ACCEPT_PRIORITY, JSON_CONTENT_TYPE, SSZ_CONTENT_TYPE,
};

/// Implements endpoints from the Beacon API to access data from the consensus layer.
#[derive(Clone, Debug)]
pub struct ConsensusApi {
    primary: ClientWithBaseUrl,
    fallback: ClientWithBaseUrl,
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
        let primary =
            ClientWithBaseUrl::new(primary, request_timeout, ContentType::Ssz).map_err(|err| {
                anyhow!("Unable to create primary client for consensus data provider: {err:?}")
            })?;
        if let Err(err) = Self::check_provider(&primary).await {
            warn!("Primary consensus data provider may be offline: {err:?}");
        }
        let fallback = ClientWithBaseUrl::new(fallback, request_timeout, ContentType::Ssz)
            .map_err(|err| {
                anyhow!("Unable to create fallback client for consensus data provider: {err:?}")
            })?;
        if let Err(err) = Self::check_provider(&fallback).await {
            warn!("Fallback consensus data provider may be offline: {err:?}");
        }

        Ok(Self { primary, fallback })
    }

    /// Request the finalized root of the beacon state.
    pub async fn get_beacon_state_finalized_root(&self) -> anyhow::Result<RootResponse> {
        let endpoint = "/eth/v1/beacon/states/finalized/root".to_string();
        Ok(self.request(endpoint, None).await?.data)
    }

    /// Requests the `LightClientBootstrap` structure corresponding to a given post-Altair beacon
    /// block root.
    pub async fn get_light_client_bootstrap(
        &self,
        block_root: B256,
    ) -> anyhow::Result<LightClientBootstrapDeneb> {
        let endpoint = format!("/eth/v1/beacon/light_client/bootstrap/{block_root}");
        Ok(self.request(endpoint, None).await?.data)
    }

    /// Retrieves hashTreeRoot of `BeaconBlock/BeaconBlockHeader`
    /// Block identifier can be one of: "head" (canonical head in node's view),
    /// "genesis", "finalized", <slot>, <hex encoded blockRoot with 0x prefix>.
    pub async fn get_beacon_block_root<S: AsRef<str> + Display>(
        &self,
        block_id: S,
    ) -> anyhow::Result<RootResponse> {
        let endpoint = format!("/eth/v1/beacon/blocks/{block_id}/root");
        Ok(self.request(endpoint, None).await?.data)
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
        Ok(self
            .request_list(endpoint, None)
            .await?
            .into_iter()
            .map(|response| response.data)
            .collect())
    }

    /// Requests the latest `LightClientOptimisticUpdate` known by the server.
    pub async fn get_light_client_optimistic_update(
        &self,
    ) -> anyhow::Result<LightClientOptimisticUpdateDeneb> {
        let endpoint = "/eth/v1/beacon/light_client/optimistic_update".to_string();
        Ok(self.request(endpoint, None).await?.data)
    }

    /// Requests the latest `LightClientFinalityUpdate` known by the server.
    pub async fn get_light_client_finality_update(
        &self,
    ) -> anyhow::Result<LightClientFinalityUpdateDeneb> {
        let endpoint = "/eth/v1/beacon/light_client/finality_update".to_string();
        Ok(self.request(endpoint, None).await?.data)
    }

    /// Requests the Node's `Version` string.
    pub async fn get_node_version(&self) -> anyhow::Result<VersionResponse> {
        let endpoint = "/eth/v1/node/version".to_string();
        Ok(self.request(endpoint, None).await?.data)
    }

    /// Requests the `BeaconState` structure corresponding to the current head of the beacon chain.
    pub async fn get_beacon_state(&self) -> anyhow::Result<BeaconStateElectra> {
        let endpoint = "/eth/v2/debug/beacon/states/finalized".to_string();
        Ok(self
            .request(endpoint, Some(DEFAULT_BEACON_STATE_REQUEST_TIMEOUT))
            .await?
            .data)
    }

    /// Make a request to the cl provider. If the primary provider fails, it will retry with the
    /// fallback.
    async fn request<T>(
        &self,
        endpoint: String,
        custom_timeout: Option<Duration>,
    ) -> anyhow::Result<VersionedDataResponse<T>>
    where
        T: Decode + DeserializeOwned + Clone,
    {
        match Self::request_no_fallback(endpoint.clone(), &self.primary, custom_timeout).await {
            Ok(response) => Ok(response),
            Err(err) => {
                warn!("Error requesting consensus data from provider, retrying with fallback provider: {err:?}");
                Self::request_no_fallback(endpoint, &self.fallback, custom_timeout)
                    .await
                    .map_err(|err| {
                        anyhow!("Unable to request consensus data from fallback provider: {err:?}")
                    })
            }
        }
    }

    /// Make a request to the cl provider. If the primary provider fails, it will retry with the
    /// fallback.
    ///
    /// This is used for lists of data, where the response is a list of T.
    async fn request_list<T>(
        &self,
        endpoint: String,
        custom_timeout: Option<Duration>,
    ) -> anyhow::Result<Vec<VersionedDataResponse<T>>>
    where
        T: Decode + DeserializeOwned + Clone,
    {
        match Self::request_list_no_fallback(endpoint.clone(), &self.primary, custom_timeout).await
        {
            Ok(response) => Ok(response),
            Err(err) => {
                warn!("Error requesting consensus data from provider, retrying with fallback provider: {err:?}");
                Self::request_list_no_fallback(endpoint, &self.fallback, custom_timeout)
                    .await
                    .map_err(|err| {
                        anyhow!("Unable to request consensus data from fallback provider: {err:?}")
                    })
            }
        }
    }

    /// Makes a request and returns the response and the content type.
    async fn base_request(
        endpoint: String,
        client: &ClientWithBaseUrl,
        custom_timeout: Option<Duration>,
        response_is_list: bool,
    ) -> anyhow::Result<(Response, ContentType)> {
        let request = client.get(&endpoint)?;
        let request = match custom_timeout {
            Some(timeout) => request.timeout(timeout),
            None => request,
        };
        let request = match response_is_list {
            true => {
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
                headers.insert(ACCEPT, HeaderValue::from_static(JSON_ACCEPT_PRIORITY));
                request.headers(headers)
            }
            false => request,
        };
        let response = request.send().await?;
        let content_type = response.headers().get(CONTENT_TYPE);
        let Some(content_type) = content_type else {
            return Err(anyhow!("No content type found in response"));
        };
        let content_type = content_type
            .to_str()
            .map_err(|_| anyhow!("Unable to convert content type to string: {content_type:?}"))?;

        Ok(match content_type {
            SSZ_CONTENT_TYPE => (response, ContentType::Ssz),
            JSON_CONTENT_TYPE => (response, ContentType::Json),
            _ => bail!("Unexpected content type: {content_type:?} {response:?}"),
        })
    }

    async fn request_no_fallback<T>(
        endpoint: String,
        client: &ClientWithBaseUrl,
        custom_timeout: Option<Duration>,
    ) -> anyhow::Result<VersionedDataResponse<T>>
    where
        T: Decode + DeserializeOwned + Clone,
    {
        let (response, content_type) =
            Self::base_request(endpoint.clone(), client, custom_timeout, false).await?;

        Ok(match content_type {
            ContentType::Ssz => {
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
            ContentType::Json => response
                .json::<VersionedDataResult<T>>()
                .await?
                .response()?,
        })
    }

    async fn request_list_no_fallback<T>(
        endpoint: String,
        client: &ClientWithBaseUrl,
        custom_timeout: Option<Duration>,
    ) -> anyhow::Result<Vec<VersionedDataResponse<T>>>
    where
        T: Decode + DeserializeOwned + Clone,
    {
        let (response, content_type) =
            Self::base_request(endpoint.clone(), client, custom_timeout, true).await?;

        // todo: add support for ssz lists
        Ok(match content_type {
            ContentType::Json => response
                .json::<Vec<VersionedDataResult<T>>>()
                .await?
                .into_iter()
                .map(|response| response.response())
                .collect::<Result<Vec<_>, _>>()?,
            _ => bail!("We only support JSON for lists, but got {content_type:?}"),
        })
    }

    /// Check if the provider is up and running by requesting the version.
    /// The request will error if the provider is not reachable or if the version is not returned.
    pub async fn check_provider(client: &ClientWithBaseUrl) -> anyhow::Result<VersionResponse> {
        let endpoint = "/eth/v1/node/version".to_string();
        Ok(Self::request_no_fallback(endpoint.clone(), client, None)
            .await?
            .data)
    }
}
