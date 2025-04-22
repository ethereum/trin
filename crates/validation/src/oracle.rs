use alloy::primitives::{Bytes, B256};
use anyhow::{anyhow, bail};
use ethportal_api::{
    consensus::{header::BeaconBlockHeader, historical_summaries::HistoricalSummaries},
    light_client::store::LightClientStore,
    types::{
        content_key::beacon::HistoricalSummariesWithProofKey,
        execution::header_with_proof::HeaderWithProof,
        jsonrpc::{
            endpoints::{BeaconEndpoint, HistoryEndpoint},
            request::{BeaconJsonRpcRequest, HistoryJsonRpcRequest, StateJsonRpcRequest},
        },
        portal::GetContentInfo,
    },
    BeaconContentKey, BeaconContentValue, ContentValue, HistoryContentKey, HistoryContentValue,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation.
#[derive(Clone, Debug, Default)]
pub struct HeaderOracle {
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub beacon_jsonrpc_tx: Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>,
    pub state_jsonrpc_tx: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
}

impl HeaderOracle {
    pub fn new() -> Self {
        Self {
            history_jsonrpc_tx: None,
            beacon_jsonrpc_tx: None,
            state_jsonrpc_tx: None,
        }
    }

    pub fn history_jsonrpc_tx(
        &self,
    ) -> anyhow::Result<mpsc::UnboundedSender<HistoryJsonRpcRequest>> {
        match self.history_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("History network is not available")),
        }
    }

    pub fn beacon_jsonrpc_tx(&self) -> anyhow::Result<mpsc::UnboundedSender<BeaconJsonRpcRequest>> {
        match self.beacon_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("Beacon network is not available")),
        }
    }

    pub fn state_jsonrpc_tx(&self) -> anyhow::Result<mpsc::UnboundedSender<StateJsonRpcRequest>> {
        match self.state_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("State network is not available")),
        }
    }

    /// Returns the HeaderWithProof for the given block hash by performing a recursive find content
    /// request.
    pub async fn recursive_find_header_by_hash_with_proof(
        &self,
        block_hash: B256,
    ) -> anyhow::Result<HeaderWithProof> {
        let content_key = HistoryContentKey::new_block_header_by_hash(block_hash);
        let endpoint = HistoryEndpoint::GetContent(content_key.clone());

        let GetContentInfo { content, .. } = self.send_history_request(endpoint).await?;
        let content: HistoryContentValue = HistoryContentValue::decode(&content_key, &content)?;

        match content {
            HistoryContentValue::BlockHeaderWithProof(content) => Ok(content),
            _ => Err(anyhow!(
                "Invalid HistoryContentValue received from HeaderWithProof lookup, expected BlockHeaderWithProof: {content:?}"
            )),
        }
    }

    /// Return latest finalized root of the beacon state.
    pub async fn get_finalized_state_root(&self) -> anyhow::Result<B256> {
        let endpoint = BeaconEndpoint::FinalizedStateRoot;
        self.send_beacon_request(endpoint).await
    }

    /// Return latest finalized beacon header.
    pub async fn get_finalized_header(&self) -> anyhow::Result<BeaconBlockHeader> {
        let endpoint = BeaconEndpoint::FinalizedHeader;
        self.send_beacon_request(endpoint).await
    }

    /// Return current light client store
    pub async fn get_light_client_store(&self) -> anyhow::Result<LightClientStore> {
        let endpoint = BeaconEndpoint::LightClientStore;
        self.send_beacon_request(endpoint).await
    }

    async fn send_history_request<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: HistoryEndpoint,
    ) -> anyhow::Result<T> {
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest { endpoint, resp };
        let tx = self.history_jsonrpc_tx()?;
        tx.send(request)?;

        match resp_rx.recv().await {
            Some(Ok(response)) => Ok(serde_json::from_value(response)?),
            Some(Err(err)) => bail!("History network request error: {err:?}"),
            None => bail!("No response from History network"),
        }
    }

    async fn send_beacon_request<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: BeaconEndpoint,
    ) -> anyhow::Result<T> {
        let (resp, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = BeaconJsonRpcRequest { endpoint, resp };
        let tx = self.beacon_jsonrpc_tx()?;
        tx.send(request)?;

        match resp_rx.recv().await {
            Some(Ok(response)) => Ok(serde_json::from_value(response)?),
            Some(Err(err)) => bail!("Beacon network request error: {err:?}"),
            None => bail!("No response from Beacon network"),
        }
    }

    /// Return HistoricalSummary for the given epoch
    pub async fn get_historical_summary(&self, epoch: u64) -> anyhow::Result<HistoricalSummaries> {
        let content_key =
            BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
                epoch,
            });
        let endpoint = BeaconEndpoint::LocalContent(content_key.clone());
        let content: Bytes = self.send_beacon_request(endpoint).await?;
        let content: BeaconContentValue = BeaconContentValue::decode(&content_key, &content)?;

        match content {
            BeaconContentValue::HistoricalSummariesWithProof(content) => Ok(content.historical_summaries_with_proof.historical_summaries),
            _ => Err(anyhow!(
                "Invalid BeaconContentValue received from HistoricalSummaries local_content, expected HistoricalSummariesWithProof: {content:?}"
            )),
        }
    }
}
