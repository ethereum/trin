use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use async_trait::async_trait;
use ethereum_types::H256;
use serde_json::{json, Value};
use ssz::{Decode, Encode};
use tokio::sync::mpsc;

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        types::{HistoryJsonRpcRequest, Params},
    },
    portalnet::{
        storage::{ContentStore, PortalStorage, PortalStorageConfig},
        types::{
            content_key::{
                HistoryContentKey, IdentityContentKey, MasterAccumulator as MasterAccumulatorKey,
                SszNone,
            },
            messages::ProtocolId,
        },
    },
    types::{accumulator::MasterAccumulator, header::Header},
    utils::provider::TrustedProvider,
};

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation. Currently, it just proxies these requests
/// on to the trusted provider.
#[derive(Clone, Debug)]
pub struct HeaderOracle {
    pub trusted_provider: TrustedProvider,
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<tokio::sync::mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub master_accumulator: MasterAccumulator,
    pub portal_storage: Arc<RwLock<PortalStorage>>,
}

impl HeaderOracle {
    pub fn new(trusted_provider: TrustedProvider, storage_config: PortalStorageConfig) -> Self {
        let portal_storage = Arc::new(RwLock::new(
            PortalStorage::new(storage_config, ProtocolId::History).unwrap(),
        ));
        Self {
            trusted_provider,
            history_jsonrpc_tx: None,
            master_accumulator: MasterAccumulator::default(),
            portal_storage,
        }
    }

    /// 1. Sample latest accumulator from 10 peers
    /// 2. Get latest master accumulator from portal storage
    /// 3. Update PortalStorage if new accumulator from network is latest
    /// 4. Set current master accumulator to latest
    pub async fn bootstrap(&mut self) {
        // Get latest master accumulator from AccumulatorDB
        let latest_macc_content_key =
            HistoryContentKey::MasterAccumulator(MasterAccumulatorKey::Latest(SszNone::new()));
        let latest_local_macc: &Option<Vec<u8>> = &self
            .portal_storage
            .as_ref()
            .read()
            .unwrap()
            .get(&latest_macc_content_key)
            .unwrap_or(None);
        let latest_local_macc = match latest_local_macc {
            Some(val) => MasterAccumulator::from_ssz_bytes(val).unwrap_or_default(),
            None => MasterAccumulator::default(),
        };

        // Sample latest accumulator from 10 network peers
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest {
            endpoint: HistoryEndpoint::SampleLatestMasterAccumulator,
            resp: resp_tx,
            params: Params::None,
        };
        let history_jsonrpc_tx = match self.history_jsonrpc_tx.as_ref() {
            Some(val) => val,
            None => {
                // use latest_local_macc if history jsonrpc is unavailable
                self.master_accumulator = latest_local_macc;
                return;
            }
        };
        history_jsonrpc_tx.send(request).unwrap();
        let latest_network_macc: MasterAccumulator = match resp_rx.recv().await {
            Some(val) => serde_json::from_value(val.unwrap()).unwrap_or_default(),
            None => MasterAccumulator::default(),
        };

        // Set current macc to latest macc
        self.master_accumulator = latest_local_macc.clone();

        // Update portal storage with latest network macc if network macc is latest
        if latest_local_macc.latest_height() < latest_network_macc.latest_height() {
            let _ = &self
                .portal_storage
                .as_ref()
                .write()
                .unwrap()
                .put(latest_macc_content_key, &latest_local_macc.as_ssz_bytes());
        }
    }

    // Currently falls back to trusted provider, to be updated to use canonical block indices network.
    pub fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<String> {
        let hex_number = format!("0x{:02X}", block_number);
        let method = "eth_getBlockByNumber".to_string();
        let params = Params::Array(vec![json!(hex_number), json!(false)]);
        let response: Value = self
            .trusted_provider
            .dispatch_http_request(method, params)?;
        let hash = match response["result"]["hash"].as_str() {
            Some(val) => val.trim_start_matches("0x"),
            None => {
                return Err(anyhow!(
                    "Unable to validate content received from trusted provider."
                ))
            }
        };
        Ok(hash.to_owned())
    }

    pub fn get_header_by_hash(&self, block_hash: H256) -> anyhow::Result<Header> {
        let block_hash = format!("0x{:02X}", block_hash);
        let method = "eth_getBlockByHash".to_string();
        let params = Params::Array(vec![json!(block_hash), json!(false)]);
        let response: Value = self
            .trusted_provider
            .dispatch_http_request(method, params)?;
        let header = Header::from_get_block_jsonrpc_response(response)?;
        Ok(header)
    }

    // To be updated to use chain history || header gossip network.
    pub fn _is_hash_canonical() -> anyhow::Result<bool> {
        Ok(true)
    }
}

/// Used by all overlay-network Validators to validate content in the overlay service.
#[async_trait]
pub trait Validator<TContentKey> {
    async fn validate_content(
        &self,
        content_key: &TContentKey,
        content: &[u8],
    ) -> anyhow::Result<()>
    where
        TContentKey: 'async_trait;
}

/// For use in tests where no validation needs to be performed.
pub struct MockValidator {}

#[async_trait]
impl Validator<IdentityContentKey> for MockValidator {
    async fn validate_content(
        &self,
        _content_key: &IdentityContentKey,
        _content: &[u8],
    ) -> anyhow::Result<()>
    where
        IdentityContentKey: 'async_trait,
    {
        Ok(())
    }
}
