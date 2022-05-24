use anyhow::anyhow;
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::jsonrpc::service::dispatch_infura_request;
use crate::jsonrpc::types::{HistoryJsonRpcRequest, JsonRequest, Params};
use crate::portalnet::types::content_key::IdentityContentKey;
use crate::portalnet::types::messages::ByteList;

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation. Currently, it just proxies these requests
/// on to infura.
#[derive(Clone)]
pub struct HeaderOracle {
    pub infura_url: String,
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<tokio::sync::mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub header_gossip_jsonrpc_tx: Option<bool>,
    pub block_indices_jsonrpc_tx: Option<bool>,
    pub state_jsonrpc_tx: Option<bool>,
}

impl Default for HeaderOracle {
    fn default() -> Self {
        Self {
            infura_url: "https://mainnet.infura.io:443/v3/".to_string(),
            history_jsonrpc_tx: None,
            header_gossip_jsonrpc_tx: None,
            block_indices_jsonrpc_tx: None,
            state_jsonrpc_tx: None,
        }
    }
}

impl HeaderOracle {
    // Currently falls back to infura, to be updated to use canonical block indices network.
    pub fn get_hash_at_height(&mut self, hex_number: String) -> anyhow::Result<String> {
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            params: Params::Array(vec![json!(hex_number), json!(false)]),
            method: "eth_getBlockByNumber".to_string(),
            id: 1,
        };
        let response: Value = match dispatch_infura_request(request, &self.infura_url) {
            Ok(val) => match serde_json::from_str(&val) {
                Ok(val) => val,
                Err(msg) => {
                    return Err(anyhow!("Unable to validate content with Infura: {:?}", msg))
                }
            },
            Err(msg) => return Err(anyhow!("Unable to validate content with Infura: {:?}", msg)),
        };
        let infura_hash = match response["result"]["hash"].as_str() {
            Some(val) => val.trim_start_matches("0x"),
            None => {
                return Err(anyhow!(
                    "Unable to validate content with Infura: Invalid Infura response."
                ))
            }
        };
        Ok(infura_hash.to_owned())
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
        &mut self,
        content_key: &TContentKey,
        content: &ByteList,
    ) -> anyhow::Result<()>
    where
        TContentKey: 'async_trait;
}

/// For use in tests where no validation needs to be performed.
pub struct MockValidator {}

#[async_trait]
impl Validator<IdentityContentKey> for MockValidator {
    async fn validate_content(
        &mut self,
        _content_key: &IdentityContentKey,
        _content: &ByteList,
    ) -> anyhow::Result<()>
    where
        IdentityContentKey: 'async_trait,
    {
        Ok(())
    }
}
