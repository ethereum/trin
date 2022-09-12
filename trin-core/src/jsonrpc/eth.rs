use anyhow::anyhow;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        handlers::proxy_query_to_history_subnet,
        types::{GetBlockByHashParams, HistoryJsonRpcRequest, Params},
    },
    portalnet::types::content_key::{BlockHeader, HistoryContentKey},
    types::header::Header,
    utils::bytes::{hex_decode, hex_encode},
};

/// eth_getBlockByHash
pub async fn get_block_by_hash(
    params: Params,
    history_jsonrpc_tx: &Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
) -> anyhow::Result<Value> {
    let params: GetBlockByHashParams = params.clone().try_into()?;
    let content_key = HistoryContentKey::BlockHeader(BlockHeader {
        chain_id: 1,
        block_hash: params.block_hash,
    });
    let endpoint = HistoryEndpoint::RecursiveFindContent;
    let bytes_content_key: Vec<u8> = content_key.into();
    let hex_content_key = hex_encode(bytes_content_key);
    let overlay_params = Params::Array(vec![Value::String(hex_content_key)]);

    let resp = match history_jsonrpc_tx.as_ref() {
        Some(tx) => proxy_query_to_history_subnet(tx, endpoint, overlay_params).await,
        None => Err(anyhow!("Chain history subnetwork unavailable.")),
    };

    match resp {
        Ok(Value::String(val)) => hex_decode(val.as_str())
            .and_then(|bytes| {
                rlp::decode::<Header>(bytes.as_ref()).map_err(|_| anyhow!("Invalid RLP"))
            })
            .map(|header| json!(header)),
        Ok(Value::Null) => Ok(Value::Null),
        Ok(_) => Err(anyhow!("Invalid JSON value")),
        Err(err) => Err(err),
    }
}
