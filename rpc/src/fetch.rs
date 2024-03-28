use alloy_primitives::B256;
/// Fetch data from related Portal networks
use serde_json::Value;
use tokio::sync::mpsc;

use ethportal_api::{
    types::{
        execution::{block_body::BlockBody, header::Header},
        jsonrpc::{endpoints::HistoryEndpoint, request::HistoryJsonRpcRequest},
    },
    utils::bytes::hex_decode,
    ContentValue, HistoryContentKey, HistoryContentValue,
};

use crate::errors::RpcServeError;

pub async fn proxy_query_to_history_subnet(
    network: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    endpoint: HistoryEndpoint,
) -> Result<Value, RpcServeError> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = HistoryJsonRpcRequest {
        endpoint,
        resp: resp_tx,
    };
    let _ = network.send(message);

    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => {
                if msg.contains("Unable to locate content on the network") {
                    let error_details: Value = serde_json::from_str(&msg).map_err(|e| {
                        RpcServeError::Message(format!(
                            "Failed to parse error message from history subnet: {e:?}",
                        ))
                    })?;
                    let message = error_details["message"]
                        .as_str()
                        .expect("Failed to parse error message from history subnet")
                        .to_string();
                    let trace = match error_details.get("trace") {
                        Some(trace) => serde_json::from_value(trace.clone())
                            .expect("Failed to parse query trace"),
                        None => None,
                    };
                    Err(RpcServeError::ContentNotFound { message, trace })
                } else {
                    Err(RpcServeError::Message(msg))
                }
            }
        },
        None => Err(RpcServeError::Message(
            "Internal error: No response from chain history subnetwork".to_string(),
        )),
    }
}

pub async fn find_header_by_hash(
    network: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    block_hash: B256,
) -> Result<Header, RpcServeError> {
    // Request the block header from the history subnet.
    let content_key: HistoryContentKey = HistoryContentKey::BlockHeaderWithProof(block_hash.into());
    let header = find_content_by_hash(network, content_key).await?;

    match header {
        HistoryContentValue::BlockHeaderWithProof(h) => Ok(h.header),
        wrong_val => Err(RpcServeError::Message(format!(
            "Internal trin error: got back a non-header from a key that must only point to headers; got {wrong_val:?}"
        ))),
    }
}

pub async fn find_block_body_by_hash(
    network: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    block_hash: B256,
) -> Result<BlockBody, RpcServeError> {
    // Request the block body from the history subnet.
    let content_key: HistoryContentKey = HistoryContentKey::BlockBody(block_hash.into());
    let body = find_content_by_hash(network, content_key).await?;

    match body {
        HistoryContentValue::BlockBody(body) => Ok(body),
        wrong_val => Err(RpcServeError::Message(format!(
            "Internal trin error: got back a non-body from a key that must only point to bodies; got {wrong_val:?}"
        ))),
    }
}

async fn find_content_by_hash(
    network: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    content_key: HistoryContentKey,
) -> Result<HistoryContentValue, RpcServeError> {
    let endpoint = HistoryEndpoint::RecursiveFindContent(content_key.clone());
    let mut result = proxy_query_to_history_subnet(network, endpoint).await?;
    let content = match result["content"].take() {
        serde_json::Value::String(s) => s,
        wrong_type => {
            let message =
                format!("Invalid internal representation of {content_key:?}; json: {wrong_type:?}");
            return Err(RpcServeError::Message(message));
        }
    };
    let content: Vec<u8> =
        hex_decode(&content).expect("decoding the trin hex-encoded data failed, odd");
    HistoryContentValue::decode(&content).map_err(|err| {
        let message =
            format!("Invalid internal representation of {content_key:?}; could not decode: {err}");
        RpcServeError::Message(message)
    })
}
