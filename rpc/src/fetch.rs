use std::fmt::Debug;

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

use ethportal_api::{
    types::{
        execution::{block_body::BlockBody, header::Header},
        history::ContentInfo,
        jsonrpc::{
            endpoints::{HistoryEndpoint, SubnetworkEndpoint},
            request::{HistoryJsonRpcRequest, JsonRpcRequest},
        },
        query_trace::QueryTrace,
    },
    HistoryContentKey, HistoryContentValue,
};

use crate::{
    errors::{ContentNotFoundJsonError, RpcServeError},
    serde::from_value,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContentNotFoundError {
    message: String,
    trace: Option<QueryTrace>,
}

/// Fetch and deserialize data from Portal subnetwork.
pub async fn proxy_to_subnet<TEndpoint, TOutput>(
    network: &mpsc::UnboundedSender<JsonRpcRequest<TEndpoint>>,
    endpoint: TEndpoint,
) -> Result<TOutput, RpcServeError>
where
    TEndpoint: SubnetworkEndpoint + Clone,
    TOutput: serde::de::DeserializeOwned,
{
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = JsonRpcRequest {
        endpoint,
        resp: resp_tx,
    };
    let _ = network.send(message);

    let Some(response) = resp_rx.recv().await else {
        return Err(RpcServeError::Message(format!(
            "Internal error: No response from {} subnetwork",
            TEndpoint::subnetwork()
        )));
    };

    match response {
        Ok(result) => from_value(result),
        Err(msg) => {
            if msg.contains("Unable to locate content on the network") {
                let error: ContentNotFoundJsonError = serde_json::from_str(&msg).map_err(|e| {
                    RpcServeError::Message(format!(
                        "Failed to parse error message from {} subnetwork: {e:?}",
                        TEndpoint::subnetwork()
                    ))
                })?;
                Err(error.into())
            } else {
                Err(RpcServeError::Message(msg))
            }
        }
    }
}

pub async fn find_header_by_hash(
    network: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    block_hash: B256,
) -> Result<Header, RpcServeError> {
    // Request the block header from the history subnet.
    let content_key = HistoryContentKey::BlockHeaderWithProof(block_hash.into());
    let content_value = find_content_by_hash(network, content_key).await?;

    match content_value {
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
    let content_key = HistoryContentKey::BlockBody(block_hash.into());
    let content_value = find_content_by_hash(network, content_key).await?;

    match content_value {
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
    let endpoint = HistoryEndpoint::RecursiveFindContent(content_key);
    let response: ContentInfo = proxy_to_subnet(network, endpoint).await?;
    let ContentInfo::Content { content, .. } = response else {
        return Err(RpcServeError::Message(format!(
            "Invalid response variant: RecursiveFindContent should contain content value; got {response:?}"
        )));
    };

    Ok(content)
}
