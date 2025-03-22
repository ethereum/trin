use ethportal_api::types::jsonrpc::{endpoints::SubnetworkEndpoint, request::JsonRpcRequest};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::{
    errors::{ContentNotFoundJsonError, RpcServeError},
    serde::from_value,
};

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
                if let Ok(err) = serde_json::from_str::<ContentNotFoundJsonError>(&msg) {
                    return Err(err.into());
                }
            }

            Err(RpcServeError::Message(msg))
        }
    }
}
