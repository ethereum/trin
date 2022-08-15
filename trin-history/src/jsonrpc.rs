use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::network::HistoryNetwork;
use trin_core::utils::bytes::hex_encode;
use trin_core::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        types::{
            FindContentParams, FindNodesParams, HistoryJsonRpcRequest, LocalContentParams,
            PingParams, RecursiveFindContentParams, SendOfferParams, StoreParams,
        },
        utils::bucket_entries_to_json,
    },
    portalnet::{
        types::{
            content_key::HistoryContentKey,
            messages::{Content, FindContent, Request, Response, SszEnr},
        },
        Enr,
    },
    types::header::Header,
};

/// Handles History network JSON-RPC requests
pub struct HistoryRequestHandler {
    pub network: Arc<HistoryNetwork>,
    pub history_rx: mpsc::UnboundedReceiver<HistoryJsonRpcRequest>,
}

impl HistoryRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.history_rx.recv().await {
            match request.endpoint {
                HistoryEndpoint::LocalContent => {
                    let response =
                        match LocalContentParams::<HistoryContentKey>::try_from(request.params) {
                            Ok(params) => {
                                match &self.network.overlay.storage.read().get(&params.content_key)
                                {
                                    Ok(val) => match val {
                                        Some(val) => Ok(Value::String(hex_encode(val.clone()))),
                                        None => Err(format!(
                                            "Unable to find content key in local storage: {:?}",
                                            params.content_key
                                        )),
                                    },
                                    Err(_) => Err(format!(
                                        "Unable to find content key in local storage: {:?}",
                                        params.content_key
                                    )),
                                }
                            }
                            Err(msg) => Err(format!("Invalid LocalContent params: {msg:?}")),
                        };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Store => {
                    let response = match StoreParams::<HistoryContentKey>::try_from(request.params)
                    {
                        Ok(params) => {
                            let content_key = params.content_key.clone();
                            let content = params.content.clone();
                            match self
                                .network
                                .overlay
                                .storage
                                .write()
                                .store(&content_key, &content)
                            {
                                Ok(_) => Ok(Value::String("true".to_string())),
                                Err(msg) => Ok(Value::String(msg.to_string())),
                            }
                        }
                        Err(msg) => Ok(Value::String(msg.to_string())),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::RecursiveFindContent => {
                    let find_content_params =
                        match RecursiveFindContentParams::try_from(request.params) {
                            Ok(params) => params,
                            Err(msg) => {
                                let _ = request.resp.send(Err(format!(
                                    "Invalid RecursiveFindContent params: {:?}",
                                    msg.code
                                )));
                                return;
                            }
                        };

                    let content_key = find_content_params.content_key.to_vec();
                    let find_content_request = Request::FindContent(FindContent { content_key });
                    let first_response = match self
                        .network
                        .overlay
                        .initiate_overlay_request(find_content_request)
                        .await
                    {
                        Ok(content) => content,
                        Err(msg) => {
                            let _ = request.resp.send(Err(format!(
                                "Unable to initialize RecursiveFindContent request: {:?}",
                                msg
                            )));
                            return;
                        }
                    };
                    // Pretty much all this logic is temporary hack that will be replaced by
                    // iterative find content support
                    let response = match first_response {
                        Response::Content(val) => match val {
                            // Perform secondary lookup if initial response is `enrs`
                            Content::Enrs(enrs) => {
                                let target_enr: SszEnr = enrs.first().unwrap().clone();
                                let target_enr: Enr = target_enr.into();
                                match self
                                    .network
                                    .overlay
                                    .send_find_content(
                                        target_enr,
                                        find_content_params.content_key.into(),
                                    )
                                    .await
                                {
                                    Ok(content) => match content {
                                        Content::Content(val) => {
                                            match rlp::decode::<Header>(&val) {
                                                Ok(header) => Ok(json!(header)),
                                                Err(_) => Err(
                                                    "Content retrieved has invalid RLP encoding"
                                                        .to_string(),
                                                ),
                                            }
                                        }
                                        _ => Err("Unable to retrieve content from the network."
                                            .to_string()),
                                    },
                                    Err(msg) => Err(format!(
                                        "RecursiveFindContent request timeout: {:?}",
                                        msg
                                    )),
                                }
                            }
                            // Return value if initial response is `content`
                            Content::Content(val) => match rlp::decode::<Header>(&val) {
                                Ok(header) => Ok(json!(header)),
                                Err(_) => {
                                    Err("Content retrieved has invalid RLP encoding".to_string())
                                }
                            },
                            _ => Err("Unsupported content".to_string()),
                        },
                        _ => Err("Invalid RecursiveFindContent params".to_string()),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::DataRadius => {
                    let radius = &self.network.overlay.data_radius;
                    let _ = request.resp.send(Ok(Value::String(radius.to_string())));
                }
                HistoryEndpoint::FindContent => {
                    let response = match FindContentParams::try_from(request.params) {
                        Ok(val) => match self
                            .network
                            .overlay
                            .send_find_content(val.enr.into(), val.content_key.into())
                            .await
                        {
                            Ok(content) => match content.try_into() {
                                Ok(val) => Ok(val),
                                Err(_) => Err("Content response decoding error".to_string()),
                            },
                            Err(msg) => Err(format!("FindContent request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid FindContent params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::FindNodes => {
                    let response = match FindNodesParams::try_from(request.params) {
                        Ok(val) => match self
                            .network
                            .overlay
                            .send_find_nodes(val.enr.into(), val.distances)
                            .await
                        {
                            Ok(nodes) => Ok(nodes.into()),
                            Err(msg) => Err(format!("FindNodes request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid FindNodes params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::SendOffer => {
                    let response = match SendOfferParams::try_from(request.params) {
                        Ok(val) => {
                            let content_keys =
                                val.content_keys.iter().map(|key| key.to_vec()).collect();

                            match self
                                .network
                                .overlay
                                .send_offer(content_keys, val.enr.into())
                                .await
                            {
                                Ok(accept) => Ok(accept.into()),
                                Err(msg) => Err(format!("SendOffer request timeout: {:?}", msg)),
                            }
                        }
                        Err(msg) => Err(format!("Invalid SendOffer params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Ping => {
                    let response = match PingParams::try_from(request.params) {
                        Ok(val) => match self.network.overlay.send_ping(val.enr.into()).await {
                            Ok(pong) => Ok(pong.into()),
                            Err(msg) => Err(format!("Ping request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid Ping params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::RoutingTableInfo => {
                    let bucket_entries_json =
                        bucket_entries_to_json(self.network.overlay.bucket_entries());

                    let _ = request.resp.send(Ok(bucket_entries_json));
                }
            }
        }
    }
}
