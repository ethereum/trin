use crate::{errors::RpcServeError, serde::from_value};
use alloy_primitives::B256;

use crate::jsonrpsee::core::{async_trait, RpcResult};
use discv5::enr::NodeId;
use ethportal_api::{
    types::{
        beacon::{ContentInfo, PaginateLocalContentInfo, TraceContentInfo},
        enr::Enr,
        jsonrpc::{endpoints::BeaconEndpoint, request::BeaconJsonRpcRequest},
        portal::{AcceptInfo, DataRadius, FindNodesInfo, PongInfo, TraceGossipInfo},
    },
    BeaconContentKey, BeaconContentValue, BeaconNetworkApiServer, RoutingTableInfo,
};
use serde_json::Value;
use tokio::sync::mpsc;

pub struct BeaconNetworkApi {
    network: mpsc::UnboundedSender<BeaconJsonRpcRequest>,
}

impl BeaconNetworkApi {
    #[allow(dead_code)]
    pub fn new(network: mpsc::UnboundedSender<BeaconJsonRpcRequest>) -> Self {
        Self { network }
    }

    pub async fn proxy_query_to_beacon_subnet(
        &self,
        endpoint: BeaconEndpoint,
    ) -> Result<Value, RpcServeError> {
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let message = BeaconJsonRpcRequest {
            endpoint,
            resp: resp_tx,
        };
        let _ = self.network.send(message);

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
                            .ok_or_else(|| {
                                RpcServeError::Message(
                                    "Failed to parse error message, invalid `message` field"
                                        .to_string(),
                                )
                            })?
                            .to_string();
                        let trace = match error_details.get("trace") {
                            Some(trace) => serde_json::from_value(trace.clone()).map_err(|e| {
                                RpcServeError::Message(format!(
                                    "Failed to parse error message, invalid trace: {e:?}",
                                ))
                            })?,
                            None => None,
                        };
                        Err(RpcServeError::ContentNotFound { message, trace })
                    } else {
                        Err(RpcServeError::Message(msg))
                    }
                }
            },
            None => Err(RpcServeError::Message(
                "Internal error: No response from chain beacon subnetwork".to_string(),
            )),
        }
    }
}

#[async_trait]
impl BeaconNetworkApiServer for BeaconNetworkApi {
    /// Returns meta information about overlay routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        let endpoint = BeaconEndpoint::RoutingTableInfo;
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: RoutingTableInfo = from_value(result)?;
        Ok(result)
    }

    /// Write an Ethereum Node Record to the overlay routing table.
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool> {
        let endpoint = BeaconEndpoint::AddEnr(enr);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: bool = from_value(result)?;
        Ok(result)
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = BeaconEndpoint::GetEnr(node_id);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: Enr = from_value(result)?;
        Ok(result)
    }

    /// Delete Node ID from the overlay routing table.
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool> {
        let endpoint = BeaconEndpoint::DeleteEnr(node_id);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: bool = from_value(result)?;
        Ok(result)
    }

    /// Fetch the ENR representation associated with the given Node ID.
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = BeaconEndpoint::LookupEnr(node_id);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: Enr = from_value(result)?;
        Ok(result)
    }

    /// Send a PING message to the designated node and wait for a PONG response
    async fn ping(&self, enr: Enr) -> RpcResult<PongInfo> {
        let endpoint = BeaconEndpoint::Ping(enr);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: PongInfo = from_value(result)?;
        Ok(result)
    }

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo> {
        let endpoint = BeaconEndpoint::FindNodes(enr, distances);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: FindNodesInfo = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target node within in the network
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>> {
        let endpoint = BeaconEndpoint::RecursiveFindNodes(node_id);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: Vec<Enr> = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target node within in the network
    async fn radius(&self) -> RpcResult<DataRadius> {
        let endpoint = BeaconEndpoint::DataRadius;
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: DataRadius = from_value(result)?;
        Ok(result)
    }

    async fn optimistic_state_root(&self) -> RpcResult<B256> {
        let endpoint = BeaconEndpoint::OptimisticStateRoot;
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: B256 = from_value(result)?;
        Ok(result)
    }

    /// Send FINDCONTENT message to get the content with a content key.
    async fn find_content(
        &self,
        enr: Enr,
        content_key: BeaconContentKey,
    ) -> RpcResult<ContentInfo> {
        let endpoint = BeaconEndpoint::FindContent(enr, content_key);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: ContentInfo = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target content key in the network
    async fn recursive_find_content(
        &self,
        content_key: BeaconContentKey,
    ) -> RpcResult<ContentInfo> {
        let endpoint = BeaconEndpoint::RecursiveFindContent(content_key);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        Ok(from_value(result)?)
    }

    /// Lookup a target content key in the network. Return tracing info.
    async fn trace_recursive_find_content(
        &self,
        content_key: BeaconContentKey,
    ) -> RpcResult<TraceContentInfo> {
        let endpoint = BeaconEndpoint::TraceRecursiveFindContent(content_key);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let info: TraceContentInfo = from_value(result)?;
        Ok(info)
    }

    /// Pagination of local content keys
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo> {
        let endpoint = BeaconEndpoint::PaginateLocalContentKeys(offset, limit);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: PaginateLocalContentInfo = from_value(result)?;
        Ok(result)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return the number of peers that the content was gossiped to.
    async fn gossip(
        &self,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
    ) -> RpcResult<u32> {
        let endpoint = BeaconEndpoint::Gossip(content_key, content_value);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: u32 = from_value(result)?;
        Ok(result)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return tracing info.
    async fn trace_gossip(
        &self,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
    ) -> RpcResult<TraceGossipInfo> {
        let endpoint = BeaconEndpoint::TraceGossip(content_key, content_value);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: TraceGossipInfo = from_value(result)?;
        Ok(result)
    }

    /// Send an OFFER request with given ContentKey, to the designated peer and wait for a response.
    /// If the content value is provided, a "populated" offer is used, which will not store the
    /// content locally. Otherwise a regular offer is sent, after validating that the content is
    /// available locally.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    async fn offer(
        &self,
        enr: Enr,
        content_key: BeaconContentKey,
        content_value: Option<BeaconContentValue>,
    ) -> RpcResult<AcceptInfo> {
        let endpoint = BeaconEndpoint::Offer(enr, content_key, content_value);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: AcceptInfo = from_value(result)?;
        Ok(result)
    }

    /// Store content key with a content data to the local database.
    async fn store(
        &self,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
    ) -> RpcResult<bool> {
        let endpoint = BeaconEndpoint::Store(content_key, content_value);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        let result: bool = from_value(result)?;
        Ok(result)
    }

    /// Get a content from the local database.
    async fn local_content(&self, content_key: BeaconContentKey) -> RpcResult<BeaconContentValue> {
        let endpoint = BeaconEndpoint::LocalContent(content_key);
        let result = self.proxy_query_to_beacon_subnet(endpoint).await?;
        Ok(from_value(result)?)
    }
}

impl std::fmt::Debug for BeaconNetworkApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconNetworkApi").finish_non_exhaustive()
    }
}
