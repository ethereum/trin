use discv5::enr::NodeId;
use ethportal_api::{
    types::{
        enr::Enr,
        jsonrpc::{endpoints::StateEndpoint, request::StateJsonRpcRequest},
        portal::{AcceptInfo, DataRadius, FindNodesInfo, PongInfo, TraceGossipInfo},
        state::{ContentInfo, PaginateLocalContentInfo, TraceContentInfo},
    },
    RoutingTableInfo, StateContentKey, StateContentValue, StateNetworkApiServer,
};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::{
    errors::RpcServeError,
    jsonrpsee::core::{async_trait, RpcResult},
    serde::from_value,
};

pub struct StateNetworkApi {
    network: mpsc::UnboundedSender<StateJsonRpcRequest>,
}

impl StateNetworkApi {
    pub fn new(network: mpsc::UnboundedSender<StateJsonRpcRequest>) -> Self {
        Self { network }
    }

    pub async fn proxy_query_to_state_subnet(
        &self,
        endpoint: StateEndpoint,
    ) -> Result<Value, RpcServeError> {
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let message = StateJsonRpcRequest {
            endpoint,
            resp: resp_tx,
        };
        let _ = self.network.send(message);

        match resp_rx.recv().await {
            Some(val) => match val {
                Ok(result) => Ok(result),
                Err(msg) => Err(RpcServeError::Message(msg)),
            },
            None => Err(RpcServeError::Message(
                "Internal error: No response from chain state subnetwork".to_string(),
            )),
        }
    }
}

#[async_trait]
impl StateNetworkApiServer for StateNetworkApi {
    /// Returns meta information about overlay routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        let endpoint = StateEndpoint::RoutingTableInfo;
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: RoutingTableInfo = from_value(result)?;
        Ok(result)
    }

    /// Write an Ethereum Node Record to the overlay routing table.
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool> {
        let endpoint = StateEndpoint::AddEnr(enr);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: bool = from_value(result)?;
        Ok(result)
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = StateEndpoint::GetEnr(node_id);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: Enr = from_value(result)?;
        Ok(result)
    }

    /// Delete Node ID from the overlay routing table.
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool> {
        let endpoint = StateEndpoint::DeleteEnr(node_id);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: bool = from_value(result)?;
        Ok(result)
    }

    /// Fetch the ENR representation associated with the given Node ID.
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = StateEndpoint::LookupEnr(node_id);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: Enr = from_value(result)?;
        Ok(result)
    }

    /// Send a PING message to the designated node and wait for a PONG response
    async fn ping(&self, enr: Enr) -> RpcResult<PongInfo> {
        let endpoint = StateEndpoint::Ping(enr);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: PongInfo = from_value(result)?;
        Ok(result)
    }

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo> {
        let endpoint = StateEndpoint::FindNodes(enr, distances);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: FindNodesInfo = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target node within in the network
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>> {
        let endpoint = StateEndpoint::RecursiveFindNodes(node_id);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: Vec<Enr> = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target node within in the network
    async fn radius(&self) -> RpcResult<DataRadius> {
        let endpoint = StateEndpoint::DataRadius;
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: DataRadius = from_value(result)?;
        Ok(result)
    }

    /// Send FINDCONTENT message to get the content with a content key.
    async fn find_content(&self, enr: Enr, content_key: StateContentKey) -> RpcResult<ContentInfo> {
        let endpoint = StateEndpoint::FindContent(enr, content_key);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: ContentInfo = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target content key in the network
    async fn recursive_find_content(&self, content_key: StateContentKey) -> RpcResult<ContentInfo> {
        let endpoint = StateEndpoint::RecursiveFindContent(content_key);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: ContentInfo = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target content key in the network. Return tracing info.
    async fn trace_recursive_find_content(
        &self,
        content_key: StateContentKey,
    ) -> RpcResult<TraceContentInfo> {
        let endpoint = StateEndpoint::TraceRecursiveFindContent(content_key);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let info: TraceContentInfo = from_value(result)?;
        Ok(info)
    }

    /// Pagination of local content keys
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo> {
        let endpoint = StateEndpoint::PaginateLocalContentKeys(offset, limit);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: PaginateLocalContentInfo = from_value(result)?;
        Ok(result)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return the number of peers that the content was gossiped to.
    async fn gossip(
        &self,
        content_key: StateContentKey,
        content_value: StateContentValue,
    ) -> RpcResult<u32> {
        let endpoint = StateEndpoint::Gossip(content_key, content_value);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: u32 = from_value(result)?;
        Ok(result)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return tracing info.
    async fn trace_gossip(
        &self,
        content_key: StateContentKey,
        content_value: StateContentValue,
    ) -> RpcResult<TraceGossipInfo> {
        let endpoint = StateEndpoint::TraceGossip(content_key, content_value);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
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
        content_key: StateContentKey,
        content_value: Option<StateContentValue>,
    ) -> RpcResult<AcceptInfo> {
        let endpoint = StateEndpoint::Offer(enr, content_key, content_value);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: AcceptInfo = from_value(result)?;
        Ok(result)
    }

    /// Store content key with a content data to the local database.
    async fn store(
        &self,
        content_key: StateContentKey,
        content_value: StateContentValue,
    ) -> RpcResult<bool> {
        let endpoint = StateEndpoint::Store(content_key, content_value);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        let result: bool = from_value(result)?;
        Ok(result)
    }

    /// Get a content from the local database.
    async fn local_content(&self, content_key: StateContentKey) -> RpcResult<StateContentValue> {
        let endpoint = StateEndpoint::LocalContent(content_key);
        let result = self.proxy_query_to_state_subnet(endpoint).await?;
        Ok(from_value(result)?)
    }
}

impl std::fmt::Debug for StateNetworkApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateNetworkApi").finish_non_exhaustive()
    }
}
