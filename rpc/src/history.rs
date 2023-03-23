use crate::jsonrpsee::core::{async_trait, Error, RpcResult};
use anyhow::anyhow;
use ethportal_api::jsonrpsee::core::__reexports::serde_json::from_value;
use ethportal_api::jsonrpsee::core::__reexports::serde_json::Value;
use ethportal_api::types::discv5::{NodeId, RoutingTableInfo};
use ethportal_api::types::portal::{
    AcceptInfo, ContentInfo, DataRadius, FindNodesInfo, PaginateLocalContentInfo, PongInfo,
    TraceContentInfo,
};
use ethportal_api::HistoryContentKey;
use ethportal_api::HistoryContentValue;
use ethportal_api::HistoryNetworkApiServer;
use tokio::sync::mpsc;
use trin_types::enr::Enr;
use trin_types::jsonrpc::endpoints::HistoryEndpoint;
use trin_types::jsonrpc::request::HistoryJsonRpcRequest;

pub struct HistoryNetworkApi {
    network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
}

impl HistoryNetworkApi {
    pub fn new(network: mpsc::UnboundedSender<HistoryJsonRpcRequest>) -> Self {
        Self { network }
    }

    pub async fn proxy_query_to_history_subnet(
        &self,
        endpoint: HistoryEndpoint,
    ) -> anyhow::Result<Value> {
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let message = HistoryJsonRpcRequest {
            endpoint,
            resp: resp_tx,
        };
        let _ = self.network.send(message);

        match resp_rx.recv().await {
            Some(val) => match val {
                Ok(result) => Ok(result),
                Err(msg) => Err(anyhow!(msg)),
            },
            None => Err(anyhow!(
                "Internal error: No response from chain history subnetwork"
            )),
        }
    }
}

#[async_trait]
impl HistoryNetworkApiServer for HistoryNetworkApi {
    /// Returns meta information about overlay routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        let endpoint = HistoryEndpoint::RoutingTableInfo;
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: RoutingTableInfo = from_value(result)?;
        Ok(result)
    }

    /// Write an Ethereum Node Record to the overlay routing table.
    async fn add_enr(&self, _enr: Enr) -> RpcResult<bool> {
        Err(Error::MethodNotFound("add_enr".to_owned()))
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, _node_id: NodeId) -> RpcResult<Enr> {
        Err(Error::MethodNotFound("get_enr".to_owned()))
    }

    /// Delete Node ID from the overlay routing table.
    async fn delete_enr(&self, _node_id: NodeId) -> RpcResult<bool> {
        Err(Error::MethodNotFound("delete_enr".to_owned()))
    }

    /// Fetch the ENR representation associated with the given Node ID and optional sequence number.
    async fn lookup_enr(&self, _node_id: NodeId, _enr_seq: Option<u32>) -> RpcResult<Enr> {
        Err(Error::MethodNotFound("lookup_enr".to_owned()))
    }

    /// Send a PING message to the designated node and wait for a PONG response
    async fn ping(&self, enr: Enr, data_radius: Option<DataRadius>) -> RpcResult<PongInfo> {
        let endpoint = HistoryEndpoint::Ping(enr, data_radius);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: PongInfo = from_value(result)?;
        Ok(result)
    }

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the designated
    /// peer and wait for a response
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo> {
        let endpoint = HistoryEndpoint::FindNodes(enr, distances);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: FindNodesInfo = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target node within in the network
    async fn recursive_find_nodes(&self, _node_id: NodeId) -> RpcResult<Vec<Enr>> {
        Err(Error::MethodNotFound("recursive_find_nodes".to_owned()))
    }

    /// Lookup a target node within in the network
    async fn radius(&self) -> RpcResult<DataRadius> {
        let endpoint = HistoryEndpoint::DataRadius;
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: DataRadius = from_value(result)?;
        Ok(result)
    }

    /// Send FINDCONTENT message to get the content with a content key.
    async fn find_content(
        &self,
        enr: Enr,
        content_key: HistoryContentKey,
    ) -> RpcResult<ContentInfo> {
        let endpoint = HistoryEndpoint::FindContent(enr, content_key);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: ContentInfo = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target content key in the network
    async fn recursive_find_content(
        &self,
        content_key: HistoryContentKey,
    ) -> RpcResult<HistoryContentValue> {
        let endpoint = HistoryEndpoint::RecursiveFindContent(content_key);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: HistoryContentValue = from_value(result)?;
        Ok(result)
    }

    /// Lookup a target content key in the network. Return tracing info.
    async fn trace_recursive_find_content(
        &self,
        content_key: HistoryContentKey,
    ) -> RpcResult<TraceContentInfo> {
        let endpoint = HistoryEndpoint::TraceRecursiveFindContent(content_key);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: TraceContentInfo = from_value(result)?;
        Ok(result)
    }

    /// Pagination of local content keys
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo> {
        let endpoint = HistoryEndpoint::PaginateLocalContentKeys(offset, limit);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: PaginateLocalContentInfo = from_value(result)?;
        Ok(result)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all peers.
    /// Return the number of peers that the content was gossiped to.
    async fn gossip(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<u32> {
        let endpoint = HistoryEndpoint::Gossip(content_key, content_value);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: u32 = from_value(result)?;
        Ok(result)
    }

    /// Send an OFFER request with given ContentKey, to the designated peer and wait for a response.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist receive.
    async fn offer(
        &self,
        enr: Enr,
        content_key: HistoryContentKey,
        content_value: Option<HistoryContentValue>,
    ) -> RpcResult<AcceptInfo> {
        let endpoint = HistoryEndpoint::Offer(enr, content_key, content_value);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: AcceptInfo = from_value(result)?;
        Ok(result)
    }

    /// Store content key with a content data to the local database.
    async fn store(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<bool> {
        let endpoint = HistoryEndpoint::Store(content_key, content_value);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: bool = from_value(result)?;
        Ok(result)
    }

    /// Get a content from the local database
    async fn local_content(
        &self,
        content_key: HistoryContentKey,
    ) -> RpcResult<HistoryContentValue> {
        let endpoint = HistoryEndpoint::LocalContent(content_key);
        let result = self.proxy_query_to_history_subnet(endpoint).await?;
        let result: HistoryContentValue = match result {
            Value::Null => HistoryContentValue::Unknown(String::from("")),
            other => from_value(other)?,
        };
        Ok(result)
    }
}

impl std::fmt::Debug for HistoryNetworkApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryNetworkApi").finish_non_exhaustive()
    }
}
