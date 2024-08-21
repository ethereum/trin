use discv5::enr::NodeId;
use tokio::sync::mpsc;

use ethportal_api::{
    types::{
        enr::Enr,
        history::{ContentInfo, PaginateLocalContentInfo, TraceContentInfo},
        jsonrpc::{endpoints::HistoryEndpoint, request::HistoryJsonRpcRequest},
        portal::{AcceptInfo, DataRadius, FindNodesInfo, PongInfo, TraceGossipInfo},
    },
    HistoryContentKey, HistoryContentValue, HistoryNetworkApiServer, RoutingTableInfo,
};

use crate::{
    fetch::proxy_to_subnet,
    jsonrpsee::core::{async_trait, RpcResult},
};

pub struct HistoryNetworkApi {
    network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
}

impl HistoryNetworkApi {
    pub fn new(network: mpsc::UnboundedSender<HistoryJsonRpcRequest>) -> Self {
        Self { network }
    }
}

#[async_trait]
impl HistoryNetworkApiServer for HistoryNetworkApi {
    /// Returns meta information about overlay routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        let endpoint = HistoryEndpoint::RoutingTableInfo;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Write an Ethereum Node Record to the overlay routing table.
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool> {
        let endpoint = HistoryEndpoint::AddEnr(enr);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = HistoryEndpoint::GetEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Delete Node ID from the overlay routing table.
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool> {
        let endpoint = HistoryEndpoint::DeleteEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Fetch the ENR representation associated with the given Node ID.
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = HistoryEndpoint::LookupEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send a PING message to the designated node and wait for a PONG response
    async fn ping(&self, enr: Enr) -> RpcResult<PongInfo> {
        let endpoint = HistoryEndpoint::Ping(enr);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo> {
        let endpoint = HistoryEndpoint::FindNodes(enr, distances);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Lookup a target node within in the network
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>> {
        let endpoint = HistoryEndpoint::RecursiveFindNodes(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Lookup a target node within in the network
    async fn radius(&self) -> RpcResult<DataRadius> {
        let endpoint = HistoryEndpoint::DataRadius;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send FINDCONTENT message to get the content with a content key.
    async fn find_content(
        &self,
        enr: Enr,
        content_key: HistoryContentKey,
    ) -> RpcResult<ContentInfo> {
        let endpoint = HistoryEndpoint::FindContent(enr, content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Lookup a target content key in the network
    async fn recursive_find_content(
        &self,
        content_key: HistoryContentKey,
    ) -> RpcResult<ContentInfo> {
        let endpoint = HistoryEndpoint::RecursiveFindContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Lookup a target content key in the network. Return tracing info.
    async fn trace_recursive_find_content(
        &self,
        content_key: HistoryContentKey,
    ) -> RpcResult<TraceContentInfo> {
        let endpoint = HistoryEndpoint::TraceRecursiveFindContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Pagination of local content keys
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo> {
        let endpoint = HistoryEndpoint::PaginateLocalContentKeys(offset, limit);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return the number of peers that the content was gossiped to.
    async fn gossip(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<u32> {
        let endpoint = HistoryEndpoint::Gossip(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return tracing info.
    async fn trace_gossip(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<TraceGossipInfo> {
        let endpoint = HistoryEndpoint::TraceGossip(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send an OFFER request with given ContentKey, to the designated peer and wait for a response.
    /// Does not store content locally.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    async fn offer(
        &self,
        enr: Enr,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<AcceptInfo> {
        let endpoint = HistoryEndpoint::Offer(enr, content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send an OFFER request with given ContentKey, to the designated peer.
    /// Does not store the content locally.
    /// Returns true if the content was accepted and successfully transferred,
    /// returns false if the content was not accepted or the transfer failed.
    async fn trace_offer(
        &self,
        enr: Enr,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<bool> {
        let endpoint = HistoryEndpoint::TraceOffer(enr, content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send an OFFER request with given ContentKeys, to the designated peer and wait for a
    /// response. Requires the content keys to be stored locally.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    async fn wire_offer(
        &self,
        enr: Enr,
        content_keys: Vec<HistoryContentKey>,
    ) -> RpcResult<AcceptInfo> {
        let endpoint = HistoryEndpoint::WireOffer(enr, content_keys);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Store content key with a content data to the local database.
    async fn store(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<bool> {
        let endpoint = HistoryEndpoint::Store(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Get a content from the local database.
    async fn local_content(
        &self,
        content_key: HistoryContentKey,
    ) -> RpcResult<HistoryContentValue> {
        let endpoint = HistoryEndpoint::LocalContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }
}

impl std::fmt::Debug for HistoryNetworkApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryNetworkApi").finish_non_exhaustive()
    }
}
