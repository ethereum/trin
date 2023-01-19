use crate::jsonrpsee::core::{async_trait, RpcResult};
use ethportal_api::types::discv5::{Enr, NodeId, RoutingTableInfo};
use ethportal_api::types::portal::{
    AcceptInfo, ContentInfo, DataRadius, PaginateLocalContentInfo, PongInfo, TraceContentInfo,
};
use ethportal_api::HistoryNetworkApiServer;
use ethportal_api::{HistoryContentItem, HistoryContentKey};

use tokio::sync::mpsc;
use trin_core::jsonrpc::types::HistoryJsonRpcRequest;

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
        todo!()
    }

    /// Write an Ethereum Node Record to the overlay routing table.
    async fn add_enr(&self, _enr: Enr) -> RpcResult<bool> {
        todo!()
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, _node_id: NodeId) -> RpcResult<Enr> {
        todo!()
    }

    /// Delete Node ID from the overlay routing table.
    async fn delete_enr(&self, _node_id: NodeId) -> RpcResult<bool> {
        todo!()
    }

    /// Fetch the ENR representation associated with the given Node ID and optional sequence number.
    async fn lookup_enr(&self, _node_id: NodeId, _enr_seq: Option<u32>) -> RpcResult<Enr> {
        todo!()
    }

    /// Send a PING message to the designated node and wait for a PONG response
    async fn ping(&self, _enr: Enr, _data_radius: Option<DataRadius>) -> RpcResult<PongInfo> {
        todo!()
    }

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the designated
    /// peer and wait for a response
    async fn find_nodes(&self, _enr: Enr, _distances: Vec<u16>) -> RpcResult<Vec<Enr>> {
        todo!()
    }

    /// Lookup a target node within in the network
    async fn recursive_find_nodes(&self, _node_id: NodeId) -> RpcResult<Vec<Enr>> {
        todo!()
    }

    /// Send FINDCONTENT message to get the content with a content key.
    async fn find_content(
        &self,
        _enr: Enr,
        _content_key: HistoryContentKey,
    ) -> RpcResult<ContentInfo> {
        todo!()
    }

    /// Lookup a target content key in the network
    async fn recursive_find_content(
        &self,
        _content_key: HistoryContentKey,
    ) -> RpcResult<HistoryContentItem> {
        todo!()
    }

    /// Lookup a target content key in the network. Return tracing info.
    async fn trace_recursive_find_content(
        &self,
        _content_key: HistoryContentKey,
    ) -> RpcResult<TraceContentInfo> {
        todo!()
    }

    /// Pagination of local content keys
    async fn paginate_local_content_keys(
        &self,
        _offset: u64,
        _limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo> {
        todo!()
    }

    /// Send the provided content item to interested peers. Clients may choose to send to some or all peers.
    /// Return the number of peers that the content was gossiped to.
    async fn offer(
        &self,
        _content_key: HistoryContentKey,
        _content_value: HistoryContentItem,
    ) -> RpcResult<u32> {
        todo!()
    }

    /// Send OFFER with a set og content keys that this node has content available for.
    /// Return the ACCEPT response.
    async fn send_offer(
        &self,
        _enr: Enr,
        _content_keys: Vec<HistoryContentKey>,
    ) -> RpcResult<AcceptInfo> {
        todo!()
    }

    /// Store content key with a content data to the local database.
    async fn store(
        &self,
        _content_key: HistoryContentKey,
        _content_value: HistoryContentItem,
    ) -> RpcResult<bool> {
        todo!()
    }

    /// Get a content from the local database
    async fn local_content(
        &self,
        _content_key: HistoryContentKey,
    ) -> RpcResult<HistoryContentItem> {
        todo!()
    }
}

impl std::fmt::Debug for HistoryNetworkApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryNetworkApi").finish_non_exhaustive()
    }
}
