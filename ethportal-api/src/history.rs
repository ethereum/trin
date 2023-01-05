use crate::types::{
    content_item::HistoryContentItem,
    content_key::HistoryContentKey,
    discv5::{Enr, NodeId, RoutingTableInfo},
    portal::{
        AcceptInfo, ContentInfo, DataRadius, PaginateLocalContentInfo, PongInfo, TraceContentInfo,
    },
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Portal History JSON-RPC endpoints
#[cfg(any(feature = "client", feature = "server"))]
#[cfg_attr(feature = "client", rpc(client, namespace = "portal"))]
#[cfg_attr(feature = "server", rpc(server, namespace = "portal"))]
pub trait HistoryNetworkApi {
    /// Returns meta information about overlay routing table.
    #[method(name = "historyRoutingTableInfo")]
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo>;

    /// Write an Ethereum Node Record to the overlay routing table.
    #[method(name = "historyAddEnr")]
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool>;

    /// Fetch the latest ENR associated with the given node ID.
    #[method(name = "historyGetEnr")]
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Delete Node ID from the overlay routing table.
    #[method(name = "historyDeleteEnr")]
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool>;

    /// Fetch the ENR representation associated with the given Node ID and optional sequence number.
    #[method(name = "historyLookupEnr")]
    async fn lookup_enr(&self, node_id: NodeId, enr_seq: Option<u32>) -> RpcResult<Enr>;

    /// Send a PING message to the designated node and wait for a PONG response
    #[method(name = "historyPing")]
    async fn ping(&self, enr: Enr, data_radius: Option<DataRadius>) -> RpcResult<PongInfo>;

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the designated
    /// peer and wait for a response
    #[method(name = "historyFindNodes")]
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<Vec<Enr>>;

    /// Lookup a target node within in the network
    #[method(name = "historyRecursiveFindNodes")]
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>>;

    /// Send FINDCONTENT message to get the content with a content key.
    #[method(name = "historyFindContent")]
    async fn find_content(
        &self,
        enr: Enr,
        content_key: HistoryContentKey,
    ) -> RpcResult<ContentInfo>;

    /// Lookup a target content key in the network
    #[method(name = "historyRecursiveFindContent")]
    async fn recursive_find_content(
        &self,
        content_key: HistoryContentKey,
    ) -> RpcResult<HistoryContentItem>;

    /// Lookup a target content key in the network. Return tracing info.
    #[method(name = "historyTraceRecursiveFindContent")]
    async fn trace_recursive_find_content(
        &self,
        content_key: HistoryContentKey,
    ) -> RpcResult<TraceContentInfo>;

    /// Pagination of local content keys
    #[method(name = "historyPaginateLocalContentKeys")]
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo>;

    /// Send the provided content item to interested peers. Clients may choose to send to some or all peers.
    /// Return the number of peers that the content was gossiped to.
    #[method(name = "historyOffer")]
    async fn offer(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentItem,
    ) -> RpcResult<u32>;

    /// Send OFFER with a set og content keys that this node has content available for.
    /// Return the ACCEPT response.
    #[method(name = "historySendOffer")]
    async fn send_offer(
        &self,
        enr: Enr,
        content_keys: Vec<HistoryContentKey>,
    ) -> RpcResult<AcceptInfo>;

    /// Store content key with a content data to the local database.
    #[method(name = "historyStore")]
    async fn store(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentItem,
    ) -> RpcResult<bool>;

    /// Get a content from the local database
    #[method(name = "historyLocalContent")]
    async fn local_content(&self, content_key: HistoryContentKey) -> RpcResult<HistoryContentItem>;
}
