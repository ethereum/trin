use crate::{
    types::{
        content_key::history::HistoryContentKey,
        enr::Enr,
        history::{ContentInfo, PaginateLocalContentInfo, TraceContentInfo},
        portal::{AcceptInfo, DataRadius, FindNodesInfo, PongInfo, TraceGossipInfo},
    },
    HistoryContentValue, RoutingTableInfo,
};
use discv5::enr::NodeId;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Portal History JSON-RPC endpoints
#[rpc(client, server, namespace = "portal")]
pub trait HistoryNetworkApi {
    /// Returns meta information about overlay routing table.
    #[method(name = "historyRoutingTableInfo")]
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo>;

    /// Returns the node data radios
    #[method(name = "historyRadius")]
    async fn radius(&self) -> RpcResult<DataRadius>;

    /// Write an Ethereum Node Record to the overlay routing table.
    #[method(name = "historyAddEnr")]
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool>;

    /// Fetch the latest ENR associated with the given node ID.
    #[method(name = "historyGetEnr")]
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Delete Node ID from the overlay routing table.
    #[method(name = "historyDeleteEnr")]
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool>;

    /// Fetch the ENR representation associated with the given Node ID.
    #[method(name = "historyLookupEnr")]
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Send a PING message to the designated node and wait for a PONG response
    #[method(name = "historyPing")]
    async fn ping(&self, enr: Enr) -> RpcResult<PongInfo>;

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    #[method(name = "historyFindNodes")]
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo>;

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
    ) -> RpcResult<ContentInfo>;

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

    /// Send the provided content value to interested peers. Clients may choose to send to some or
    /// all peers. Return the number of peers that the content was gossiped to.
    #[method(name = "historyGossip")]
    async fn gossip(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<u32>;

    /// Send the provided content value to interested peers. Clients may choose to send to some or
    /// all peers. Return tracing info detailing the gossip propagation.
    #[method(name = "historyTraceGossip")]
    async fn trace_gossip(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<TraceGossipInfo>;

    /// Send an OFFER request with given ContentKey, to the designated peer and wait for a response.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    #[method(name = "historyOffer")]
    async fn offer(
        &self,
        enr: Enr,
        content_key: HistoryContentKey,
        content_value: Option<HistoryContentValue>,
    ) -> RpcResult<AcceptInfo>;

    /// Store content key with a content data to the local database.
    #[method(name = "historyStore")]
    async fn store(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> RpcResult<bool>;

    /// Get a content value from the local database
    #[method(name = "historyLocalContent")]
    async fn local_content(&self, content_key: HistoryContentKey)
        -> RpcResult<HistoryContentValue>;
}
