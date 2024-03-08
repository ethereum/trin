use crate::{
    types::{
        content_key::state::StateContentKey,
        enr::Enr,
        portal::{AcceptInfo, DataRadius, FindNodesInfo, PongInfo, TraceGossipInfo},
        state::{ContentInfo, PaginateLocalContentInfo, TraceContentInfo},
    },
    RoutingTableInfo, StateContentValue,
};
use discv5::enr::NodeId;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Portal State JSON-RPC endpoints
#[rpc(client, server, namespace = "portal")]
pub trait StateNetworkApi {
    /// Returns meta information about overlay routing table.
    #[method(name = "stateRoutingTableInfo")]
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo>;

    /// Returns the node data radios
    #[method(name = "stateRadius")]
    async fn radius(&self) -> RpcResult<DataRadius>;

    /// Write an Ethereum Node Record to the overlay routing table.
    #[method(name = "stateAddEnr")]
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool>;

    /// Fetch the latest ENR associated with the given node ID.
    #[method(name = "stateGetEnr")]
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Delete Node ID from the overlay routing table.
    #[method(name = "stateDeleteEnr")]
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool>;

    /// Fetch the ENR representation associated with the given Node ID.
    #[method(name = "stateLookupEnr")]
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Send a PING message to the designated node and wait for a PONG response
    #[method(name = "statePing")]
    async fn ping(&self, enr: Enr) -> RpcResult<PongInfo>;

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    #[method(name = "stateFindNodes")]
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo>;

    /// Lookup a target node within in the network
    #[method(name = "stateRecursiveFindNodes")]
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>>;

    /// Send FINDCONTENT message to get the content with a content key.
    #[method(name = "stateFindContent")]
    async fn find_content(&self, enr: Enr, content_key: StateContentKey) -> RpcResult<ContentInfo>;

    /// Lookup a target content key in the network
    #[method(name = "stateRecursiveFindContent")]
    async fn recursive_find_content(&self, content_key: StateContentKey) -> RpcResult<ContentInfo>;

    /// Lookup a target content key in the network. Return tracing info.
    #[method(name = "stateTraceRecursiveFindContent")]
    async fn trace_recursive_find_content(
        &self,
        content_key: StateContentKey,
    ) -> RpcResult<TraceContentInfo>;

    /// Pagination of local content keys
    #[method(name = "statePaginateLocalContentKeys")]
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo>;

    /// Send the provided content value to interested peers. Clients may choose to send to some or
    /// all peers. Return the number of peers that the content was gossiped to.
    #[method(name = "stateGossip")]
    async fn gossip(
        &self,
        content_key: StateContentKey,
        content_value: StateContentValue,
    ) -> RpcResult<u32>;

    /// Send the provided content value to interested peers. Clients may choose to send to some or
    /// all peers. Return tracing info detailing the gossip propagation.
    #[method(name = "stateTraceGossip")]
    async fn trace_gossip(
        &self,
        content_key: StateContentKey,
        content_value: StateContentValue,
    ) -> RpcResult<TraceGossipInfo>;

    /// Send an OFFER request with given ContentKey, to the designated peer and wait for a response.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    #[method(name = "stateOffer")]
    async fn offer(
        &self,
        enr: Enr,
        content_key: StateContentKey,
        content_value: Option<StateContentValue>,
    ) -> RpcResult<AcceptInfo>;

    /// Store content key with a content data to the local database.
    #[method(name = "stateStore")]
    async fn store(
        &self,
        content_key: StateContentKey,
        content_value: StateContentValue,
    ) -> RpcResult<bool>;

    /// Get a content from the local database
    #[method(name = "stateLocalContent")]
    async fn local_content(&self, content_key: StateContentKey) -> RpcResult<StateContentValue>;
}
