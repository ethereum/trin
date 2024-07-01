use crate::{
    types::{
        beacon::{ContentInfo, PaginateLocalContentInfo, TraceContentInfo},
        content_key::beacon::BeaconContentKey,
        enr::Enr,
        portal::{AcceptInfo, DataRadius, FindNodesInfo, PongInfo, TraceGossipInfo},
    },
    BeaconContentValue, RoutingTableInfo,
};
use alloy_primitives::B256;
use discv5::enr::NodeId;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Portal Beacon JSON-RPC endpoints
#[rpc(client, server, namespace = "portal")]
pub trait BeaconNetworkApi {
    /// Returns meta information about overlay routing table.
    #[method(name = "beaconRoutingTableInfo")]
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo>;

    /// Returns the node data radios
    #[method(name = "beaconRadius")]
    async fn radius(&self) -> RpcResult<DataRadius>;

    /// Write an Ethereum Node Record to the overlay routing table.
    #[method(name = "beaconAddEnr")]
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool>;

    /// Fetch the latest ENR associated with the given node ID.
    #[method(name = "beaconGetEnr")]
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Delete Node ID from the overlay routing table.
    #[method(name = "beaconDeleteEnr")]
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool>;

    /// Fetch the ENR representation associated with the given Node ID.
    #[method(name = "beaconLookupEnr")]
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Send a PING message to the designated node and wait for a PONG response
    #[method(name = "beaconPing")]
    async fn ping(&self, enr: Enr) -> RpcResult<PongInfo>;

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    #[method(name = "beaconFindNodes")]
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo>;

    /// Lookup a target node within in the network
    #[method(name = "beaconRecursiveFindNodes")]
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>>;

    /// Get the optimistic root of the optimistic header.
    #[method(name = "beaconOptimisticStateRoot")]
    async fn optimistic_state_root(&self) -> RpcResult<B256>;

    /// Send FINDCONTENT message to get the content with a content key.
    #[method(name = "beaconFindContent")]
    async fn find_content(&self, enr: Enr, content_key: BeaconContentKey)
        -> RpcResult<ContentInfo>;

    /// Lookup a target content key in the network
    #[method(name = "beaconRecursiveFindContent")]
    async fn recursive_find_content(&self, content_key: BeaconContentKey)
        -> RpcResult<ContentInfo>;

    /// Lookup a target content key in the network. Return tracing info.
    #[method(name = "beaconTraceRecursiveFindContent")]
    async fn trace_recursive_find_content(
        &self,
        content_key: BeaconContentKey,
    ) -> RpcResult<TraceContentInfo>;

    /// Pagination of local content keys
    #[method(name = "beaconPaginateLocalContentKeys")]
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo>;

    /// Send the provided content value to interested peers. Clients may choose to send to some or
    /// all peers. Return the number of peers that the content was gossiped to.
    #[method(name = "beaconGossip")]
    async fn gossip(
        &self,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
    ) -> RpcResult<u32>;

    /// Send the provided content value to interested peers. Clients may choose to send to some or
    /// all peers. Return tracing info detailing the gossip propagation.
    #[method(name = "beaconTraceGossip")]
    async fn trace_gossip(
        &self,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
    ) -> RpcResult<TraceGossipInfo>;

    /// Send an OFFER request with given ContentKey, to the designated peer and wait for a response.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    #[method(name = "beaconOffer")]
    async fn offer(
        &self,
        enr: Enr,
        content_key: BeaconContentKey,
        content_value: Option<BeaconContentValue>,
    ) -> RpcResult<AcceptInfo>;

    /// Store content key with a content data to the local database.
    #[method(name = "beaconStore")]
    async fn store(
        &self,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
    ) -> RpcResult<bool>;

    /// Get a content from the local database
    #[method(name = "beaconLocalContent")]
    async fn local_content(&self, content_key: BeaconContentKey) -> RpcResult<BeaconContentValue>;
}
