use alloy::primitives::bytes::Bytes;
use discv5::enr::NodeId;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::types::{
    discv5::{NodeInfo, Pong, RoutingTableInfo},
    enr::Enr,
    network::Subnetwork,
};

/// Discv5 JSON-RPC endpoints
#[rpc(client, server, namespace = "discv5")]
pub trait Discv5Api {
    /// Returns ENR and Node ID information of the local discv5 node.
    #[method(name = "nodeInfo")]
    async fn node_info(&self) -> RpcResult<NodeInfo>;

    /// Update the socket address of the local node record.
    #[method(name = "updateNodeInfo")]
    async fn update_node_info(&self, socket_addr: String, is_tcp: bool) -> RpcResult<NodeInfo>;

    /// Returns meta information about discv5 routing table.
    #[method(name = "routingTableInfo")]
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo>;

    /// Write an Ethereum Node Record to the routing table.
    #[method(name = "addEnr")]
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool>;

    /// Fetch the latest ENR associated with the given node ID.
    #[method(name = "getEnr")]
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Delete Node ID from the routing table.
    #[method(name = "deleteEnr")]
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool>;

    /// Fetch the ENR representation associated with the given Node ID.
    #[method(name = "lookupEnr")]
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Look up ENRs closest to the given target
    #[method(name = "recursiveFindNodes")]
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>>;

    /// Send a TALKREQ request with a payload to a given peer and wait for response.
    #[method(name = "talkReq")]
    async fn talk_req(&self, enr: Enr, protocol: Subnetwork, request: Vec<u8>) -> RpcResult<Bytes>;

    /// Send a PING message to the designated node and wait for a PONG response.
    #[method(name = "ping")]
    async fn ping(&self, enr: Enr) -> RpcResult<Pong>;

    /// Send a FINDNODE request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response.
    #[method(name = "findNode")]
    async fn find_node(&self, enr: Enr, distances: Vec<u64>) -> RpcResult<Vec<Enr>>;
}
