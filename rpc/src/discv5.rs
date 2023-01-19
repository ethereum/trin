use crate::jsonrpsee::core::{async_trait, RpcResult};
use ethportal_api::types::discv5::{Enr, NodeId, NodeInfo, RoutingTableInfo};
use ethportal_api::Discv5ApiServer;
use std::sync::Arc;
use trin_core::portalnet::discovery::Discovery;

pub struct Discv5Api {
    discv5: Arc<Discovery>,
}

impl Discv5Api {
    pub fn new(discv5: Arc<Discovery>) -> Self {
        Self { discv5 }
    }
}

#[async_trait]
impl Discv5ApiServer for Discv5Api {
    /// Returns ENR and Node ID information of the local discv5 node.
    async fn node_info(&self) -> RpcResult<NodeInfo> {
        todo!()
    }

    /// Update the socket address of the local node record.
    async fn update_node_info(
        &self,
        _socket_addr: String,
        _is_tcp: Option<bool>,
    ) -> RpcResult<NodeInfo> {
        todo!()
    }

    /// Returns meta information about discv5 routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        todo!()
    }

    /// Write an Ethereum Node Record to the routing table.
    async fn add_enr(&self, _enr: Enr) -> RpcResult<bool> {
        todo!()
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, _node_id: NodeId) -> RpcResult<Enr> {
        todo!()
    }

    /// Delete Node ID from the routing table.
    async fn delete_enr(&self, _node_id: NodeId) -> RpcResult<bool> {
        todo!()
    }

    /// Fetch the ENR representation associated with the given Node ID and optional sequence number.
    async fn lookup_enr(&self, _node_id: NodeId, _enr_seq: Option<u32>) -> RpcResult<Enr> {
        todo!()
    }
}

impl std::fmt::Debug for Discv5Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discv5Api").finish_non_exhaustive()
    }
}
