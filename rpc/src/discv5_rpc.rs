use crate::errors::RpcServeError;

use crate::jsonrpsee::core::{async_trait, RpcResult};
use discv5::enr::NodeId;
use ethportal_api::{types::enr::Enr, Discv5ApiServer, NodeInfo, RoutingTableInfo};
use portalnet::discovery::Discovery;
use std::sync::Arc;

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
        Ok(self
            .discv5
            .node_info()
            .map_err(|err| RpcServeError::Message(err.to_string()))?)
    }

    /// Update the socket address of the local node record.
    async fn update_node_info(
        &self,
        _socket_addr: String,
        _is_tcp: Option<bool>,
    ) -> RpcResult<NodeInfo> {
        Err(RpcServeError::MethodNotFound("update_node_info".to_owned()))?
    }

    /// Returns meta information about discv5 routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        Ok(self.discv5.routing_table_info())
    }

    /// Write an Ethereum Node Record to the routing table.
    async fn add_enr(&self, _enr: Enr) -> RpcResult<bool> {
        Err(RpcServeError::MethodNotFound("add_enr".to_owned()))?
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, _node_id: NodeId) -> RpcResult<Enr> {
        Err(RpcServeError::MethodNotFound("get_enr".to_owned()))?
    }

    /// Delete Node ID from the routing table.
    async fn delete_enr(&self, _node_id: NodeId) -> RpcResult<bool> {
        Err(RpcServeError::MethodNotFound("delete_enr".to_owned()))?
    }

    /// Fetch the ENR representation associated with the given Node ID.
    async fn lookup_enr(&self, _node_id: NodeId) -> RpcResult<Enr> {
        Err(RpcServeError::MethodNotFound("lookup_enr".to_owned()))?
    }
}

impl std::fmt::Debug for Discv5Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discv5Api").finish_non_exhaustive()
    }
}
