use std::{net::SocketAddr, sync::Arc};

use alloy::primitives::bytes::Bytes;
use discv5::enr::NodeId;
use ethportal_api::{
    types::{discv5::Pong, enr::Enr, network::Subnetwork},
    Discv5ApiServer, NodeInfo, RoutingTableInfo,
};
use portalnet::discovery::Discovery;

use crate::{
    errors::RpcServeError,
    jsonrpsee::core::{async_trait, RpcResult},
};

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
    async fn update_node_info(&self, socket_addr: String, is_tcp: bool) -> RpcResult<NodeInfo> {
        let socket_addr = socket_addr
            .parse::<SocketAddr>()
            .map_err(|err| RpcServeError::Message(format!("Unable to decode SocketAddr: {err}")))?;
        match self.discv5.update_local_enr_socket(socket_addr, is_tcp) {
            true => self.node_info().await,
            false => Err(RpcServeError::Message("Unable to update node info".to_string()).into()),
        }
    }

    /// Returns meta information about discv5 routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        Ok(self.discv5.routing_table_info())
    }

    /// Write an Ethereum Node Record to the routing table.
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool> {
        match self.discv5.add_enr(enr) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        Ok(self
            .discv5
            .find_enr(&node_id)
            .ok_or_else(|| RpcServeError::Message("ENR not found".to_string()))?)
    }

    /// Delete Node ID from the routing table.
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool> {
        Ok(self.discv5.remove_node(&node_id))
    }

    /// Fetch the ENR representation associated with the given Node ID.
    async fn lookup_enr(&self, _node_id: NodeId) -> RpcResult<Enr> {
        Err(RpcServeError::MethodNotFound("lookup_enr".to_owned()))?
    }

    /// Look up ENRs closest to the given target
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>> {
        match self.discv5.recursive_find_nodes(node_id).await {
            Ok(enrs) => Ok(enrs),
            Err(err) => Err(RpcServeError::Message(format!(
                "Unable to send recursive_find_nodes request: {err}"
            ))
            .into()),
        }
    }

    /// Send a TALKREQ request with a payload to a given peer and wait for response.
    async fn talk_req(&self, enr: Enr, protocol: String, request: Vec<u8>) -> RpcResult<Bytes> {
        let subnetwork = protocol
            .parse::<Subnetwork>()
            .map_err(|err| RpcServeError::Message(format!("Unable to parse Subnetwork: {err}")))?;
        self.discv5
            .send_talk_req(enr, subnetwork, request)
            .await
            .map_err(|err| RpcServeError::Message(err.to_string()).into())
    }

    /// Send a PING message to the designated node and wait for a PONG response.
    async fn ping(&self, enr: Enr) -> RpcResult<Pong> {
        let pong = self
            .discv5
            .send_ping(enr)
            .await
            .map_err(|err| RpcServeError::Message(err.to_string()))?;
        Ok(pong.into())
    }
}

impl std::fmt::Debug for Discv5Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discv5Api").finish_non_exhaustive()
    }
}
