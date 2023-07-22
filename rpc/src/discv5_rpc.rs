use std::future::Future;
use std::str::FromStr;
use crate::jsonrpsee::core::{async_trait, RpcResult};
use discv5::enr::NodeId;
use ethportal_api::jsonrpsee::core::Error;
use ethportal_api::types::enr::Enr;
use ethportal_api::Discv5ApiServer;
use ethportal_api::{NodeInfo, RoutingTableInfo};
use portalnet::discovery::Discovery;
use std::sync::Arc;
use discv5::RequestError;
use discv5::service::Pong;
use ethportal_api::types::portal::FindNodesInfo;
use portalnet::types::messages::ProtocolId;

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
        Ok(self.discv5.node_info()?)
    }

    /// Update the socket address of the local node record.
    async fn update_node_info(&self, socket_addr: String, is_tcp: bool) -> RpcResult<bool> {
        let socket_addr = std::net::SocketAddr::from_str(&socket_addr[..])
            .map_err(|err| Error::Custom(format!("Unable to decode SocketAddr: {}", err)))?;
        Ok(self.discv5.update_node_info(socket_addr, is_tcp))
    }

    /// Returns meta information about discv5 routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        Ok(self.discv5.routing_table_info())
    }

    /// Write an Ethereum Node Record to the routing table.
    async fn add_enr(&self, _enr: Enr) -> RpcResult<bool> {
        match self.discv5.add_enr(enr) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, _node_id: NodeId) -> RpcResult<Enr> {
        match self.discv5.find_enr(&node_id.into()) {
            None => Err(Error::Custom("ENR not found for get_enr".into())),
            Some(enr) => Ok(enr),
        }
    }

    /// Delete Node ID from the routing table.
    async fn delete_enr(&self, _node_id: NodeId) -> RpcResult<bool> {
        match self.discv5.remove_node(&node_id.into()) {
            true => Ok(true),
            false => Ok(false),
        }
    }

    /// Fetch the ENR representation associated with the given Node ID.
    async fn lookup_enr(&self, _node_id: NodeId) -> RpcResult<Enr> {
        Err(Error::MethodNotFound("lookup_enr".to_owned()))
    }

    /// Send a PING message to the designated node and wait for a PONG response
    async fn send_ping(&self, enr: Enr) -> RpcResult<Pong> {
        match self.discv5.send_ping(enr) {
            Ok(talk_resp) => Ok(talk_resp),
            Err(err) => Err(Error::Custom(format!(
                "Unable to send talk request: {}",
                err
            ))),
        }
    }

    /// Send a FINDNODE request for nodes that fall within the given set of distances, to the designated peer and wait for a response.
    async fn find_node(&self, _enr: Enr, _distances: Vec<u16>) -> RpcResult<FindNodesInfo> {
        Err(Error::MethodNotFound("find_nodes".to_owned()))
    }

    /// Send a TALKREQ request with a payload to a given peer and wait for response.
    async fn talk_req(&self, enr: Enr, protocol: String, request: Vec<u8>) -> RpcResult<Vec<u8>> {
        let protocol_id = ProtocolId::from_str(&protocol[..])
            .map_err(|err| Error::Custom(format!("Unable to decode Protocol ID: {}", err)))?;
        match self.discv5.send_talk_req(enr, protocol_id, request).await {
            Ok(talk_resp) => Ok(talk_resp),
            Err(err) => Err(Error::Custom(format!(
                "Unable to send talk request: {}",
                err
            ))),
        }
    }

    /// Look up ENRs closest to the given target
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>> {
        match self.discv5.recursive_find_nodes(node_id.into()).await {
            Ok(enrs) => Ok(enrs),
            Err(err) => Err(Error::Custom(format!(
                "Unable to send recursive_find_nodes request: {}",
                err
            ))),
        }
    }
}

impl std::fmt::Debug for Discv5Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discv5Api").finish_non_exhaustive()
    }
}
