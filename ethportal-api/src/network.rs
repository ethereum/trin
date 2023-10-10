use crate::types::enr::Enr;
use crate::types::portal::FindNodesInfo;
use crate::types::portal::{
    AcceptInfo, ContentInfo, DataRadius, PaginateLocalContentInfo, PongInfo, TraceContentInfo,
};
use crate::PossibleBeaconContentValue;
use crate::{PossibleHistoryContentValue, RoutingTableInfo};
use discv5::enr::NodeId;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub enum RecursiveFindContentResult {
    BeaconContent(Box<PossibleBeaconContentValue>),
    HistoryContent(ContentInfo),
}

#[derive(Clone, Serialize, Deserialize)]
pub enum LocalContentResult {
    Beacon(Box<PossibleBeaconContentValue>),
    History(Box<PossibleHistoryContentValue>),
}

#[rpc(client, server, namespace = "portal")]
pub trait NetworkApi<ContentKey, ContentValue> {
    #[method(name = "routingTableInfo")]
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo>;

    #[method(name = "radius")]
    async fn radius(&self) -> RpcResult<DataRadius>;

    #[method(name = "addEnr")]
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool>;

    #[method(name = "getEnr")]
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    #[method(name = "deleteEnr")]
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool>;

    #[method(name = "lookupEnr")]
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    #[method(name = "ping")]
    async fn ping(&self, enr: Enr) -> RpcResult<PongInfo>;

    #[method(name = "findNodes")]
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo>;

    #[method(name = "recursiveFindNodes")]
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>>;

    #[method(name = "findContent")]
    async fn find_content(&self, enr: Enr, content_key: ContentKey) -> RpcResult<ContentInfo>;

    #[method(name = "recursiveFindContent")]
    async fn recursive_find_content(
        &self,
        content_key: ContentKey,
    ) -> RpcResult<RecursiveFindContentResult>;

    #[method(name = "traceRecursiveFindContent")]
    async fn trace_recursive_find_content(
        &self,
        content_key: ContentKey,
    ) -> RpcResult<TraceContentInfo>;

    #[method(name = "paginateLocalContentKeys")]
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo>;

    #[method(name = "gossip")]
    async fn gossip(&self, content_key: ContentKey, content_value: ContentValue) -> RpcResult<u32>;

    #[method(name = "offer")]
    async fn offer(
        &self,
        enr: Enr,
        content_key: ContentKey,
        content_value: Option<ContentValue>,
    ) -> RpcResult<AcceptInfo>;

    #[method(name = "store")]
    async fn store(&self, content_key: ContentKey, content_value: ContentValue) -> RpcResult<bool>;

    #[method(name = "localContent")]
    async fn local_content(&self, content_key: ContentKey) -> RpcResult<LocalContentResult>;
}
