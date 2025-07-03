use discv5::enr::NodeId;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde_json::Value;

use crate::{
    types::{
        enr::Enr,
        ping_extensions::extension_types::PingExtensionType,
        portal::{
            AcceptInfo, DataRadius, FindContentInfo, FindNodesInfo, GetContentInfo,
            PaginateLocalContentInfo, PongInfo, PutContentInfo, TraceContentInfo,
        },
        portal_wire::OfferTrace,
    },
    LegacyHistoryContentKey, RawContentValue, RoutingTableInfo,
};

/// Portal History JSON-RPC endpoints
#[rpc(client, server, namespace = "portal")]
pub trait LegacyHistoryNetworkApi {
    /// Returns meta information about overlay routing table.
    #[method(name = "legacyHistoryRoutingTableInfo")]
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo>;

    /// Returns the node data radios
    #[method(name = "legacyHistoryRadius")]
    async fn radius(&self) -> RpcResult<DataRadius>;

    /// Write an Ethereum Node Record to the overlay routing table.
    #[method(name = "legacyHistoryAddEnr")]
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool>;

    /// Fetch the latest ENR associated with the given node ID.
    #[method(name = "legacyHistoryGetEnr")]
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Delete Node ID from the overlay routing table.
    #[method(name = "legacyHistoryDeleteEnr")]
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool>;

    /// Fetch the ENR representation associated with the given Node ID.
    #[method(name = "legacyHistoryLookupEnr")]
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr>;

    /// Send a PING message to the designated node and wait for a PONG response
    #[method(name = "legacyHistoryPing")]
    async fn ping(
        &self,
        enr: Enr,
        payload_type: Option<PingExtensionType>,
        payload: Option<Value>,
    ) -> RpcResult<PongInfo>;

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    #[method(name = "legacyHistoryFindNodes")]
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo>;

    /// Lookup a target node within in the network
    #[method(name = "legacyHistoryRecursiveFindNodes")]
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>>;

    /// Send FINDCONTENT message to get the content with a content key.
    #[method(name = "legacyHistoryFindContent")]
    async fn find_content(
        &self,
        enr: Enr,
        content_key: LegacyHistoryContentKey,
    ) -> RpcResult<FindContentInfo>;

    /// First checks local storage if content is not found lookup a target content key in the
    /// network
    #[method(name = "legacyHistoryGetContent")]
    async fn get_content(&self, content_key: LegacyHistoryContentKey) -> RpcResult<GetContentInfo>;

    /// First checks local storage if content is not found lookup a target content key in the
    /// network. Return tracing info.
    #[method(name = "legacyHistoryTraceGetContent")]
    async fn trace_get_content(
        &self,
        content_key: LegacyHistoryContentKey,
    ) -> RpcResult<TraceContentInfo>;

    /// Pagination of local content keys
    #[method(name = "legacyHistoryPaginateLocalContentKeys")]
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo<LegacyHistoryContentKey>>;

    /// Send the provided content value to interested peers. Clients may choose to send to some or
    /// all peers. Return the number of peers that the content was gossiped to.
    #[method(name = "legacyHistoryPutContent")]
    async fn put_content(
        &self,
        content_key: LegacyHistoryContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<PutContentInfo>;

    /// Send an OFFER request with given ContentItems, to the designated peer and wait for a
    /// response. Does not store the content locally.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    #[method(name = "legacyHistoryOffer")]
    async fn offer(
        &self,
        enr: Enr,
        content_items: Vec<(LegacyHistoryContentKey, RawContentValue)>,
    ) -> RpcResult<AcceptInfo>;

    /// Send an OFFER request with given ContentItems, to the designated peer.
    /// Does not store the content locally.
    /// Returns trace info for the offer.
    #[method(name = "legacyHistoryTraceOffer")]
    async fn trace_offer(
        &self,
        enr: Enr,
        content_key: LegacyHistoryContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<OfferTrace>;

    /// Store content key with a content data to the local database.
    #[method(name = "legacyHistoryStore")]
    async fn store(
        &self,
        content_key: LegacyHistoryContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<bool>;

    /// Get a content value from the local database
    #[method(name = "legacyHistoryLocalContent")]
    async fn local_content(
        &self,
        content_key: LegacyHistoryContentKey,
    ) -> RpcResult<RawContentValue>;
}
