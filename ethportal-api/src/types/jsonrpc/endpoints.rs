use crate::types::content_key::{BeaconContentKey, HistoryContentKey};
use crate::types::content_value::{BeaconContentValue, HistoryContentValue};
use crate::types::enr::Enr;
use crate::types::node_id::NodeId;

/// Discv5 JSON-RPC endpoints. Start with "discv5_" prefix
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Discv5Endpoint {
    NodeInfo,
    RoutingTableInfo,
}

/// State network JSON-RPC endpoints. Start with "portal_state" prefix
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StateEndpoint {
    DataRadius,
    FindContent,
    FindNodes,
    LocalContent,
    SendOffer,
    Store,
    Ping,
    RecursiveFindContent,
    RoutingTableInfo,
}

/// History network JSON-RPC endpoints. Start with "portal_history" prefix
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HistoryEndpoint {
    /// params: [enr]
    AddEnr(Enr),
    /// params: None
    DataRadius,
    /// params: [node_id]
    DeleteEnr(NodeId),
    /// params: [enr, content_key]
    FindContent(Enr, HistoryContentKey),
    /// params: [enr, distances]
    FindNodes(Enr, Vec<u16>),
    /// params: [node_id]
    GetEnr(NodeId),
    /// params: content_key
    LocalContent(HistoryContentKey),
    /// params: [node_id]
    LookupEnr(NodeId),
    /// params: [content_key, content_value]
    Gossip(HistoryContentKey, HistoryContentValue),
    /// params: [enr, content_key]
    Offer(Enr, HistoryContentKey, Option<HistoryContentValue>),
    /// params: [enr]
    Ping(Enr),
    /// params: content_key
    RecursiveFindContent(HistoryContentKey),
    /// params: content_key
    TraceRecursiveFindContent(HistoryContentKey),
    /// params: [content_key, content_value]
    Store(HistoryContentKey, HistoryContentValue),
    /// params: None
    RoutingTableInfo,
    // This endpoint is not History network specific
    /// params: [offset, limit]
    PaginateLocalContentKeys(u64, u64),
    /// params: [node_id]
    RecursiveFindNodes(NodeId),
}

/// Beacon network JSON-RPC endpoints. Start with "portal_beacon" prefix
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BeaconEndpoint {
    /// params: enr
    AddEnr(Enr),
    /// params: None
    DataRadius,
    /// params: node_id
    DeleteEnr(NodeId),
    /// params: [enr, content_key]
    FindContent(Enr, BeaconContentKey),
    /// params: [enr, distances]
    FindNodes(Enr, Vec<u16>),
    /// params: node_id
    GetEnr(NodeId),
    /// params: content_key
    LocalContent(BeaconContentKey),
    /// params: node_id
    LookupEnr(NodeId),
    /// params: [content_key, content_value]
    Gossip(BeaconContentKey, BeaconContentValue),
    /// params: [enr, content_key]
    Offer(Enr, BeaconContentKey, Option<BeaconContentValue>),
    /// params: enr
    Ping(Enr),
    /// params: content_key
    RecursiveFindContent(BeaconContentKey),
    /// params: content_key
    TraceRecursiveFindContent(BeaconContentKey),
    /// params: [content_key, content_value]
    Store(BeaconContentKey, BeaconContentValue),
    /// params: None
    RoutingTableInfo,
    /// params: [offset, limit]
    PaginateLocalContentKeys(u64, u64),
    /// params: [node_id]
    RecursiveFindNodes(NodeId),
}

/// Global portal network endpoints supported by trin, Discv5, Ethereum and all overlay network endpoints supported by portal network requests
// When adding a json-rpc endpoint, make sure to...
// - Update `docs/jsonrpc_api.md`
// - Add tests to ethportal-peertest
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TrinEndpoint {
    Discv5Endpoint(Discv5Endpoint),
    HistoryEndpoint(HistoryEndpoint),
    StateEndpoint(StateEndpoint),
    BeaconEndpoint(BeaconEndpoint),
}
