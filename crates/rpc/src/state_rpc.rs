use discv5::enr::NodeId;
use ethportal_api::{
    types::{
        enr::Enr,
        jsonrpc::{endpoints::StateEndpoint, request::StateJsonRpcRequest},
        ping_extensions::consts::STATE_SUPPORTED_EXTENSIONS,
        portal::{
            AcceptInfo, DataRadius, FindContentInfo, FindNodesInfo, GetContentInfo,
            PaginateLocalContentInfo, PongInfo, PutContentInfo, TraceContentInfo,
            TracePutContentInfo, MAX_CONTENT_KEYS_PER_OFFER,
        },
        portal_wire::OfferTrace,
    },
    ContentValue, RawContentValue, RoutingTableInfo, StateContentKey, StateContentValue,
    StateNetworkApiServer,
};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::{
    errors::RpcServeError,
    fetch::proxy_to_subnet,
    jsonrpsee::core::{async_trait, RpcResult},
    ping_extension::parse_ping_payload,
};

pub struct StateNetworkApi {
    network: mpsc::UnboundedSender<StateJsonRpcRequest>,
}

impl StateNetworkApi {
    pub fn new(network: mpsc::UnboundedSender<StateJsonRpcRequest>) -> Self {
        Self { network }
    }
}

#[async_trait]
impl StateNetworkApiServer for StateNetworkApi {
    /// Returns meta information about overlay routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        let endpoint = StateEndpoint::RoutingTableInfo;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Write an Ethereum Node Record to the overlay routing table.
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool> {
        let endpoint = StateEndpoint::AddEnr(enr);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = StateEndpoint::GetEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Delete Node ID from the overlay routing table.
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool> {
        let endpoint = StateEndpoint::DeleteEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Fetch the ENR representation associated with the given Node ID.
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = StateEndpoint::LookupEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send a PING message to the designated node and wait for a PONG response
    async fn ping(
        &self,
        enr: Enr,
        payload_type: Option<u16>,
        payload: Option<Value>,
    ) -> RpcResult<PongInfo> {
        let (payload_type, payload) =
            parse_ping_payload(STATE_SUPPORTED_EXTENSIONS, payload_type, payload)?;
        let endpoint = StateEndpoint::Ping(enr, payload_type, payload);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo> {
        let endpoint = StateEndpoint::FindNodes(enr, distances);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Lookup a target node within in the network
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>> {
        let endpoint = StateEndpoint::RecursiveFindNodes(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Lookup a target node within in the network
    async fn radius(&self) -> RpcResult<DataRadius> {
        let endpoint = StateEndpoint::DataRadius;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send FINDCONTENT message to get the content with a content key.
    async fn find_content(
        &self,
        enr: Enr,
        content_key: StateContentKey,
    ) -> RpcResult<FindContentInfo> {
        let endpoint = StateEndpoint::FindContent(enr, content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// First checks local storage if content is not found lookup a target content key in the
    /// network
    async fn get_content(&self, content_key: StateContentKey) -> RpcResult<GetContentInfo> {
        let endpoint = StateEndpoint::GetContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// First checks local storage if content is not found lookup a target content key in the
    /// network. Return tracing info.
    async fn trace_get_content(&self, content_key: StateContentKey) -> RpcResult<TraceContentInfo> {
        let endpoint = StateEndpoint::TraceGetContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Pagination of local content keys
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo<StateContentKey>> {
        let endpoint = StateEndpoint::PaginateLocalContentKeys(offset, limit);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return the number of peers that the content was gossiped to.
    async fn put_content(
        &self,
        content_key: StateContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<PutContentInfo> {
        let content_value =
            StateContentValue::decode(&content_key, &content_value).map_err(RpcServeError::from)?;
        let endpoint = StateEndpoint::PutContent(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return tracing info.
    async fn trace_put_content(
        &self,
        content_key: StateContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<TracePutContentInfo> {
        let content_value =
            StateContentValue::decode(&content_key, &content_value).map_err(RpcServeError::from)?;
        let endpoint = StateEndpoint::TracePutContent(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send an OFFER request with given ContentItems, to the designated peer and wait for a
    /// response. Does not store content locally.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    async fn offer(
        &self,
        enr: Enr,
        content_items: Vec<(StateContentKey, RawContentValue)>,
    ) -> RpcResult<AcceptInfo> {
        if !(1..=MAX_CONTENT_KEYS_PER_OFFER).contains(&content_items.len()) {
            return Err(RpcServeError::Message(format!(
                "Invalid amount of content items: {}",
                content_items.len()
            ))
            .into());
        }
        let content_items = content_items
            .into_iter()
            .map(|(key, value)| StateContentValue::decode(&key, &value).map(|value| (key, value)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(RpcServeError::from)?;
        let endpoint = StateEndpoint::Offer(enr, content_items);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send an OFFER request with given ContentItems, to the designated peer.
    /// Does not store the content locally.
    /// Returns trace info from the offer.
    async fn trace_offer(
        &self,
        enr: Enr,
        content_key: StateContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<OfferTrace> {
        let content_value =
            StateContentValue::decode(&content_key, &content_value).map_err(RpcServeError::from)?;
        let endpoint = StateEndpoint::TraceOffer(enr, content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Store content key with a content data to the local database.
    async fn store(
        &self,
        content_key: StateContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<bool> {
        let content_value =
            StateContentValue::decode(&content_key, &content_value).map_err(RpcServeError::from)?;
        let endpoint = StateEndpoint::Store(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Get a content from the local database.
    async fn local_content(&self, content_key: StateContentKey) -> RpcResult<RawContentValue> {
        let endpoint = StateEndpoint::LocalContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }
}

impl std::fmt::Debug for StateNetworkApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateNetworkApi").finish_non_exhaustive()
    }
}
