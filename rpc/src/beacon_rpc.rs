use alloy::primitives::B256;
use discv5::enr::NodeId;
use ethportal_api::{
    consensus::header::BeaconBlockHeader,
    light_client::store::LightClientStore,
    types::{
        consensus::light_client::{
            finality_update::LightClientFinalityUpdate,
            optimistic_update::LightClientOptimisticUpdate,
        },
        enr::Enr,
        jsonrpc::{endpoints::BeaconEndpoint, request::BeaconJsonRpcRequest},
        portal::{
            AcceptInfo, DataRadius, FindContentInfo, FindNodesInfo, GetContentInfo,
            PaginateLocalContentInfo, PongInfo, TraceContentInfo, TraceGossipInfo,
            MAX_CONTENT_KEYS_PER_OFFER,
        },
        portal_wire::OfferTrace,
    },
    BeaconContentKey, BeaconContentValue, BeaconNetworkApiServer, ContentValue, RawContentValue,
    RoutingTableInfo,
};
use tokio::sync::mpsc;

use crate::{
    errors::RpcServeError,
    fetch::proxy_to_subnet,
    jsonrpsee::core::{async_trait, RpcResult},
};

pub struct BeaconNetworkApi {
    network: mpsc::UnboundedSender<BeaconJsonRpcRequest>,
}

impl BeaconNetworkApi {
    #[allow(dead_code)]
    pub fn new(network: mpsc::UnboundedSender<BeaconJsonRpcRequest>) -> Self {
        Self { network }
    }
}

#[async_trait]
impl BeaconNetworkApiServer for BeaconNetworkApi {
    /// Returns meta information about overlay routing table.
    async fn routing_table_info(&self) -> RpcResult<RoutingTableInfo> {
        let endpoint = BeaconEndpoint::RoutingTableInfo;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Write an Ethereum Node Record to the overlay routing table.
    async fn add_enr(&self, enr: Enr) -> RpcResult<bool> {
        let endpoint = BeaconEndpoint::AddEnr(enr);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Fetch the latest ENR associated with the given node ID.
    async fn get_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = BeaconEndpoint::GetEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Delete Node ID from the overlay routing table.
    async fn delete_enr(&self, node_id: NodeId) -> RpcResult<bool> {
        let endpoint = BeaconEndpoint::DeleteEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Returns the local store of the light client.
    async fn light_client_store(&self) -> RpcResult<LightClientStore> {
        let endpoint = BeaconEndpoint::LightClientStore;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Fetch the ENR representation associated with the given Node ID.
    async fn lookup_enr(&self, node_id: NodeId) -> RpcResult<Enr> {
        let endpoint = BeaconEndpoint::LookupEnr(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send a PING message to the designated node and wait for a PONG response
    async fn ping(&self, enr: Enr) -> RpcResult<PongInfo> {
        let endpoint = BeaconEndpoint::Ping(enr);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send a FINDNODES request for nodes that fall within the given set of distances, to the
    /// designated peer and wait for a response
    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> RpcResult<FindNodesInfo> {
        let endpoint = BeaconEndpoint::FindNodes(enr, distances);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Lookup a target node within in the network
    async fn recursive_find_nodes(&self, node_id: NodeId) -> RpcResult<Vec<Enr>> {
        let endpoint = BeaconEndpoint::RecursiveFindNodes(node_id);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Lookup a target node within in the network
    async fn radius(&self) -> RpcResult<DataRadius> {
        let endpoint = BeaconEndpoint::DataRadius;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Get the optimistic state root of the optimistic beacon header.
    async fn optimistic_state_root(&self) -> RpcResult<B256> {
        let endpoint = BeaconEndpoint::OptimisticStateRoot;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Get the finalized state root of the finalized beacon header.
    async fn finalized_state_root(&self) -> RpcResult<B256> {
        let endpoint = BeaconEndpoint::FinalizedStateRoot;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Get the finalized beacon header.
    async fn finalized_header(&self) -> RpcResult<BeaconBlockHeader> {
        let endpoint = BeaconEndpoint::FinalizedHeader;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Get the latest optimistic update.
    async fn optimistic_update(&self) -> RpcResult<LightClientOptimisticUpdate> {
        let endpoint = BeaconEndpoint::OptimisticUpdate;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Get the latest finality update.
    async fn finality_update(&self) -> RpcResult<LightClientFinalityUpdate> {
        let endpoint = BeaconEndpoint::FinalityUpdate;
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send FINDCONTENT message to get the content with a content key.
    async fn find_content(
        &self,
        enr: Enr,
        content_key: BeaconContentKey,
    ) -> RpcResult<FindContentInfo> {
        let endpoint = BeaconEndpoint::FindContent(enr, content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// First checks local storage if content is not found lookup a target content key in the
    /// network
    async fn get_content(&self, content_key: BeaconContentKey) -> RpcResult<GetContentInfo> {
        let endpoint = BeaconEndpoint::GetContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// First checks local storage if content is not found lookup a target content key in the
    /// network. Return tracing info.
    async fn trace_get_content(
        &self,
        content_key: BeaconContentKey,
    ) -> RpcResult<TraceContentInfo> {
        let endpoint = BeaconEndpoint::TraceGetContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Pagination of local content keys
    async fn paginate_local_content_keys(
        &self,
        offset: u64,
        limit: u64,
    ) -> RpcResult<PaginateLocalContentInfo<BeaconContentKey>> {
        let endpoint = BeaconEndpoint::PaginateLocalContentKeys(offset, limit);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return the number of peers that the content was gossiped to.
    async fn gossip(
        &self,
        content_key: BeaconContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<u32> {
        let content_value = BeaconContentValue::decode(&content_key, &content_value)
            .map_err(RpcServeError::from)?;
        let endpoint = BeaconEndpoint::Gossip(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send the provided content to interested peers. Clients may choose to send to some or all
    /// peers. Return tracing info.
    async fn trace_gossip(
        &self,
        content_key: BeaconContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<TraceGossipInfo> {
        let content_value = BeaconContentValue::decode(&content_key, &content_value)
            .map_err(RpcServeError::from)?;
        let endpoint = BeaconEndpoint::TraceGossip(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send an OFFER request with given ContentItems, to the designated peer and wait for a
    /// response. Does not store content locally.
    /// Returns the content keys bitlist upon successful content transmission or empty bitlist
    /// receive.
    async fn offer(
        &self,
        enr: Enr,
        content_items: Vec<(BeaconContentKey, RawContentValue)>,
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
            .map(|(key, value)| {
                BeaconContentValue::decode(&key, &value)
                    .map(|value| (key, value))
                    .map_err(RpcServeError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let endpoint = BeaconEndpoint::Offer(enr, content_items);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Send an OFFER request with given ContentItems, to the designated peer.
    /// Does not store the content locally.
    /// Returns trace info from the offer.
    async fn trace_offer(
        &self,
        enr: Enr,
        content_key: BeaconContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<OfferTrace> {
        let content_value = BeaconContentValue::decode(&content_key, &content_value)
            .map_err(RpcServeError::from)?;
        let endpoint = BeaconEndpoint::TraceOffer(enr, content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Store content key with a content data to the local database.
    async fn store(
        &self,
        content_key: BeaconContentKey,
        content_value: RawContentValue,
    ) -> RpcResult<bool> {
        let content_value = BeaconContentValue::decode(&content_key, &content_value)
            .map_err(RpcServeError::from)?;
        let endpoint = BeaconEndpoint::Store(content_key, content_value);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }

    /// Get a content from the local database.
    async fn local_content(&self, content_key: BeaconContentKey) -> RpcResult<RawContentValue> {
        let endpoint = BeaconEndpoint::LocalContent(content_key);
        Ok(proxy_to_subnet(&self.network, endpoint).await?)
    }
}

impl std::fmt::Debug for BeaconNetworkApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconNetworkApi").finish_non_exhaustive()
    }
}
