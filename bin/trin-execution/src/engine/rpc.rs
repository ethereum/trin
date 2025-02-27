use alloy::{
    primitives::bytes::Bytes,
    rpc::types::{
        engine::{
            ExecutionPayloadBodiesV1, ExecutionPayloadInputV2, ExecutionPayloadV1,
            ExecutionPayloadV2, ExecutionPayloadV3, ForkchoiceState, ForkchoiceUpdated,
            PayloadAttributes, PayloadId, PayloadStatus, TransitionConfiguration,
        },
        Block, BlockId, Filter, Log, SyncStatus, TransactionRequest,
    },
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use revm_primitives::{Address, B256, U256};

/// Engine Api JSON-RPC endpoints
#[rpc(client, server, namespace = "engine")]
pub trait EngineApi {
    #[method(name = "exchangeCapabilities")]
    async fn exchange_capabilities(
        &self,
        supported_capabilities: Vec<String>,
    ) -> RpcResult<Vec<String>>;

    #[method(name = "exchangeTransitionConfigurationV1")]
    async fn exchange_transition_configuration_v1(
        &self,
        transition_configuration: TransitionConfiguration,
    ) -> RpcResult<TransitionConfiguration>;

    #[method(name = "forkchoiceUpdatedV1")]
    async fn fork_choice_updated_v1(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated>;

    #[method(name = "forkchoiceUpdatedV2")]
    async fn fork_choice_updated_v2(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated>;

    #[method(name = "forkchoiceUpdatedV3")]
    async fn fork_choice_updated_v3(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated>;

    #[method(name = "getPayloadBodiesByHashV1")]
    async fn get_payload_bodies_by_hash_v1(
        &self,
        block_hashes: Vec<B256>,
    ) -> RpcResult<ExecutionPayloadBodiesV1>;

    #[method(name = "getPayloadBodiesByRangeV1")]
    async fn get_payload_bodies_by_range_v1(
        &self,
        start: u64,
        count: u64,
    ) -> RpcResult<ExecutionPayloadBodiesV1>;

    #[method(name = "getPayloadV1")]
    async fn get_payload_v1(&self, payload_id: PayloadId) -> RpcResult<ExecutionPayloadV1>;

    #[method(name = "getPayloadV2")]
    async fn get_payload_v2(&self, payload_id: PayloadId) -> RpcResult<ExecutionPayloadV2>;

    #[method(name = "getPayloadV3")]
    async fn get_payload_v3(&self, payload_id: PayloadId) -> RpcResult<ExecutionPayloadV3>;

    #[method(name = "getPayloadV4")]
    async fn get_payload_v4(&self, payload_id: PayloadId) -> RpcResult<ExecutionPayloadV3>;

    #[method(name = "newPayloadV1")]
    async fn new_payload_v1(&self, payload: ExecutionPayloadV1) -> RpcResult<PayloadStatus>;

    #[method(name = "newPayloadV2")]
    async fn new_payload_v2(&self, payload: ExecutionPayloadInputV2) -> RpcResult<PayloadStatus>;

    #[method(name = "newPayloadV3")]
    async fn new_payload_v3(
        &self,
        payload: ExecutionPayloadV3,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
    ) -> RpcResult<PayloadStatus>;

    #[method(name = "newPayloadV4")]
    async fn new_payload_v4(
        &self,
        payload: ExecutionPayloadV3,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
    ) -> RpcResult<PayloadStatus>;
}

/// A subset of Eth JSON-RPC endpoints under the Engine Api's JWT authentication
#[rpc(client, server, namespace = "eth")]
pub trait EngineEthApi {
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> RpcResult<String>;

    #[method(name = "call")]
    async fn call(&self, transaction: TransactionRequest, block: BlockId) -> RpcResult<Bytes>;

    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U256>;

    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(
        &self,
        block_hash: B256,
        hydrated_transactions: bool,
    ) -> RpcResult<Block>;

    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(
        &self,
        block_number: u64,
        hydrated_transactions: bool,
    ) -> RpcResult<Block>;

    #[method(name = "getCode")]
    async fn get_code(&self, address: Address, block: BlockId) -> RpcResult<Bytes>;

    #[method(name = "getLogs")]
    async fn get_logs(&self, filter: Filter) -> RpcResult<Vec<Log>>;

    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, bytes: Bytes) -> RpcResult<B256>;

    #[method(name = "syncing")]
    async fn syncing(&self) -> RpcResult<SyncStatus>;
}
