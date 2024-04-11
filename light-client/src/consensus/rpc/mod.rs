pub mod mock_rpc;
pub mod nimbus_rpc;
pub mod portal_rpc;

use super::types::{
    LightClientBootstrapDeneb, LightClientFinalityUpdateDeneb, LightClientOptimisticUpdateDeneb,
    LightClientUpdateDeneb,
};
use anyhow::Result;
use async_trait::async_trait;

// implements https://github.com/ethereum/beacon-APIs/tree/master/apis/beacon/light_client
#[async_trait]
pub trait ConsensusRpc: Send + Sync + Clone {
    fn new(path: &str) -> Self;
    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<LightClientBootstrapDeneb>;
    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<LightClientUpdateDeneb>>;
    async fn get_finality_update(&self) -> Result<LightClientFinalityUpdateDeneb>;
    async fn get_optimistic_update(&self) -> Result<LightClientOptimisticUpdateDeneb>;
    async fn chain_id(&self) -> Result<u64>;
    fn name(&self) -> String;
}
