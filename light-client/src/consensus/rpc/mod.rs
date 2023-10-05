pub mod mock_rpc;
pub mod nimbus_rpc;

use async_trait::async_trait;
use eyre::Result;

use super::types::{
    LightClientBootstrapCapella, LightClientFinalityUpdateCapella,
    LightClientOptimisticUpdateCapella, LightClientUpdateCapella,
};

// implements https://github.com/ethereum/beacon-APIs/tree/master/apis/beacon/light_client
#[async_trait]
pub trait ConsensusRpc {
    fn new(path: &str) -> Self;
    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<LightClientBootstrapCapella>;
    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<LightClientUpdateCapella>>;
    async fn get_finality_update(&self) -> Result<LightClientFinalityUpdateCapella>;
    async fn get_optimistic_update(&self) -> Result<LightClientOptimisticUpdateCapella>;
    async fn chain_id(&self) -> Result<u64>;
}
