pub mod mock_rpc;
pub mod nimbus_rpc;

use super::types::{Bootstrap, FinalityUpdate, OptimisticUpdate, Update};
use async_trait::async_trait;
use eyre::Result;

// implements https://github.com/ethereum/beacon-APIs/tree/master/apis/beacon/light_client
#[async_trait]
pub trait ConsensusRpc {
    fn new(path: &str) -> Self;
    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap>;
    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>>;
    async fn get_finality_update(&self) -> Result<FinalityUpdate>;
    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate>;
    async fn chain_id(&self) -> Result<u64>;
}
