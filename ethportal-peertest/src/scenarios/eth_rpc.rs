use alloy_primitives::U256;
use tracing::info;

use ethportal_api::EthApiClient;
use trin_validation::constants::CHAIN_ID;

use crate::Peertest;

pub async fn test_eth_chain_id(peertest: &Peertest) {
    info!("Testing eth_chainId");
    let target = &peertest.bootnode.ipc_client;
    let chain_id = target.chain_id().await.unwrap();
    // For now, the chain ID is always 1 -- portal only supports mainnet Ethereum
    assert_eq!(chain_id, U256::from(CHAIN_ID));
}
