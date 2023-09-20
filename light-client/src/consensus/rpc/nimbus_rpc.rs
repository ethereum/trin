use crate::consensus::types::u64_deserialize;
use async_trait::async_trait;
use eyre::Result;
use std::cmp;

use super::ConsensusRpc;
use crate::consensus::constants::MAX_REQUEST_LIGHT_CLIENT_UPDATES;
use crate::consensus::types::{
    LightClientBootstrapCapella, LightClientFinalityUpdateCapella,
    LightClientOptimisticUpdateCapella, LightClientUpdateCapella,
};
use crate::errors::RpcError;

#[derive(Debug)]
pub struct NimbusRpc {
    rpc: String,
}

#[async_trait]
impl ConsensusRpc for NimbusRpc {
    fn new(rpc: &str) -> Self {
        NimbusRpc {
            rpc: rpc.to_string(),
        }
    }

    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<LightClientBootstrapCapella> {
        let root_hex = hex::encode(block_root);
        let req = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/0x{}",
            self.rpc, root_hex
        );

        let client = reqwest::Client::new();
        let res = client
            .get(req)
            .send()
            .await
            .map_err(|e| RpcError::new("bootstrap", e))?
            .json::<BootstrapResponse>()
            .await
            .map_err(|e| RpcError::new("bootstrap", e))?;

        Ok(res.data)
    }

    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<LightClientUpdateCapella>> {
        let count = cmp::min(count, MAX_REQUEST_LIGHT_CLIENT_UPDATES);
        let req = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.rpc, period, count
        );

        let client = reqwest::Client::new();
        let res = client
            .get(req)
            .send()
            .await
            .map_err(|e| RpcError::new("updates", e))?
            .json::<UpdateResponse>()
            .await
            .map_err(|e| RpcError::new("updates", e))?;

        Ok(res.iter().map(|d| d.data.clone()).collect())
    }

    async fn get_finality_update(&self) -> Result<LightClientFinalityUpdateCapella> {
        let req = format!("{}/eth/v1/beacon/light_client/finality_update", self.rpc);
        let res = reqwest::get(req)
            .await
            .map_err(|e| RpcError::new("finality_update", e))?
            .json::<FinalityUpdateResponse>()
            .await
            .map_err(|e| RpcError::new("finality_update", e))?;

        Ok(res.data)
    }

    async fn get_optimistic_update(&self) -> Result<LightClientOptimisticUpdateCapella> {
        let req = format!("{}/eth/v1/beacon/light_client/optimistic_update", self.rpc);
        let res = reqwest::get(req)
            .await
            .map_err(|e| RpcError::new("optimistic_update", e))?
            .json::<OptimisticUpdateResponse>()
            .await
            .map_err(|e| RpcError::new("optimistic_update", e))?;

        Ok(res.data)
    }

    async fn chain_id(&self) -> Result<u64> {
        let req = format!("{}/eth/v1/config/spec", self.rpc);
        let res = reqwest::get(req)
            .await
            .map_err(|e| RpcError::new("spec", e))?
            .json::<SpecResponse>()
            .await
            .map_err(|e| RpcError::new("spec", e))?;

        Ok(res.data.chain_id)
    }
}

type UpdateResponse = Vec<UpdateData>;

#[derive(serde::Deserialize, Debug)]
struct UpdateData {
    data: LightClientUpdateCapella,
}

#[derive(serde::Deserialize, Debug)]
struct FinalityUpdateResponse {
    data: LightClientFinalityUpdateCapella,
}

#[derive(serde::Deserialize, Debug)]
struct OptimisticUpdateResponse {
    data: LightClientOptimisticUpdateCapella,
}

#[derive(serde::Deserialize, Debug)]
struct BootstrapResponse {
    data: LightClientBootstrapCapella,
}

#[derive(serde::Deserialize, Debug)]
struct SpecResponse {
    data: Spec,
}

#[derive(serde::Deserialize, Debug)]
struct Spec {
    #[serde(rename = "DEPOSIT_NETWORK_ID", deserialize_with = "u64_deserialize")]
    chain_id: u64,
}
