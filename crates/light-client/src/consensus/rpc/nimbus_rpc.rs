use std::cmp;

use alloy::primitives::B256;
use anyhow::Result;
use async_trait::async_trait;

use super::ConsensusRpc;
use crate::{
    consensus::{
        constants::MAX_REQUEST_LIGHT_CLIENT_UPDATES,
        types::{
            u64_deserialize, LightClientBootstrapElectra, LightClientFinalityUpdateElectra,
            LightClientOptimisticUpdateElectra, LightClientUpdateElectra,
        },
    },
    errors::RpcError,
};

#[derive(Clone, Debug)]
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

    async fn get_bootstrap(&self, block_root: B256) -> Result<LightClientBootstrapElectra> {
        let req = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/{}",
            self.rpc, block_root
        );

        let client = reqwest::Client::new();
        let result = client
            .get(req)
            .send()
            .await
            .map_err(|err| RpcError::new("bootstrap", err))?
            .json::<BootstrapResponse>()
            .await
            .map_err(|err| RpcError::new("bootstrap", err))?;

        Ok(result.data)
    }

    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<LightClientUpdateElectra>> {
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

    async fn get_finality_update(&self) -> Result<LightClientFinalityUpdateElectra> {
        let req = format!("{}/eth/v1/beacon/light_client/finality_update", self.rpc);
        let res = reqwest::get(req)
            .await
            .map_err(|err| RpcError::new("finality_update", err))?
            .json::<FinalityUpdateResponse>()
            .await
            .map_err(|err| RpcError::new("finality_update", err))?;

        Ok(res.data)
    }

    async fn get_optimistic_update(&self) -> Result<LightClientOptimisticUpdateElectra> {
        let req = format!("{}/eth/v1/beacon/light_client/optimistic_update", self.rpc);
        let res = reqwest::get(req)
            .await
            .map_err(|err| RpcError::new("optimistic_update", err))?
            .json::<OptimisticUpdateResponse>()
            .await
            .map_err(|err| RpcError::new("optimistic_update", err))?;

        Ok(res.data)
    }

    async fn chain_id(&self) -> Result<u64> {
        let req = format!("{}/eth/v1/config/spec", self.rpc);
        let res = reqwest::get(req)
            .await
            .map_err(|err| RpcError::new("spec", err))?
            .json::<SpecResponse>()
            .await
            .map_err(|err| RpcError::new("spec", err))?;

        Ok(res.data.chain_id)
    }

    fn name(&self) -> String {
        "nimbus".to_string()
    }
}

type UpdateResponse = Vec<UpdateData>;

#[derive(serde::Deserialize, Debug)]
struct UpdateData {
    data: LightClientUpdateElectra,
}

#[derive(serde::Deserialize, Debug)]
struct FinalityUpdateResponse {
    data: LightClientFinalityUpdateElectra,
}

#[derive(serde::Deserialize, Debug)]
struct OptimisticUpdateResponse {
    data: LightClientOptimisticUpdateElectra,
}

#[derive(serde::Deserialize, Debug)]
struct BootstrapResponse {
    data: LightClientBootstrapElectra,
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
