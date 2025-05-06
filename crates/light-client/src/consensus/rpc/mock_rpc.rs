use std::{fs::read_to_string, path::PathBuf};

use alloy::primitives::B256;
use anyhow::Result;
use async_trait::async_trait;

use super::ConsensusRpc;
use crate::consensus::types::{
    LightClientBootstrapElectra, LightClientFinalityUpdateElectra,
    LightClientOptimisticUpdateElectra, LightClientUpdateElectra,
};

#[derive(Clone, Debug)]
pub struct MockRpc {
    testdata: PathBuf,
}

#[async_trait]
impl ConsensusRpc for MockRpc {
    fn new(path: &str) -> Self {
        MockRpc {
            testdata: PathBuf::from(path),
        }
    }

    async fn get_bootstrap(&self, _block_root: B256) -> Result<LightClientBootstrapElectra> {
        let bootstrap = read_to_string(self.testdata.join("bootstrap.json"))?;
        Ok(serde_json::from_str(&bootstrap)?)
    }

    async fn get_updates(&self, _period: u64, _count: u8) -> Result<Vec<LightClientUpdateElectra>> {
        let updates = read_to_string(self.testdata.join("updates.json"))?;
        Ok(serde_json::from_str(&updates)?)
    }

    async fn get_finality_update(&self) -> Result<LightClientFinalityUpdateElectra> {
        let finality = read_to_string(self.testdata.join("finality.json"))?;
        Ok(serde_json::from_str(&finality)?)
    }

    async fn get_optimistic_update(&self) -> Result<LightClientOptimisticUpdateElectra> {
        let optimistic = read_to_string(self.testdata.join("optimistic.json"))?;
        Ok(serde_json::from_str(&optimistic)?)
    }

    async fn chain_id(&self) -> Result<u64> {
        anyhow::bail!("not implemented")
    }

    fn name(&self) -> String {
        "mock".to_string()
    }
}
