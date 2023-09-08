use std::sync::Arc;
use std::time::Duration;

use eyre::Result;

use crate::config::client_config::Config;
use crate::consensus::rpc::nimbus_rpc::NimbusRpc;
use crate::consensus::types::Header;
use crate::consensus::ConsensusLightClient;

use crate::errors::NodeError;

pub struct Node {
    pub consensus: ConsensusLightClient<NimbusRpc>,
    pub config: Arc<Config>,
    pub history_size: usize,
}

impl Node {
    pub fn new(config: Arc<Config>) -> Result<Self, NodeError> {
        let consensus_rpc = &config.consensus_rpc;
        let checkpoint_hash = &config.checkpoint.as_ref().unwrap();

        let consensus = ConsensusLightClient::new(consensus_rpc, checkpoint_hash, config.clone())
            .map_err(NodeError::ConsensusClientCreationError)?;

        Ok(Node {
            consensus,
            config,
            history_size: 64,
        })
    }

    pub async fn sync(&mut self) -> Result<(), NodeError> {
        self.consensus
            .check_rpc()
            .await
            .map_err(NodeError::ConsensusSyncError)?;

        self.consensus
            .sync()
            .await
            .map_err(NodeError::ConsensusSyncError)
    }

    pub async fn advance(&mut self) -> Result<(), NodeError> {
        self.consensus
            .advance()
            .await
            .map_err(NodeError::ConsensusAdvanceError)
    }

    pub fn duration_until_next_update(&self) -> Duration {
        self.consensus
            .duration_until_next_update()
            .to_std()
            .unwrap()
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain.chain_id
    }

    pub fn get_header(&self) -> Result<Header> {
        self.check_head_age()?;
        Ok(self.consensus.get_header().clone())
    }

    pub fn get_last_checkpoint(&self) -> Option<Vec<u8>> {
        self.consensus.last_checkpoint.clone()
    }

    fn check_head_age(&self) -> Result<(), NodeError> {
        let synced_slot = self.consensus.get_header().slot;
        let expected_slot = self.consensus.expected_current_slot();
        let slot_delay = expected_slot - synced_slot;

        if slot_delay > 10 {
            return Err(NodeError::OutOfSync(slot_delay));
        }

        Ok(())
    }
}
