use crate::{cli::TrinExecutionConfig, types::block_to_trace::BlockToTrace};

#[derive(Debug, Clone)]
pub struct StateConfig {
    /// This flag when enabled will storage all the trie keys from block execution in a cache, this
    /// is needed for gossiping the storage trie's changes.
    pub cache_contract_storage_changes: bool,
    pub block_to_trace: BlockToTrace,
}

#[allow(clippy::derivable_impls)]
impl Default for StateConfig {
    fn default() -> Self {
        Self {
            cache_contract_storage_changes: false,
            block_to_trace: BlockToTrace::None,
        }
    }
}

impl From<TrinExecutionConfig> for StateConfig {
    fn from(cli_config: TrinExecutionConfig) -> Self {
        Self {
            cache_contract_storage_changes: false,
            block_to_trace: cli_config.block_to_trace,
        }
    }
}
