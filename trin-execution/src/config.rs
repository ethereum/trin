#[derive(Debug, Clone)]
pub struct StateConfig {
    /// This flag when enabled will storage all the trie keys from block execution in a cache, this
    /// is needed for gossiping the storage trie's changes.
    pub cache_contract_storage_changes: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for StateConfig {
    fn default() -> Self {
        Self {
            cache_contract_storage_changes: false,
        }
    }
}
