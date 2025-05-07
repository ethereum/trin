use alloy::primitives::{FixedBytes, B256};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub fn u64_to_hex_string(val: u64) -> String {
    format!("0x{val:x}")
}

#[derive(Default, Debug, TreeHash)]
struct ForkData {
    current_version: FixedBytes<4>,
    genesis_validator_root: B256,
}

pub fn compute_fork_data_root(
    current_version: FixedBytes<4>,
    genesis_validator_root: B256,
) -> B256 {
    let fork_data = ForkData {
        current_version,
        genesis_validator_root,
    };
    fork_data.tree_hash_root()
}
