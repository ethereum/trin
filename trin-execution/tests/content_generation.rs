use alloy_rlp::Decodable;
use anyhow::{ensure, Result};
use eth_trie::{decode_node, node::Node, RootWithTrieDiff};
use ethportal_api::{
    types::{
        content_value::state::{ContractBytecode, TrieNode},
        state_trie::account_state::AccountState,
    },
    ContentValue, OverlayContentKey, StateContentKey, StateContentValue,
};
use revm::DatabaseRef;
use revm_primitives::keccak256;
use tracing::info;
use tracing_test::traced_test;
use trin_execution::{
    config::StateConfig,
    content::{
        create_account_content_key, create_account_content_value, create_contract_content_key,
        create_contract_content_value, create_storage_content_key, create_storage_content_value,
    },
    execution::TrinExecution,
    trie_walker::TrieWalker,
    types::block_to_trace::BlockToTrace,
    utils::full_nibble_path_to_address_hash,
};
use trin_utils::dir::create_temp_test_dir;

#[derive(Default)]
struct Stats {
    total_content_count: usize,
    block_content_count: usize,
    total_gossip_size: usize,
    block_gossip_size: usize,
    total_storage_size: usize,
    block_storage_size: usize,
}

impl Stats {
    fn reset_block_stats(&mut self) {
        self.block_content_count = 0;
        self.block_gossip_size = 0;
        self.block_storage_size = 0;
    }

    /// Panics if either is `Err`
    fn check_content(&mut self, key: Result<StateContentKey>, value: Result<StateContentValue>) {
        let key = key.expect("Content key should be present");
        let value = value.expect("Content key should be present");
        let value_without_proof = match &value {
            StateContentValue::AccountTrieNodeWithProof(account_trie_node_with_proof) => {
                StateContentValue::TrieNode(TrieNode {
                    node: account_trie_node_with_proof
                        .proof
                        .last()
                        .expect("Account trie proof must have at least one trie node")
                        .clone(),
                })
            }
            StateContentValue::ContractStorageTrieNodeWithProof(
                contract_storage_trie_node_with_proof,
            ) => StateContentValue::TrieNode(TrieNode {
                node: contract_storage_trie_node_with_proof
                    .storage_proof
                    .last()
                    .expect("Storage trie proof much have at least one trie node")
                    .clone(),
            }),
            StateContentValue::ContractBytecodeWithProof(contract_bytecode_with_proof) => {
                StateContentValue::ContractBytecode(ContractBytecode {
                    code: contract_bytecode_with_proof.code.clone(),
                })
            }
            _ => panic!("Content value doesn't contain proof!"),
        };
        let gossip_size = key.to_bytes().len() + value.encode().len();
        let storage_size = 32 + key.to_bytes().len() + value_without_proof.encode().len();
        self.block_content_count += 1;
        self.total_content_count += 1;
        self.block_gossip_size += gossip_size;
        self.total_gossip_size += gossip_size;
        self.block_storage_size += storage_size;
        self.total_storage_size += storage_size;
    }

    fn print_block_stats(&self, block_number: u64) {
        info!(
            count = self.block_content_count,
            gossip_size = self.block_gossip_size,
            storage_size = self.block_storage_size,
            "Block {block_number} finished.",
        );
    }

    fn print_total_stats(&self, block_number: u64) {
        info!(
            count = self.total_content_count,
            gossip_size = self.total_gossip_size,
            storage_size = self.total_storage_size,
            "Finished all {block_number} blocks.",
        );
    }
}

/// Tests that we can execute and generate content up to a specified block.
///
/// The block is specified manually by set `blocks` variable.
///
/// Following command should be used for running:
///
/// ```
/// BLOCKS=1000000 cargo test -p trin-execution --test content_generation -- --include-ignored --nocapture
/// ```
#[tokio::test]
#[traced_test]
#[ignore = "takes too long"]
async fn test_we_can_generate_content_key_values_up_to_x() -> Result<()> {
    let blocks = std::env::var("BLOCKS")?.parse::<u64>()?;

    let temp_directory = create_temp_test_dir()?;
    let mut trin_execution = TrinExecution::new(
        temp_directory.path(),
        StateConfig {
            cache_contract_storage_changes: true,
            block_to_trace: BlockToTrace::None,
        },
    )
    .await?;

    let mut stats = Stats::default();

    for block_number in 0..=blocks {
        stats.reset_block_stats();

        let RootWithTrieDiff {
            root: root_hash,
            trie_diff: changed_nodes,
        } = trin_execution.process_next_block().await?;
        let block = trin_execution
            .era_manager
            .lock()
            .await
            .last_fetched_block()
            .await?
            .clone();
        ensure!(
            block_number == block.header.number,
            "Block number doesn't match!"
        );
        ensure!(
            trin_execution.get_root()? == block.header.state_root,
            "State root doesn't match"
        );

        let walk_diff = TrieWalker::new(root_hash, changed_nodes);
        for node in walk_diff.nodes.keys() {
            let block_hash = block.header.hash();
            let account_proof = walk_diff.get_proof(*node);

            // check account content key/value
            stats.check_content(
                create_account_content_key(&account_proof),
                create_account_content_value(block_hash, &account_proof),
            );

            let Some(encoded_last_node) = account_proof.proof.last() else {
                panic!("Account proof is empty");
            };

            let Node::Leaf(leaf) = decode_node(&mut encoded_last_node.as_ref())? else {
                continue;
            };
            let account: AccountState = Decodable::decode(&mut leaf.value.as_slice())?;

            // reconstruct the address hash from the path so that we can fetch the
            // address from the database
            let mut partial_key_path = leaf.key.get_data().to_vec();
            partial_key_path.pop();
            let full_key_path = [&account_proof.path.clone(), partial_key_path.as_slice()].concat();
            let address_hash = full_nibble_path_to_address_hash(&full_key_path);

            // check contract code content key/value
            if account.code_hash != keccak256([]) {
                let code = trin_execution
                    .database
                    .code_by_hash_ref(account.code_hash)?;
                stats.check_content(
                    create_contract_content_key(address_hash, account.code_hash),
                    create_contract_content_value(block_hash, &account_proof, code),
                );
            }

            // check contract storage content key/value
            let storage_changed_nodes = trin_execution.database.get_storage_trie_diff(address_hash);
            let storage_walk_diff = TrieWalker::new(account.storage_root, storage_changed_nodes);
            for storage_node in storage_walk_diff.nodes.keys() {
                let storage_proof = storage_walk_diff.get_proof(*storage_node);

                stats.check_content(
                    create_storage_content_key(&storage_proof, address_hash),
                    create_storage_content_value(block_hash, &account_proof, &storage_proof),
                );
            }
        }

        // flush the database cache
        // This is used for gossiping storage trie diffs
        trin_execution.database.storage_cache.clear();
        stats.print_block_stats(block_number);
    }
    temp_directory.close()?;
    stats.print_total_stats(blocks);
    Ok(())
}
