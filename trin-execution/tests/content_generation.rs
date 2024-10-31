use alloy::rlp::Decodable;
use anyhow::{ensure, Result};
use eth_trie::{decode_node, node::Node, RootWithTrieDiff};
use ethportal_api::{
    types::{
        content_value::state::{ContractBytecode, TrieNode},
        state_trie::account_state::AccountState,
    },
    ContentValue, OverlayContentKey, StateContentKey, StateContentValue,
};
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

#[derive(Default, Debug)]
struct Stats {
    content_count: usize,
    gossip_size: usize,
    storage_size: usize,
    account_trie_count: usize,
    contract_storage_trie_count: usize,
    contract_bytecode_count: usize,
}

impl Stats {
    /// Panics if either is `Err`
    fn check_content(&mut self, key: &StateContentKey, value: &StateContentValue) {
        let value_without_proof = match &value {
            StateContentValue::AccountTrieNodeWithProof(account_trie_node_with_proof) => {
                self.account_trie_count += 1;
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
            ) => {
                self.contract_storage_trie_count += 1;
                StateContentValue::TrieNode(TrieNode {
                    node: contract_storage_trie_node_with_proof
                        .storage_proof
                        .last()
                        .expect("Storage trie proof much have at least one trie node")
                        .clone(),
                })
            }
            StateContentValue::ContractBytecodeWithProof(contract_bytecode_with_proof) => {
                self.contract_bytecode_count += 1;
                StateContentValue::ContractBytecode(ContractBytecode {
                    code: contract_bytecode_with_proof.code.clone(),
                })
            }
            _ => panic!("Content value doesn't contain proof!"),
        };
        let gossip_size = key.to_bytes().len() + value.encode().len();
        let storage_size = 32 + key.to_bytes().len() + value_without_proof.encode().len();
        self.content_count += 1;
        self.gossip_size += gossip_size;
        self.storage_size += storage_size;
    }
}

/// Tests that we can execute and generate content up to a specified block.
///
/// The block is specified manually by set `blocks` variable.
///
/// Following command should be used for running:
///
/// ```
/// BLOCKS=1000000 cargo test --release -p trin-execution --test content_generation -- --include-ignored --nocapture
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
            cache_contract_changes: true,
            block_to_trace: BlockToTrace::None,
        },
    )
    .await?;

    let mut stats = Stats::default();

    for block_number in 0..=blocks {
        let mut block_stats = Stats::default();

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

        let walk_diff = TrieWalker::new_partial_trie(root_hash, changed_nodes)?;
        for account_proof in walk_diff {
            let block_hash = block.header.hash();

            // check account content key/value
            let content_key =
                create_account_content_key(&account_proof).expect("Content key should be present");
            let content_value = create_account_content_value(block_hash, &account_proof)
                .expect("Content key should be present");
            block_stats.check_content(&content_key, &content_value);
            stats.check_content(&content_key, &content_value);

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
                if let Some(code) = trin_execution
                    .database
                    .get_newly_created_contract(account.code_hash)
                {
                    let content_key = create_contract_content_key(address_hash, account.code_hash)
                        .expect("Content key should be present");
                    let content_value =
                        create_contract_content_value(block_hash, &account_proof, code)
                            .expect("Content key should be present");
                    block_stats.check_content(&content_key, &content_value);
                    stats.check_content(&content_key, &content_value);
                }
            }

            // check contract storage content key/value
            let storage_changed_nodes = trin_execution.database.get_storage_trie_diff(address_hash);
            let storage_walk_diff =
                TrieWalker::new_partial_trie(account.storage_root, storage_changed_nodes)?;
            for storage_proof in storage_walk_diff {
                let content_key = create_storage_content_key(&storage_proof, address_hash)
                    .expect("Content key should be present");
                let content_value =
                    create_storage_content_value(block_hash, &account_proof, &storage_proof)
                        .expect("Content key should be present");
                block_stats.check_content(&content_key, &content_value);
                stats.check_content(&content_key, &content_value);
            }
        }

        // flush the database cache
        // This is used for gossiping storage trie diffs
        trin_execution.database.clear_contract_cache();
        info!("Block {block_number} finished: {block_stats:?}");
    }
    temp_directory.close()?;
    info!("Finished all {blocks} blocks: {stats:?}");
    Ok(())
}
