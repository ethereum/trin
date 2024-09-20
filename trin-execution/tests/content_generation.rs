use alloy_rlp::Decodable;
use anyhow::{ensure, Result};
use eth_trie::{decode_node, node::Node, RootWithTrieDiff};
use ethportal_api::types::state_trie::account_state::AccountState;
use revm::DatabaseRef;
use revm_primitives::keccak256;
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

/// Tests that we can execute and generate content up to a specified block.
///
/// The block is specified manually by set `blocks` variable.
///
/// Following command should be used for running:
///
/// ```
/// cargo test -p trin-execution --test content_generation -- --include-ignored --nocapture
/// ```
#[tokio::test]
#[traced_test]
#[ignore = "takes too long"]
async fn test_we_can_generate_content_key_values_up_to_x() -> Result<()> {
    // set last block to test for
    let blocks = 1_000_000;

    let temp_directory = create_temp_test_dir()?;

    let mut trin_execution = TrinExecution::new(
        temp_directory.path(),
        StateConfig {
            cache_contract_storage_changes: true,
            block_to_trace: BlockToTrace::None,
        },
    )
    .await?;

    for block_number in 0..=blocks {
        println!("Starting block: {block_number}");

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

        let mut content_pairs = 0;
        let walk_diff = TrieWalker::new(root_hash, changed_nodes);
        for node in walk_diff.nodes.keys() {
            let block_hash = block.header.hash();
            let account_proof = walk_diff.get_proof(*node);

            // check account content key/value
            assert!(create_account_content_key(&account_proof).is_ok());
            assert!(create_account_content_value(block_hash, &account_proof).is_ok());
            content_pairs += 1;

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
                assert!(create_contract_content_key(address_hash, account.code_hash).is_ok());
                assert!(create_contract_content_value(block_hash, &account_proof, code).is_ok());
                content_pairs += 1;
            }

            // check contract storage content key/value
            let storage_changed_nodes = trin_execution.database.get_storage_trie_diff(address_hash);
            let storage_walk_diff = TrieWalker::new(account.storage_root, storage_changed_nodes);
            for storage_node in storage_walk_diff.nodes.keys() {
                let storage_proof = storage_walk_diff.get_proof(*storage_node);
                assert!(create_storage_content_key(&storage_proof, address_hash).is_ok());
                assert!(
                    create_storage_content_value(block_hash, &account_proof, &storage_proof)
                        .is_ok()
                );
                content_pairs += 1;
            }
        }

        // flush the database cache
        // This is used for gossiping storage trie diffs
        trin_execution.database.storage_cache.clear();
        println!("Block {block_number} finished. Total content key/value pairs: {content_pairs}");
    }
    temp_directory.close()?;
    Ok(())
}
