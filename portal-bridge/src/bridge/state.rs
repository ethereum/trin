use std::{path::PathBuf, sync::Arc};

use alloy_rlp::Decodable;
use anyhow::anyhow;
use eth_trie::{decode_node, node::Node, RootWithTrieDiff};
use revm::DatabaseRef;
use revm_primitives::{keccak256, Bytecode, SpecId, B256};
use surf::{Client, Config};
use tokio::sync::{mpsc::UnboundedSender, OwnedSemaphorePermit, Semaphore};
use tracing::{error, info};

use crate::{
    gossip_engine::GossipRequest,
    types::mode::{BridgeMode, ModeType},
};
use e2store::utils::get_shuffled_era1_files;
use ethportal_api::{
    types::state_trie::account_state::AccountState as AccountStateInfo, StateContentKey,
    StateContentValue,
};
use trin_execution::{
    config::StateConfig,
    content::{
        create_account_content_key, create_account_content_value, create_contract_content_key,
        create_contract_content_value, create_storage_content_key, create_storage_content_value,
    },
    era::manager::EraManager,
    execution::State,
    spec_id::get_spec_block_number,
    storage::utils::setup_temp_dir,
    trie_walker::TrieWalker,
    types::{block_to_trace::BlockToTrace, trie_proof::TrieProof},
    utils::full_nibble_path_to_address_hash,
};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::oracle::HeaderOracle;

pub struct StateBridge {
    pub mode: BridgeMode,
    pub gossip_tx: UnboundedSender<GossipRequest>,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
    pub era1_files: Vec<String>,
    pub http_client: Client,
    pub metrics: BridgeMetricsReporter,
    pub gossip_semaphore: Arc<Semaphore>,
}

impl StateBridge {
    pub async fn new(
        mode: BridgeMode,
        gossip_tx: UnboundedSender<GossipRequest>,
        header_oracle: HeaderOracle,
        epoch_acc_path: PathBuf,
        gossip_limit: usize,
    ) -> anyhow::Result<Self> {
        let http_client: Client = Config::new()
            .add_header("Content-Type", "application/xml")
            .expect("to be able to add header")
            .try_into()?;
        let era1_files = get_shuffled_era1_files(&http_client).await?;
        let metrics = BridgeMetricsReporter::new("state".to_string(), &format!("{mode:?}"));
        // We are using a semaphore to limit the amount of active gossip transfers to make sure
        // we don't overwhelm the trin client
        let gossip_semaphore = Arc::new(Semaphore::new(gossip_limit));
        Ok(Self {
            mode,
            gossip_tx,
            header_oracle,
            epoch_acc_path,
            era1_files,
            http_client,
            metrics,
            gossip_semaphore,
        })
    }

    pub async fn launch(&self) {
        info!("Launching state bridge: {:?}", self.mode);
        match self.mode.clone() {
            BridgeMode::Single(ModeType::Block(last_block)) => {
                if last_block > get_spec_block_number(SpecId::DAO_FORK) {
                    panic!(
                        "State bridge only supports blocks up to {} for the time being.",
                        get_spec_block_number(SpecId::DAO_FORK)
                    );
                }
                self.launch_state(last_block)
                    .await
                    .expect("State bridge failed");
            }
            _ => panic!("State bridge only supports State modes."),
        }
        info!("Bridge mode: {:?} complete.", self.mode);
    }

    async fn launch_state(&self, last_block: u64) -> anyhow::Result<()> {
        info!("Gossiping state data from block 0 to {last_block}");
        let temp_directory = setup_temp_dir()?;

        // Enable contract storage changes caching required for gossiping the storage trie
        let state_config = StateConfig {
            cache_contract_storage_changes: true,
            block_to_trace: BlockToTrace::None,
        };
        let mut state = State::new(Some(temp_directory.path().to_path_buf()), state_config)?;
        let starting_block = 0;
        let mut era_manager = EraManager::new(starting_block).await?;
        for block_number in starting_block..=last_block {
            info!("Gossipping state for block at height: {block_number}");

            let block = era_manager.get_next_block().await?;

            // process block
            let RootWithTrieDiff {
                root: root_hash,
                trie_diff: changed_nodes,
            } = match block_number == 0 {
                true => state
                    .initialize_genesis()
                    .map_err(|e| anyhow!("unable to create genesis state: {e}"))?,
                false => state.process_block(block)?,
            };

            let walk_diff = TrieWalker::new(root_hash, changed_nodes);

            // gossip block's new state transitions
            for node in walk_diff.nodes.keys() {
                let account_proof = walk_diff.get_proof(*node);

                // gossip the account
                self.gossip_account(&account_proof, block.header.hash())
                    .await?;

                let Some(encoded_last_node) = account_proof.proof.last() else {
                    error!("Account proof is empty. This should never happen maybe there is a bug in trie_walker?");
                    continue;
                };

                let decoded_node = decode_node(&mut encoded_last_node.as_ref())
                    .expect("Should should only be passing valid encoded nodes");
                let Node::Leaf(leaf) = decoded_node else {
                    continue;
                };
                let account: AccountStateInfo = Decodable::decode(&mut leaf.value.as_slice())?;

                // reconstruct the address hash from the path so that we can fetch the
                // address from the database
                let mut partial_key_path = leaf.key.get_data().to_vec();
                partial_key_path.pop();
                let full_key_path =
                    [&account_proof.path.clone(), partial_key_path.as_slice()].concat();
                let address_hash = full_nibble_path_to_address_hash(&full_key_path);

                // if the code_hash is empty then then don't try to gossip the contract bytecode
                if account.code_hash != keccak256([]) {
                    // gossip contract bytecode
                    let code = state.database.code_by_hash_ref(account.code_hash)?;
                    self.gossip_contract_bytecode(
                        address_hash,
                        &account_proof,
                        block.header.hash(),
                        account.code_hash,
                        code,
                    )
                    .await?;
                }

                // gossip contract storage
                let storage_changed_nodes = state.database.get_storage_trie_diff(address_hash);

                let storage_walk_diff =
                    TrieWalker::new(account.storage_root, storage_changed_nodes);

                for storage_node in storage_walk_diff.nodes.keys() {
                    let storage_proof = storage_walk_diff.get_proof(*storage_node);
                    self.gossip_storage(
                        &account_proof,
                        &storage_proof,
                        address_hash,
                        block.header.hash(),
                    )
                    .await?;
                }
            }

            // flush the database cache
            // This is used for gossiping storage trie diffs
            state.database.storage_cache.clear();
        }
        Ok(())
    }

    async fn gossip_account(
        &self,
        account_proof: &TrieProof,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let permit = self.acquire_gossip_permit().await;
        let content_key = create_account_content_key(account_proof)?;
        let content_value = create_account_content_value(block_hash, account_proof)?;
        Self::serve_state_content(self.gossip_tx.clone(), content_key, content_value, permit).await
    }

    async fn gossip_contract_bytecode(
        &self,
        address_hash: B256,
        account_proof: &TrieProof,
        block_hash: B256,
        code_hash: B256,
        code: Bytecode,
    ) -> anyhow::Result<()> {
        let permit = self.acquire_gossip_permit().await;
        let code_content_key = create_contract_content_key(address_hash, code_hash)?;
        let code_content_value = create_contract_content_value(block_hash, account_proof, code)?;
        Self::serve_state_content(
            self.gossip_tx.clone(),
            code_content_key,
            code_content_value,
            permit,
        )
        .await
    }

    async fn gossip_storage(
        &self,
        account_proof: &TrieProof,
        storage_proof: &TrieProof,
        address_hash: B256,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let permit = self.acquire_gossip_permit().await;
        let storage_content_key = create_storage_content_key(storage_proof, address_hash)?;
        let storage_content_value =
            create_storage_content_value(block_hash, account_proof, storage_proof)?;
        Self::serve_state_content(
            self.gossip_tx.clone(),
            storage_content_key,
            storage_content_value,
            permit,
        )
        .await
    }

    async fn serve_state_content(
        gossip_tx: UnboundedSender<GossipRequest>,
        content_key: StateContentKey,
        content_value: StateContentValue,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        info!("Serving state content for content key: {content_key}");
        let (resp_tx, resp_rx) = futures::channel::oneshot::channel();
        let gossip_request = GossipRequest::from((content_key, content_value, resp_tx));
        let _x = gossip_tx
            .send(gossip_request)
            .map_err(|e| anyhow!("unable to send state content gossip request: {e}"));
        // permit.forget();
        if let Err(e) = resp_rx.await {
            error!("Failed to gossip state content: {e}");
        }
        drop(permit);
        Ok(())
    }

    async fn acquire_gossip_permit(&self) -> OwnedSemaphorePermit {
        self.gossip_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("to be able to acquire semaphore")
    }
}
