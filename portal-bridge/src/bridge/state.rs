use std::{path::PathBuf, sync::Arc};

use alloy_rlp::Decodable;
use e2store::utils::get_shuffled_era1_files;
use eth_trie::{decode_node, node::Node, RootWithTrieDiff};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::state_trie::account_state::AccountState as AccountStateInfo, ContentValue, Enr,
    StateContentKey, StateNetworkApiClient,
};
use revm::Database;
use revm_primitives::{keccak256, Bytecode, SpecId, B256};
use surf::{Client, Config};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::{error, info};
use trin_execution::{
    config::StateConfig,
    content::{
        create_account_content_key, create_account_content_value, create_contract_content_key,
        create_contract_content_value, create_storage_content_key, create_storage_content_value,
    },
    execution::TrinExecution,
    spec_id::get_spec_block_number,
    storage::utils::setup_temp_dir,
    trie_walker::TrieWalker,
    types::{block_to_trace::BlockToTrace, trie_proof::TrieProof},
    utils::full_nibble_path_to_address_hash,
};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::oracle::HeaderOracle;

use crate::{
    //bridge::history::SERVE_BLOCK_TIMEOUT,
    census::{ContentKey, EnrsRequest},
    types::mode::{BridgeMode, ModeType},
};

pub struct StateBridge {
    pub mode: BridgeMode,
    pub portal_client: HttpClient,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
    pub era1_files: Vec<String>,
    pub http_client: Client,
    pub metrics: BridgeMetricsReporter,
    // Semaphore used to limit the amount of active gossip transfers
    // to make sure we don't overwhelm the trin client
    pub gossip_semaphore: Arc<Semaphore>,
    // Used to request all interested enrs in the network from census process.
    // If None, the bridge will use the default gossip mode.
    pub census_tx: mpsc::UnboundedSender<EnrsRequest>,
}

impl StateBridge {
    pub async fn new(
        mode: BridgeMode,
        portal_client: HttpClient,
        header_oracle: HeaderOracle,
        epoch_acc_path: PathBuf,
        gossip_limit: usize,
        census_tx: mpsc::UnboundedSender<EnrsRequest>,
    ) -> anyhow::Result<Self> {
        let http_client: Client = Config::new()
            .add_header("Content-Type", "application/xml")
            .expect("to be able to add header")
            .try_into()?;
        let era1_files = get_shuffled_era1_files(&http_client).await?;
        let metrics = BridgeMetricsReporter::new("state".to_string(), &format!("{mode:?}"));
        let gossip_semaphore = Arc::new(Semaphore::new(gossip_limit));
        Ok(Self {
            mode,
            portal_client,
            header_oracle,
            epoch_acc_path,
            era1_files,
            http_client,
            metrics,
            gossip_semaphore,
            census_tx,
        })
    }

    pub async fn launch(&self) {
        info!("Launching state bridge: {:?}", self.mode);
        match self.mode.clone() {
            BridgeMode::Single(ModeType::Block(last_block)) => {
                if last_block > get_spec_block_number(SpecId::MERGE) {
                    panic!(
                        "State bridge only supports blocks up to {} for the time being.",
                        get_spec_block_number(SpecId::MERGE)
                    );
                }
                self.launch_state(last_block)
                    .await
                    .expect("State bridge failed");
            }
            _ => panic!("State bridge only supports backfill using 'single' mode to specify the terminating block number."),
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
        let mut trin_execution =
            TrinExecution::new(Some(temp_directory.path().to_path_buf()), state_config).await?;
        for block_number in 0..=last_block {
            info!("Gossipping state for block at height: {block_number}");

            // process block
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
                    let code = trin_execution.database.code_by_hash(account.code_hash)?;
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
                let storage_changed_nodes =
                    trin_execution.database.get_storage_trie_diff(address_hash);

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
            trin_execution.database.storage_cache.clear();
        }
        Ok(())
    }

    async fn request_enrs(&self, content_key: &StateContentKey) -> anyhow::Result<Vec<Enr>> {
        let (resp_tx, resp_rx) = futures::channel::oneshot::channel();
        let enrs_request = EnrsRequest {
            content_key: ContentKey::State(content_key.clone()),
            resp_tx,
        };
        self.census_tx.send(enrs_request)?;
        Ok(resp_rx.await?)
    }

    async fn gossip_account(
        &self,
        account_proof: &TrieProof,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let content_key = create_account_content_key(account_proof)?;
        let content_value = create_account_content_value(block_hash, account_proof)?;
        let enrs = self.request_enrs(&content_key).await?;
        for enr in enrs {
            let permit = self.acquire_gossip_permit().await;
            let _result = StateNetworkApiClient::trace_offer(
                &self.portal_client,
                enr,
                content_key.clone(),
                content_value.encode(),
            )
            .await;
            drop(permit);
        }
        Ok(())
    }

    async fn _gossip_account_async(
        &self,
        account_proof: &TrieProof,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let content_key = create_account_content_key(account_proof)?;
        let content_value = create_account_content_value(block_hash, account_proof)?;
        let enrs = self.request_enrs(&content_key).await?;
        let mut handles = Vec::new();
        for enr in enrs {
            let permit = self.acquire_gossip_permit().await;
            let portal_client = self.portal_client.clone();
            let content_key = content_key.clone();
            let content_value = content_value.clone();
            let handle = tokio::spawn(async move {
                // todo: add timeout to trace_offer
                let result = StateNetworkApiClient::trace_offer(
                    &portal_client,
                    enr,
                    content_key.clone(),
                    content_value.encode(),
                )
                .await;
                drop(permit);
                result
            });
            handles.push(handle);
        }
        for handle in handles {
            let _result = handle.await?;
        }
        Ok(())
    }

    async fn gossip_contract_bytecode(
        &self,
        address_hash: B256,
        account_proof: &TrieProof,
        block_hash: B256,
        code_hash: B256,
        code: Bytecode,
    ) -> anyhow::Result<()> {
        let code_content_key = create_contract_content_key(address_hash, code_hash)?;
        let code_content_value = create_contract_content_value(block_hash, account_proof, code)?;
        let enrs = self.request_enrs(&code_content_key).await?;
        for enr in enrs {
            let permit = self.acquire_gossip_permit().await;
            let _result = StateNetworkApiClient::trace_offer(
                &self.portal_client,
                enr,
                code_content_key.clone(),
                code_content_value.encode(),
            )
            .await;
            drop(permit);
        }
        Ok(())
    }

    async fn gossip_storage(
        &self,
        account_proof: &TrieProof,
        storage_proof: &TrieProof,
        address_hash: B256,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let storage_content_key = create_storage_content_key(storage_proof, address_hash)?;
        let storage_content_value =
            create_storage_content_value(block_hash, account_proof, storage_proof)?;
        let enrs = self.request_enrs(&storage_content_key).await?;
        for enr in enrs {
            let permit = self.acquire_gossip_permit().await;
            let _result = StateNetworkApiClient::trace_offer(
                &self.portal_client,
                enr,
                storage_content_key.clone(),
                storage_content_value.encode(),
            )
            .await;
            drop(permit);
        }
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
