use std::sync::{Arc, Mutex};

use alloy_rlp::Decodable;
use eth_trie::{decode_node, node::Node, RootWithTrieDiff};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::state_trie::account_state::AccountState as AccountStateInfo, ContentValue, Enr,
    OverlayContentKey, StateContentKey, StateContentValue, StateNetworkApiClient,
};
use revm::Database;
use revm_primitives::{keccak256, Bytecode, SpecId, B256};
use tokio::{
    sync::{mpsc, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tracing::{debug, enabled, error, info, warn, Level};
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

use crate::{
    bridge::history::SERVE_BLOCK_TIMEOUT,
    census::{ContentKey, EnrsRequest},
    types::mode::{BridgeMode, ModeType},
};

pub struct StateBridge {
    mode: BridgeMode,
    portal_client: HttpClient,
    metrics: BridgeMetricsReporter,
    // Semaphore used to limit the amount of active offer transfers
    // to make sure we don't overwhelm the trin client
    offer_semaphore: Arc<Semaphore>,
    // Used to request all interested enrs in the network from census process.
    census_tx: mpsc::UnboundedSender<EnrsRequest>,
}

impl StateBridge {
    pub async fn new(
        mode: BridgeMode,
        portal_client: HttpClient,
        offer_limit: usize,
        census_tx: mpsc::UnboundedSender<EnrsRequest>,
    ) -> anyhow::Result<Self> {
        let metrics = BridgeMetricsReporter::new("state".to_string(), &format!("{mode:?}"));
        let offer_semaphore = Arc::new(Semaphore::new(offer_limit));
        Ok(Self {
            mode,
            portal_client,
            metrics,
            offer_semaphore,
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

    async fn gossip_account(
        &self,
        account_proof: &TrieProof,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let content_key = create_account_content_key(account_proof)?;
        let content_value = create_account_content_value(block_hash, account_proof)?;
        self.spawn_offer_tasks(content_key, content_value).await;
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
        let content_key = create_contract_content_key(address_hash, code_hash)?;
        let content_value = create_contract_content_value(block_hash, account_proof, code)?;
        self.spawn_offer_tasks(content_key, content_value).await;
        Ok(())
    }

    async fn gossip_storage(
        &self,
        account_proof: &TrieProof,
        storage_proof: &TrieProof,
        address_hash: B256,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let content_key = create_storage_content_key(storage_proof, address_hash)?;
        let content_value = create_storage_content_value(block_hash, account_proof, storage_proof)?;
        self.spawn_offer_tasks(content_key, content_value).await;
        Ok(())
    }

    // request enrs interested in the content key from Census
    async fn request_enrs(&self, content_key: &StateContentKey) -> anyhow::Result<Vec<Enr>> {
        let (resp_tx, resp_rx) = futures::channel::oneshot::channel();
        let enrs_request = EnrsRequest {
            content_key: ContentKey::State(content_key.clone()),
            resp_tx,
        };
        self.census_tx.send(enrs_request)?;
        Ok(resp_rx.await?)
    }

    // spawn individual offer tasks of the content key for each interested enr found in Census
    async fn spawn_offer_tasks(
        &self,
        content_key: StateContentKey,
        content_value: StateContentValue,
    ) {
        let Ok(enrs) = self.request_enrs(&content_key).await else {
            error!("Failed to request enrs for content key, skipping offer: {content_key:?}");
            return;
        };
        let offer_report = Arc::new(Mutex::new(OfferReport::new(
            content_key.clone(),
            enrs.len(),
        )));
        for enr in enrs.clone() {
            let permit = self.acquire_offer_permit().await;
            let portal_client = self.portal_client.clone();
            let content_key = content_key.clone();
            let content_value = content_value.clone();
            let offer_report = offer_report.clone();
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                let timer = metrics.start_process_timer("spawn_offer_state_proof");
                match timeout(
                    SERVE_BLOCK_TIMEOUT,
                    StateNetworkApiClient::trace_offer(
                        &portal_client,
                        enr.clone(),
                        content_key.clone(),
                        content_value.encode(),
                    ),
                )
                .await
                {
                    Ok(result) => match result {
                        Ok(result) => {
                            offer_report
                                .lock()
                                .expect("to acquire lock")
                                .update(&enr, result);
                        }
                        Err(e) => {
                            offer_report
                                .lock()
                                .expect("to acquire lock")
                                .update(&enr, false);
                            warn!("Error offering to: {enr}, error: {e:?}");
                        }
                    },
                    Err(_) => {
                        offer_report
                            .lock()
                            .expect("to acquire lock")
                            .update(&enr, false);
                        error!("trace_offer timed out on state proof {content_key}: indicating a bug is present");
                    }
                };
                drop(permit);
                metrics.stop_process_timer(timer);
            });
        }
    }

    async fn acquire_offer_permit(&self) -> OwnedSemaphorePermit {
        self.offer_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("to be able to acquire semaphore")
    }
}

// Individual report for outcomes of offering a state content key
struct OfferReport {
    content_key: StateContentKey,
    total: usize,
    success: Vec<Enr>,
    // includes both enrs that rejected offer and failed txs
    // in the future we may want to differentiate between these cases
    // and return a more detailed report from `trace_offer`
    fail: Vec<Enr>,
}

impl OfferReport {
    fn new(content_key: StateContentKey, total: usize) -> Self {
        Self {
            content_key,
            total,
            success: Vec::new(),
            fail: Vec::new(),
        }
    }

    fn update(&mut self, enr: &Enr, success: bool) {
        if success {
            self.success.push(enr.clone());
        } else {
            self.fail.push(enr.clone());
        }
        if self.total == self.success.len() + self.fail.len() {
            self.report();
        }
    }

    fn report(&self) {
        if enabled!(Level::DEBUG) {
            debug!(
                "Successfully offered to {}/{} peers. Content key: {}. Failed: {:?}",
                self.success.len(),
                self.total,
                self.content_key.to_hex(),
                self.fail,
            );
        } else {
            info!(
                "Successfully offered to {}/{} peers. Content key: {}",
                self.success.len(),
                self.total,
                self.content_key.to_hex(),
            );
        }
    }
}
