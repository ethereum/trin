use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use alloy::{consensus::EMPTY_ROOT_HASH, rlp::Decodable};
use anyhow::ensure;
use e2store::utils::get_era2_files;
use eth_trie::{decode_node, node::Node, EthTrie, RootWithTrieDiff, Trie};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::{
        network::Subnetwork, portal_wire::OfferTrace, state_trie::account_state::AccountState,
    },
    ContentValue, Enr, OverlayContentKey, StateContentKey, StateContentValue,
    StateNetworkApiClient,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use revm::{Database, DatabaseRef};
use revm_primitives::{keccak256, Bytecode, SpecId, B256};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tracing::{debug, enabled, error, info, warn, Level};
use trin_evm::spec_id::get_spec_block_number;
use trin_execution::{
    cli::ImportStateConfig,
    config::StateConfig,
    content::{
        create_account_content_key, create_account_content_value, create_contract_content_key,
        create_contract_content_value, create_storage_content_key, create_storage_content_value,
    },
    execution::TrinExecution,
    storage::{
        account_db::AccountDB, evm_db::EvmDB, execution_position::ExecutionPosition,
        utils::setup_rocksdb,
    },
    subcommands::era2::{
        import::StateImporter,
        utils::{download_with_progress, format_eta, percentage_from_address_hash},
    },
    trie_walker::TrieWalker,
    types::{block_to_trace::BlockToTrace, trie_proof::TrieProof},
    utils::full_nibble_path_to_address_hash,
};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_utils::dir::{create_temp_dir, setup_data_dir};

use crate::{
    bridge::history::SERVE_BLOCK_TIMEOUT,
    census::Census,
    cli::BridgeId,
    types::mode::{BridgeMode, ModeType},
};

pub struct StateBridge {
    mode: BridgeMode,
    portal_client: HttpClient,
    metrics: BridgeMetricsReporter,
    // Semaphore used to limit the amount of active offer transfers
    // to make sure we don't overwhelm the trin client
    offer_semaphore: Arc<Semaphore>,
    // Used to request all interested enrs in the network.
    census: Census,
    // Global offer report for tallying total performance of state bridge
    global_offer_report: Arc<Mutex<GlobalOfferReport>>,
    // Bridge id used to determine which content keys to gossip
    bridge_id: BridgeId,
    data_dir: Option<PathBuf>,
}

impl StateBridge {
    pub async fn new(
        mode: BridgeMode,
        portal_client: HttpClient,
        offer_limit: usize,
        census: Census,
        bridge_id: BridgeId,
        data_dir: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let metrics = BridgeMetricsReporter::new("state".to_string(), &format!("{mode:?}"));
        let offer_semaphore = Arc::new(Semaphore::new(offer_limit));
        let global_offer_report = GlobalOfferReport::default();
        Ok(Self {
            mode,
            portal_client,
            metrics,
            offer_semaphore,
            census,
            global_offer_report: Arc::new(Mutex::new(global_offer_report)),
            bridge_id,
            data_dir,
        })
    }

    pub async fn launch(&self) {
        info!("Launching state bridge: {:?}", self.mode);
        let (start_block, end_block) = match self.mode.clone() {
            // TODO: This should only gossip state trie at this block
            BridgeMode::Single(ModeType::Block(block)) => (0, block),
            BridgeMode::Single(ModeType::BlockRange(start_block, end_block)) => (start_block, end_block),
            BridgeMode::Snapshot(snapshot_block) => {
                self.launch_snapshot(snapshot_block)
                    .await
                    .expect("State bridge failed");
                return;
            },
            _ => panic!("State bridge only supports 'single' mode, for single block (implies 0..=block range) or range of blocks."),
        };

        if end_block > get_spec_block_number(SpecId::MERGE) {
            panic!(
                "State bridge only supports blocks up to {} for the time being.",
                get_spec_block_number(SpecId::MERGE)
            );
        }

        self.launch_state(start_block, end_block)
            .await
            .expect("State bridge failed");
        info!("Bridge mode: {:?} complete.", self.mode);
    }

    async fn launch_state(&self, start_block: u64, end_block: u64) -> anyhow::Result<()> {
        let temp_directory = create_temp_dir("trin-bridge-state", None)?;

        // Enable contract storage changes caching required for gossiping the storage trie
        let state_config = StateConfig {
            cache_contract_changes: true,
            block_to_trace: BlockToTrace::None,
        };
        let mut trin_execution = TrinExecution::new(temp_directory.path(), state_config).await?;

        if start_block > 0 {
            info!("Executing up to block: {}", start_block - 1);
            trin_execution
                .process_range_of_blocks(start_block - 1, None)
                .await?;
            // flush the database cache
            trin_execution.database.clear_contract_cache();
        }

        info!("Gossiping state data from block {start_block} to {end_block} (inclusively)");
        while trin_execution.next_block_number() <= end_block {
            info!(
                "Gossipping state for block at height: {}",
                trin_execution.next_block_number()
            );
            // display global state offer report
            self.global_offer_report
                .lock()
                .expect("to acquire lock")
                .report();

            let root_with_trie_diff = trin_execution.process_next_block().await?;

            self.gossip_trie_diff(root_with_trie_diff, &mut trin_execution)
                .await?;
        }

        // display final global state offer report
        self.global_offer_report
            .lock()
            .expect("to acquire lock")
            .report();

        temp_directory.close()?;
        Ok(())
    }

    async fn launch_snapshot(&self, snapshot_block: u64) -> anyhow::Result<()> {
        ensure!(snapshot_block > 0, "Snapshot block must be greater than 0");

        // 1. Download the era2 file and import the state snapshot
        let data_dir = setup_data_dir("trin-execution", self.data_dir.clone(), false)?;
        let next_block_number = {
            let rocks_db = Arc::new(setup_rocksdb(&data_dir)?);
            let execution_position = ExecutionPosition::initialize_from_db(rocks_db.clone())?;
            execution_position.next_block_number()
        };

        if next_block_number == snapshot_block + 1 {
            info!("State snapshot already imported. Skipping import.");
        } else {
            // Remove the existing database and create a new fresh folder
            info!("Deleting existing database and importing state snapshot");
            std::fs::remove_dir_all(&data_dir)
                .and_then(|_| std::fs::create_dir(&data_dir))
                .expect("Failed to delete existing database");

            let http_client = Client::builder()
                .default_headers(HeaderMap::from_iter([(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/xml"),
                )]))
                .build()?;

            let era2_files = get_era2_files(&http_client).await?;
            let era2_blocks = era2_files.keys().cloned().collect::<Vec<_>>();

            ensure!(
                era2_files.contains_key(&snapshot_block),
                "Era2 file doesn't exist for requested snapshot block: try these {era2_blocks:?}"
            );

            info!(
                "Downloading era2 file for snapshot block: {}",
                snapshot_block
            );

            let path_to_era2 = data_dir.join(format!("era2-{snapshot_block}.bin"));
            if let Err(e) = download_with_progress(
                &http_client,
                &era2_files[&snapshot_block],
                path_to_era2.clone(),
            )
            .await
            {
                return Err(anyhow::anyhow!("Failed to download era2 file: {e}"));
            };

            let import_state_config = ImportStateConfig { path_to_era2 };

            let state_importer = StateImporter::new(import_state_config, &data_dir).await?;
            let header = state_importer.import().await?;
            info!(
                "Imported state from era2: {} {}",
                header.number, header.state_root,
            );
        }

        info!("State snapshot imported successfully, starting state bridge");

        // 2. Start the state bridge

        let rocks_db = Arc::new(setup_rocksdb(&data_dir)?);

        let execution_position = ExecutionPosition::initialize_from_db(rocks_db.clone())?;
        ensure!(
            execution_position.next_block_number() > 0,
            "Trin execution not initialized!"
        );

        let mut evm_db = EvmDB::new(StateConfig::default(), rocks_db, &execution_position)
            .expect("Failed to create EVM database");

        self.gossip_whole_state_snapshot(&mut evm_db, execution_position)
            .await
            .expect("State bridge failed");
        Ok(())
    }

    async fn gossip_trie_diff(
        &self,
        root_with_trie_diff: RootWithTrieDiff,
        trin_execution: &mut TrinExecution,
    ) -> anyhow::Result<()> {
        let block_hash = trin_execution
            .era_manager
            .lock()
            .await
            .last_fetched_block()
            .await?
            .header
            .hash();

        let walk_diff =
            TrieWalker::new_partial_trie(root_with_trie_diff.root, root_with_trie_diff.trie_diff)?;

        // gossip block's new state transitions
        let mut content_idx = 0;
        for account_proof in walk_diff {
            // gossip the account
            self.gossip_account(&account_proof, block_hash, content_idx)
                .await?;
            content_idx += 1;

            let Some(encoded_last_node) = account_proof.proof.last() else {
                error!("Account proof is empty. This should never happen maybe there is a bug in trie_walker?");
                continue;
            };

            let decoded_node = decode_node(&mut encoded_last_node.as_ref())
                .expect("Should should only be passing valid encoded nodes");
            let Node::Leaf(leaf) = decoded_node else {
                continue;
            };
            let account: AccountState = Decodable::decode(&mut leaf.value.as_slice())?;

            // reconstruct the address hash from the path so that we can fetch the
            // address from the database
            let mut partial_key_path = leaf.key.get_data().to_vec();
            partial_key_path.pop();
            let full_key_path = [&account_proof.path.clone(), partial_key_path.as_slice()].concat();
            let address_hash = full_nibble_path_to_address_hash(&full_key_path);

            // if the code_hash is empty then then don't try to gossip the contract bytecode
            if account.code_hash != keccak256([]) {
                // gossip contract bytecode
                if let Some(code) = trin_execution
                    .database
                    .get_newly_created_contract(account.code_hash)
                {
                    self.gossip_contract_bytecode(
                        address_hash,
                        &account_proof,
                        block_hash,
                        account.code_hash,
                        code,
                        content_idx,
                    )
                    .await?;
                    content_idx += 1;
                }
            }

            // gossip contract storage
            let storage_changed_nodes = trin_execution.database.get_storage_trie_diff(address_hash);

            let storage_walk_diff =
                TrieWalker::new_partial_trie(account.storage_root, storage_changed_nodes)?;

            for storage_proof in storage_walk_diff {
                self.gossip_storage(
                    &account_proof,
                    &storage_proof,
                    address_hash,
                    block_hash,
                    content_idx,
                )
                .await?;
                content_idx += 1;
            }
        }

        // flush the database cache
        // This is used for gossiping storage trie diffs and newly created contracts
        trin_execution.database.clear_contract_cache();

        Ok(())
    }

    async fn gossip_whole_state_snapshot(
        &self,
        evm_db: &mut EvmDB,
        execution_position: ExecutionPosition,
    ) -> anyhow::Result<()> {
        let start = Instant::now();

        let number = execution_position.next_block_number() - 1;
        let block_hash = evm_db.block_hash(number)?;

        let mut leaf_count = 0;

        let root_hash = evm_db.trie.lock().root_hash()?;
        let mut content_idx = 0;
        let state_walker = TrieWalker::new(root_hash, evm_db.trie.lock().db.clone())?;
        for account_proof in state_walker {
            // gossip the account
            self.gossip_account(&account_proof, block_hash, content_idx)
                .await?;
            content_idx += 1;

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

            leaf_count += 1;
            if leaf_count % 100 == 0 {
                let elapsed_secs = start.elapsed().as_secs_f64();
                let percentage_done = percentage_from_address_hash(address_hash);

                if percentage_done > 0.0 {
                    let estimated_total_time = elapsed_secs / (percentage_done / 100.0);
                    let eta_secs = estimated_total_time - elapsed_secs;

                    let eta_formatted = format_eta(eta_secs);

                    info!(
                        "Processed {leaf_count} leaves, {:.2}% done, ETA: {}, last address_hash processed: {address_hash}",
                        percentage_done, eta_formatted
                    );
                } else {
                    info!(
                        "Processed {leaf_count} leaves, {:.2}% done, ETA: calculating..., last address_hash processed: {address_hash}",
                        percentage_done
                    );
                }
            }

            // check contract code content key/value
            if account.code_hash != keccak256([]) {
                let code: Bytecode = evm_db.code_by_hash_ref(account.code_hash)?;

                self.gossip_contract_bytecode(
                    address_hash,
                    &account_proof,
                    block_hash,
                    account.code_hash,
                    code,
                    content_idx,
                )
                .await?;
                content_idx += 1;
            }

            // check contract storage content key/value
            if account.storage_root != EMPTY_ROOT_HASH {
                let account_db = AccountDB::new(address_hash, evm_db.db.clone());
                let trie = EthTrie::from(Arc::new(account_db), account.storage_root)?.db;

                let storage_walker = TrieWalker::new(account.storage_root, trie)?;
                for storage_proof in storage_walker {
                    self.gossip_storage(
                        &account_proof,
                        &storage_proof,
                        address_hash,
                        block_hash,
                        content_idx,
                    )
                    .await?;
                    content_idx += 1;
                }
            }
        }

        info!("Took {} seconds to complete", start.elapsed().as_secs());

        Ok(())
    }

    async fn gossip_account(
        &self,
        account_proof: &TrieProof,
        block_hash: B256,
        content_idx: u64,
    ) -> anyhow::Result<()> {
        // check if the bridge should gossip the content key
        if !self.bridge_id.is_selected(content_idx) {
            return Ok(());
        }
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
        content_idx: u64,
    ) -> anyhow::Result<()> {
        // check if the bridge should gossip the content key
        if !self.bridge_id.is_selected(content_idx) {
            return Ok(());
        }
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
        content_idx: u64,
    ) -> anyhow::Result<()> {
        // check if the bridge should gossip the content key
        if !self.bridge_id.is_selected(content_idx) {
            return Ok(());
        }
        let content_key = create_storage_content_key(storage_proof, address_hash)?;
        let content_value = create_storage_content_value(block_hash, account_proof, storage_proof)?;
        self.spawn_offer_tasks(content_key, content_value).await;
        Ok(())
    }

    // spawn individual offer tasks of the content key for each interested enr found in Census
    async fn spawn_offer_tasks(
        &self,
        content_key: StateContentKey,
        content_value: StateContentValue,
    ) {
        let Ok(enrs) = self
            .census
            .select_peers(Subnetwork::State, &content_key.content_id())
        else {
            error!("Failed to request enrs for content key, skipping offer: {content_key:?}");
            return;
        };
        let offer_report = Arc::new(Mutex::new(OfferReport::new(
            content_key.clone(),
            enrs.len(),
        )));
        let encoded_content_value = content_value.encode();
        for enr in enrs.clone() {
            let permit = self.acquire_offer_permit().await;
            let census = self.census.clone();
            let portal_client = self.portal_client.clone();
            let content_key = content_key.clone();
            let encoded_content_value = encoded_content_value.clone();
            let offer_report = offer_report.clone();
            let metrics = self.metrics.clone();
            let global_offer_report = self.global_offer_report.clone();
            tokio::spawn(async move {
                let timer = metrics.start_process_timer("spawn_offer_state_proof");

                let start_time = Instant::now();
                let content_value_size = encoded_content_value.len();

                let result = timeout(
                    SERVE_BLOCK_TIMEOUT,
                    StateNetworkApiClient::trace_offer(
                        &portal_client,
                        enr.clone(),
                        content_key.clone(),
                        encoded_content_value,
                    ),
                )
                .await;

                let offer_trace = match &result {
                    Ok(Ok(result)) => {
                        if matches!(result, &OfferTrace::Failed) {
                            warn!("Internal error offering to: {enr}");
                        }
                        result
                    }
                    Ok(Err(err)) => {
                        warn!("Error offering to: {enr}, error: {err:?}");
                        &OfferTrace::Failed
                    }
                    Err(_) => {
                        error!("trace_offer timed out on state proof {content_key}: indicating a bug is present");
                        &OfferTrace::Failed
                    }
                };

                census.record_offer_result(
                    Subnetwork::State,
                    enr.node_id(),
                    content_value_size,
                    start_time.elapsed(),
                    offer_trace,
                );

                // Update report and metrics
                global_offer_report
                    .lock()
                    .expect("to acquire lock")
                    .update(offer_trace);
                offer_report
                    .lock()
                    .expect("to acquire lock")
                    .update(&enr, offer_trace);

                metrics.report_offer(
                    match content_key {
                        StateContentKey::AccountTrieNode(_) => "account_trie_node",
                        StateContentKey::ContractStorageTrieNode(_) => "contract_storage_trie_node",
                        StateContentKey::ContractBytecode(_) => "contract_bytecode",
                    },
                    match offer_trace {
                        OfferTrace::Success(_) => "success",
                        OfferTrace::Declined => "declined",
                        OfferTrace::Failed => "failed",
                    },
                );

                // Release permit
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

/// Global report for outcomes of offering state content keys from long-running state bridge
#[derive(Default)]
struct GlobalOfferReport {
    success: usize,
    failed: usize,
    declined: usize,
}

impl GlobalOfferReport {
    fn update(&mut self, trace: &OfferTrace) {
        match trace {
            OfferTrace::Success(_) => self.success += 1,
            OfferTrace::Failed => self.failed += 1,
            OfferTrace::Declined => self.declined += 1,
        }
    }

    fn report(&self) {
        let total = self.success + self.failed + self.declined;
        if total == 0 {
            return;
        }
        info!(
            "State offer report: Total Offers: {}. Successful: {}% ({}). Declined: {}% ({}). Failed: {}% ({}).",
            total,
            100 * self.success / total,
            self.success,
            100 * self.declined / total,
            self.declined,
            100 * self.failed / total,
            self.failed,
        );
    }
}

/// Individual report for outcomes of offering a state content key
struct OfferReport {
    content_key: StateContentKey,
    /// total number of enrs interested in the content key
    total: usize,
    success: Vec<Enr>,
    failed: Vec<Enr>,
    declined: Vec<Enr>,
}

impl OfferReport {
    fn new(content_key: StateContentKey, total: usize) -> Self {
        Self {
            content_key,
            total,
            success: Vec::new(),
            failed: Vec::new(),
            declined: Vec::new(),
        }
    }

    fn update(&mut self, enr: &Enr, trace: &OfferTrace) {
        match trace {
            // since the state bridge only offers one content key at a time,
            // we can assume that a successful offer means the lone content key
            // was successfully offered
            OfferTrace::Success(_) => self.success.push(enr.clone()),
            OfferTrace::Failed => self.failed.push(enr.clone()),
            OfferTrace::Declined => self.declined.push(enr.clone()),
        }
        if self.total == self.success.len() + self.failed.len() + self.declined.len() {
            self.report();
        }
    }

    fn report(&self) {
        if enabled!(Level::DEBUG) {
            debug!(
                "Successfully offered to {}/{} peers. Content key: {}. Declined: {:?}. Failed: {:?}",
                self.success.len(),
                self.total,
                self.content_key.to_hex(),
                self.declined,
                self.failed,
            );
        } else {
            info!(
                "Successfully offered to {}/{} peers. Content key: {}. Declined: {}. Failed: {}.",
                self.success.len(),
                self.total,
                self.content_key.to_hex(),
                self.declined.len(),
                self.failed.len(),
            );
        }
    }
}
