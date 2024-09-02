use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use anyhow::{anyhow, bail, ensure};
use eth_trie::{RootWithTrieDiff, Trie};
use ethportal_api::types::{
    execution::transaction::Transaction,
    state_trie::account_state::AccountState as AccountStateInfo,
};
use revm::{
    db::states::{bundle_state::BundleRetention, State as RevmState},
    inspector_handle_register,
    inspectors::TracerEip3155,
    DatabaseCommit, Evm,
};
use revm_primitives::{Env, ResultAndState, SpecId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::info;

use crate::{
    block_reward::get_block_reward,
    dao_fork::process_dao_fork,
    era::{
        manager::EraManager,
        types::{ProcessedBlock, TransactionsWithSender},
    },
    metrics::{
        set_int_gauge_vec, start_timer_vec, stop_timer, BLOCK_HEIGHT, BLOCK_PROCESSING_TIMES,
        TRANSACTION_PROCESSING_TIMES,
    },
    spec_id::{get_spec_block_number, get_spec_id},
    storage::{
        account::Account,
        evm_db::EvmDB,
        execution_position::ExecutionPosition,
        utils::{get_default_data_dir, setup_rocksdb},
    },
    transaction::TxEnvModifier,
};

use super::{config::StateConfig, types::trie_proof::TrieProof, utils::address_to_nibble_path};

#[derive(Debug, Serialize, Deserialize)]
struct AllocBalance {
    balance: U256,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenesisConfig {
    alloc: HashMap<Address, AllocBalance>,
    state_root: B256,
}

pub struct State {
    pub database: EvmDB,
    pub config: StateConfig,
    execution_position: ExecutionPosition,
    pub era_manager: Arc<Mutex<EraManager>>,
    pub node_data_directory: PathBuf,
}

const GENESIS_STATE_FILE: &str = "trin-execution/resources/genesis/mainnet.json";
const TEST_GENESIS_STATE_FILE: &str = "resources/genesis/mainnet.json";

impl State {
    pub async fn new(path: Option<PathBuf>, config: StateConfig) -> anyhow::Result<Self> {
        let node_data_directory = match path {
            Some(path_buf) => path_buf,
            None => get_default_data_dir()?,
        };
        let db = Arc::new(setup_rocksdb(node_data_directory.clone())?);
        let execution_position = ExecutionPosition::initialize_from_db(db.clone())?;

        let database = EvmDB::new(config.clone(), db, &execution_position)
            .expect("Failed to create EVM database");

        let era_manager = Arc::new(Mutex::new(
            EraManager::new(execution_position.next_block_number()).await?,
        ));

        Ok(State {
            execution_position,
            config,
            era_manager,
            database,
            node_data_directory,
        })
    }

    pub fn initialize_genesis(&mut self) -> anyhow::Result<RootWithTrieDiff> {
        ensure!(
            self.execution_position.next_block_number() == 0,
            "Trying to initialize genesis but received block {}",
            self.execution_position.next_block_number(),
        );

        let genesis_file = if Path::new(GENESIS_STATE_FILE).is_file() {
            File::open(GENESIS_STATE_FILE)?
        } else if Path::new(TEST_GENESIS_STATE_FILE).is_file() {
            File::open(TEST_GENESIS_STATE_FILE)?
        } else {
            bail!("Genesis file not found")
        };
        let genesis: GenesisConfig = serde_json::from_reader(BufReader::new(genesis_file))?;

        for (address, alloc_balance) in genesis.alloc {
            let mut account = Account::default();
            account.balance += alloc_balance.balance;
            self.database.trie.lock().insert(
                keccak256(address).as_ref(),
                &alloy_rlp::encode(AccountStateInfo::from(&account)),
            )?;
            self.database
                .db
                .put(keccak256(address.as_slice()), alloy_rlp::encode(account))?;
        }

        let root_with_trie_diff = self.get_root_with_trie_diff()?;
        ensure!(
            root_with_trie_diff.root == genesis.state_root,
            "Root doesn't match state root from genesis file"
        );

        self.execution_position.set_next_block_number(
            self.database.db.clone(),
            1,
            root_with_trie_diff.root,
        )?;

        Ok(root_with_trie_diff)
    }

    /// This is a lot faster then process_block() as it executes the range in memory, but we won't
    /// return the trie diff so you can use this to sync up to the block you want, then use
    /// `process_block()` to get the trie diff to gossip on the state bridge
    pub async fn process_range_of_blocks(
        &mut self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<RootWithTrieDiff> {
        info!("Processing blocks from {} to {} (inclusive)", start, end);
        let database = RevmState::builder()
            .with_database(self.database.clone())
            .with_bundle_update()
            .build();

        let mut evm: Evm<(), RevmState<EvmDB>> = Evm::builder().with_db(database).build();
        let mut cumulative_gas_used = 0;
        let mut cumulative_gas_expected = 0;
        let range_start = Instant::now();
        let mut last_block_executed = start - 1;
        for block_number in start..=end {
            if get_spec_id(block_number).is_enabled_in(SpecId::SPURIOUS_DRAGON) {
                evm.db_mut().set_state_clear_flag(true);
            } else {
                evm.db_mut().set_state_clear_flag(false);
            };
            let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["fetching_block_from_era"]);
            let block = self
                .era_manager
                .lock()
                .await
                .get_next_block()
                .await?
                .clone();
            stop_timer(timer);

            // insert blockhash into database and remove old one
            let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["insert_blockhash"]);
            self.database.db.put(
                keccak256(B256::from(U256::from(block.header.number))),
                block.header.hash(),
            )?;
            if block.header.number >= 8192 {
                self.database.db.delete(keccak256(B256::from(U256::from(
                    block.header.number - 8192,
                ))))?;
            }
            stop_timer(timer);

            cumulative_gas_used += self.execute_block(&block, &mut evm)?;
            cumulative_gas_expected += block.header.gas_used.to::<u64>();
            last_block_executed = block_number;

            // Commit the bundle if we have reached the limits, to prevent to much memory usage
            // We won't use this during the dos attack to avoid writing empty accounts to disk
            if !(2_200_000..2_700_000).contains(&block_number)
                && should_we_commit_block_execution_early(
                    block_number - start,
                    evm.context.evm.db.bundle_size_hint() as u64,
                    cumulative_gas_used,
                    range_start.elapsed(),
                )
            {
                break;
            }
        }

        ensure!(
            cumulative_gas_used == cumulative_gas_expected,
            "Cumulative gas used doesn't match gas expected! Irreversible! Block number: {}",
            end
        );

        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["commit_bundle"]);
        evm.db_mut().merge_transitions(BundleRetention::PlainState);
        let state_bundle = evm.db_mut().take_bundle();
        self.database.commit_bundle(state_bundle)?;
        stop_timer(timer);

        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["get_root_with_trie_diff"]);
        let RootWithTrieDiff {
            root,
            trie_diff: changed_nodes,
        } = self.get_root_with_trie_diff()?;
        let header_state_root = self
            .era_manager
            .lock()
            .await
            .last_fetched_block()
            .await?
            .header
            .state_root;
        if root != header_state_root {
            panic!(
                "State root doesn't match! Irreversible! Block number: {}",
                last_block_executed
            )
        }
        stop_timer(timer);

        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["set_block_execution_number"]);
        self.execution_position.set_next_block_number(
            self.database.db.clone(),
            last_block_executed + 1,
            root,
        )?;
        stop_timer(timer);

        Ok(RootWithTrieDiff {
            root,
            trie_diff: changed_nodes,
        })
    }

    pub async fn process_block(&mut self, block_number: u64) -> anyhow::Result<RootWithTrieDiff> {
        self.process_range_of_blocks(block_number, block_number)
            .await
    }

    pub fn execute_block(
        &self,
        block: &ProcessedBlock,
        evm: &mut Evm<(), RevmState<EvmDB>>,
    ) -> anyhow::Result<u64> {
        let execute_block_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["execute_block"]);
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["initialize_evm"]);
        info!("State EVM processing block {}", block.header.number);

        // initialize evm environment
        let mut env = Env::default();
        env.block.number = U256::from(block.header.number);
        env.block.coinbase = block.header.author;
        env.block.timestamp = U256::from(block.header.timestamp);
        if get_spec_id(block.header.number).is_enabled_in(SpecId::MERGE) {
            env.block.difficulty = U256::ZERO;
            env.block.prevrandao = block.header.mix_hash;
        } else {
            env.block.difficulty = block.header.difficulty;
            env.block.prevrandao = None;
        }
        env.block.basefee = block.header.base_fee_per_gas.unwrap_or_default();
        env.block.gas_limit = block.header.gas_limit;

        // EIP-4844 excess blob gas of this block, introduced in Cancun
        if let Some(excess_blob_gas) = block.header.excess_blob_gas {
            env.block
                .set_blob_excess_gas_and_price(u64::from_be_bytes(excess_blob_gas.to_be_bytes()));
        }

        evm.context.evm.env = Box::new(env);
        evm.handler.modify_spec_id(get_spec_id(block.header.number));

        stop_timer(timer);

        // execute transactions
        let mut cumulative_gas_used = 0;

        let cumulative_transaction_timer =
            start_timer_vec(&BLOCK_PROCESSING_TIMES, &["cumulative_transaction"]);
        for transaction in block.transactions.iter() {
            let transaction_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["transaction"]);
            let transaction_execution_timer =
                start_timer_vec(&BLOCK_PROCESSING_TIMES, &["transaction_execution"]);
            let evm_result = self.execute_transaction(transaction, evm)?;
            cumulative_gas_used += evm_result.result.gas_used();
            stop_timer(transaction_execution_timer);
            let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["commit_state"]);
            evm.db_mut().commit(evm_result.state);
            stop_timer(timer);
            stop_timer(transaction_timer);
        }
        stop_timer(cumulative_transaction_timer);

        // update beneficiary
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["update_beneficiary"]);
        let _ = evm.db_mut().increment_balances(get_block_reward(block));

        // check if dao fork, if it is drain accounts and transfer it to beneficiary
        if block.header.number == get_spec_block_number(SpecId::DAO_FORK) {
            process_dao_fork(evm)?;
        }
        stop_timer(timer);
        stop_timer(execute_block_timer);
        set_int_gauge_vec(&BLOCK_HEIGHT, block.header.number as i64, &[]);
        Ok(cumulative_gas_used)
    }

    fn execute_transaction(
        &self,
        tx: &TransactionsWithSender,
        evm: &mut Evm<(), RevmState<EvmDB>>,
    ) -> anyhow::Result<ResultAndState> {
        let block_number = evm.context.evm.env.block.number.to::<u64>();

        let timer = start_timer_vec(&TRANSACTION_PROCESSING_TIMES, &["modify_tx"]);
        evm.context.evm.env.tx.caller = tx.sender_address;
        match &tx.transaction {
            Transaction::Legacy(tx) => tx.modify(block_number, &mut evm.context.evm.env.tx),
            Transaction::EIP1559(tx) => tx.modify(block_number, &mut evm.context.evm.env.tx),
            Transaction::AccessList(tx) => tx.modify(block_number, &mut evm.context.evm.env.tx),
            Transaction::Blob(tx) => tx.modify(block_number, &mut evm.context.evm.env.tx),
        }

        if self.config.block_to_trace.should_trace(block_number) {
            let output_path = self
                .node_data_directory
                .as_path()
                .join("evm_traces")
                .join(format!("block_{block_number}"));
            fs::create_dir_all(&output_path)?;
            let output_file =
                File::create(output_path.join(format!("tx_{}.json", tx.transaction.hash())))?;
            let mut evm_with_tracer = Evm::builder()
                .with_env(evm.context.evm.inner.env.clone())
                .with_spec_id(evm.handler.cfg.spec_id)
                .with_db(&mut evm.context.evm.inner.db)
                .with_external_context(TracerEip3155::new(Box::new(output_file)))
                .append_handler_register(inspector_handle_register)
                .build();
            let result = evm_with_tracer.transact()?;
            return Ok(result);
        };
        stop_timer(timer);

        let timer = start_timer_vec(&TRANSACTION_PROCESSING_TIMES, &["transact"]);
        let result = evm.transact()?;
        stop_timer(timer);
        Ok(result)
    }

    pub fn next_block_number(&self) -> u64 {
        self.execution_position.next_block_number()
    }

    pub fn get_root(&mut self) -> anyhow::Result<B256> {
        Ok(self.database.trie.lock().root_hash()?)
    }

    pub fn get_root_with_trie_diff(&mut self) -> anyhow::Result<RootWithTrieDiff> {
        Ok(self.database.trie.lock().root_hash_with_changed_nodes()?)
    }

    pub fn get_account_state(&self, account: &Address) -> anyhow::Result<AccountStateInfo> {
        let account_state = self.database.db.get(keccak256(account))?;
        match account_state {
            Some(account) => {
                let account: Account = Decodable::decode(&mut account.as_slice())?;
                Ok(AccountStateInfo::from(&account))
            }
            None => Ok(AccountStateInfo::default()),
        }
    }

    pub fn get_proof(&mut self, address: Address) -> anyhow::Result<TrieProof> {
        let proof: Vec<Bytes> = self
            .database
            .trie
            .lock()
            .get_proof(keccak256(address).as_slice())?
            .into_iter()
            .map(Bytes::from)
            .collect();
        let last_node = proof.last().ok_or(anyhow!("Missing proof!"))?;

        let eth_trie::node::Node::Leaf(last_node) = eth_trie::decode_node(&mut last_node.as_ref())?
        else {
            bail!("Last node in the proof should be leaf!")
        };
        let mut last_node_nibbles = last_node.key.clone();
        if last_node_nibbles.is_leaf() {
            last_node_nibbles.pop();
        } else {
            bail!("Nibbles of the last node should have LEAF Marker")
        }

        let mut path = address_to_nibble_path(address);
        if path.ends_with(last_node_nibbles.get_data()) {
            path.truncate(path.len() - last_node_nibbles.len());
        } else {
            bail!("Path should have a suffix of last node's nibbles")
        }

        Ok(TrieProof { path, proof })
    }

    pub fn get_proofs(&mut self, accounts: &BTreeSet<Address>) -> anyhow::Result<Vec<TrieProof>> {
        accounts
            .iter()
            .map(|account| self.get_proof(*account))
            .collect()
    }
}

/// This function is used to determine if we should commit the block execution early.
/// We want this for a few reasons
/// - To prevent memory usage from getting too high
/// - To cap the amount of time it takes to commit everything to the database, the bigger the
///   changes the more time it takes The various limits are arbitrary and can be adjusted as needed,
///   but are based on the current state of the network and what we have seen so far
pub fn should_we_commit_block_execution_early(
    blocks_processed: u64,
    pending_cache_size_mb: u64,
    cumulative_gas_used: u64,
    elapsed: Duration,
) -> bool {
    blocks_processed >= 500_000
        || pending_cache_size_mb >= 5_000_000
        || cumulative_gas_used >= 30_000_000 * 50_000
        || elapsed >= Duration::from_secs(30 * 60)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        config::StateConfig, era::utils::process_era1_file, storage::utils::setup_temp_dir,
    };

    use super::State;
    use alloy_primitives::Address;
    use revm_primitives::hex::FromHex;

    #[tokio::test]
    async fn test_we_generate_the_correct_state_root_for_the_first_8192_blocks() {
        let temp_directory = setup_temp_dir().unwrap();
        let mut state = State::new(
            Some(temp_directory.path().to_path_buf()),
            StateConfig::default(),
        )
        .await
        .unwrap();
        let _ = state.initialize_genesis().unwrap();
        let raw_era1 = fs::read("../test_assets/era1/mainnet-00000-5ec1ffb8.era1").unwrap();
        let processed_era = process_era1_file(raw_era1, 0).unwrap();
        for block in processed_era.blocks {
            if block.header.number == 0 {
                // initialize genesis state processes this block so we skip it
                state
                    .era_manager
                    .lock()
                    .await
                    .get_next_block()
                    .await
                    .unwrap();
                continue;
            }
            state.process_block(block.header.number).await.unwrap();
            assert_eq!(state.get_root().unwrap(), block.header.state_root);
        }
    }

    #[tokio::test]
    async fn test_get_proof() {
        let temp_directory = setup_temp_dir().unwrap();
        let mut state = State::new(
            Some(temp_directory.path().to_path_buf()),
            StateConfig::default(),
        )
        .await
        .unwrap();
        let _ = state.initialize_genesis().unwrap();
        let valid_proof = state
            .get_proof(Address::from_hex("0x001d14804b399c6ef80e64576f657660804fec0b").unwrap())
            .unwrap();
        assert_eq!(valid_proof.path, [5, 9, 2, 13]);
        // the proof is already tested by eth-trie.rs
    }
}
