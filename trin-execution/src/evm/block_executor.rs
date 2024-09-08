use std::{
    collections::HashMap,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure};
use eth_trie::{RootWithTrieDiff, Trie};
use ethportal_api::{
    types::{
        execution::transaction::Transaction,
        state_trie::account_state::AccountState as AccountStateInfo,
    },
    Header,
};
use revm::{
    db::{states::bundle_state::BundleRetention, State},
    inspectors::TracerEip3155,
    DatabaseCommit, Evm,
};
use revm_primitives::{keccak256, Address, Env, ResultAndState, SpecId, B256, U256};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    era::types::{ProcessedBlock, TransactionsWithSender},
    evm::post_block_beneficiaries::get_post_block_beneficiaries,
    metrics::{
        set_int_gauge_vec, start_timer_vec, stop_timer, BLOCK_HEIGHT, BLOCK_PROCESSING_TIMES,
        TRANSACTION_PROCESSING_TIMES,
    },
    spec_id::get_spec_id,
    storage::{account::Account as RocksAccount, evm_db::EvmDB},
    transaction::TxEnvModifier,
    types::block_to_trace::BlockToTrace,
};

use super::blocking::execute_transaction_with_external_context;

const BLOCKHASH_SERVE_WINDOW: u64 = 256;
const GENESIS_STATE_FILE: &str = "trin-execution/resources/genesis/mainnet.json";
const TEST_GENESIS_STATE_FILE: &str = "resources/genesis/mainnet.json";

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

/// BlockExecutor is a struct that is responsible for executing blocks or a block in memory.
/// The use case is
/// - initialize the BlockExecutor with a database
/// - execute blocks
/// - commit the changes and retrieve the result
pub struct BlockExecutor<'a> {
    evm: Evm<'a, (), State<EvmDB>>,
    cumulative_gas_used: u64,
    block_to_trace: BlockToTrace,
    node_data_directory: PathBuf,
}

impl<'a> BlockExecutor<'a> {
    pub fn new(
        database: EvmDB,
        block_to_trace: BlockToTrace,
        node_data_directory: PathBuf,
    ) -> Self {
        let state_database = State::builder()
            .with_database(database)
            .with_bundle_update()
            .build();
        let evm: Evm<(), State<EvmDB>> = Evm::builder().with_db(state_database).build();

        Self {
            evm,
            cumulative_gas_used: 0,
            block_to_trace,
            node_data_directory,
        }
    }

    fn set_evm_environment_from_block(&mut self, header: &Header) {
        let timer: prometheus_exporter::prometheus::HistogramTimer =
            start_timer_vec(&BLOCK_PROCESSING_TIMES, &["initialize_evm"]);
        if get_spec_id(header.number).is_enabled_in(SpecId::SPURIOUS_DRAGON) {
            self.evm.db_mut().set_state_clear_flag(true);
        } else {
            self.evm.db_mut().set_state_clear_flag(false);
        };

        // initialize evm environment
        let mut env = Env::default();
        env.block.number = U256::from(header.number);
        env.block.coinbase = header.author;
        env.block.timestamp = U256::from(header.timestamp);
        if get_spec_id(header.number).is_enabled_in(SpecId::MERGE) {
            env.block.difficulty = U256::ZERO;
            env.block.prevrandao = header.mix_hash;
        } else {
            env.block.difficulty = header.difficulty;
            env.block.prevrandao = None;
        }
        env.block.basefee = header.base_fee_per_gas.unwrap_or_default();
        env.block.gas_limit = header.gas_limit;

        // EIP-4844 excess blob gas of this block, introduced in Cancun
        if let Some(excess_blob_gas) = header.excess_blob_gas {
            env.block
                .set_blob_excess_gas_and_price(u64::from_be_bytes(excess_blob_gas.to_be_bytes()));
        }

        self.evm.context.evm.env = Box::new(env);
        self.evm.handler.modify_spec_id(get_spec_id(header.number));
        stop_timer(timer);
    }

    fn set_transaction_evm_context(&mut self, tx: &TransactionsWithSender) {
        let timer = start_timer_vec(&TRANSACTION_PROCESSING_TIMES, &["modify_tx"]);

        let block_number = self.block_number();
        let tx_env = &mut self.evm.context.evm.env.tx;

        tx_env.caller = tx.sender_address;
        match &tx.transaction {
            Transaction::Legacy(tx) => tx.modify(block_number, tx_env),
            Transaction::EIP1559(tx) => tx.modify(block_number, tx_env),
            Transaction::AccessList(tx) => tx.modify(block_number, tx_env),
            Transaction::Blob(tx) => tx.modify(block_number, tx_env),
        }
        stop_timer(timer);
    }

    fn increment_balances(
        &mut self,
        balances: impl IntoIterator<Item = (Address, u128)>,
    ) -> anyhow::Result<()> {
        Ok(self.evm.db_mut().increment_balances(balances)?)
    }

    pub fn commit_bundle(mut self) -> anyhow::Result<RootWithTrieDiff> {
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["commit_bundle"]);
        self.evm
            .db_mut()
            .merge_transitions(BundleRetention::PlainState);
        let state_bundle = self.evm.db_mut().take_bundle();
        self.evm.db_mut().database.commit_bundle(state_bundle)?;
        stop_timer(timer);

        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["get_root_with_trie_diff"]);
        let RootWithTrieDiff {
            root,
            trie_diff: changed_nodes,
        } = self
            .evm
            .db_mut()
            .database
            .trie
            .lock()
            .root_hash_with_changed_nodes()?;

        stop_timer(timer);

        Ok(RootWithTrieDiff {
            root,
            trie_diff: changed_nodes,
        })
    }

    fn process_genesis(&mut self) -> anyhow::Result<()> {
        let genesis_file = if Path::new(GENESIS_STATE_FILE).is_file() {
            File::open(GENESIS_STATE_FILE)?
        } else if Path::new(TEST_GENESIS_STATE_FILE).is_file() {
            File::open(TEST_GENESIS_STATE_FILE)?
        } else {
            bail!("Genesis file not found")
        };
        let genesis: GenesisConfig = serde_json::from_reader(BufReader::new(genesis_file))?;

        for (address, alloc_balance) in genesis.alloc {
            let address_hash = keccak256(address);
            let mut account = RocksAccount::default();
            account.balance += alloc_balance.balance;
            self.evm.db().database.trie.lock().insert(
                address_hash.as_ref(),
                &alloy_rlp::encode(AccountStateInfo::from(&account)),
            )?;
            self.evm
                .db()
                .database
                .db
                .put(address_hash, alloy_rlp::encode(account))?;
        }

        Ok(())
    }

    pub fn execute_block(&mut self, block: &ProcessedBlock) -> anyhow::Result<()> {
        info!("State EVM processing block {}", block.header.number);

        let execute_block_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["execute_block"]);

        if block.header.number == 0 {
            self.process_genesis()?;
            return Ok(());
        }

        self.set_evm_environment_from_block(&block.header);

        // execute transactions
        let cumulative_transaction_timer =
            start_timer_vec(&BLOCK_PROCESSING_TIMES, &["cumulative_transaction"]);
        let mut block_gas_used = 0;
        for transaction in block.transactions.iter() {
            let transaction_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["transaction"]);
            let evm_result = self.execute_transaction(transaction)?;
            block_gas_used += evm_result.result.gas_used();
            let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["commit_state"]);
            self.evm.db_mut().commit(evm_result.state);
            stop_timer(timer);
            stop_timer(transaction_timer);
        }
        stop_timer(cumulative_transaction_timer);

        ensure!(
            block_gas_used == block.header.gas_used.to::<u64>(),
            "Block gas used mismatch at {} != {}",
            block_gas_used,
            block.header.gas_used
        );
        self.cumulative_gas_used += block_gas_used;

        // update beneficiaries
        let beneficiary_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["update_beneficiary"]);
        let beneficiaries = get_post_block_beneficiaries(&mut self.evm, block)?;
        let _ = self.increment_balances(beneficiaries);
        stop_timer(beneficiary_timer);

        self.manage_block_hash_serve_window(&block.header)?;

        stop_timer(execute_block_timer);
        set_int_gauge_vec(&BLOCK_HEIGHT, block.header.number as i64, &[]);
        Ok(())
    }

    fn execute_transaction(
        &mut self,
        tx: &TransactionsWithSender,
    ) -> anyhow::Result<ResultAndState> {
        self.set_transaction_evm_context(tx);
        let block_number = self.block_number();

        let timer = start_timer_vec(&TRANSACTION_PROCESSING_TIMES, &["transact"]);

        let result = if self.block_to_trace.should_trace(block_number) {
            let output_path = self
                .node_data_directory
                .as_path()
                .join("evm_traces")
                .join(format!("block_{block_number}"));
            fs::create_dir_all(&output_path)?;
            let output_file =
                File::create(output_path.join(format!("tx_{}.json", tx.transaction.hash())))?;
            let tracer = TracerEip3155::new(Box::new(output_file));
            execute_transaction_with_external_context(
                *self.evm.context.evm.inner.env.clone(),
                tracer,
                &mut self.evm.context.evm.inner.db,
            )?
        } else {
            self.evm.transact()?
        };
        stop_timer(timer);

        Ok(result)
    }

    /// insert block hash into database and remove old one
    fn manage_block_hash_serve_window(&self, header: &Header) -> anyhow::Result<()> {
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["insert_blockhash"]);
        self.evm.db().database.db.put(
            keccak256(B256::from(U256::from(header.number))),
            header.hash(),
        )?;
        if header.number >= BLOCKHASH_SERVE_WINDOW {
            self.evm
                .db()
                .database
                .db
                .delete(keccak256(B256::from(U256::from(
                    header.number - BLOCKHASH_SERVE_WINDOW,
                ))))?;
        }
        stop_timer(timer);
        Ok(())
    }

    pub fn cumulative_gas_used(&self) -> u64 {
        self.cumulative_gas_used
    }

    pub fn bundle_size_hint(&self) -> usize {
        self.evm.db().bundle_size_hint()
    }

    fn block_number(&self) -> u64 {
        self.evm.context.evm.env.block.number.to::<u64>()
    }
}
