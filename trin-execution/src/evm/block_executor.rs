use std::{
    collections::HashMap,
    fs::{self, File},
    path::PathBuf,
};

use anyhow::ensure;
use eth_trie::{RootWithTrieDiff, Trie};
use ethportal_api::types::execution::transaction::Transaction;
use revm::{
    db::{states::bundle_state::BundleRetention, State},
    inspectors::TracerEip3155,
    DatabaseCommit, Evm,
};
use revm_primitives::{keccak256, Account, Address, Env, ResultAndState, SpecId, B256, U256};
use tracing::info;

use crate::{
    block_reward::get_block_reward,
    dao_fork::{DAO_HARDFORK_BENEFICIARY, DAO_HARDKFORK_ACCOUNTS},
    era::types::{ProcessedBlock, TransactionsWithSender},
    metrics::{
        set_int_gauge_vec, start_timer_vec, stop_timer, BLOCK_HEIGHT, BLOCK_PROCESSING_TIMES,
        TRANSACTION_PROCESSING_TIMES,
    },
    spec_id::{get_spec_block_number, get_spec_id},
    storage::evm_db::EvmDB,
    transaction::TxEnvModifier,
    types::block_to_trace::BlockToTrace,
};

use super::blocking::execute_transaction_with_external_context;

const BLOCKHASH_SERVE_WINDOW: u64 = 256;

/// BlockExecutor is a struct that is responsible for executing blocks or a block in memory.
/// The use case is
/// - initialize the BlockExecutor with a database
/// - execute blocks
/// - commit the changes and retrieve the result
pub struct BlockExecutor<'a> {
    pub evm: Evm<'a, (), State<EvmDB>>,
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

    fn set_evm_environment_from_block(&mut self, block: &ProcessedBlock) {
        let timer: prometheus_exporter::prometheus::HistogramTimer =
            start_timer_vec(&BLOCK_PROCESSING_TIMES, &["initialize_evm"]);
        if get_spec_id(block.header.number).is_enabled_in(SpecId::SPURIOUS_DRAGON) {
            self.evm.db_mut().set_state_clear_flag(true);
        } else {
            self.evm.db_mut().set_state_clear_flag(false);
        };

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

        self.evm.context.evm.env = Box::new(env);
        self.evm
            .handler
            .modify_spec_id(get_spec_id(block.header.number));
        stop_timer(timer);
    }

    pub fn set_transaction_evm_context(&mut self, tx: &TransactionsWithSender) {
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

    pub fn commit(&mut self, evm_state: HashMap<Address, Account>) {
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["commit_state"]);
        self.evm.db_mut().commit(evm_state);
        stop_timer(timer);
    }

    pub fn transact(&mut self) -> anyhow::Result<ResultAndState> {
        Ok(self.evm.transact()?)
    }

    pub fn increment_balances(
        &mut self,
        balances: impl IntoIterator<Item = (Address, u128)>,
    ) -> anyhow::Result<()> {
        Ok(self.evm.db_mut().increment_balances(balances)?)
    }

    pub fn process_dao_fork(&mut self) -> anyhow::Result<()> {
        // drain balances from DAO hardfork accounts
        let drained_balances = self.evm.db_mut().drain_balances(DAO_HARDKFORK_ACCOUNTS)?;
        let drained_balance_sum: u128 = drained_balances.iter().sum();

        // transfer drained balance to beneficiary
        self.increment_balances([(DAO_HARDFORK_BENEFICIARY, drained_balance_sum)].into_iter())?;

        Ok(())
    }

    pub fn commit_bundle(&mut self) -> anyhow::Result<RootWithTrieDiff> {
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

    pub fn execute_block(&mut self, block: &ProcessedBlock) -> anyhow::Result<()> {
        info!("State EVM processing block {}", block.header.number);

        let execute_block_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["execute_block"]);
        self.set_evm_environment_from_block(block);

        // execute transactions
        let cumulative_transaction_timer =
            start_timer_vec(&BLOCK_PROCESSING_TIMES, &["cumulative_transaction"]);
        let mut block_gas_used = 0;
        for transaction in block.transactions.iter() {
            let transaction_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["transaction"]);
            let evm_result = self.execute_transaction(transaction)?;
            block_gas_used += evm_result.result.gas_used();
            self.commit(evm_result.state);
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

        // update beneficiary
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["update_beneficiary"]);
        let _ = self.increment_balances(get_block_reward(block));

        // check if dao fork, if it is drain accounts and transfer it to beneficiary
        if block.header.number == get_spec_block_number(SpecId::DAO_FORK) {
            self.process_dao_fork()?;
        }

        self.manage_block_hash_serve_window(block)?;

        stop_timer(timer);
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
            self.transact()?
        };
        stop_timer(timer);

        Ok(result)
    }

    /// insert block hash into database and remove old one
    fn manage_block_hash_serve_window(&self, block: &ProcessedBlock) -> anyhow::Result<()> {
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["insert_blockhash"]);
        self.evm.db().database.db.put(
            keccak256(B256::from(U256::from(block.header.number))),
            block.header.hash(),
        )?;
        if block.header.number >= BLOCKHASH_SERVE_WINDOW {
            self.evm
                .db()
                .database
                .db
                .delete(keccak256(B256::from(U256::from(
                    block.header.number - BLOCKHASH_SERVE_WINDOW,
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

    pub fn block_number(&self) -> u64 {
        self.evm.context.evm.env.block.number.to::<u64>()
    }
}
