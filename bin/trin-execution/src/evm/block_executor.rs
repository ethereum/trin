use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::ensure;
use eth_trie::{RootWithTrieDiff, Trie};
use ethportal_api::{
    types::{execution::transaction::Transaction, state_trie::account_state::AccountState},
    Header,
};
use revm::{
    db::{states::bundle_state::BundleRetention, State},
    inspectors::TracerEip3155,
    DatabaseCommit, Evm,
};
use revm_primitives::{keccak256, Address, ResultAndState, SpecId, B256, U256};
use serde::{Deserialize, Serialize};
use tracing::info;
use trin_evm::{
    create_block_env, create_evm_with_tracer, spec_id::get_spec_id, tx_env_modifier::TxEnvModifier,
};

use super::post_block_beneficiaries::get_post_block_beneficiaries;
use crate::{
    era::types::{ProcessedBlock, TransactionsWithSender},
    evm::pre_block_contracts::apply_pre_block_contracts,
    metrics::{
        set_int_gauge_vec, start_timer_vec, stop_timer, BLOCK_HEIGHT, BLOCK_PROCESSING_TIMES,
        TRANSACTION_PROCESSING_TIMES,
    },
    storage::evm_db::EvmDB,
};

pub const BLOCKHASH_SERVE_WINDOW: u64 = 256;

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
///
/// The use case is
/// - initialize the BlockExecutor with a database
/// - execute blocks
/// - commit the changes and retrieve the result
pub struct BlockExecutor<'a> {
    /// The evm used for block execution.
    evm: Evm<'a, (), State<EvmDB>>,
    /// The time when BlockExecutor was created.
    creation_time: Instant,
    /// The number of executed blocks.
    executed_blocks: u64,
    /// Sum of gas used of all executed blocks.
    cumulative_gas_used: u64,
}

impl BlockExecutor<'_> {
    pub fn new(database: EvmDB) -> Self {
        let state_database = State::builder()
            .with_database(database)
            .with_bundle_update()
            .build();
        let evm: Evm<(), State<EvmDB>> = Evm::builder().with_db(state_database).build();

        Self {
            evm,
            creation_time: Instant::now(),
            executed_blocks: 0,
            cumulative_gas_used: 0,
        }
    }

    fn set_evm_environment(&mut self, header: &Header) {
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["initialize_evm"]);

        // update spec id
        let spec_id = get_spec_id(header.number);
        self.evm.modify_spec_id(spec_id);
        self.evm
            .db_mut()
            .set_state_clear_flag(spec_id.is_enabled_in(SpecId::SPURIOUS_DRAGON));

        // initialize evm environment
        *self.evm.block_mut() = create_block_env(header);
        self.evm.tx_mut().clear();

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
        let root_with_trie_diff = self
            .evm
            .db_mut()
            .database
            .trie
            .lock()
            .root_hash_with_changed_nodes()?;

        stop_timer(timer);

        Ok(root_with_trie_diff)
    }

    fn process_genesis(&mut self) -> anyhow::Result<()> {
        let genesis: GenesisConfig =
            serde_json::from_str(include_str!("../../resources/genesis/mainnet.json"))?;

        for (address, alloc_balance) in genesis.alloc {
            let address_hash = keccak256(address);
            let mut account = AccountState::default();
            account.balance += alloc_balance.balance;
            self.evm
                .db()
                .database
                .trie
                .lock()
                .insert(address_hash.as_ref(), &alloy::rlp::encode(&account))?;
            self.evm
                .db()
                .database
                .db
                .put(address_hash, alloy::rlp::encode(account))?;
        }

        Ok(())
    }

    pub fn execute_block(&mut self, block: &ProcessedBlock) -> anyhow::Result<()> {
        self.execute_block_with_tracer(block, |_| None)
    }

    pub fn execute_block_with_tracer(
        &mut self,
        block: &ProcessedBlock,
        tx_tracer_fn: impl Fn(&Transaction) -> Option<TracerEip3155>,
    ) -> anyhow::Result<()> {
        info!("State EVM processing block {}", block.header.number);

        let execute_block_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["execute_block"]);

        if block.header.number == 0 {
            self.process_genesis()?;
            return Ok(());
        }

        self.set_evm_environment(&block.header);

        // apply pre block contracts such as eip-4788
        apply_pre_block_contracts(&mut self.evm, &block.header)?;

        // execute transactions
        let cumulative_transaction_timer =
            start_timer_vec(&BLOCK_PROCESSING_TIMES, &["cumulative_transaction"]);
        let mut block_gas_used = 0;
        for transaction in block.transactions.iter() {
            let transaction_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["transaction"]);

            let evm_result = self.execute_transaction(transaction, &tx_tracer_fn)?;
            block_gas_used += evm_result.result.gas_used();

            let commit_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["commit_state"]);
            self.evm.db_mut().commit(evm_result.state);
            stop_timer(commit_timer);

            stop_timer(transaction_timer);
        }
        stop_timer(cumulative_transaction_timer);

        ensure!(
            block_gas_used == block.header.gas_used.to::<u64>(),
            "Block gas used mismatch at {} != {}",
            block_gas_used,
            block.header.gas_used
        );
        self.executed_blocks += 1;
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
        tracer_fn: impl Fn(&Transaction) -> Option<TracerEip3155>,
    ) -> anyhow::Result<ResultAndState> {
        let block_number = self.evm.block().number.to();

        // Set transaction environment
        let timer = start_timer_vec(&TRANSACTION_PROCESSING_TIMES, &["modify_tx"]);
        tx.modify(block_number, self.evm.tx_mut());
        stop_timer(timer);

        // Execute transaction
        let timer = start_timer_vec(&TRANSACTION_PROCESSING_TIMES, &["transact"]);
        let result = match tracer_fn(&tx.transaction) {
            Some(tracer) => {
                create_evm_with_tracer(self.evm.block().clone(), tx, self.evm.db_mut(), tracer)
                    .transact()?
            }
            None => self.evm.transact()?,
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

    /// This function is used to determine if we should commit the block execution early.
    ///
    /// We want this for a few reasons
    /// - To prevent memory usage from getting too high
    /// - To cap the amount of time it takes to commit everything to the database, the bigger the
    ///   changes the more time it takes.
    ///
    /// The various limits are arbitrary and can be adjusted as needed,
    /// but are based on the current state of the network and what we have seen so far.
    pub fn should_commit(&self) -> bool {
        self.executed_blocks >= 500_000
            || self.evm.db().bundle_size_hint() >= 5_000_000
            || self.cumulative_gas_used >= 30_000_000 * 50_000
            || self.creation_time.elapsed() >= Duration::from_secs(30 * 60)
    }
}
