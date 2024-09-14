use std::{
    collections::HashMap,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure};
use eth_trie::{RootWithTrieDiff, Trie};
use ethportal_api::{types::state_trie::account_state::AccountState, Header};
use revm::{
    db::{states::bundle_state::BundleRetention, State},
    inspectors::TracerEip3155,
    DatabaseCommit, Evm,
};
use revm_primitives::{keccak256, Address, ResultAndState, SpecId, B256, U256};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    era::types::{ProcessedBlock, TransactionsWithSender},
    metrics::{
        set_int_gauge_vec, start_timer_vec, stop_timer, BLOCK_HEIGHT, BLOCK_PROCESSING_TIMES,
        TRANSACTION_PROCESSING_TIMES,
    },
    storage::evm_db::EvmDB,
    types::block_to_trace::BlockToTrace,
};

use super::{
    create_block_env, create_evm_with_tracer,
    post_block_beneficiaries::get_post_block_beneficiaries, spec_id::get_spec_id,
    tx_env_modifier::TxEnvModifier,
};

pub const BLOCKHASH_SERVE_WINDOW: u64 = 256;
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
            let mut account = AccountState::default();
            account.balance += alloc_balance.balance;
            self.evm
                .db()
                .database
                .trie
                .lock()
                .insert(address_hash.as_ref(), &alloy_rlp::encode(&account))?;
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

        self.set_evm_environment(&block.header);

        // execute transactions
        let cumulative_transaction_timer =
            start_timer_vec(&BLOCK_PROCESSING_TIMES, &["cumulative_transaction"]);
        let mut block_gas_used = 0;
        for transaction in block.transactions.iter() {
            let transaction_timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["transaction"]);

            let evm_result = self.execute_transaction(transaction)?;
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
        let block_number = self.evm.block().number.to();

        // Set transaction environment
        let timer = start_timer_vec(&TRANSACTION_PROCESSING_TIMES, &["modify_tx"]);
        tx.modify(block_number, self.evm.tx_mut());
        stop_timer(timer);

        // Execute transaction
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

            create_evm_with_tracer(self.evm.block().clone(), tx, self.evm.db_mut(), tracer)
                .transact()?
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
}
