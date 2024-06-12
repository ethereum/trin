use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::EMPTY_STRING_CODE;
use anyhow::{anyhow, bail, ensure, Error};
use eth_trie::{RootWithTrieDiff, Trie};
use ethportal_api::types::{
    execution::transaction::Transaction,
    state_trie::account_state::AccountState as AccountStateInfo,
};
use revm::{
    db::EmptyDB, inspector_handle_register, inspectors::NoOpInspector, DatabaseCommit, Evm,
};
use revm_primitives::{Env, SpecId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::BufReader,
};
use tracing::info;

use crate::types::{
    era1::BlockTuple,
    state::{
        block_reward::get_block_reward,
        database::{CacheDB, DbAccount},
        spec_id::get_spec_id,
        transaction::TxEnvModifier,
    },
};

use super::trie_walker::AccountProof;

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
    pub database: CacheDB<EmptyDB>,
    next_block_number: u64,
}

const GENESIS_STATE_FILE: &str = "resources/genesis/mainnet.json";

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        State {
            next_block_number: 0,
            database: CacheDB::new(EmptyDB::default()),
        }
    }

    pub fn initialize_genesis(&mut self) -> anyhow::Result<RootWithTrieDiff> {
        ensure!(
            self.next_block_number == 0,
            "Trying to initialize genesis but received block {}",
            self.next_block_number,
        );

        let genesis_file = File::open(GENESIS_STATE_FILE)?;
        let genesis: GenesisConfig = serde_json::from_reader(BufReader::new(genesis_file))?;

        for (address, alloc_balance) in genesis.alloc {
            let mut account = DbAccount::default();
            account.info.balance += alloc_balance.balance;
            let account_info = account.info.clone();
            self.database.accounts.insert(address, account);
            self.database.trie.lock().insert(
                keccak256(address).as_ref(),
                &alloy_rlp::encode(AccountStateInfo {
                    nonce: account_info.nonce,
                    balance: account_info.balance,
                    storage_root: keccak256([EMPTY_STRING_CODE]),
                    code_hash: account_info.code_hash,
                }),
            )?;
        }

        let root_with_trie_diff = self.get_root_with_trie_diff()?;
        ensure!(
            root_with_trie_diff.root == genesis.state_root,
            "Root doesn't match state root from genesis file"
        );

        self.next_block_number += 1;

        Ok(root_with_trie_diff)
    }

    pub fn process_block(&mut self, block_tuple: &BlockTuple) -> anyhow::Result<RootWithTrieDiff> {
        info!(
            "State EVM processing block {}",
            block_tuple.header.header.number
        );
        ensure!(
            self.next_block_number == block_tuple.header.header.number,
            "Expected block {}, received {}",
            self.next_block_number,
            block_tuple.header.header.number
        );

        // initialize evm environment
        let mut env = Env::default();
        env.block.number = U256::from(block_tuple.header.header.number);
        env.block.coinbase = block_tuple.header.header.author;
        env.block.timestamp = U256::from(block_tuple.header.header.timestamp);
        if get_spec_id(block_tuple.header.header.number).is_enabled_in(SpecId::MERGE) {
            env.block.difficulty = U256::ZERO;
            env.block.prevrandao = block_tuple.header.header.mix_hash;
        } else {
            env.block.difficulty = block_tuple.header.header.difficulty;
            env.block.prevrandao = None;
        }
        env.block.basefee = block_tuple
            .header
            .header
            .base_fee_per_gas
            .unwrap_or_default();
        env.block.gas_limit = block_tuple.header.header.gas_limit;

        // EIP-4844 excess blob gas of this block, introduced in Cancun
        if let Some(excess_blob_gas) = block_tuple.header.header.excess_blob_gas {
            env.block
                .set_blob_excess_gas_and_price(u64::from_be_bytes(excess_blob_gas.to_be_bytes()));
        }

        // insert blockhash into database
        self.database.block_hashes.insert(
            U256::from(block_tuple.header.header.number),
            block_tuple.header.header.hash(),
        );

        // execute transactions
        let transactions = block_tuple
            .body
            .body
            .transactions()
            .map_err(|err| Error::msg(format!("Error getting transactions: {err:?}")))?;
        for transaction in transactions {
            self.execute_transaction(transaction, &env)?;
        }

        // update beneficiary
        for (beneficiary, reward) in get_block_reward(block_tuple) {
            let mut account = self.get_account_state(&beneficiary)?;
            account.balance += U256::from(reward);
            self.database
                .trie
                .lock()
                .insert(keccak256(beneficiary).as_ref(), &alloy_rlp::encode(account))?;

            match self.database.accounts.get_mut(&beneficiary) {
                Some(account) => {
                    account.info.balance += U256::from(reward);
                }
                None => {
                    let mut account = DbAccount::default();
                    account.info.balance += U256::from(reward);
                    self.database.accounts.insert(beneficiary, account);
                }
            }
        }

        let RootWithTrieDiff {
            root,
            trie_diff: changed_nodes,
        } = self.get_root_with_trie_diff()?;
        if root != block_tuple.header.header.state_root {
            panic!(
                "State root doesn't match! Irreversible! Block number: {}",
                self.next_block_number
            )
        }

        self.next_block_number += 1;

        Ok(RootWithTrieDiff {
            root,
            trie_diff: changed_nodes,
        })
    }

    fn execute_transaction(
        &mut self,
        tx: Transaction,
        evm_evnironment: &Env,
    ) -> anyhow::Result<()> {
        let block_number = evm_evnironment.block.number.to::<u64>();
        let evm_result = Evm::builder()
            .with_ref_db(&self.database)
            .with_env(Box::new(evm_evnironment.clone()))
            .with_spec_id(get_spec_id(block_number))
            .modify_tx_env(|tx_env| {
                tx_env.caller = tx
                    .get_transaction_sender_address(
                        get_spec_id(block_number).is_enabled_in(SpecId::SPURIOUS_DRAGON),
                    )
                    .expect("We should always be able to get the sender address of a transaction");
                match tx {
                    Transaction::Legacy(tx) => tx.modify(block_number, tx_env),
                    Transaction::EIP1559(tx) => tx.modify(block_number, tx_env),
                    Transaction::AccessList(tx) => tx.modify(block_number, tx_env),
                    Transaction::Blob(tx) => tx.modify(block_number, tx_env),
                }
            })
            .with_external_context(NoOpInspector)
            .append_handler_register(inspector_handle_register)
            .build()
            .transact()?;
        self.database.commit(evm_result.state);
        Ok(())
    }

    pub fn get_root(&mut self) -> anyhow::Result<B256> {
        Ok(self.database.trie.lock().root_hash()?)
    }

    pub fn get_root_with_trie_diff(&mut self) -> anyhow::Result<RootWithTrieDiff> {
        Ok(self.database.trie.lock().root_hash_with_changed_nodes()?)
    }

    pub fn get_account_state(&self, account: &Address) -> anyhow::Result<AccountStateInfo> {
        let account_state = self.database.accounts.get(account);
        match account_state {
            Some(account_db) => Ok(AccountStateInfo {
                nonce: account_db.info.nonce,
                balance: account_db.info.balance,
                storage_root: account_db.trie.lock().root_hash()?,
                code_hash: account_db.info.code_hash,
            }),
            None => Ok(AccountStateInfo::default()),
        }
    }

    pub fn get_proof(&mut self, account: &Address) -> anyhow::Result<AccountProof> {
        let proof: Vec<Bytes> = self
            .database
            .trie
            .lock()
            .get_proof(keccak256(account).as_slice())?
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

        let mut path: Vec<u8> = keccak256(*account)
            .into_iter()
            .flat_map(|b| [b >> 4, b & 0xF])
            .collect();
        if path.ends_with(last_node_nibbles.get_data()) {
            path.truncate(path.len() - last_node_nibbles.len());
        } else {
            bail!("Path should have a suffix of last node's nibbles")
        }

        Ok(AccountProof { path, proof })
    }

    pub fn get_proofs(
        &mut self,
        accounts: &BTreeSet<Address>,
    ) -> anyhow::Result<Vec<AccountProof>> {
        accounts
            .iter()
            .map(|account| self.get_proof(account))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::types::era1::Era1;

    use super::State;
    use alloy_primitives::Address;
    use revm_primitives::hex::FromHex;

    #[test_log::test]
    fn test_we_generate_the_correct_state_root_for_the_first_8192_blocks() {
        let mut state = State::new();
        let _ = state.initialize_genesis();
        let raw_era1 = fs::read("../test_assets/era1/mainnet-00000-5ec1ffb8.era1").unwrap();
        for block_tuple in Era1::iter_tuples(raw_era1) {
            if block_tuple.header.header.number == 0 {
                continue;
            }
            state.process_block(&block_tuple).unwrap();
            assert_eq!(
                state.get_root().unwrap(),
                block_tuple.header.header.state_root
            );
        }
    }

    #[test_log::test]
    fn test_get_proof() {
        let mut state = State::new();
        let _ = state.initialize_genesis().unwrap();
        let valid_proof = state
            .get_proof(&Address::from_hex("0x001d14804b399c6ef80e64576f657660804fec0b").unwrap())
            .unwrap();
        assert_eq!(valid_proof.path, [5, 9, 2, 13]);
        // the proof is already tested by eth-trie.rs
    }
}
