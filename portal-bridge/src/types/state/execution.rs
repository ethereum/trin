use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use anyhow::{ensure, Error};
use eth_trie::{EthTrie, MemoryDB, Trie};
use ethportal_api::types::state_trie::account_state::AccountState;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::BufReader,
    sync::Arc,
};

use crate::types::{era1::BlockTuple, state::block_reward::get_block_reward};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountProof {
    pub address: Address,
    pub state: AccountState,
    pub proof: Vec<Bytes>,
}

#[warn(dead_code)]
pub struct State {
    pub accounts: BTreeSet<Address>,
    trie: Box<EthTrie<MemoryDB>>,
    next_block_number: u64,
}

const GENESIS_STATE_FILE: &str = "resources/genesis/mainnet.json";

impl State {
    pub fn new() -> anyhow::Result<Self> {
        let mut trie = EthTrie::new(Arc::new(MemoryDB::new(false)));
        let mut accounts = BTreeSet::new();

        let genesis_file = File::open(GENESIS_STATE_FILE)?;
        let genesis: GenesisConfig = serde_json::from_reader(BufReader::new(genesis_file))?;

        for (address, alloc_balance) in genesis.alloc {
            accounts.insert(address);

            let mut account = AccountState::default();
            account.balance += alloc_balance.balance;
            trie.insert(keccak256(address).as_ref(), &alloy_rlp::encode(account))?;
        }

        let root = B256::from_slice(trie.root_hash()?.as_slice());
        ensure!(
            root == genesis.state_root,
            "Root doesn't match state root from genesis file"
        );
        Ok(State {
            accounts,
            trie: Box::from(trie),
            next_block_number: 1,
        })
    }

    pub fn process_block(&mut self, block_tuple: &BlockTuple) -> anyhow::Result<BTreeSet<Address>> {
        ensure!(
            self.next_block_number == block_tuple.header.header.number,
            "Expected block {}, received {}",
            self.next_block_number,
            block_tuple.header.header.number
        );

        let mut updated_accounts = BTreeSet::new();
        // execute transactions
        let transactions = block_tuple
            .body
            .body
            .transactions()
            .map_err(|err| Error::msg(format!("Error getting transactions: {err:?}")))?;
        for _tranasction in transactions {}

        // update beneficiary
        for (beneficiary, reward) in get_block_reward(block_tuple) {
            let mut account = self.get_account_state(&beneficiary)?;
            account.balance += U256::from(reward);
            self.trie
                .insert(keccak256(beneficiary).as_ref(), &alloy_rlp::encode(account))?;

            self.accounts.insert(beneficiary);
            updated_accounts.insert(beneficiary);
        }

        if self.get_root()? != block_tuple.header.header.state_root {
            panic!(
                "State root doesn't match! Irreversible! Block number: {}",
                self.next_block_number
            )
        }

        self.next_block_number += 1;

        Ok(updated_accounts)
    }

    pub fn get_root(&mut self) -> anyhow::Result<B256> {
        Ok(self.trie.root_hash()?)
    }

    pub fn get_account_state(&self, account: &Address) -> anyhow::Result<AccountState> {
        let account_state = self.trie.get(keccak256(account).as_slice())?;
        match account_state {
            Some(encoded) => AccountState::decode(&mut encoded.as_slice()).map_err(Error::from),
            None => Ok(AccountState::default()),
        }
    }

    pub fn get_proof(&mut self, account: &Address) -> anyhow::Result<AccountProof> {
        Ok(AccountProof {
            address: *account,
            state: self.get_account_state(account)?,
            proof: self
                .trie
                .get_proof(keccak256(account).as_slice())?
                .into_iter()
                .map(Bytes::from)
                .collect(),
        })
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

    #[test]
    fn test_we_generate_the_correct_state_root_for_the_first_8192_blocks() {
        let mut state = State::new().unwrap();
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
}
