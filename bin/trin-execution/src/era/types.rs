use ethportal_api::{
    types::execution::{transaction::Transaction, withdrawal::Withdrawal},
    Header,
};
use revm_primitives::{Address, SpecId, TxEnv};
use trin_evm::{spec_id::get_spec_block_number, tx_env_modifier::TxEnvModifier};

#[derive(Debug, Clone)]
pub struct TransactionsWithSender {
    pub transaction: Transaction,
    pub sender_address: Address,
}

impl TxEnvModifier for TransactionsWithSender {
    fn modify(&self, block_number: u64, tx_env: &mut TxEnv) {
        tx_env.caller = self.sender_address;
        match &self.transaction {
            Transaction::Legacy(tx) => tx.modify(block_number, tx_env),
            Transaction::AccessList(tx) => tx.modify(block_number, tx_env),
            Transaction::EIP1559(tx) => tx.modify(block_number, tx_env),
            Transaction::Blob(tx) => tx.modify(block_number, tx_env),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessedBlock {
    pub header: Header,
    pub uncles: Option<Vec<Header>>,
    pub withdrawals: Option<Vec<Withdrawal>>,
    pub transactions: Vec<TransactionsWithSender>,
}

pub struct ProcessedEra {
    pub blocks: Vec<ProcessedBlock>,
    pub era_type: EraType,
    pub epoch_index: u64,
    pub first_block_number: u64,
}

impl ProcessedEra {
    pub fn contains_block(&self, block_number: u64) -> bool {
        (self.first_block_number..self.first_block_number + self.len() as u64)
            .contains(&block_number)
    }

    pub fn get_block(&self, block_number: u64) -> &ProcessedBlock {
        &self.blocks[block_number as usize - self.first_block_number as usize]
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraType {
    Era,
    Era1,
}

impl EraType {
    pub fn for_block_number(block_number: u64) -> Self {
        if block_number < get_spec_block_number(SpecId::MERGE) {
            Self::Era1
        } else {
            Self::Era
        }
    }
}
