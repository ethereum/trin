use alloy::{
    consensus::{Header, TxEip4844Variant, TxEnvelope},
    eips::eip4895::Withdrawal,
};
use e2store::e2hs::{E2HSMemory, BLOCKS_PER_E2HS};
use revm::context::TxEnv;
use revm_primitives::Address;
use trin_evm::tx_env_modifier::TxEnvModifier;

#[derive(Debug, Clone)]
pub struct TransactionsWithSender {
    pub transaction: TxEnvelope,
    pub sender_address: Address,
}

impl TxEnvModifier for TransactionsWithSender {
    fn modify(&self, block_number: u64, tx_env: &mut TxEnv) {
        tx_env.caller = self.sender_address;
        match &self.transaction {
            TxEnvelope::Legacy(tx) => tx.tx().modify(block_number, tx_env),
            TxEnvelope::Eip2930(tx) => tx.tx().modify(block_number, tx_env),
            TxEnvelope::Eip1559(tx) => tx.tx().modify(block_number, tx_env),
            TxEnvelope::Eip4844(tx) => match tx.tx() {
                TxEip4844Variant::TxEip4844(tx_eip4844) => tx_eip4844.modify(block_number, tx_env),
                TxEip4844Variant::TxEip4844WithSidecar(tx_eip4844_with_sidecar) => {
                    tx_eip4844_with_sidecar.tx.modify(block_number, tx_env)
                }
            },
            _ => unimplemented!("TxEnvelope not supported: {:?}", self.transaction),
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

pub struct ProcessedE2HS {
    pub blocks: Vec<ProcessedBlock>,
    pub index: u64,
}

impl ProcessedE2HS {
    pub fn contains_block(&self, block_number: u64) -> bool {
        self.index == E2HSMemory::index_from_block_number(block_number)
    }

    pub fn get_block(&self, block_number: u64) -> Option<&ProcessedBlock> {
        let first_block_number = self.index as usize * BLOCKS_PER_E2HS;
        self.blocks.get(block_number as usize - first_block_number)
    }
}
