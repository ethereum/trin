use alloy::{
    consensus::{Header, TxEip4844Variant, TxEnvelope},
    eips::eip4895::Withdrawal,
};
use e2store::e2hs::BLOCKS_PER_E2HS;
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
        let first_block_number = self.blocks[0].header.number;
        (first_block_number..first_block_number + BLOCKS_PER_E2HS as u64).contains(&block_number)
    }

    pub fn get_block(&self, block_number: u64) -> &ProcessedBlock {
        &self.blocks[block_number as usize - self.blocks[0].header.number as usize]
    }
}
