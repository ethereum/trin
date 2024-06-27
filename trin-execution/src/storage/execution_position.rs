use std::sync::Arc;

use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable, EMPTY_STRING_CODE};
use revm_primitives::{keccak256, B256};
use rocksdb::DB as RocksDB;
use serde::{Deserialize, Serialize};

// The location in the database which describes the current execution position.
pub const EXECUTION_POSITION_DB_KEY: &[u8; 18] = b"EXECUTION_POSITION";

#[derive(Debug, Clone, Serialize, Deserialize, RlpDecodable, RlpEncodable)]
pub struct ExecutionPosition {
    /// Version of the current execution state struct
    version: u8,

    state_root: B256,

    /// The block number we are currently executing
    block_execution_number: u64,

    /// The index of the transaction we are currently executing
    transaction_index: u64,
}

impl ExecutionPosition {
    pub fn initialize_from_db(db: Arc<RocksDB>) -> anyhow::Result<Self> {
        Ok(match db.get(EXECUTION_POSITION_DB_KEY)? {
            Some(raw_execution_position) => {
                Decodable::decode(&mut raw_execution_position.as_slice())?
            }
            None => Self {
                version: 0,
                block_execution_number: 0,
                state_root: keccak256([EMPTY_STRING_CODE]),
                transaction_index: 0,
            },
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn block_execution_number(&self) -> u64 {
        self.block_execution_number
    }

    pub fn state_root(&self) -> B256 {
        self.state_root
    }

    pub fn transaction_index(&self) -> u64 {
        self.transaction_index
    }

    pub fn increase_block_execution_number(
        &mut self,
        db: Arc<RocksDB>,
        state_root: B256,
    ) -> anyhow::Result<()> {
        self.block_execution_number += 1;
        self.state_root = state_root;
        self.transaction_index = 0;
        db.put(EXECUTION_POSITION_DB_KEY, alloy_rlp::encode(self))?;
        Ok(())
    }

    pub fn increase_transaction_index(&mut self, db: Arc<RocksDB>) -> anyhow::Result<()> {
        self.transaction_index += 1;
        db.put(EXECUTION_POSITION_DB_KEY, alloy_rlp::encode(self))?;
        Ok(())
    }
}
