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

    /// The next block number to be executed.
    next_block_number: u64,
}

impl ExecutionPosition {
    pub fn initialize_from_db(db: Arc<RocksDB>) -> anyhow::Result<Self> {
        Ok(match db.get(EXECUTION_POSITION_DB_KEY)? {
            Some(raw_execution_position) => {
                Decodable::decode(&mut raw_execution_position.as_slice())?
            }
            None => Self {
                version: 0,
                next_block_number: 0,
                state_root: keccak256([EMPTY_STRING_CODE]),
            },
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn next_block_number(&self) -> u64 {
        self.next_block_number
    }

    pub fn state_root(&self) -> B256 {
        self.state_root
    }

    pub fn set_next_block_number(
        &mut self,
        db: Arc<RocksDB>,
        block_number: u64,
        state_root: B256,
    ) -> anyhow::Result<()> {
        self.next_block_number = block_number;
        self.state_root = state_root;
        db.put(EXECUTION_POSITION_DB_KEY, alloy_rlp::encode(self))?;
        Ok(())
    }
}
