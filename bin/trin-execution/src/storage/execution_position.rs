use std::sync::Arc;

use alloy::{
    consensus::{Header, EMPTY_ROOT_HASH},
    rlp::{Decodable, RlpDecodable, RlpEncodable},
};
use redb::{Database as ReDB, TableDefinition};
use revm_primitives::B256;
use serde::{Deserialize, Serialize};

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("execution");
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
    pub fn initialize_from_db(db: Arc<ReDB>) -> anyhow::Result<Self> {
        let txn = db.begin_read()?;
        let table = txn.open_table(TABLE)?;
        match table.get(EXECUTION_POSITION_DB_KEY.as_slice())? {
            Some(value) => Ok(Decodable::decode(&mut value.value())?),
            None => Ok(Self::default()),
        }
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

    pub fn update_position(&mut self, db: Arc<ReDB>, header: &Header) -> anyhow::Result<()> {
        self.next_block_number = header.number + 1;
        self.state_root = header.state_root;

        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(TABLE)?;
            table.insert(
                EXECUTION_POSITION_DB_KEY.as_slice(),
                &alloy::rlp::encode(self)[..],
            )?;
        }
        txn.commit()?;
        Ok(())
    }
}

impl Default for ExecutionPosition {
    fn default() -> Self {
        Self {
            version: 0,
            next_block_number: 0,
            state_root: EMPTY_ROOT_HASH,
        }
    }
}
