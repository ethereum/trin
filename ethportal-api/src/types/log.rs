use crate::types::bytes::Bytes;
use ethereum_types::{Address, Bloom, BloomInput, H256};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

/// A log produced by a transaction.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
pub struct TransactionLog {
    /// H160. the contract that emitted the log
    pub address: Address,

    /// topics: Array of 0 to 4 32 Bytes of indexed log arguments.
    /// (In solidity: The first topic is the hash of the signature of the event
    /// (e.g. `Deposit(address,bytes32,uint256)`), except you declared the event
    /// with the anonymous specifier.)
    pub topics: Vec<H256>,

    /// Data
    pub data: Bytes,
}

impl TransactionLog {
    /// Calculates the bloom of this log entry.
    pub fn bloom(&self) -> Bloom {
        self.topics.iter().fold(
            Bloom::from(BloomInput::Raw(self.address.as_bytes())),
            |mut b, t| {
                b.accrue(BloomInput::Raw(t.as_bytes()));
                b
            },
        )
    }
}
