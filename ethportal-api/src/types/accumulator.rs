use ethereum_types::{H256, U256};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use std::ops::Deref;

/// Max number of blocks / epoch = 2 ** 13
pub const EPOCH_SIZE: usize = 8192;

/// Individual record for a historical header.
/// Block hash and total difficulty are used to validate whether a header is canonical or not.
/// Every HeaderRecord is 64bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Decode, Encode, Deserialize, Serialize)]
pub struct HeaderRecord {
    pub block_hash: H256,
    pub total_difficulty: U256,
}

/// SSZ List[HeaderRecord, max_length = EPOCH_SIZE]
/// List of (block_number, block_hash) for each header in the current epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochAccumulator(VariableList<HeaderRecord, typenum::U8192>);

impl Deref for EpochAccumulator {
    type Target = VariableList<HeaderRecord, typenum::U8192>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;
    use ssz::Decode;
    use std::fs;

    #[test]
    fn ssz_serde_encode_decode_fluffy_epoch_accumulator() {
        // values sourced from: https://github.com/status-im/portal-spec-tests
        let epoch_acc_ssz = fs::read("./src/assets/test/fluffy_epoch_acc.bin").unwrap();
        let epoch_acc_hex = format!("0x{}", hex::encode(&epoch_acc_ssz));
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc_ssz).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
        assert_eq!(epoch_acc.as_ssz_bytes(), epoch_acc_ssz);
        assert_eq!(
            serde_json::to_string(&json!(epoch_acc_hex)).unwrap(),
            serde_json::to_string(&epoch_acc).unwrap()
        );
    }

    #[test]
    fn ssz_serde_encode_decode_ultralight_epoch_accumulator() {
        let epoch_acc_hex =
            fs::read_to_string("./src/assets/test/ultralight_testEpoch.hex").unwrap();
        let epoch_acc_ssz = hex::decode(epoch_acc_hex.strip_prefix("0x").unwrap()).unwrap();
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc_ssz).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
        assert_eq!(epoch_acc.as_ssz_bytes(), epoch_acc_ssz);
        assert_eq!(
            serde_json::to_string(&json!(epoch_acc_hex)).unwrap(),
            serde_json::to_string(&epoch_acc).unwrap()
        );
    }
}
