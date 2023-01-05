use ethereum_types::{H256, U256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

impl Serialize for EpochAccumulator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ssz_epoch_acc = &self.0.as_ssz_bytes();
        serializer.serialize_str(&format!("0x{}", hex::encode(ssz_epoch_acc)))
    }
}

impl<'de> Deserialize<'de> for EpochAccumulator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let epoch_acc = EpochAccumulator::from_ssz_bytes(
            &hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)?,
        )
        .map_err(|_| {
            serde::de::Error::custom("Unable to decode EpochAccumulator from ssz bytes")
        })?;

        Ok(epoch_acc)
    }
}

impl Encode for EpochAccumulator {
    // note: MAX_LENGTH attributes (defined in portal history spec) are not currently enforced
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl Decode for EpochAccumulator {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let header_records = VariableList::from_ssz_bytes(bytes)?;
        Ok(Self(header_records))
    }
}

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
