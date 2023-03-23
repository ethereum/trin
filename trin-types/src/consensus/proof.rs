use ethereum_types::H256;
use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};

use trin_utils::bytes::hex_decode;

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1/specs/phase0/beacon-chain.md
#[derive(Debug, PartialEq, Clone)]
pub struct Proof([H256; 33]);

impl Decode for Proof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut proof = [H256::zero(); 33];
        let decoded: Vec<H256> = bytes
            .chunks(32) // split into chunks of 32 bytes
            .map(H256::from_slice)
            .collect();
        for (i, val) in decoded.into_iter().enumerate() {
            proof[i] = val;
        }
        Ok(Self(proof))
    }
    fn ssz_fixed_len() -> usize {
        33 * 32
    }
}

impl Encode for Proof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.ssz_bytes_len());

        for item in self.0 {
            item.ssz_append(buf);
        }
    }
    fn ssz_bytes_len(&self) -> usize {
        33 * 32
    }
    fn ssz_fixed_len() -> usize {
        33 * 32
    }
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let result: Vec<String> = Deserialize::deserialize(deserializer)?;
        assert_eq!(result.len(), 33);
        let mut proof = [H256::zero(); 33];
        for (i, val) in result.into_iter().enumerate() {
            proof[i] = H256::from_slice(&hex_decode(&val).map_err(serde::de::Error::custom)?);
        }
        Ok(Self(proof))
    }
}

impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_seq(Some(33))?;
        for val in self.0 {
            s.serialize_element(&val)?;
        }
        s.end()
    }
}
