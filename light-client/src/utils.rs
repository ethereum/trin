use crate::types::Bytes32;
use alloy::primitives::B256;
use anyhow::Result;
use ssz::{Decode, TryFromIter};
use ssz_types::FixedVector;

pub fn bytes_to_bytes32(bytes: &[u8]) -> Bytes32 {
    FixedVector::try_from_iter(bytes.to_vec()).expect("should convert bytes to fixed vector")
}

pub fn bytes32_to_node(bytes: &Bytes32) -> Result<B256> {
    let array = <[u8; 32]>::try_from(bytes.as_ref())
        .map_err(|_| anyhow::anyhow!("Failed to convert bytes to array"))?;
    B256::from_ssz_bytes(&array).map_err(|_| anyhow::anyhow!("Failed to decode SSZ bytes"))
}

pub fn u64_to_hex_string(val: u64) -> String {
    format!("0x{val:x}")
}
