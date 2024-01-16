use crate::types::Bytes32;
use anyhow::Result;
use ssz_rs::{Node, Vector};

pub fn bytes_to_bytes32(bytes: &[u8]) -> Bytes32 {
    Vector::from_iter(bytes.to_vec())
}

pub fn bytes32_to_node(bytes: &Bytes32) -> Result<Node> {
    Ok(Node::from_bytes(bytes.as_slice().try_into()?))
}

pub fn u64_to_hex_string(val: u64) -> String {
    format!("0x{val:x}")
}
