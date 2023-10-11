use ethereum_types::U256;
use ruint::Uint;

pub fn u256_to_uint256(u256: U256) -> Uint<256, 4> {
    let mut bytes = [0u8; 32];
    u256.to_big_endian(&mut bytes);
    Uint::from_be_bytes(bytes)
}

pub fn u64_to_uint256(val: u64) -> Uint<256, 4> {
    let u64_bytes: &[u8] = &val.to_be_bytes();
    let high_zero_bytes: &[u8] = &[0u8; 24];
    let bytes: [u8; 32] = [high_zero_bytes, u64_bytes]
        .concat()
        .try_into()
        .expect("8 bytes + 24 bytes should be 32 bytes");
    Uint::from_be_bytes(bytes)
}
