use alloy_primitives::{B256, U256};

// sets the global tracing subscriber, to be used by all other tests
pub fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(trin_utils::log::detect_ansi_support())
        .finish();
    // returns err if already set, which is fine and we just ignore the err
    let _ = tracing::subscriber::set_global_default(subscriber);
}

// Convert an ethereum-types U256 to an ethers-rs U256
// Because the test files are compiled individually, this gets detected as dead code in
// self_peertest.rs, even though it is used in rpc_server.rs. So we disable the warning.
#[allow(dead_code)]
pub fn u256_to_ethers_u256(u256: U256) -> ethers_core::types::U256 {
    ethers_core::types::U256::from_big_endian(B256::from(u256).as_slice())
}

// Convert a primitive u64 to an ethers-rs U256
// Because the test files are compiled individually, this gets detected as dead code in
// self_peertest.rs, even though it is used in rpc_server.rs. So we disable the warning.
#[allow(dead_code)]
pub fn u64_to_ethers_u256(u64: u64) -> ethers_core::types::U256 {
    let bytes = u64.to_be_bytes();
    ethers_core::types::U256::from_big_endian(&bytes)
}
