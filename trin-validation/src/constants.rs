// Execution Layer hard forks https://ethereum.org/en/history/
pub const SHANGHAI_BLOCK_NUMBER: u64 = 17_034_870;
pub const MERGE_BLOCK_NUMBER: u64 = 15_537_394;
pub const LONDON_BLOCK_NUMBER: u64 = 12_965_000;
pub const BERLIN_BLOCK_NUMBER: u64 = 12_244_000;
pub const ISTANBUL_BLOCK_NUMBER: u64 = 9_069_000;
pub const CONSTANTINOPLE_BLOCK_NUMBER: u64 = 7_280_000;
pub const BYZANTIUM_BLOCK_NUMBER: u64 = 4_370_000;
pub const HOMESTEAD_BLOCK_NUMBER: u64 = 1_150_000;
pub const CAPELLA_FORK_EPOCH: u64 = 194_048;
pub const SLOTS_PER_EPOCH: u64 = 32;

/// The default hash of the pre-merge accumulator at the time of the merge block.
pub const DEFAULT_PRE_MERGE_ACC_HASH: &str =
    "0x8eac399e24480dce3cfe06f4bdecba51c6e5d0c46200e3e8611a0b44a3a69ff9";

/// Max number of blocks / epoch = 2 ** 13
pub const EPOCH_SIZE: u64 = 8192;

// Max number of epochs = 2 ** 17
// const MAX_HISTORICAL_EPOCHS: usize = 131072;

// EIP-155 chain ID for Ethereum mainnet
pub const CHAIN_ID: usize = 1;
