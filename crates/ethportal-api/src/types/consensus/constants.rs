//! Consensus specs constants.
//!
//! Mostly taken from: https://github.com/ethereum/consensus-specs/blob/d8cfdf2626c1219a40048f8fa3dd103ae8c0b040/presets/mainnet/phase0.yaml
//!
//! These should eventually be part of the Chain configuration parameters.

/// Number of slots per Epoch.
///
/// 2**5 (= 32) slots 6.4 minutes
pub const SLOTS_PER_EPOCH: u64 = 32;

/// Number of slots per HistoricalRoot / HistoricalSummary.
///
/// 2**13 (= 8,192) slots ~27 hours
pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;

/// The Epoch of the mainnet Capella fork.
///
/// April 12, 2023, 10:27:35pm UTC
/// Source: https://github.com/ethereum/consensus-specs/blob/d8cfdf2626c1219a40048f8fa3dd103ae8c0b040/configs/mainnet.yaml
pub const CAPELLA_FORK_EPOCH: u64 = 194_048;
