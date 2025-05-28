//! Consensus specs constants.
//!
//! Mostly taken from:
//! https://github.com/ethereum/consensus-specs/blob/d8cfdf2626c1219a40048f8fa3dd103ae8c0b040/presets/mainnet/phase0.yaml
//! or
//! https://github.com/ethereum/consensus-specs/blob/d8cfdf2626c1219a40048f8fa3dd103ae8c0b040/configs/mainnet.yaml
//!
//! These should eventually be part of the Chain configuration parameters.

use std::time::Duration;

/// Number of slots per Epoch.
///
/// 2**5 (= 32) slots 6.4 minutes
pub const SLOTS_PER_EPOCH: u64 = 32;

/// Number of slots per HistoricalRoot / HistoricalSummary.
///
/// 2**13 (= 8,192) slots ~27 hours
pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;

/// Seconds per slot
///
/// 12 seconds
pub const SECONDS_PER_SLOT: Duration = Duration::from_secs(12);

/// The Epoch of the mainnet Capella fork.
///
/// April 12, 2023, 10:27:35pm UTC
pub const CAPELLA_FORK_EPOCH: u64 = 194_048;

/// The Epoch of the mainnet Deneb fork.
///
/// March 13, 2024, 01:55:35pm UTC
pub const DENEB_FORK_EPOCH: u64 = 269_568;

/// The Epoch of the mainnet Electra fork.
///
/// May 7, 2025, 10:05:11am UTC
pub const ELECTRA_FORK_EPOCH: u64 = 364_032;
