use std::str::FromStr;

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
/// - Backfill: starts at block 0
/// - StartFromEpoch: starts at the given epoch
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeMode {
    Latest,
    Backfill,
    StartFromEpoch(u64),
}

type ParseError = &'static str;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            "backfill" => Ok(BridgeMode::Backfill),
            val => u64::from_str(val)
                .map(BridgeMode::StartFromEpoch)
                .map_err(|_| "Invalid bridge mode arg"),
        }
    }
}
