use std::path::PathBuf;
use std::str::FromStr;

use trin_validation::constants::EPOCH_SIZE;

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
/// - StartFromEpoch: starts at the given epoch
///   - ex: "e123" starts at epoch 123
/// - Single: executes a single block
///   - ex: "b123" executes block 123
#[derive(Clone, Debug, PartialEq, Default, Eq)]
pub enum BridgeMode {
    #[default]
    Latest,
    Backfill(ModeType),
    Single(ModeType),
    Test(PathBuf),
}

type ParseError = &'static str;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            val => {
                let index = val
                    .find(':')
                    .ok_or("Invalid bridge mode arg: missing ':'")?;
                let (mode, val) = val.split_at(index);
                match mode {
                    "backfill" => {
                        let mode_type = ModeType::from_str(&val[1..])?;
                        Ok(BridgeMode::Backfill(mode_type))
                    }
                    "single" => {
                        let mode_type = ModeType::from_str(&val[1..])?;
                        Ok(BridgeMode::Single(mode_type))
                    }
                    "test" => {
                        let path =
                            PathBuf::from_str(&val[1..]).map_err(|_| "Invalid test asset path")?;
                        Ok(BridgeMode::Test(path))
                    }
                    _ => Err("Invalid bridge mode arg: type prefix"),
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeType {
    Epoch(u64),
    Block(u64),
}

impl ModeType {
    pub fn block_number(&self) -> u64 {
        match self {
            ModeType::Epoch(epoch) => epoch * EPOCH_SIZE as u64,
            ModeType::Block(block) => *block,
        }
    }
}

impl FromStr for ModeType {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "e" => {
                let epoch = s[1..]
                    .parse()
                    .map_err(|_| "Invalid bridge mode arg: epoch number")?;
                Ok(ModeType::Epoch(epoch))
            }
            "b" => {
                let block = s[1..]
                    .parse()
                    .map_err(|_| "Invalid bridge mode arg: block number")?;
                Ok(ModeType::Block(block))
            }
            _ => Err("Invalid bridge mode arg: type prefix"),
        }
    }
}

#[cfg(test)]
mod test {
    use clap::Parser;
    use rstest::rstest;

    use super::*;
    use crate::cli::BridgeConfig;

    #[rstest]
    #[case("latest", BridgeMode::Latest)]
    #[case("single:b0", BridgeMode::Single(ModeType::Block(0)))]
    #[case("single:b1000", BridgeMode::Single(ModeType::Block(1000)))]
    #[case("single:e0", BridgeMode::Single(ModeType::Epoch(0)))]
    #[case("single:e1000", BridgeMode::Single(ModeType::Epoch(1000)))]
    #[case("backfill:b0", BridgeMode::Backfill(ModeType::Block(0)))]
    #[case("backfill:b1000", BridgeMode::Backfill(ModeType::Block(1000)))]
    #[case("backfill:e0", BridgeMode::Backfill(ModeType::Epoch(0)))]
    #[case("backfill:e1000", BridgeMode::Backfill(ModeType::Epoch(1000)))]
    #[case(
        "test:/usr/eth/test.json",
        BridgeMode::Test(PathBuf::from("/usr/eth/test.json"))
    )]
    fn test_mode_flag(#[case] actual: String, #[case] expected: BridgeMode) {
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--node-count",
            "1",
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--mode",
            &actual,
            "trin",
        ]);
        assert_eq!(bridge_config.mode, expected);
    }
}
