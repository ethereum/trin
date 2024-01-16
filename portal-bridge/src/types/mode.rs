use std::{path::PathBuf, str::FromStr};

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
/// - StartFromEpoch: starts at the given epoch
///   - ex: "e123" starts at epoch 123
/// - Single: executes a single block
///   - ex: "b123" executes block 123
/// - BlockRange: generates test data from block x to y
///   - ex: "r10-12" backfills a block range from #10 to #12 (inclusive)
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
    BlockRange(u64, u64),
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
            "r" => {
                let range_vec = s[1..]
                    .split('-')
                    .map(|range_input| {
                        range_input.parse().expect(
                            "Range format invalid, expected backfill:rX-Y (eg. backfill:r10-100)",
                        )
                    })
                    .collect::<Vec<u64>>();

                if range_vec.len() != 2 {
                    return Err("Invalid bridge mode arg: expected 2 numbers in range");
                }

                let start_block = range_vec[0].to_owned();
                let end_block = range_vec[1].to_owned();

                if start_block > end_block {
                    return Err("Invalid bridge mode arg: end_block is less than start_block");
                }

                Ok(ModeType::BlockRange(start_block, end_block))
            }
            _ => Err("Invalid bridge mode arg: type prefix"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cli::BridgeConfig;
    use clap::Parser;
    use rstest::rstest;

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
