use std::{ops::Range, path::PathBuf, str::FromStr};

use anyhow::anyhow;

use trin_validation::constants::EPOCH_SIZE;

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
/// - StartFromEpoch: starts at the given epoch
///   - ex: "e123" starts at epoch 123
/// - Single: executes a single block
///   - ex: "b123" executes block 123
/// - BlockRange: generates test data from block x to y
///   - ex: "r10-12" backfills a block range from #10 to #12 (inclusive)
/// - FourFours: gossips randomly sequenced era1 files
///   - ex: "fourfours"
/// - FourFours: gossips single era1 file
///  - ex: "fourfours:mainnet-00000-5ec1ffb8.era1"
#[derive(Clone, Debug, PartialEq, Default, Eq)]
pub enum BridgeMode {
    #[default]
    Latest,
    FourFours(Option<String>),
    Backfill(ModeType),
    Single(ModeType),
    Test(PathBuf),
}

impl BridgeMode {
    // Returns *exclusive* block range to gossip based on the mode & latest block.
    // Returns an error if the block range contains a block that is greater than latest_block.
    pub fn get_block_range(&self, latest_block: u64) -> anyhow::Result<Range<u64>> {
        let (is_single_mode, mode_type) = match self {
            BridgeMode::Backfill(val) => (false, val),
            BridgeMode::Single(val) => (true, val),
            BridgeMode::Latest => {
                return Err(anyhow!("BridgeMode `latest` does not have a block range"))
            }
            BridgeMode::FourFours(_) => {
                return Err(anyhow!(
                    "BridgeMode `fourfours` does not have a block range"
                ))
            }
            BridgeMode::Test(_) => {
                return Err(anyhow!("BridgeMode `test` does not have a block range"))
            }
        };
        let (start, end) = match mode_type.clone() {
            ModeType::Epoch(epoch_number) => {
                let end_block = match is_single_mode {
                    true => (epoch_number + 1) * EPOCH_SIZE as u64,
                    false => latest_block + 1,
                };
                (epoch_number * EPOCH_SIZE as u64, end_block)
            }
            ModeType::Block(block) => {
                let end_block = match is_single_mode {
                    true => block,
                    false => latest_block,
                };
                (block, end_block + 1)
            }
            ModeType::BlockRange(start_block, end_block) => (start_block, end_block + 1),
        };
        if end > (latest_block + 1) {
            return Err(anyhow!(
                "Invalid bridge mode range: block range contains block that is greater than latest_block"
            ));
        }
        Ok(Range { start, end })
    }
}

type ParseError = &'static str;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            val => {
                // parse fourfours mode
                if val.starts_with("fourfours") {
                    match val.find(':') {
                        Some(index) => {
                            let path = &val[index + 1..];
                            return Ok(BridgeMode::FourFours(Some(path.to_string())));
                        }
                        None => return Ok(BridgeMode::FourFours(None)),
                    }
                }
                // parse backfill, single, and test modes
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
    #[case("fourfours", BridgeMode::FourFours(None))]
    #[case(
        "fourfours:mainnet-00000-5ec1ffb8.era1",
        BridgeMode::FourFours(Some("mainnet-00000-5ec1ffb8.era1".to_string()))
    )]
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

    #[rstest]
    // backfill
    #[case(BridgeMode::Backfill(ModeType::Epoch(0)), 1_000, (0, 1_001))]
    #[case(BridgeMode::Backfill(ModeType::Epoch(1)), 10_000, (8_192, 10_001))]
    #[case(BridgeMode::Backfill(ModeType::Block(0)), 1_000, (0, 1_001))]
    #[case(BridgeMode::Backfill(ModeType::Block(100)), 10_000, (100, 10_001))]
    #[case(BridgeMode::Backfill(ModeType::BlockRange(100_000, 100_001)), 100_002, (100_000, 100_002))]
    #[case(BridgeMode::Backfill(ModeType::BlockRange(100, 200)), 100_001, (100, 201))]
    #[case(BridgeMode::Backfill(ModeType::BlockRange(100, 100_000)), 100_001, (100, 100_001))]
    // backfill across epoch boundaries
    #[case(BridgeMode::Backfill(ModeType::Epoch(0)), 10_000, (0, 10_001))]
    #[case(BridgeMode::Backfill(ModeType::Block(0)), 10_000, (0, 10_001))]
    #[case(BridgeMode::Backfill(ModeType::BlockRange(8_000, 9_000)), 10_000, (8_000, 9_001))]
    // single
    #[case(BridgeMode::Single(ModeType::Epoch(0)), 10_000, (0, 8192))]
    #[case(BridgeMode::Single(ModeType::Epoch(0)), 8191, (0, 8192))]
    #[case(BridgeMode::Single(ModeType::Epoch(10)), 100_000, (81_920, 90_112))]
    #[case(BridgeMode::Single(ModeType::Block(100)), 10_000, (100, 101))]
    #[case(BridgeMode::Single(ModeType::Block(10_000)), 10_001, (10_000, 10_001))]
    fn test_get_block_range(
        #[case] mode: BridgeMode,
        #[case] latest_block: u64,
        #[case] expected: (u64, u64),
    ) {
        let actual = mode.get_block_range(latest_block).unwrap();
        let expected = Range {
            start: expected.0,
            end: expected.1,
        };
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case(BridgeMode::Single(ModeType::Epoch(0)), 8_190)]
    #[case(BridgeMode::Single(ModeType::Epoch(1)), 1_000)]
    #[case(BridgeMode::Single(ModeType::Block(1_001)), 1_000)]
    #[case(BridgeMode::Single(ModeType::BlockRange(1_000, 2_000)), 1_000)]
    #[case(BridgeMode::Latest, 1_000)]
    #[case(BridgeMode::Test(PathBuf::from("./data.json")), 1_000)]
    fn test_get_block_range_invalid(#[case] mode: BridgeMode, #[case] latest_block: u64) {
        let actual = mode.get_block_range(latest_block);
        assert!(actual.is_err());
    }
}
