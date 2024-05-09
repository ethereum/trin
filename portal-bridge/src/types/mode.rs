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
#[derive(Clone, Debug, PartialEq, Default, Eq)]
pub enum BridgeMode {
    #[default]
    Latest,
    FourFours(FourFoursMode),
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
            BridgeMode::FourFours(_) => {
                return Err(anyhow!(
                    "BridgeMode `fourfours` does not have a block range"
                ))
            }
            BridgeMode::Latest => {
                return Err(anyhow!("BridgeMode `latest` does not have a block range"))
            }
            BridgeMode::Test(_) => {
                return Err(anyhow!("BridgeMode `test` does not have a block range"))
            }
        };
        let (start, end) = match mode_type.clone() {
            ModeType::Epoch(epoch_number) => {
                let end_block = match is_single_mode {
                    true => (epoch_number + 1) * EPOCH_SIZE,
                    false => latest_block + 1,
                };
                (epoch_number * EPOCH_SIZE, end_block)
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

type ParseError = String;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            "fourfours" => Ok(BridgeMode::FourFours(FourFoursMode::Random)),
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
                    "fourfours" => {
                        let mode_type = FourFoursMode::from_str(&val[1..])?;
                        Ok(BridgeMode::FourFours(mode_type))
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
                    _ => Err("Invalid bridge mode arg: type prefix".to_string()),
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
        if s.is_empty() {
            return Err("Invalid bridge mode arg: empty string".to_string());
        }
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
                    return Err("Invalid bridge mode arg: expected 2 numbers in range".to_string());
                }

                let start_block = range_vec[0].to_owned();
                let end_block = range_vec[1].to_owned();

                if start_block > end_block {
                    return Err(
                        "Invalid bridge mode arg: end_block is less than start_block".to_string(),
                    );
                }

                Ok(ModeType::BlockRange(start_block, end_block))
            }
            _ => Err("Invalid bridge mode arg: type prefix".to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FourFoursMode {
    Random,
    // Gossips a single, randomly selected epoch
    RandomSingle,
    // Gossips a single, randomly selected epoch, with a floor epoch
    RandomSingleWithFloor(u64),
    // Gossips the single epoch given
    Single(u64),
    // Gossips a block range from within a single epoch
    Range(u64, u64),
    // Hunter mode tries to efficiently find missing data, by sampling a given number of blocks
    // (sample_size, threshold)
    Hunter(u64, u64),
}

const RANDOM_SINGLE_MODE: &str = "random_epoch";

impl FromStr for FourFoursMode {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("Invalid bridge fourfours mode arg: empty string".to_string());
        }
        if s.starts_with("hunter") {
            let mut split = s.split(':');
            let _ = split.next();
            let sample_size = split
                .next()
                .expect("Invalid 4444s bridge hunter mode arg: missing sample size")
                .parse()
                .expect("Invalid 4444s bridge hunter mode arg: invalid sample size");
            let threshold = split
                .next()
                .expect("Invalid 4444s bridge hunter mode arg: missing threshold")
                .parse()
                .expect("Invalid 4444s bridge hunter mode arg: invalid threshold");
            return Ok(FourFoursMode::Hunter(sample_size, threshold));
        }
        if s.starts_with(RANDOM_SINGLE_MODE) {
            match s.split(':').nth(1) {
                Some(floor_epoch) => {
                    let floor_epoch = floor_epoch
                        .parse()
                        .map_err(|_| "Invalid 4444s bridge mode arg: floor epoch number")?;
                    if floor_epoch > 1896 {
                        return Err(format!("Invalid 4444s bridge mode arg: era1 epoch greater than 1896 was given: {floor_epoch}"));
                    }
                    return Ok(FourFoursMode::RandomSingleWithFloor(floor_epoch));
                }
                None => return Ok(FourFoursMode::RandomSingle),
            }
        }
        match &s[..1] {
            "e" => {
                let epoch = s[1..]
                    .parse()
                    .map_err(|_| "Invalid 4444s bridge mode arg: era1 epoch number")?;
                if epoch > 1896 {
                    return Err(format!("Invalid 4444s bridge mode arg: era1 epoch greater than 1896 was given: {epoch}"));
                }
                Ok(FourFoursMode::Single(epoch))
            }
            "r" => {
                let range_vec = s[1..]
                    .split('-')
                    .map(|range_input| {
                        range_input.parse().expect(
                            "Range format invalid, expected fourfours:rX-Y (eg. fourfours:r10-100)",
                        )
                    })
                    .collect::<Vec<u64>>();

                if range_vec.len() != 2 {
                    return Err(
                        "Invalid 4444s bridge mode arg: expected 2 numbers in range".to_string()
                    );
                }
                let start_block = range_vec[0].to_owned();
                let end_block = range_vec[1].to_owned();
                if start_block > end_block {
                    return Err(
                        "Invalid 4444s bridge mode arg: end_block is less than start_block"
                            .to_string(),
                    );
                }
                let start_epoch = start_block / EPOCH_SIZE;
                let end_epoch = end_block / EPOCH_SIZE;
                if start_epoch != end_epoch {
                    return Err(
                        "Invalid 4444s bridge mode arg: start_block and end_block are not in the same epoch"
                            .to_string(),
                    );
                }
                if start_epoch > 1896 {
                    return Err(format!("Invalid 4444s bridge mode arg: era1 epoch greater than 1896 was given: {start_epoch}"));
                }

                Ok(FourFoursMode::Range(start_block, end_block))
            }
            _ => Err("Invalid 4444s bridge mode arg: type prefix".to_string()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
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
    #[case("fourfours", BridgeMode::FourFours(FourFoursMode::Random))]
    #[case(format!("fourfours:{RANDOM_SINGLE_MODE}"), 
        BridgeMode::FourFours(FourFoursMode::RandomSingle)
    )]
    #[case(format!("fourfours:{RANDOM_SINGLE_MODE}:0"), 
        BridgeMode::FourFours(FourFoursMode::RandomSingleWithFloor(0))
    )]
    #[case(format!("fourfours:{RANDOM_SINGLE_MODE}:1500"), 
        BridgeMode::FourFours(FourFoursMode::RandomSingleWithFloor(1500))
    )]
    #[case("fourfours:e1", BridgeMode::FourFours(FourFoursMode::Single(1)))]
    #[case("fourfours:r1-10", BridgeMode::FourFours(FourFoursMode::Range(1, 10)))]
    #[case(
        "test:/usr/eth/test.json",
        BridgeMode::Test(PathBuf::from("/usr/eth/test.json"))
    )]
    fn test_mode_flag(#[case] actual: String, #[case] expected: BridgeMode) {
        let bridge_mode = BridgeMode::from_str(&actual).unwrap();
        assert_eq!(bridge_mode, expected);
    }

    #[rstest]
    #[case("latest:")]
    #[case("latest:block")]
    #[case("backfill:")]
    #[case("backfill:x")]
    #[case("backfill:epoch")]
    #[case("single:")]
    #[case("single:x")]
    #[case("fourfours:")]
    #[case("fourfours:1")]
    #[case("fourfours:r1")]
    #[case("fourfours:1-100")]
    #[case("fourfours:x1-100")]
    #[case("fourfours:r1-10-100")]
    // invalid range
    #[case("fourfours:r100-1")]
    // range is not within a single epoch
    #[case("fourfours:r1-10000")]
    // range is post-merge
    #[case("fourfours:r19000000-19000100")]
    #[case("fourfours:random_epoch:")]
    // epoch is post-merge
    #[case("fourfours:random_epoch:1900")]
    fn test_invalid_mode_flag(#[case] actual: String) {
        let bridge_mode = BridgeMode::from_str(&actual);
        assert!(bridge_mode.is_err());
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
