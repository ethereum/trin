use std::str::FromStr;

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
/// - BlockRange: generates test data from block x to y
///   - ex: "r10-12" backfills a block range from #10 to #12 (inclusive)
/// - Snapshot: gossips a State snapshot, this mode is only used for the state network
///  - ex: "snapshot:1000000" gossips the state snapshot at block 1000000
#[derive(Clone, Debug, PartialEq, Default, Eq)]
pub enum BridgeMode {
    #[default]
    Latest,
    E2HS,
    EphemeralHistory,
    Single(ModeType),
    Snapshot(u64),
}

type ParseError = String;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            "e2hs" => Ok(BridgeMode::E2HS),
            "ephemeral-history" => Ok(BridgeMode::EphemeralHistory),
            val => {
                let index = val
                    .find(':')
                    .ok_or("Invalid bridge mode arg: missing ':'")?;
                let (mode, val) = val.split_at(index);
                match mode {
                    "single" => {
                        let mode_type = ModeType::from_str(&val[1..])?;
                        Ok(BridgeMode::Single(mode_type))
                    }
                    "snapshot" => {
                        let snapshot = val[1..]
                            .parse()
                            .map_err(|_| "Invalid snapshot arg: snapshot number")?;
                        Ok(BridgeMode::Snapshot(snapshot))
                    }
                    _ => Err("Invalid bridge mode arg: type prefix".to_string()),
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeType {
    BlockRange(u64, u64),
}

impl FromStr for ModeType {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("Invalid bridge mode arg: empty string".to_string());
        }
        match &s[..1] {
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

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("latest", BridgeMode::Latest)]
    fn test_mode_flag(#[case] actual: String, #[case] expected: BridgeMode) {
        let bridge_mode = BridgeMode::from_str(&actual).unwrap();
        assert_eq!(bridge_mode, expected);
    }

    #[rstest]
    #[case("latest:")]
    #[case("latest:block")]
    #[case("single:")]
    #[case("single:x")]
    fn test_invalid_mode_flag(#[case] actual: String) {
        let bridge_mode = BridgeMode::from_str(&actual);
        assert!(bridge_mode.is_err());
    }
}
