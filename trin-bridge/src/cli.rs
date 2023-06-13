use crate::types::NetworkKind;
use clap::Parser;
use std::path::PathBuf;
use std::str::FromStr;

// max value of 16 b/c...
// - reliably calculate spaced private keys in a reasonable time
// - for values b/w 16 - 256, calculated spaced private keys are
//   less and less evenly spread
// - running more than 16 trin nodes simultaneously is not thoroughly tested
pub const MAX_NODE_COUNT: u8 = 16;
const DEFAULT_SUBNETWORK: &str = "history";

#[derive(Parser, Debug, PartialEq)]
#[command(name = "Trin Bridge", about = "Feed the network")]
pub struct BridgeConfig {
    #[arg(
        long,
        help = "number of trin nodes to launch - must be between 1 and 16",
        value_parser = check_node_count
    )]
    pub node_count: u8,

    #[arg(long, help = "path to portalnet client executable")]
    pub executable_path: PathBuf,

    #[arg(
        long,
        default_value = "latest",
        help = "['latest', 'backfill', <u64> to provide the starting epoch]"
    )]
    pub mode: BridgeMode,

    #[arg(
        long = "epoch-accumulator-path",
        help = "Path to epoch accumulator repo for bridge mode"
    )]
    pub epoch_acc_path: PathBuf,

    #[arg(
        long = "network",
        help = "Comma-separated list of which portal subnetworks to activate",
        default_value = DEFAULT_SUBNETWORK,
        use_value_delimiter = true
    )]
    pub network: Vec<NetworkKind>,
}

fn check_node_count(val: &str) -> Result<u8, String> {
    let node_count: u8 = val.parse().map_err(|_| "Invalid node count".to_string())?;
    if node_count > 0 && node_count <= MAX_NODE_COUNT {
        Ok(node_count)
    } else {
        Err(format!("Node count must be between 1 and {MAX_NODE_COUNT}"))
    }
}

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
/// - Backfill: starts at block 0
/// - StartFromEpoch: starts at the given epoch
///   - ex: "e123" starts at epoch 123
/// - Single: executes a single block
///   - ex: "b123" executes block 123
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeMode {
    Latest,
    Backfill,
    StartFromEpoch(u64),
    Single(u64),
}

type ParseError = &'static str;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            "backfill" => Ok(BridgeMode::Backfill),
            val => match &val[..1] {
                "e" => {
                    let epoch = val[1..]
                        .parse()
                        .map_err(|_| "Invalid bridge mode arg: epoch number")?;
                    Ok(BridgeMode::StartFromEpoch(epoch))
                }
                "b" => {
                    let block = val[1..]
                        .parse()
                        .map_err(|_| "Invalid bridge mode arg: block number")?;
                    Ok(BridgeMode::Single(block))
                }
                _ => Err("Invalid bridge mode arg: type prefix"),
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_default_bridge_config() {
        const NODE_COUNT: &str = "1";
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "test",
            "--node-count",
            NODE_COUNT,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--network",
            "history,beacon",
        ]);
        assert_eq!(bridge_config.node_count, 1);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(bridge_config.mode, BridgeMode::Latest);
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(
            bridge_config.network,
            vec![NetworkKind::History, NetworkKind::Beacon]
        );
    }

    #[test]
    fn test_bridge_config_with_epoch() {
        const NODE_COUNT: &str = "1";
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        const EPOCH: &str = "e100";
        let bridge_config = BridgeConfig::parse_from([
            "test",
            "--node-count",
            NODE_COUNT,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--mode",
            EPOCH,
        ]);
        assert_eq!(bridge_config.node_count, 1);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(bridge_config.mode, BridgeMode::StartFromEpoch(100));
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(bridge_config.network, vec![NetworkKind::History]);
    }

    #[test]
    fn test_bridge_config_with_max_node_count() {
        let node_count_string = MAX_NODE_COUNT.to_string();
        let node_count: &str = node_count_string.as_str();
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "test",
            "--node-count",
            node_count,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
        ]);
        assert_eq!(bridge_config.node_count, 16);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(bridge_config.mode, BridgeMode::Latest);
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(bridge_config.network, vec![NetworkKind::History]);
    }

    #[test]
    #[should_panic(
        expected = "Invalid network arg. Expected either 'beacon', 'history' or 'state'"
    )]
    fn test_invalid_network_arg() {
        BridgeConfig::try_parse_from(["test", "--network", "das"].iter()).unwrap();
    }
}
