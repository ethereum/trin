use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

// max value of 16 b/c...
// - reliably calculate spaced private keys in a reasonable time
// - for values b/w 16 - 256, calculated spaced private keys are
//   less and less evenly spread
// - running more than 16 trin nodes simultaneously is not thoroughly tested
pub const MAX_NODE_COUNT: u8 = 16;

#[derive(StructOpt, Debug, PartialEq)]
#[structopt(name = "Trin Bridge", about = "Feed the network")]
pub struct BridgeConfig {
    #[structopt(
        long,
        help = "number of trin nodes to launch - must be between 1 and 16",
        validator(check_node_count)
    )]
    pub node_count: u8,

    #[structopt(long, help = "path to portalnet client executable")]
    pub executable_path: PathBuf,

    #[structopt(
        long,
        default_value = "latest",
        help = "['latest', 'backfill', <u64> to provide the starting epoch]"
    )]
    pub mode: BridgeMode,

    #[structopt(
        long = "epoch-accumulator-path",
        help = "Path to epoch accumulator repo for bridge mode",
        parse(from_os_str)
    )]
    pub epoch_acc_path: PathBuf,
}

fn check_node_count(val: String) -> Result<(), String> {
    let node_count: u8 = val.parse().map_err(|_| "Invalid node count".to_string())?;
    if node_count > 0 && node_count <= MAX_NODE_COUNT {
        Ok(())
    } else {
        Err(format!("Node count must be between 1 and {MAX_NODE_COUNT}"))
    }
}

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
