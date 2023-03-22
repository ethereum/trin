use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(StructOpt, Debug, PartialEq)]
#[structopt(name = "Trin Bridge", about = "Feed the network")]
pub struct BridgeConfig {
    #[structopt(long, help = "number of trin nodes to launch")]
    pub node_count: u64,

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
