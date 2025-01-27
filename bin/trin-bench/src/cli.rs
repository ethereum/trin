use std::path::PathBuf;

use clap::Parser;
use url::Url;

pub const APP_NAME: &str = "trin-bench";
const DEFAULT_EPOCH_ACC_PATH: &str = "./portal-accumulators";

#[derive(Parser, Debug, Clone)]
#[command(
    name = "Trin Bench",
    about = "Benchmarks sending blocks from one trin client to another"
)]
pub struct TrinBenchConfig {
    #[arg(
        long = "web3-http-address-node-1",
        help = "address to accept json-rpc http connections"
    )]
    pub web3_http_address_node_1: Url,

    #[arg(
        long = "web3-http-address-node-2",
        help = "address to accept json-rpc http connections"
    )]
    pub web3_http_address_node_2: Url,

    #[arg(
        long,
        help = "The first era to start sending blocks from",
        default_value = "1"
    )]
    pub start_era1: u16,

    #[arg(long, help = "The last era to send blocks from", default_value = "5")]
    pub end_era1: u16,

    #[arg(
        long = "epoch-accumulator-path",
        help = "Path to epoch accumulator repo for bridge mode",
        default_value = DEFAULT_EPOCH_ACC_PATH
    )]
    pub epoch_acc_path: PathBuf,

    #[arg(
        long,
        help = "The max amount of offer requests to have open at any given time",
        default_value = "10"
    )]
    pub offer_concurrency: usize,
}
