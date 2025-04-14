use std::path::PathBuf;

use clap::Parser;
use portal_bridge::DEFAULT_BASE_EL_ENDPOINT;
use url::Url;

pub const DEFAULT_EPOCH_ACC_PATH: &str = "./portal-accumulators";

#[derive(Parser, Debug, Clone)]
#[command(name = "E2HS Writer", about = "Generate E2HS files")]
pub struct WriterConfig {
    #[arg(long, help = "Target directory where E2HS files will be written")]
    pub target_dir: String,

    #[arg(long, help = "Epoch used to generate E2HS file")]
    pub epoch: u64,

    #[arg(
        long = "epoch-accumulator-path",
        help = "Path to epoch accumulator repo",
        default_value = DEFAULT_EPOCH_ACC_PATH
    )]
    pub epoch_acc_path: PathBuf,

    #[arg(
        long = "el-provider",
        default_value = DEFAULT_BASE_EL_ENDPOINT,
        help = "Data provider for execution layer data. (pandaops url / infura url with api key / local node url)",
    )]
    pub el_provider: Url,
}
