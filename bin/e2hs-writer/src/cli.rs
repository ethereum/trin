use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use portal_bridge::{constants::DEFAULT_TOTAL_REQUEST_TIMEOUT, DEFAULT_BASE_EL_ENDPOINT};
use url::Url;

pub const DEFAULT_PORTAL_ACCUMULATOR_PATH: &str = "./portal-accumulators";

#[derive(Parser, Debug, Clone)]
#[command(name = "E2HS Writer", about = "Generate E2HS files")]
pub struct WriterConfig {
    #[command(subcommand)]
    pub command: E2HSWriterSubCommands,
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum E2HSWriterSubCommands {
    /// Used to generate a single E2HS file for a given period, then exits
    SingleGenerator(SingleGeneratorConfig),
    /// A long-running process that generates E2HS files for the head of the chain and uploads the
    /// files to an S3 bucket. Backfilling files that don't exist.
    HeadGenerator(HeadGeneratorConfig),
}

#[derive(Args, Debug, Clone, PartialEq)]
pub struct SingleGeneratorConfig {
    #[arg(long, help = "Target directory where E2HS files will be written")]
    pub target_dir: PathBuf,

    #[arg(long, help = "Index of the E2HS file to generate")]
    pub index: u64,

    #[arg(
        long = "portal-accumulator-path",
        help = "Path to portal accumulator repo",
        default_value = DEFAULT_PORTAL_ACCUMULATOR_PATH
    )]
    pub portal_accumulator_path: PathBuf,

    #[arg(
        long = "el-provider",
        default_value = DEFAULT_BASE_EL_ENDPOINT,
        help = "Data provider for execution layer data. (pandaops url / infura url with api key / local node url)",
    )]
    pub el_provider: Url,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub struct HeadGeneratorConfig {
    #[arg(
        long = "el-provider",
        help = "Data provider for execution layer data. (pandaops url / infura url with api key / local node url)"
    )]
    pub el_provider: Url,

    #[arg(
        long = "cl-provider",
        help = "Data provider for consensus layer data. (pandaops url / local node url)"
    )]
    pub cl_provider: Url,

    #[arg(
        default_value_t = DEFAULT_TOTAL_REQUEST_TIMEOUT,
        long = "request-timeout",
        help = "The timeout in seconds is applied from when the request starts connecting until the response body has finished. Also considered a total deadline.",
    )]
    pub request_timeout: u64,

    #[arg(long, help = "Name of the s3 bucket to upload E2HS files to")]
    pub bucket_name: String,
}
