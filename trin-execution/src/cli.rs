use std::net::SocketAddr;

use clap::Parser;

use crate::types::block_to_trace::BlockToTrace;

#[derive(Parser, Debug, Clone)]
#[command(name = "Trin Execution", about = "Executing blocks with no devp2p")]
pub struct TrinExecutionConfig {
    #[arg(
        short = 'e',
        long = "ephemeral",
        help = "Use temporary data storage that is deleted on exit."
    )]
    pub ephemeral: bool,

    #[arg(
        long,
        default_value = "none",
        help = "The block traces will be dumped to the working directory: Configuration options ['none', 'block:<number>', 'all']."
    )]
    pub block_to_trace: BlockToTrace,

    #[arg(
        long = "enable-metrics-with-url",
        help = "Enable prometheus metrics reporting (provide local IP/Port from which your Prometheus server is configured to fetch metrics)"
    )]
    pub enable_metrics_with_url: Option<SocketAddr>,
}
