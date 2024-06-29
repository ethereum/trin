use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "Trin Execution", about = "Executing blocks with no devp2p")]
pub struct TrinExecutionConfig {
    #[arg(
        short = 'e',
        long = "ephemeral",
        help = "Use temporary data storage that is deleted on exit."
    )]
    pub ephemeral: bool,
}
