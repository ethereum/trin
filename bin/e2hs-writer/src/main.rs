#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

pub mod cli;
pub mod subcommands;

use clap::Parser;
use cli::E2HSWriterSubCommands;
use subcommands::{head_generator::HeadGenerator, single_generator};
use tracing::info;
use trin_utils::log::init_tracing_logger;

use crate::single_generator::single_generator;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing_logger();
    info!("Running E2HS writer");
    let config = cli::WriterConfig::parse();
    info!("With configuration: {config:?}");

    match config.command {
        E2HSWriterSubCommands::SingleGenerator(config) => {
            single_generator(config).await?;
        }
        E2HSWriterSubCommands::HeadGenerator(config) => {
            let mut head_generator = HeadGenerator::new(config).await?;
            head_generator.run().await?;
        }
    }

    Ok(())
}
