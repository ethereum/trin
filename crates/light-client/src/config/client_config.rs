use std::{path::PathBuf, process::exit};

use alloy::primitives::{FixedBytes, B256};
use ethportal_api::consensus::constants::SLOTS_PER_EPOCH;
use figment::{
    providers::{Format, Serialized, Toml},
    Figment,
};
use serde::Deserialize;

use crate::config::{networks, BaseConfig, ChainConfig, CliConfig, Forks};

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    pub consensus_rpc: String,
    pub rpc_port: Option<u16>,
    pub default_checkpoint: B256,
    #[serde(default)]
    pub checkpoint: Option<B256>,
    pub data_dir: Option<PathBuf>,
    pub chain: ChainConfig,
    pub forks: Forks,
    pub max_checkpoint_age: u64,
    pub fallback: Option<String>,
    pub load_external_fallback: bool,
    pub strict_checkpoint_age: bool,
}

impl Config {
    pub fn from_file(config_path: &PathBuf, network: &str, cli_config: &CliConfig) -> Self {
        let base_config = match network {
            "mainnet" => networks::mainnet(),
            _ => BaseConfig::default(),
        };

        let base_provider = Serialized::from(base_config, network);
        let toml_provider = Toml::file(config_path).nested();
        let cli_provider = cli_config.as_provider(network);

        let config_res = Figment::new()
            .merge(base_provider)
            .merge(toml_provider)
            .merge(cli_provider)
            .select(network)
            .extract();

        match config_res {
            Ok(config) => config,
            Err(err) => {
                match err.kind {
                    figment::error::Kind::MissingField(field) => {
                        let field = field.replace('_', "-");

                        println!("\x1b[91merror\x1b[0m: missing configuration field: {field}");

                        println!("\n\ttry supplying the propoper command line argument: --{field}");
                    }
                    _ => println!("cannot parse configuration: {err}"),
                }
                exit(1);
            }
        }
    }

    pub fn fork_version(&self, slot: u64) -> FixedBytes<4> {
        let epoch = slot / SLOTS_PER_EPOCH;

        if epoch >= self.forks.electra.epoch {
            self.forks.electra.fork_version
        } else if epoch >= self.forks.deneb.epoch {
            self.forks.deneb.fork_version
        } else if epoch >= self.forks.capella.epoch {
            self.forks.capella.fork_version
        } else if epoch >= self.forks.bellatrix.epoch {
            self.forks.bellatrix.fork_version
        } else if epoch >= self.forks.altair.epoch {
            self.forks.altair.fork_version
        } else {
            self.forks.genesis.fork_version
        }
    }

    pub fn to_base_config(&self) -> BaseConfig {
        BaseConfig {
            rpc_port: self.rpc_port.unwrap_or(8545),
            consensus_rpc: Some(self.consensus_rpc.clone()),
            default_checkpoint: self.default_checkpoint,
            chain: self.chain.clone(),
            forks: self.forks.clone(),
            max_checkpoint_age: self.max_checkpoint_age,
        }
    }
}
