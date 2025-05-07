use alloy::primitives::{b256, fixed_bytes};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter};

use crate::config::{BaseConfig, ChainConfig, Fork, Forks};

#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    EnumIter,
    Display,
    Hash,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
)]
pub enum Network {
    Mainnet,
    Sepolia,
}

impl Network {
    pub fn to_base_config(self) -> BaseConfig {
        match self {
            Self::Mainnet => mainnet(),
            Self::Sepolia => sepolia(),
        }
    }
}

pub fn mainnet() -> BaseConfig {
    BaseConfig {
        default_checkpoint: b256!(
            "0x766647f3c4e1fc91c0db9a9374032ae038778411fbff222974e11f2e3ce7dadf"
        ),
        rpc_port: 8545,
        consensus_rpc: Some("https://www.lightclientdata.org".to_string()),
        chain: ChainConfig {
            chain_id: 1,
            genesis_time: 1606824023,
            genesis_root: b256!(
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
            ),
        },
        forks: Forks {
            genesis: Fork {
                epoch: 0,
                fork_version: fixed_bytes!("0x00000000"),
            },
            altair: Fork {
                epoch: 74_240,
                fork_version: fixed_bytes!("0x01000000"),
            },
            bellatrix: Fork {
                epoch: 144_896,
                fork_version: fixed_bytes!("0x02000000"),
            },
            capella: Fork {
                epoch: 194_048,
                fork_version: fixed_bytes!("0x03000000"),
            },
            deneb: Fork {
                epoch: 269_568,
                fork_version: fixed_bytes!("0x04000000"),
            },
            electra: Fork {
                epoch: 364_032,
                fork_version: fixed_bytes!("0x05000000"),
            },
        },
        max_checkpoint_age: 1_209_600, // 14 days
    }
}

pub fn sepolia() -> BaseConfig {
    BaseConfig {
        default_checkpoint: b256!(
            "0x234931a3fe5d791f06092477357e2d65dcf6fa6cad048680eb93ad3ea494bbcd"
        ),
        rpc_port: 8545,
        consensus_rpc: None,
        chain: ChainConfig {
            chain_id: 11155111,
            genesis_time: 1655733600,
            genesis_root: b256!(
                "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
            ),
        },
        forks: Forks {
            genesis: Fork {
                epoch: 0,
                fork_version: fixed_bytes!("0x90000069"),
            },
            altair: Fork {
                epoch: 50,
                fork_version: fixed_bytes!("0x90000070"),
            },
            bellatrix: Fork {
                epoch: 100,
                fork_version: fixed_bytes!("0x90000071"),
            },
            capella: Fork {
                epoch: 56_832,
                fork_version: fixed_bytes!("0x90000072"),
            },
            deneb: Fork {
                epoch: 132_608,
                fork_version: fixed_bytes!("0x90000073"),
            },
            electra: Fork {
                epoch: 222_464,
                fork_version: fixed_bytes!("0x90000074"),
            },
        },
        max_checkpoint_age: 1_209_600, // 14 days
    }
}

#[cfg(test)]
mod tests {
    use ethportal_api::consensus::fork::ForkName;

    use super::*;
    use crate::utils::compute_fork_data_root;

    #[test]
    fn fork_digest() {
        let config = mainnet();

        let check_fork = |fork: &Fork, fork_name: ForkName| {
            let fork_data_root =
                compute_fork_data_root(fork.fork_version, config.chain.genesis_root);
            assert_eq!(
                fork_name.as_fork_digest().as_slice(),
                &fork_data_root[..4],
                "Checking fork digest for {fork_name}"
            )
        };

        check_fork(&config.forks.bellatrix, ForkName::Bellatrix);
        check_fork(&config.forks.capella, ForkName::Capella);
        check_fork(&config.forks.deneb, ForkName::Deneb);
        check_fork(&config.forks.electra, ForkName::Electra);
    }
}
