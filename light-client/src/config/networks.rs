use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter};

use crate::config::{utils::hex_str_to_bytes, BaseConfig, ChainConfig, Fork, Forks};

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
}

impl Network {
    pub fn to_base_config(self) -> BaseConfig {
        match self {
            Self::Mainnet => mainnet(),
        }
    }
}

pub fn mainnet() -> BaseConfig {
    BaseConfig {
        default_checkpoint: hex_str_to_bytes(
            "0x766647f3c4e1fc91c0db9a9374032ae038778411fbff222974e11f2e3ce7dadf",
        )
        .expect("should be a valid hex str"),
        rpc_port: 8545,
        consensus_rpc: Some("https://www.lightclientdata.org".to_string()),
        chain: ChainConfig {
            chain_id: 1,
            genesis_time: 1606824023,
            genesis_root: hex_str_to_bytes(
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            )
            .expect("should be a valid hex str"),
        },
        forks: Forks {
            genesis: Fork {
                epoch: 0,
                fork_version: hex_str_to_bytes("0x00000000").expect("should be a valid hex str"),
            },
            altair: Fork {
                epoch: 74240,
                fork_version: hex_str_to_bytes("0x01000000").expect("should be a valid hex str"),
            },
            bellatrix: Fork {
                epoch: 144896,
                fork_version: hex_str_to_bytes("0x02000000").expect("should be a valid hex str"),
            },
            capella: Fork {
                epoch: 194048,
                fork_version: hex_str_to_bytes("0x03000000").expect("should be a valid hex str"),
            },
            deneb: Fork {
                epoch: 269568,
                fork_version: hex_str_to_bytes("0x04000000").expect("should be a valid hex str"),
            },
        },
        max_checkpoint_age: 1_209_600, // 14 days
    }
}
