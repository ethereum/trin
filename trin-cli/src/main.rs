pub mod dashboard;
use clap::{Args, Parser, Subcommand};

use std::path::Path;

use ethereum_types::H256;
use thiserror::Error;

use dashboard::grafana::{GrafanaAPI, DASHBOARD_TEMPLATES};
use ethportal_api::{BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, HistoryContentKey};
use trin_utils::bytes::hex_encode;

#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "trin-cli",
    version = "0.0.1",
    author = "Ethereum Foundation",
    about = "Portal Network command line utilities"
)]
enum Trin {
    #[command(subcommand)]
    EncodeKey(EncodeKey),
    CreateDashboard(DashboardConfig),
}

// TODO: Remove clippy allow once a variant with non-"Block" prefix is added.
/// Encode a content key.
#[derive(Subcommand, Debug, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum EncodeKey {
    /// Encode the content key for a block header.
    BlockHeader {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[arg(long)]
        block_hash: H256,
    },
    /// Encode the content key for a block body.
    BlockBody {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[arg(long)]
        block_hash: H256,
    },
    /// Encode the content key for a block's transaction receipts.
    BlockReceipts {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[arg(long)]
        block_hash: H256,
    },
}

#[derive(Args, Debug, PartialEq)]
#[command(name = "create-dashboard")]
#[allow(clippy::enum_variant_names)]
struct DashboardConfig {
    #[arg(default_value = "http://localhost:3000")]
    grafana_address: String,

    #[arg(default_value = "admin")]
    grafana_username: String,

    #[arg(default_value = "admin")]
    grafana_password: String,

    #[arg(default_value = "http://host.docker.internal:9090")]
    prometheus_address: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Trin::parse() {
        Trin::EncodeKey(content_key) => encode_content_key(content_key),
        Trin::CreateDashboard(dashboard_config) => create_dashboard(dashboard_config),
    }
}

fn encode_content_key(content_key: EncodeKey) -> Result<(), Box<dyn std::error::Error>> {
    let key = match content_key {
        EncodeKey::BlockHeader { block_hash } => {
            HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
                block_hash: block_hash.into(),
            })
        }
        EncodeKey::BlockBody { block_hash } => HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: block_hash.into(),
        }),
        EncodeKey::BlockReceipts { block_hash } => {
            HistoryContentKey::BlockReceipts(BlockReceiptsKey {
                block_hash: block_hash.into(),
            })
        }
    };

    println!("{}", hex_encode(Into::<Vec<u8>>::into(key)));

    Ok(())
}

fn create_dashboard(dashboard_config: DashboardConfig) -> Result<(), Box<dyn std::error::Error>> {
    let grafana = GrafanaAPI::new(
        dashboard_config.grafana_username,
        dashboard_config.grafana_password,
        dashboard_config.grafana_address,
    );

    let prometheus_uid = grafana.create_datasource(
        "prometheus".to_string(),
        "prometheus".to_string(),
        dashboard_config.prometheus_address,
    )?;

    // Create a dashboard from each pre-defined template
    for template_path in DASHBOARD_TEMPLATES.iter() {
        let dashboard_url = grafana.create_dashboard(template_path, &prometheus_uid)?;
        println!("Dashboard successfully created: {dashboard_url}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_trin_with_encode_key() {
        const BLOCK_HASH: &str =
            "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let trin = Trin::parse_from([
            "test",
            "encode-key",
            "block-header",
            "--block-hash",
            BLOCK_HASH,
        ]);
        assert_eq!(
            trin,
            Trin::EncodeKey(EncodeKey::BlockHeader {
                block_hash: H256::from_str(BLOCK_HASH).unwrap()
            })
        );

        let trin = Trin::parse_from([
            "test",
            "encode-key",
            "block-body",
            "--block-hash",
            BLOCK_HASH,
        ]);
        assert_eq!(
            trin,
            Trin::EncodeKey(EncodeKey::BlockBody {
                block_hash: H256::from_str(BLOCK_HASH).unwrap()
            })
        );

        let trin = Trin::parse_from([
            "test",
            "encode-key",
            "block-receipts",
            "--block-hash",
            BLOCK_HASH,
        ]);
        assert_eq!(
            trin,
            Trin::EncodeKey(EncodeKey::BlockReceipts {
                block_hash: H256::from_str(BLOCK_HASH).unwrap()
            })
        );
    }

    #[test]
    fn test_trin_with_create_dashboard() {
        let trin = Trin::parse_from([
            "test",
            "create-dashboard",
            "http://localhost:8787",
            "username",
            "password",
            "http://docker:9090",
        ]);
        assert_eq!(
            trin,
            Trin::CreateDashboard(DashboardConfig {
                grafana_address: "http://localhost:8787".to_string(),
                grafana_username: "username".to_string(),
                grafana_password: "password".to_string(),
                prometheus_address: "http://docker:9090".to_string(),
            })
        );
    }
}
