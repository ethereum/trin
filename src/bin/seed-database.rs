use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;

use discv5::enr::{CombinedKey, EnrBuilder};
use log::debug;
use rand::{distributions::Alphanumeric, Rng, RngCore};
use rlp::{Decodable, DecoderError};
use serde_json::Value;
use structopt::StructOpt;

use trin_core::portalnet::storage::PortalStorage;
use trin_core::portalnet::types::content_key::IdentityContentKey;
use trin_core::types::header::Header;
use trin_core::utils::db::get_data_dir;
use trin_history::content_key::{BlockHeader, HistoryContentKey};

// This script is used to seed testnet nodes with data from mainnetMM data dump
// https://www.dropbox.com/s/y5n36ztppltgs7x/mainnetMM.zip?dl=0
// cargo run --bin seed-database -- --private-key 0000000000000000000000000000000000000000000000000000000000000001 --data-folder ./mainnetMM

// For every 1 kb of data we store (key + value), RocksDB tends to grow by this many kb on disk...
// ...but this is a crude empirical estimation that works mainly with default value data size of 32
const DATA_OVERHEAD: f64 = 1.1783;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generator_config = GeneratorConfig::from_args();

    let mut encoded = hex::decode(&generator_config.private_key).unwrap();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut encoded).unwrap();
    let enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.build(&enr_key).unwrap()
    };
    let node_id = enr.node_id();
    let data_dir_path = get_data_dir(node_id);
    println!("Storing data for NodeID: {:02X?}", node_id);
    println!("ENR: {:?}", enr);
    println!("DB Path: {:?}", data_dir_path);

    if generator_config.overwrite {
        let _ = Command::new("rm")
            .arg("-rf")
            .arg(data_dir_path)
            .output()
            .expect("Failed to overwrite DB.");
    }

    let num_kilobytes = generator_config.kb;

    let storage_config = PortalStorage::setup_config(node_id, num_kilobytes)?;
    let storage = PortalStorage::new(storage_config)?;

    match generator_config.data_folder {
        Some(data_folder) => load_mainnet_data(storage, data_folder),
        None => load_random_data(storage, generator_config),
    }

    Ok(())
}

/// Type for data format stored in mainnetMM data dump
#[derive(Debug, Clone)]
pub struct BlockRlp {
    pub header: Option<Header>,
}

impl Decodable for BlockRlp {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let header = Header::decode_rlp(rlp).ok();
        Ok(Self { header })
    }
}

fn load_mainnet_data(mut storage: PortalStorage, data_folder: String) {
    let mainnet_data_dir = Path::new(&data_folder);
    let paths = fs::read_dir(mainnet_data_dir).unwrap();
    for path in paths {
        load_file_data(&path.unwrap().path(), &mut storage);
    }
}

fn load_file_data(path: &Path, storage: &mut PortalStorage) {
    println!("Loading data from file: {:?}", path);
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let json_blocks: Value = serde_json::from_reader(reader).unwrap();
    let mut stored_count = 0;
    let mut total_count = 0;
    match json_blocks {
        Value::Object(val) => {
            for (_block_hash, block_data) in val.into_iter() {
                match block_data {
                    Value::Object(val) => {
                        let block_rlp = val.get("rlp").unwrap().as_str().unwrap().to_string();
                        let prefix_removed_rlp = &block_rlp[2..block_rlp.len()];
                        let bytes_rlp = hex::decode(prefix_removed_rlp).unwrap();
                        let blocks: Vec<BlockRlp> = rlp::decode_list(&bytes_rlp);
                        let block = blocks.get(0).unwrap();

                        if block.header.is_some() {
                            let content_key = HistoryContentKey::BlockHeader(BlockHeader {
                                chain_id: 1u16,
                                block_hash: block.clone().header.unwrap().hash().into(),
                            });

                            let content_key_bytes: Vec<u8> = content_key.clone().into();
                            let content_key_hex = hex::encode(&content_key_bytes);
                            total_count += 1;
                            match storage.should_store(&content_key).unwrap() {
                                true => {
                                    storage.store(&content_key, &bytes_rlp).unwrap();
                                    println!("Stored content key: {:?}", content_key_hex);
                                    println!("- Block RLP: {:?}", prefix_removed_rlp.get(0..31));
                                    stored_count += 1;
                                }
                                false => {}
                            }
                        }
                    }
                    _ => debug!("Invalid deserialized type, expected an object."),
                }
            }
        }
        _ => debug!("Invalid deserialized type, expected an object."),
    }
    println!(
        "Stored {:?}/{:?} block headers from {:?}",
        stored_count, total_count, path
    );
}

fn load_random_data(mut storage: PortalStorage, generator_config: GeneratorConfig) {
    let num_kilobytes = generator_config.kb;
    let size_of_values = generator_config.value_size;
    let num_entries = ((num_kilobytes * 1000) as f64 / (size_of_values) as f64) / DATA_OVERHEAD;
    let num_of_entries = num_entries.round() as u32;

    for _ in 0..num_of_entries {
        let value = generate_random_value(size_of_values);
        let key = generate_random_content_key();

        storage.store(&key, &value).unwrap();
    }

    println!(
        "Successfully saved {} randomly generated key/value pairs to RocksDB.",
        num_of_entries
    );
}

fn generate_random_content_key() -> IdentityContentKey {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    IdentityContentKey::new(key)
}

fn generate_random_value(number_of_bytes: u32) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(number_of_bytes as usize)
        .collect()
}

// CLI Parameter Handling
#[derive(StructOpt, Debug, PartialEq)]
#[structopt(
    name = "Trin DB Util",
    version = "0.0.1",
    author = "mrferris",
    about = "Populate data in Trin DB for Testing & Development"
)]
pub struct GeneratorConfig {
    /// Number of Kilobytes to Generate
    #[structopt(
        default_value = "300",
        short,
        long,
        help = "Number of kilobytes of total data to store in the DB"
    )]
    pub kb: u32,

    /// Number of bytes per value in each random key/value pair
    #[structopt(
        default_value = "32",
        short,
        long = "value-size",
        help = "Number of bytes per value in each key/value pair to be stored in the DB"
    )]
    pub value_size: u32,

    /// If this flag is provided, the DB will be erased and overwritten
    #[structopt(short, long, help = "Overwrite the DB instead of adding to it")]
    pub overwrite: bool,

    #[structopt(
        long,
        help = "(unsafe) Hex private key to generate node id for database namespace"
    )]
    pub private_key: String,

    #[structopt(
        long,
        help = "Path to mainnetMM directory, if not included command will seed random data"
    )]
    pub data_folder: Option<String>,
}
