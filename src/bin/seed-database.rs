use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use discv5::enr::{CombinedKey, EnrBuilder};
use rand::{distributions::Alphanumeric, Rng};
use rlp::{Decodable, DecoderError};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use structopt::StructOpt;

use trin_core::portalnet::storage::{DistanceFunction, PortalStorage, PortalStorageConfig};
use trin_core::portalnet::types::uint::U256;
use trin_core::portalnet::types::content_keys::{ContentKey, HistoryContentKey, HeaderKey};
use trin_core::utils::db::get_data_dir;
use trin_core::types::header::Header;

#[derive(Debug)]
struct Block {
    _hash: String,
    rlp: String,
    _number: u64,
}

impl From<Value> for Block {
    fn from(value: Value) -> Self {
        match value {
            Value::Object(val) => {
                let values = val.values().into_iter().nth(0).unwrap();
                Self{
                    _hash: val.keys().into_iter().nth(0).unwrap().to_string(),
                    rlp: values.clone().get("rlp").unwrap().as_str().unwrap().to_string(),
                    _number: values.clone().get("number").unwrap().as_u64().unwrap(),
                }
            }
            _ => panic!("xxx")
        }
    }
}

// For every 1 kb of data we store (key + value), RocksDB tends to grow by this many kb on disk...
// ...but this is a crude empirical estimation that works mainly with default value data size of 32
const DATA_OVERHEAD: f64 = 1.1783;
const SIZE_OF_KEYS: u32 = 32;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generator_config = GeneratorConfig::from_args();

    let mut encoded = hex::decode(&generator_config.private_key).unwrap();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut encoded).unwrap();
    let enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.build(&enr_key).unwrap()
    };
    let node_id = enr.node_id();

    if generator_config.overwrite {
        let _ = Command::new("rm")
            .arg("-rf")
            .arg(get_data_dir(node_id))
            .output()
            .expect("Failed to overwrite DB.");
    }

    let db = PortalStorage::setup_rocksdb(node_id)?;
    let meta_db = PortalStorage::setup_sqlite(node_id)?;

    let storage_config = PortalStorageConfig {
        // Arbitrarily set capacity at a quarter of what we're storing.
        // todo: make this ratio configurable
        storage_capacity_kb: (generator_config.kb / 4) as u64,
        node_id,
        distance_function: DistanceFunction::Xor,
        db: Arc::new(db),
        meta_db: Arc::new(meta_db),
    };
    let storage = PortalStorage::new(storage_config, |key| sha256(key))?;

    match generator_config.data_folder {
        Some(data_folder) => load_mainnet_data(storage, data_folder),
        None => load_random_data(storage, generator_config)
    }
    
    Ok(())
}

#[derive(Debug, Clone)]
pub struct BlockRlp {
    pub header: Option<Header>,
}

impl Decodable for BlockRlp {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let header = match Header::decode_rlp(rlp, 100000000u64) {
            Ok(val) => Some(val),
            Err(_) => None,
        };
        return Ok(Self { header })
    }
}

fn load_mainnet_data(mut storage: PortalStorage, data_folder: String) {
    let mainnet_data_dir = Path::new(&data_folder);
    let paths = fs::read_dir(mainnet_data_dir).unwrap();
    for path in paths {
        load_file_data(&path.unwrap().path(), &mut storage);
    }
}

fn load_random_data(mut storage: PortalStorage, generator_config: GeneratorConfig) {
    let num_kilobytes = generator_config.kb;
    let size_of_values = generator_config.value_size;
    let num_entries = ((num_kilobytes * 1000) as f64 / (size_of_values) as f64) / DATA_OVERHEAD;
    let num_of_entries = num_entries.round() as u32;

    for _ in 0..num_of_entries {
        let value = generate_random_value(size_of_values);
        let key = generate_random_value(SIZE_OF_KEYS);

        storage.store(&key, &value).unwrap();
    }
    
    println!(
        "Successfully saved {} randomly generated key/value pairs to RocksDB.",
        num_of_entries
    );
}

fn load_file_data(path: &Path, storage: &mut PortalStorage) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let deserialized: Value = serde_json::from_reader(reader).unwrap();
    let mut stored_count = 0;
    let mut total_count = 0;
    match deserialized {
        Value::Object(val) => {
            for (key, value) in val.into_iter() {
                match value {
                    Value::Object(val) => {
                        let block: Block = Block {
                            _hash: key,
                            rlp: val.get("rlp").unwrap().as_str().unwrap().to_string(),
                            _number: val.get("number").unwrap().as_u64().unwrap(),
                        };
                        let prefix_removed = &block.rlp[2..block.rlp.len()];
                        let block_rlp = hex::decode(prefix_removed).unwrap();
                        let block: Vec<BlockRlp> = rlp::decode_list(&block_rlp);
                        let header = block[0].clone();
                        if !header.header.is_none() {
                            let header_key = HeaderKey {
                                chain_id: 1u16,
                                block_hash: header.clone().header.unwrap().hash().into(),
                            };
                            let content_key = ContentKey::HistoryContentKey(HistoryContentKey::HeaderKey(header_key));
                            let content_key_hex = hex::encode(&content_key.to_bytes());
                            match storage.should_store(&content_key_hex).unwrap() {
                                true => {
                                    let block_rlp_hex = hex::encode(block_rlp);
                                    storage.store(&content_key_hex, &block_rlp_hex).unwrap();
                                    stored_count += 1;
                                    total_count += 1;
                                },
                                false => {
                                    total_count += 1;
                                }
                            }
                        }
                    }
                    _ => panic!("Invalid deserialized type, expected an object.")
                }
            }
        }
        _ => panic!("Invalid deserialized type, expected an object.")
    }
    println!("Stored {:?}/{:?} block headers from {:?}", stored_count, total_count, path);
}

fn generate_random_value(number_of_bytes: u32) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(number_of_bytes as usize)
        .map(char::from)
        .collect()
}

// Placeholder content key -> content id conversion function
fn sha256(key: &str) -> U256 {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    let mut x = hasher.finalize();
    let y: &mut [u8; 32] = x
        .as_mut_slice()
        .try_into()
        .expect("try_into failed in hash placeholder");
    U256::from(*y)
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
    //// ummmmmmmmmmmmmmm
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

    /// If this flag is provided, the PortalStorage struct will be used to store data.
    #[structopt(short, long, help = "Use PortalStorage functionality for storing data")]
    pub portal_storage: bool,
    
    #[structopt(
        long,
        help="(unsafe) Hex private key to generate node id for database namespace"
    )]
    pub private_key: String,

    #[structopt(
        long,
        help="Path to mainnetMM directory, if not included command will seed random data"
    )]
    pub data_folder: Option<String>
}
