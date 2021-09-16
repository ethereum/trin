use structopt::StructOpt;
use rocksdb::{Options, DB};
use trin_core::utils::{get_data_dir};
use trin_core::portalnet::storage::{PortalStorage, PortalStorageConfig, DistanceFunction};
use rand::{distributions::Alphanumeric, Rng};
use std::process::Command;
use discv5::enr::NodeId;
use sha3::{Digest, Sha3_256};
use std::convert::TryInto;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {

    let generator_config = GeneratorConfig::from_args();

    if generator_config.overwrite {
        let _ = Command::new("rm")
                        .arg("-rf")
                        .arg(get_data_dir())
                        .output()
                        .expect("Failed to overwrite DB.");
    }

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    let db = DB::open(&db_opts, get_data_dir()).expect("Failed to open RocksDB.");

    let num_kilobytes = generator_config.kb;
    let size_of_keys = 32;
    let size_of_values = generator_config.value_size;

    // For every 1 kb of data we store (key + value), RocksDB tends to grow by this many kb on disk...
    // ...but this is a crude empirical estimation that works mainly with default value data size. 
    // TODO: Use perf::memory_usage_stats to be more accurate with all data sizes.
    let data_overhead = 1.1783;
    let number_of_entries = ( (num_kilobytes * 1000) as f64 / (size_of_values) as f64 ) / data_overhead;
    let number_of_entries = number_of_entries.round() as u32;

    let storage_config = PortalStorageConfig {
        storage_capacity_kb: (num_kilobytes / 4) as u64,
        node_id: NodeId::random(),
        distance_function: DistanceFunction::Xor,
    };
    let mut storage = PortalStorage::new(&storage_config, |key| {
        sha256(&key)
    }).unwrap();

    for _ in 0..number_of_entries {
        
        let value = generate_random_value(size_of_values);
        let key = generate_random_value(size_of_keys);

        println!("{} -> {}", &key, &value);

        if generator_config.portal_storage {
            storage.store(&key, &value);
        } else {
            db.put(&key, &value).expect("Failed to write DB entry.");
        }

        println!();

    } 

    db.flush().expect("Failed to flush changes to DB.");

    println!("Successfully saved {} key/value pairs to RocksDB.", number_of_entries);

    Ok(())

}

fn generate_random_value(number_of_bytes: u32) -> String {

    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(number_of_bytes as usize)
        .map(char::from)
        .collect()

}

// Placeholder content key -> content id conversion function
fn sha256(key: &str) -> [u8; 32] {

    let mut hasher = Sha3_256::new();
    hasher.update(key);
    let mut x = hasher.finalize();
    let y: &mut[u8; 32] = x.as_mut_slice().try_into().expect("Wrong length");
    //let z: &[u8; 32] = &*y;
    *y
    
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
    #[structopt(
      short,
      long,
      help = "Overwrite the DB instead of adding to it"
    )]
    pub overwrite: bool,

    /// If this flag is provided, the PortalStorage struct will be used to store data.
    #[structopt(
      short,
      long,
      help = "Use PortalStorage functionality for storing data"
    )]
    pub portal_storage: bool,

}
