use structopt::StructOpt;
use std::path::PathBuf;

use trin_core::cli::DEFAULT_WEB3_IPC_PATH;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "trin-cli",
    version = "0.0.1",
    author = "Ethereum Foundation",
    about = "Utilities for interacting with trin nodes",
)]
enum Config {
    #[structopt(
        about = "run JSON-RPC commands",
    )]
    RPC {
        #[structopt(
            default_value(DEFAULT_WEB3_IPC_PATH),
            long,
            help = "path to JSON-RPC endpoint",
        )]
        ipc: PathBuf,

        #[structopt(
            help = "e.g. discv5_routingTableInfo",
            required = true,
        )]
        endpoint: String,
    },

    #[structopt(
        about = "show list of available JSON-RPC methods",
    )]
    ListEndpoints,
}

/*
 * I have a large mapping from strings to structs describing each endpoint.
 * RPC attempts to trigger the endpoint
 * ListEndpoints operates directly on that map
 *
 * Alt: just pass the endpoint along and see if it works
 */

fn main() {
    let config = Config::from_args();

    match config {
        Config::RPC {ipc, endpoint} => {
            println!("RPC {:?} {}", ipc, endpoint);
        }
        Config::ListEndpoints => {
            println!("List Endpoints");
        }
    };
}
