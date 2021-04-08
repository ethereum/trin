#[macro_use]
extern crate lazy_static;

use std::env;
mod cli;
use cli::TrinConfig;
mod jsonrpc;
use jsonrpc::launch_trin;

fn main() {
    let trin_config = TrinConfig::new();

    let infura_project_id = match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    };

    launch_trin(trin_config, infura_project_id);
}
