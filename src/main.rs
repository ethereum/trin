use std::env;

mod cli;

fn main() {
    match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => cli::launch_trin(val),
        Err(_) => println!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    }
}
