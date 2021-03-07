mod cli;

use cli::TrinConfig;

fn main() {
    let trin_config = TrinConfig::new();
    cli::launch_trin(trin_config);
}
