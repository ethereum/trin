use std::env;

mod cli;

fn main() {
    let protocol = std::env::args().nth(1).expect("no protocol given");
    
    // TODO: things to configure:
    // use clap library for arg handling?
    //  - infura project id (not just env var?)
    //  - rpc endpoint port
    //  - rpc endpoint type (tcp, ws, ipc)
    //  - max concurrent requests (ie~ threadpool size)
    match &protocol[..] {
        "http" => println!("using http"),
        "ipc" => println!("using ipc"),
        _ => panic!("unsupported protocol: {}", protocol),
    }

    match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => cli::launch_trin(val, protocol),
        Err(_) => println!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    }
}
