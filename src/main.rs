use clap::{App, Arg};
use std::env;

mod cli;

fn main() {
    // TODO: things to configure:
    //  - infura project id (not just env var?)
    let matches = App::new("trin")
        .version("0.0.1")
        .author("carver")
        .about("super lightweight eth client thingy")
        .arg(
            Arg::with_name("protocol")
                .short("p")
                .long("protocol")
                .help("select transport protocol")
                .takes_value(true)
                .default_value("http"),
        )
        .arg(
            Arg::with_name("endpoint")
                .short("e")
                .long("endpoint")
                .help("http port")
                .takes_value(true)
                .default_value("7878"),
        )
        .arg(
            Arg::with_name("pool_size")
                .short("s")
                .long("pool_size")
                .help("max size of threadpool")
                .takes_value(true)
                .default_value("2"),
        )
        .get_matches();

    println!("Launching Trin...");
    let protocol = matches.value_of("protocol").unwrap();
    let endpoint = matches.value_of("endpoint").unwrap();
    let pool_size = matches.value_of("pool_size").unwrap();

    match protocol {
        "http" => println!("Protocol: {}\nEndpoint: {}", protocol, endpoint),
        "ipc" => match endpoint {
            "7878" => println!("Protocol: {}", protocol),
            _ => panic!("No ports for ipc connection"),
        },
        _ => panic!("Unsupported protocol: {}, supported protocols include http & ipc."),
    }
    println!("Pool Size: {}", pool_size);

    match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => cli::launch_trin(val, protocol.to_string()),
        Err(_) => println!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    }
}
