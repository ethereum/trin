use clap::{App, Arg};
use std::env;
use std::ffi::OsString;

mod cli;

use cli::TrinConfig;

impl TrinConfig {
    fn new() -> Self {
        Self::new_from(std::env::args_os().into_iter()).unwrap_or_else(|e| e.exit())
    }

    fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        // TODO: things to configure:
        //  - infura project id (not just env var?)
        let matches = App::new("trin")
            .version("0.0.1")
            .author("carver")
            .about("super lightweight eth portal")
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
                    .long("pool-size")
                    .help("max size of threadpool")
                    .takes_value(true)
                    .default_value("2"),
            )
            .get_matches_from_safe(args)
            .unwrap_or_else(|e| panic!("Unable to parse args: {}", e));

        println!("Launching Trin...");
        let protocol = matches.value_of("protocol").unwrap();
        let endpoint = matches.value_of("endpoint").unwrap();
        let endpoint = match endpoint.parse::<u32>() {
            Ok(n) => n,
            Err(_) => panic!("Provided endpoint arg is not a number"),
        };
        let pool_size = matches.value_of("pool_size").unwrap();
        let pool_size = match pool_size.parse::<u32>() {
            Ok(n) => n,
            Err(_) => panic!("Provided pool size arg is not a number"),
        };

        // parse protocol & endpoint
        match protocol {
            "http" => println!("Protocol: {}\nEndpoint: {}", protocol, endpoint),
            "ipc" => match endpoint {
                7878 => println!("Protocol: {}", protocol),
                _ => panic!("No ports for ipc connection"),
            },
            val => panic!(
                "Unsupported protocol: {}, supported protocols include http & ipc.",
                val
            ),
        }
        println!("Pool Size: {}", pool_size);

        let infura_project_id = match env::var("TRIN_INFURA_PROJECT_ID") {
            Ok(val) => val,
            Err(_) => panic!(
                "Must supply Infura key as environment variable, like:\n\
                TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
            ),
        };

        Ok(TrinConfig {
            endpoint: endpoint,
            infura_project_id: infura_project_id,
            pool_size: pool_size,
            protocol: protocol.to_string(),
        })
    }
}

fn main() {
    let trin_config = TrinConfig::new();
    cli::launch_trin(trin_config);
}

#[cfg(test)]
mod test {
    use super::*;

    fn env_is_set() -> bool {
        match env::var("TRIN_INFURA_PROJECT_ID") {
            Ok(_) => true,
            _ => false,
        }
    }

    #[test]
    fn test_default_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            protocol: "http".to_string(),
            infura_project_id: "".to_string(),
            endpoint: 7878,
            pool_size: 2,
        };
        let actual_config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert_eq!(actual_config.protocol, expected_config.protocol);
        assert_eq!(actual_config.endpoint, expected_config.endpoint);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
        assert!(!actual_config.infura_project_id.is_empty());
    }

    #[test]
    #[should_panic(expected = "Unsupported protocol: xxx")]
    fn test_invalid_protocol() {
        assert!(env_is_set());
        TrinConfig::new_from(["trin", "--protocol", "xxx"].iter()).unwrap_err();
    }

    #[test]
    fn test_custom_http_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            protocol: "http".to_string(),
            infura_project_id: "".to_string(),
            endpoint: 8080,
            pool_size: 3,
        };
        let actual_config = TrinConfig::new_from(
            [
                "trin",
                "--protocol",
                "http",
                "--endpoint",
                "8080",
                "--pool-size",
                "3",
            ]
            .iter(),
        )
        .unwrap();
        assert_eq!(actual_config.protocol, expected_config.protocol);
        assert_eq!(actual_config.endpoint, expected_config.endpoint);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
        assert!(!actual_config.infura_project_id.is_empty());
    }

    #[test]
    fn test_ipc_protocol() {
        assert!(env_is_set());
        let actual_config = TrinConfig::new_from(["trin", "--protocol", "ipc"].iter()).unwrap();
        let expected_config = TrinConfig {
            protocol: "ipc".to_string(),
            infura_project_id: "".to_string(),
            endpoint: 7878,
            pool_size: 2,
        };
        assert_eq!(actual_config.protocol, expected_config.protocol);
        assert_eq!(actual_config.endpoint, expected_config.endpoint);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
        assert!(!actual_config.infura_project_id.is_empty());
    }

    #[test]
    #[should_panic(expected = "No ports for ipc connection")]
    fn test_ipc_protocol_rejects_custom_endpoint() {
        assert!(env_is_set());
        TrinConfig::new_from(["trin", "--protocol", "ipc", "--endpoint", "7879"].iter())
            .unwrap_err();
    }
}
