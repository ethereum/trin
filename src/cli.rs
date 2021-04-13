use clap::{value_t, App, Arg};
use std::env;
use std::ffi::OsString;

#[derive(Debug, PartialEq)]
pub struct TrinConfig {
    pub protocol: String,
    pub ipc_path: String,
    pub http_port: u32,
    pub pool_size: u32,
}

const DEFAULT_IPC_PATH: &str = "/tmp/trin-jsonrpc.ipc";
const DEFAULT_HTTP_PORT: &str = "8545";

impl TrinConfig {
    pub fn new() -> Self {
        Self::new_from(env::args_os()).expect("Could not parse trin arguments")
    }

    fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = App::new("trin")
            .version("0.0.1")
            .author("carver")
            .about("super lightweight eth portal")
            .arg(
                Arg::with_name("protocol")
                    .short("p")
                    .long("protocol")
                    .help("select transport protocol")
                    .possible_values(&["http", "ipc"])
                    .takes_value(true)
                    .default_value("http"),
            )
            .arg(
                Arg::with_name("http_port")
                    .short("h")
                    .long("http-port")
                    .help("port to accept http connections")
                    .takes_value(true)
                    .default_value(&DEFAULT_HTTP_PORT),
            )
            .arg(
                Arg::with_name("ipc_path")
                    .short("i")
                    .long("ipc-path")
                    .help("path to IPC location")
                    .takes_value(true)
                    .default_value(&DEFAULT_IPC_PATH),
            )
            .arg(
                Arg::with_name("pool_size")
                    .short("s")
                    .long("pool-size")
                    .help("max size of threadpool")
                    .takes_value(true)
                    .default_value("2"),
            )
            .get_matches_from(args);

        println!("Launching trin...");
        let pool_size = value_t!(matches.value_of("pool_size"), u32)?;
        let http_port = value_t!(matches.value_of("http_port"), u32)?;
        let protocol = value_t!(matches.value_of("protocol"), String)?;
        let ipc_path = value_t!(matches.value_of("ipc_path"), String)?;

        match protocol.as_str() {
            "http" => match &ipc_path[..] {
                DEFAULT_IPC_PATH => println!("Protocol: {}\nHTTP port: {}", protocol, http_port),
                _ => panic!("Must not supply an ipc path when using http protocol"),
            },
            "ipc" => match &http_port.to_string()[..] {
                DEFAULT_HTTP_PORT => println!("Protocol: {}\nIPC path: {}", protocol, ipc_path),
                _ => panic!("Must not supply an http port when using ipc protocol"),
            },
            val => panic!("Unsupported protocol: {}", val),
        }

        println!("Pool Size: {}", pool_size);

        Ok(TrinConfig {
            http_port,
            ipc_path,
            pool_size,
            protocol,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;

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
            http_port: DEFAULT_HTTP_PORT.parse::<u32>().unwrap(),
            ipc_path: DEFAULT_IPC_PATH.to_string(),
            pool_size: 2,
            protocol: "http".to_string(),
        };
        let actual_config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert_eq!(actual_config.protocol, expected_config.protocol);
        assert_eq!(actual_config.http_port, expected_config.http_port);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
    }

    #[test]
    fn test_custom_http_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            http_port: 8080,
            ipc_path: DEFAULT_IPC_PATH.to_string(),
            pool_size: 3,
            protocol: "http".to_string(),
        };
        let actual_config = TrinConfig::new_from(
            [
                "trin",
                "--protocol",
                "http",
                "--http-port",
                "8080",
                "--pool-size",
                "3",
            ]
            .iter(),
        )
        .unwrap();
        assert_eq!(actual_config.protocol, expected_config.protocol);
        assert_eq!(actual_config.http_port, expected_config.http_port);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
    }

    #[test]
    fn test_ipc_protocol() {
        assert!(env_is_set());
        let actual_config = TrinConfig::new_from(["trin", "--protocol", "ipc"].iter()).unwrap();
        let expected_config = TrinConfig {
            http_port: DEFAULT_HTTP_PORT.parse::<u32>().unwrap(),
            ipc_path: DEFAULT_IPC_PATH.to_string(),
            pool_size: 2,
            protocol: "ipc".to_string(),
        };
        assert_eq!(actual_config.protocol, expected_config.protocol);
        assert_eq!(actual_config.http_port, expected_config.http_port);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
    }

    #[test]
    fn test_ipc_with_custom_path() {
        assert!(env_is_set());
        let actual_config = TrinConfig::new_from(
            ["trin", "--protocol", "ipc", "--ipc-path", "/path/test.ipc"].iter(),
        )
        .unwrap();
        let expected_config = TrinConfig {
            http_port: DEFAULT_HTTP_PORT.parse::<u32>().unwrap(),
            ipc_path: "/path/test.ipc".to_string(),
            pool_size: 2,
            protocol: "ipc".to_string(),
        };
        assert_eq!(actual_config.protocol, expected_config.protocol);
        assert_eq!(actual_config.http_port, expected_config.http_port);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
        assert_eq!(actual_config.ipc_path, expected_config.ipc_path);
    }

    #[test]
    #[should_panic(expected = "Must not supply an ipc path when using http")]
    fn test_http_protocol_rejects_custom_ipc_path() {
        assert!(env_is_set());
        TrinConfig::new_from(["trin", "--protocol", "http", "--ipc-path", "/path/test.ipc"].iter())
            .unwrap_err();
    }

    #[test]
    #[should_panic(expected = "Must not supply an http port when using ipc")]
    fn test_ipc_protocol_rejects_custom_http_port() {
        assert!(env_is_set());
        TrinConfig::new_from(["trin", "--protocol", "ipc", "--http-port", "7879"].iter())
            .unwrap_err();
    }
}
