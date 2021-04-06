use clap::{value_t, App, Arg};
use reqwest::blocking as reqwest;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix;
use threadpool::ThreadPool;

#[derive(Debug, PartialEq)]
pub struct TrinConfig {
    pub protocol: String,
    pub http_port: u32,
    pub pool_size: u32,
}

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
                    .default_value("8545"),
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

        match protocol.as_str() {
            "http" => {
                println!("Protocol: {}\nHTTP port: {}", protocol, http_port)
            }
            "ipc" => match http_port {
                8545 => println!("Protocol: {}", protocol),
                _ => panic!("Must not supply an http port when using ipc protocol"),
            },
            val => panic!("Unsupported protocol: {}", val),
        }

        println!("Pool Size: {}", pool_size);

        Ok(TrinConfig {
            http_port,
            pool_size,
            protocol,
        })
    }
}

pub fn launch_trin(trin_config: TrinConfig, infura_project_id: String) {
    let pool = ThreadPool::new(trin_config.pool_size as usize);

    match trin_config.protocol.as_str() {
        "ipc" => launch_ipc_client(pool, infura_project_id),
        "http" => launch_http_client(pool, infura_project_id, trin_config),
        val => panic!("Unsupported protocol: {}", val),
    }
}

fn launch_ipc_client(pool: ThreadPool, infura_project_id: String) {
    let path = "/tmp/trin-jsonrpc.ipc";
    let listener_result = unix::net::UnixListener::bind(path);
    let listener = match listener_result {
        Ok(listener) => listener,
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            // TODO something smarter than just dropping the existing file and/or
            // make sure file gets cleaned up on shutdown.
            match fs::remove_file(path) {
                Err(_) => panic!("Could not serve from existing path '{}'", path),
                Ok(()) => unix::net::UnixListener::bind(path).unwrap(),
            }
        }
        Err(err) => {
            panic!("Could not serve from path '{}': {:?}", path, err);
        }
    };

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let infura_project_id = infura_project_id.clone();
        pool.execute(move || {
            let infura_url = get_infura_url(&infura_project_id);
            let mut rx = stream.try_clone().unwrap();
            let mut tx = stream;
            serve_ipc_client(&mut rx, &mut tx, &infura_url);
        });
    }
}

fn serve_ipc_client(rx: &mut impl Read, tx: &mut impl Write, infura_url: &str) {
    println!("Welcoming...");
    let deser = serde_json::Deserializer::from_reader(rx);
    for obj in deser.into_iter::<serde_json::Value>() {
        let obj = obj.unwrap();
        assert!(obj.is_object());
        assert_eq!(obj["jsonrpc"], "2.0");
        let request_id = obj.get("id").unwrap();
        let method = obj.get("method").unwrap();

        let response = match method.as_str().unwrap() {
            "web3_clientVersion" => format!(
                r#"{{"jsonrpc":"2.0","id":{},"result":"trin 0.0.1-alpha"}}"#,
                request_id,
            )
            .into_bytes(),
            _ => {
                //Re-encode json to proxy to Infura
                let request = obj.to_string();
                match proxy_to_url(request, infura_url) {
                    Ok(result_body) => result_body,
                    Err(err) => format!(
                        r#"{{"jsonrpc":"2.0","id":"{}","error":"Infura failure: {}"}}"#,
                        request_id,
                        err.to_string(),
                    )
                    .into_bytes(),
                }
            }
        };
        tx.write_all(&response).unwrap();
    }
    println!("Clean exit");
}

fn launch_http_client(pool: ThreadPool, infura_project_id: String, trin_config: TrinConfig) {
    let uri = format!("127.0.0.1:{}", trin_config.http_port);
    let listener = TcpListener::bind(uri).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let infura_project_id = infura_project_id.clone();
                pool.execute(move || {
                    let infura_url = get_infura_url(&infura_project_id);
                    serve_http_client(stream, &infura_url);
                });
            }
            Err(e) => {
                panic!("HTTP connection failed: {}", e)
            }
        }
    }
}

fn serve_http_client(mut stream: TcpStream, infura_url: &str) {
    let mut buffer = Vec::new();

    stream.read_to_end(&mut buffer).unwrap();

    let json_request = String::from_utf8_lossy(&buffer);
    let deser = serde_json::Deserializer::from_str(&json_request);
    for obj in deser.into_iter::<serde_json::Value>() {
        let obj = obj.unwrap();
        assert!(obj.is_object());
        assert_eq!(obj["jsonrpc"], "2.0");
        let request_id = obj.get("id").unwrap();
        let method = obj.get("method").unwrap();

        let response = match method.as_str().unwrap() {
            "web3_clientVersion" => {
                let contents = format!(
                    r#"{{"jsonrpc":"2.0","id":{},"result":"trin 0.0.1-alpha"}}"#,
                    request_id
                );
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    contents.len(),
                    contents,
                )
                .into_bytes()
            }
            _ => {
                //Re-encode json to proxy to Infura
                let request = obj.to_string();
                match proxy_to_url(request, infura_url) {
                    Ok(result_body) => {
                        let contents = String::from_utf8_lossy(&result_body);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                            contents.len(),
                            contents,
                        )
                        .into_bytes()
                    }
                    Err(err) => {
                        let contents = format!(
                            r#"{{"jsonrpc":"2.0","id":"{}","error":"Infura failure: {}"}}"#,
                            request_id,
                            err.to_string(),
                        );
                        format!(
                            "HTTP/1.1 502 BAD GATEWAY\r\nContent-Length: {}\r\n\r\n{}",
                            contents.len(),
                            contents,
                        )
                        .into_bytes()
                    }
                }
            }
        };
        stream.write_all(&response).unwrap();
        stream.flush().unwrap();
    }
}

fn proxy_to_url(request: String, url: &str) -> io::Result<Vec<u8>> {
    let client = reqwest::Client::new();
    match client.post(url).body(request).send() {
        Ok(response) => {
            let status = response.status();

            if status.is_success() {
                match response.bytes() {
                    Ok(bytes) => Ok(bytes.to_vec()),
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unexpected error when accessing the response body",
                    )),
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Responded with status code: {:?}", status),
                ))
            }
        }
        Err(err) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Request failure: {:?}", err),
        )),
    }
}

fn get_infura_url(infura_project_id: &str) -> String {
    return format!("https://mainnet.infura.io:443/v3/{}", infura_project_id);
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
            http_port: 8545,
            pool_size: 2,
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
            protocol: "http".to_string(),
            http_port: 8080,
            pool_size: 3,
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
            protocol: "ipc".to_string(),
            http_port: 8545,
            pool_size: 2,
        };
        assert_eq!(actual_config.protocol, expected_config.protocol);
        assert_eq!(actual_config.http_port, expected_config.http_port);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
    }

    #[test]
    #[should_panic(expected = "Must not supply an http port when using ipc")]
    fn test_ipc_protocol_rejects_custom_http_port() {
        assert!(env_is_set());
        TrinConfig::new_from(["trin", "--protocol", "ipc", "--http-port", "7879"].iter())
            .unwrap_err();
    }
}
