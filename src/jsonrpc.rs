use crate::cli::TrinConfig;
use reqwest::blocking as reqwest;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix;
use std::panic;
use std::process;
use std::sync::Mutex;
use threadpool::ThreadPool;

lazy_static! {
    static ref IPC_PATH: Mutex<String> = Mutex::new(String::new());
}

pub fn launch_trin(trin_config: TrinConfig, infura_project_id: String) {
    let pool = ThreadPool::new(trin_config.pool_size as usize);

    match trin_config.web3_transport.as_str() {
        "ipc" => launch_ipc_client(pool, infura_project_id, &trin_config.web3_ipc_path),
        "http" => launch_http_client(pool, infura_project_id, trin_config),
        val => panic!("Unsupported web3 transport: {}", val),
    }
}

fn set_ipc_cleanup_handlers(ipc_path: &String) {
    let mut ipc_mut = IPC_PATH.lock().unwrap();
    *ipc_mut = ipc_path.to_string();

    ctrlc::set_handler(move || {
        let ipc_path: &str = &*IPC_PATH.lock().unwrap().clone();
        fs::remove_file(&ipc_path).unwrap();
        std::process::exit(1);
    })
    .expect("Error setting Ctrl-C handler.");

    let original_panic = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let ipc_path: &str = &*IPC_PATH.lock().unwrap().clone();
        fs::remove_file(&ipc_path).unwrap();
        original_panic(panic_info);
        process::exit(1);
    }));
}

fn launch_ipc_client(pool: ThreadPool, infura_project_id: String, ipc_path: &String) {
    let listener_result = unix::net::UnixListener::bind(ipc_path);
    let listener = match listener_result {
        Ok(listener) => {
            set_ipc_cleanup_handlers(ipc_path);
            listener
        }
        Err(err) => {
            panic!("Could not serve from IPC path '{}': {:?}", ipc_path, err);
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
    let uri = format!("127.0.0.1:{}", trin_config.web3_http_port);
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
