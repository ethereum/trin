use crate::cli::TrinConfig;
use reqwest::blocking as reqwest;
use serde_json;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix;
use std::panic;
use std::process;
use std::sync::Mutex;
use std::fs;
use threadpool::ThreadPool;

lazy_static! {
    static ref IPC_PATH: Mutex<String> = Mutex::new(String::new());
}


pub fn launch_trin(trin_config: TrinConfig, infura_project_id: String) {
    let pool = ThreadPool::new(trin_config.pool_size as usize);

    match trin_config.protocol.as_str() {
        "ipc" => launch_ipc_client(pool, infura_project_id, &trin_config.ipc_path),
        "http" => launch_http_client(pool, infura_project_id, trin_config),
        val => panic!("Unsupported protocol: {}", val),
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

fn serve_ipc_client(rx: &mut impl Read, tx: &mut impl Write, infura_url: &String) {
    println!("Welcoming...");
    let json_iterator = serde_json::Deserializer::from_reader(rx);
    for obj in json_iterator.into_iter::<serde_json::Value>() {
        let result = make_request(obj.unwrap(), &infura_url);
        let formatted_response = match result {
            Ok(contents) => contents.into_bytes(),
            Err(contents) => contents.into_bytes(),
        };
        tx.write_all(&formatted_response).unwrap();
    }
    println!("Clean exit");
}

fn serve_http_client(mut stream: TcpStream, infura_url: &str) {
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).unwrap();

    let json_request = String::from_utf8_lossy(&buffer);
    let json_iterator = serde_json::Deserializer::from_str(&json_request);
    for obj in json_iterator.into_iter::<serde_json::Value>() {
        let result = make_request(obj.unwrap(), &infura_url);
        let formatted_response = match result {
            Ok(contents) => format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                contents.len(),
                contents,
            )
            .into_bytes(),
            Err(contents) => format!(
                "HTTP/1.1 502 BAD GATEWAY\r\nContent-Length: {}\r\n\r\n{}",
                contents.len(),
                contents,
            )
            .into_bytes(),
        };
        stream.write(&formatted_response).unwrap();
        stream.flush().unwrap();
    }
    println!("Clean exit");
}

fn make_request(obj: serde_json::Value, infura_url: &str) -> Result<String, String> {
    assert!(obj.is_object());
    assert_eq!(obj["jsonrpc"], "2.0");
    let request_id = obj.get("id").unwrap();
    let method = obj.get("method").unwrap();
    match method.as_str().unwrap() {
        "web3_clientVersion" => Ok(format!(
            r#"{{"jsonrpc":"2.0","id":{},"result":"trin 0.0.1-alpha"}}"#,
            request_id,
        )),
        _ => {
            //Re-encode json to proxy to Infura
            let request = obj.to_string();
            match proxy_to_url(request, infura_url) {
                Ok(result_body) => Ok(std::str::from_utf8(&result_body).unwrap().to_owned()),
                Err(err) => Err(format!(
                    r#"{{"jsonrpc":"2.0","id":"{}","error":"Infura failure: {}"}}"#,
                    request_id,
                    err.to_string(),
                )),
            }
        }
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
