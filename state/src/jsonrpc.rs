use crate::cli::TrinConfig;
use crate::portalnet::protocol::{PortalEndpoint, PortalEndpointKind};
use reqwest::blocking as reqwest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

#[cfg(unix)]
use std::os::unix;

use std::sync::Mutex;
use std::{panic, process};
use threadpool::ThreadPool;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Serialize, Validate)]
struct JsonRequest {
    #[validate(custom = "validate_jsonrpc_version")]
    pub jsonrpc: String,
    pub method: String,
    pub id: u32,
}

fn validate_jsonrpc_version(jsonrpc: &str) -> Result<(), ValidationError> {
    if jsonrpc != "2.0" {
        return Err(ValidationError::new("Unsupported jsonrpc version"));
    }
    Ok(())
}

lazy_static! {
    static ref IPC_PATH: Mutex<String> = Mutex::new(String::new());
}

pub fn launch_trin(
    trin_config: TrinConfig,
    infura_project_id: String,
    portal_tx: UnboundedSender<PortalEndpoint>,
) {
    let pool = ThreadPool::new(trin_config.pool_size as usize);

    match trin_config.web3_transport.as_str() {
        "ipc" => launch_ipc_client(
            pool,
            infura_project_id,
            &trin_config.web3_ipc_path,
            portal_tx,
        ),
        "http" => launch_http_client(pool, infura_project_id, trin_config, portal_tx),
        val => panic!("Unsupported web3 transport: {}", val),
    }
}

fn set_ipc_cleanup_handlers(ipc_path: &str) {
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

#[cfg(unix)]
fn get_listener_result(ipc_path: &str) -> tokio::io::Result<unix::net::UnixListener> {
    unix::net::UnixListener::bind(ipc_path)
}

#[cfg(windows)]
fn get_listener_result(ipc_path: &str) -> tokio::io::Result<uds_windows::UnixListener> {
    uds_windows::UnixListener::bind(ipc_path)
}

fn launch_ipc_client(
    pool: ThreadPool,
    infura_project_id: String,
    ipc_path: &str,
    portal_tx: UnboundedSender<PortalEndpoint>,
) {
    let listener_result = get_listener_result(ipc_path);
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
        let portal_tx = portal_tx.clone();
        pool.execute(move || {
            let infura_url = get_infura_url(&infura_project_id);
            let mut rx = stream.try_clone().unwrap();
            let mut tx = stream;
            serve_ipc_client(&mut rx, &mut tx, &infura_url, portal_tx);
        });
    }
    println!("Clean exit");
}

fn launch_http_client(
    pool: ThreadPool,
    infura_project_id: String,
    trin_config: TrinConfig,
    portal_tx: UnboundedSender<PortalEndpoint>,
) {
    let uri = format!("127.0.0.1:{}", trin_config.web3_http_port);
    let listener = TcpListener::bind(uri).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let infura_project_id = infura_project_id.clone();
                let portal_tx = portal_tx.clone();
                pool.execute(move || {
                    let infura_url = get_infura_url(&infura_project_id);
                    serve_http_client(stream, &infura_url, portal_tx);
                });
            }
            Err(e) => {
                panic!("HTTP connection failed: {}", e)
            }
        };
    }
}

fn serve_ipc_client(
    rx: &mut impl Read,
    tx: &mut impl Write,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalEndpoint>,
) {
    let deser = serde_json::Deserializer::from_reader(rx);
    for obj in deser.into_iter::<JsonRequest>() {
        let obj = obj.unwrap();
        let formatted_response = match obj.validate() {
            Ok(_) => {
                let result = handle_request(obj, &infura_url, portal_tx.clone());
                match result {
                    Ok(contents) => contents.into_bytes(),
                    Err(contents) => contents.into_bytes(),
                }
            }
            Err(e) => format!("Unsupported trin request: {}", e).into_bytes(),
        };
        tx.write_all(&formatted_response).unwrap();
    }
}

fn serve_http_client(
    mut stream: TcpStream,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalEndpoint>,
) {
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).unwrap();

    let json_request = String::from_utf8_lossy(&buffer);
    let deser = serde_json::Deserializer::from_str(&json_request);
    for obj in deser.into_iter::<JsonRequest>() {
        let obj = obj.unwrap();
        let formatted_response = match obj.validate() {
            Ok(_) => process_http_request(obj, &infura_url, portal_tx.clone()),
            Err(e) => format!("HTTP/1.1 400 BAD REQUEST\r\n\r\n{}", e).into_bytes(),
        };
        stream.write_all(&formatted_response).unwrap();
        stream.flush().unwrap();
    }
}

fn process_http_request(
    obj: JsonRequest,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalEndpoint>,
) -> Vec<u8> {
    let result = handle_request(obj, &infura_url, portal_tx);
    match result {
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
    }
}

fn handle_request(
    obj: JsonRequest,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalEndpoint>,
) -> Result<String, String> {
    match obj.method.as_str() {
        "web3_clientVersion" => Ok(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "result": "trin 0.0.1-alpha",
        })
        .to_string()),
        _ if obj.method.as_str().starts_with("discv5") => dispatch_portal_request(obj, portal_tx),
        _ => dispatch_infura_request(obj, infura_url),
    }
}

fn dispatch_infura_request(obj: JsonRequest, infura_url: &str) -> Result<String, String> {
    //Re-encode json to proxy to Infura
    let request = serde_json::to_string(&obj).unwrap();
    match proxy_to_url(request, infura_url) {
        Ok(result_body) => Ok(std::str::from_utf8(&result_body).unwrap().to_owned()),
        Err(err) => Err(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "error": format!("Infura failure: {}", err.to_string()),
        })
        .to_string()),
    }
}

fn dispatch_portal_request(
    obj: JsonRequest,
    portal_tx: UnboundedSender<PortalEndpoint>,
) -> Result<String, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let method = obj.method.as_str();
    let message = match method {
        "discv5_nodeInfo" => PortalEndpoint {
            kind: PortalEndpointKind::NodeInfo,
            resp: resp_tx,
        },
        "discv5_routingTableInfo" => PortalEndpoint {
            kind: PortalEndpointKind::RoutingTableInfo,
            resp: resp_tx,
        },
        _ => {
            return Err(json!({
                "jsonrpc": "2.0",
                "id": obj.id,
                "error": format!("Unsupported discv5 endpoint: {}", method),
            })
            .to_string())
        }
    };
    portal_tx.send(message).unwrap();

    let res = match resp_rx.blocking_recv().unwrap() {
        Ok(val) => val,
        Err(msg) => {
            return Err(json!({
                "jsonrpc": "2.0",
                "id": obj.id,
                "error": format!("Error while processing {}: {}", method, msg),
            })
            .to_string())
        }
    };
    Ok(json!({
        "jsonrpc": "2.0",
        "id": obj.id,
        "result": res,
    })
    .to_string())
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
    use validator::ValidationErrors;

    #[test]
    fn test_json_validator_accepts_valid_json() {
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "eth_blockNumber".to_string(),
        };
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn test_json_validator_with_invalid_jsonrpc_field() {
        let request = JsonRequest {
            jsonrpc: "1.0".to_string(),
            id: 1,
            method: "eth_blockNumber".to_string(),
        };
        let errors = request.validate();
        assert!(ValidationErrors::has_error(&errors, "jsonrpc"));
    }
}
