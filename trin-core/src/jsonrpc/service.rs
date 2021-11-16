use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix;
use std::str::FromStr;
use std::sync::Mutex;
use std::{fs, panic, process};

use httparse;
use log::{debug, info, warn};
use serde_json::{json, Value};
use thiserror::Error;
use threadpool::ThreadPool;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use ureq;
use validator::Validate;

use crate::cli::TrinConfig;
use crate::jsonrpc::endpoints::TrinEndpoint;
use crate::jsonrpc::types::{JsonRequest, PortalJsonRpcRequest};

lazy_static! {
    static ref IPC_PATH: Mutex<String> = Mutex::new(String::new());
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn launch_jsonrpc_server(
    trin_config: TrinConfig,
    infura_project_id: String,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
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
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
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

    info!("listening for commands: {}", ipc_path);

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
    info!("Clean exit");
}

fn launch_http_client(
    pool: ThreadPool,
    infura_project_id: String,
    trin_config: TrinConfig,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) {
    ctrlc::set_handler(move || {
        std::process::exit(1);
    })
    .expect("Error setting Ctrl-C handler.");

    let listener = TcpListener::bind(trin_config.web3_http_address).unwrap();
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
    info!("Clean exit");
}

fn serve_ipc_client(
    rx: &mut impl Read,
    tx: &mut impl Write,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) {
    let deser = serde_json::Deserializer::from_reader(rx);
    for obj in deser.into_iter::<JsonRequest>() {
        match obj {
            Ok(obj) => {
                let formatted_response = match obj.validate() {
                    Ok(_) => {
                        let result = handle_request(obj, infura_url, portal_tx.clone());
                        match result {
                            Ok(contents) => contents.into_bytes(),
                            Err(contents) => contents.into_bytes(),
                        }
                    }
                    Err(e) => format!("Unsupported trin request: {}", e).into_bytes(),
                };
                tx.write_all(&formatted_response).unwrap();
                tx.flush().unwrap();
            }
            Err(e) => {
                debug!("An error occurred while parsing the JSON text. {}", e);
                tx.write_all(
                    &"Parse error! An error occurred while parsing the JSON text."
                        .to_string()
                        .into_bytes(),
                )
                .unwrap()
            }
        };
    }
}

fn serve_http_client(
    mut stream: TcpStream,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) {
    let mut reader = io::BufReader::new(&mut stream);
    let received: Vec<u8> = reader.fill_buf().unwrap().to_vec();
    // Mark the bytes read as consumed so the buffer will not return them in a subsequent read
    reader.consume(received.len());

    let http_body = match parse_http_body(received) {
        Ok(val) => val,
        Err(msg) => {
            respond_with_parsing_error(stream, msg.to_string());
            return;
        }
    };
    let deser = serde_json::Deserializer::from_str(&http_body);
    for obj in deser.into_iter::<JsonRequest>() {
        let obj = match obj {
            Ok(val) => val,
            Err(msg) => {
                respond_with_parsing_error(stream, msg.to_string());
                break;
            }
        };
        let formatted_response = match obj.validate() {
            Ok(_) => process_http_request(obj, infura_url, portal_tx.clone()),
            Err(e) => format!("HTTP/1.1 400 BAD REQUEST\r\n\r\n{}", e).into_bytes(),
        };
        stream.write_all(&formatted_response).unwrap();
        stream.flush().unwrap();
    }
}

fn respond_with_parsing_error(mut stream: TcpStream, msg: String) {
    warn!("Error parsing http request: {:?}", msg);
    let resp = format!("HTTP/1.1 400 BAD REQUEST\r\n\r\n{}", msg).into_bytes();
    stream.write_all(&resp).unwrap();
    stream.flush().unwrap();
}

#[derive(Error, Debug)]
pub enum HttpParseError {
    #[error("Unable to parse http request: {0}")]
    InvalidRequest(String),
}

fn parse_http_body(buf: Vec<u8>) -> Result<String, HttpParseError> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    let body_offset = match req.parse(&buf) {
        Ok(val) => match val {
            httparse::Status::Complete(offset) => offset,
            httparse::Status::Partial => {
                return Err(HttpParseError::InvalidRequest(
                    "Http buffer parse incomplete".to_owned(),
                ))
            }
        },
        Err(msg) => return Err(HttpParseError::InvalidRequest(msg.to_string())),
    };
    let body = buf[body_offset..buf.len()].to_vec();
    match String::from_utf8(body) {
        Ok(val) => Ok(val),
        Err(msg) => Err(HttpParseError::InvalidRequest(msg.to_string())),
    }
}

fn process_http_request(
    obj: JsonRequest,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) -> Vec<u8> {
    let result = handle_request(obj, infura_url, portal_tx);
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

// Match json-rpc requests by "method" and forwards request onto respective dispatcher
fn handle_request(
    obj: JsonRequest,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) -> Result<String, String> {
    let method = obj.method.as_str();
    match TrinEndpoint::from_str(method) {
        Ok(val) => dispatch_trin_request(obj, val, infura_url, portal_tx),
        Err(_) => Err(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "error": format!("Invalid JSON-RPC portal endpoint: {}", method),
        })
        .to_string()),
    }
}

fn dispatch_trin_request(
    obj: JsonRequest,
    endpoint: TrinEndpoint,
    infura_url: &str,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) -> Result<String, String> {
    match endpoint {
        TrinEndpoint::PortalEndpoint(_) => Ok(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "result": format!("trin v{}", VERSION),
        })
        .to_string()),
        TrinEndpoint::InfuraEndpoint(_) => dispatch_infura_request(obj, infura_url),
        TrinEndpoint::Discv5Endpoint(_) => dispatch_portal_request(obj, endpoint, portal_tx),
        TrinEndpoint::HistoryEndpoint(_) => dispatch_portal_request(obj, endpoint, portal_tx),
        TrinEndpoint::StateEndpoint(_) => dispatch_portal_request(obj, endpoint, portal_tx),
    }
}

// Handle all requests served by infura
fn dispatch_infura_request(obj: JsonRequest, infura_url: &str) -> Result<String, String> {
    match proxy_to_url(&obj, infura_url) {
        Ok(result_body) => Ok(std::str::from_utf8(&result_body).unwrap().to_owned()),
        Err(err) => Err(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "error": format!("Infura failure: {}", err),
        })
        .to_string()),
    }
}

// Handle all requests served by fetching data from the portal network. ie. discv5/history/state/portal
fn dispatch_portal_request(
    obj: JsonRequest,
    endpoint: TrinEndpoint,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) -> Result<String, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = PortalJsonRpcRequest {
        endpoint,
        resp: resp_tx,
        params: obj.params,
    };
    portal_tx.send(message).unwrap();

    match resp_rx.blocking_recv().unwrap() {
        Ok(val) => Ok(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "result": val,
        })
        .to_string()),
        Err(msg) => Err(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "error": format!("Error while processing {}: {}", obj.method, msg),
        })
        .to_string()),
    }
}

fn proxy_to_url(request: &JsonRequest, url: &str) -> io::Result<Vec<u8>> {
    match ureq::post(url).send_json(ureq::json!(request)) {
        Ok(response) => match response.into_string() {
            Ok(val) => Ok(val.as_bytes().to_vec()),
            Err(msg) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Error decoding response: {:?}", msg),
            )),
        },
        Err(ureq::Error::Status(code, _response)) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Responded with status code: {:?}", code),
        )),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Request failure: {:?}", err),
        )),
    }
}

fn get_infura_url(infura_project_id: &str) -> String {
    return format!("https://mainnet.infura.io:443/v3/{}", infura_project_id);
}
