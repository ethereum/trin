#[cfg(unix)]
use std::os::unix;
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    net::{TcpListener, TcpStream},
    panic,
    str::FromStr,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use httparse;
use serde_json::{json, Value};
use thiserror::Error;
use threadpool::ThreadPool;
use tokio::sync::{mpsc, mpsc::UnboundedSender};
use tracing::{debug, info, warn};
use ureq::{self, Request};
use validator::Validate;

use crate::{
    cli::TrinConfig,
    jsonrpc::{
        endpoints::TrinEndpoint,
        types::{JsonRequest, PortalJsonRpcRequest},
    },
    utils::provider::TrustedProvider,
};

pub struct JsonRpcExiter {
    should_exit: Arc<RwLock<bool>>,
}

impl JsonRpcExiter {
    pub fn new() -> Self {
        JsonRpcExiter {
            should_exit: Arc::new(RwLock::new(false)),
        }
    }

    pub fn exit(&self) {
        let mut flag = self.should_exit.write().unwrap();
        *flag = true;
    }

    pub fn is_exiting(&self) -> bool {
        let flag = self.should_exit.read().unwrap();
        *flag
    }
}

impl Default for JsonRpcExiter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn launch_jsonrpc_server(
    trin_config: TrinConfig,
    trusted_provider: TrustedProvider,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
    live_server_tx: tokio::sync::mpsc::Sender<bool>,
    json_rpc_exiter: Arc<JsonRpcExiter>,
) {
    let pool = ThreadPool::new(trin_config.pool_size as usize);

    match trin_config.web3_transport.as_str() {
        "ipc" => launch_ipc_client(
            pool,
            trusted_provider,
            &trin_config.web3_ipc_path,
            portal_tx,
            live_server_tx,
            json_rpc_exiter,
        ),
        "http" => launch_http_client(
            pool,
            trusted_provider,
            trin_config,
            portal_tx,
            live_server_tx,
        ),
        val => panic!("Unsupported web3 transport: {}", val),
    }
}

fn set_ipc_cleanup_handlers(ipc_path: &str) {
    {
        let ipc_path = ipc_path.to_string();
        if let Err(err) = ctrlc::set_handler(move || {
            if let Err(err) = fs::remove_file(&ipc_path) {
                debug!("Ctrl-C: Skipped removing {} because: {}", ipc_path, err);
            };
            std::process::exit(1);
        }) {
            warn!(
                "Could not set the Ctrl-C handler for removing the IPC socket: {}",
                err
            );
        }
    }

    {
        let ipc_path = ipc_path.to_string();
        let original_panic = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            if let Err(err) = fs::remove_file(&ipc_path) {
                debug!("Panic hook: Skipped removing {} because: {}", ipc_path, err);
            };
            original_panic(panic_info);
        }));
    }
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
    trusted_provider: TrustedProvider,
    ipc_path: &str,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
    live_server_tx: tokio::sync::mpsc::Sender<bool>,
    json_rpc_exiter: Arc<JsonRpcExiter>,
) {
    let listener_result = get_listener_result(ipc_path);
    let listener = match listener_result {
        Ok(listener) => {
            set_ipc_cleanup_handlers(ipc_path);
            listener
                .set_nonblocking(true)
                .expect("Cannot set non-blocking");
            listener
        }
        Err(err) => {
            panic!("Could not serve from IPC path '{}': {:?}", ipc_path, err);
        }
    };

    info!(path = %ipc_path, "IPC JSON-RPC server listening for commands");
    std::thread::spawn(move || {
        live_server_tx.blocking_send(true).unwrap();
    });

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => {
                // Each stream will be checked in its own thread, so can remain blocking
                s.set_nonblocking(false)
                    .expect("Couldn't set stream to block");
                s
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No one was waiting yet for the socket
                // Check if we should exit
                if json_rpc_exiter.is_exiting() {
                    break;
                } else {
                    // Wait, then check for new clients.
                    // Check 5 times per second:
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
            }
            Err(_) => break, // Socket exited
        };
        debug!("New IPC client: {:?}", stream.peer_addr().unwrap());
        let trusted_provider = trusted_provider.clone();
        let portal_tx = portal_tx.clone();
        pool.execute(move || {
            let mut rx = stream.try_clone().unwrap();
            let mut tx = stream;
            serve_ipc_client(&mut rx, &mut tx, trusted_provider, portal_tx);
        });
    }
    info!("IPC JSON-RPC server exited cleanly");

    if let Err(err) = fs::remove_file(ipc_path) {
        debug!("Clean Exit: Skipped removing {} because: {}", ipc_path, err);
    }
}

fn launch_http_client(
    pool: ThreadPool,
    trusted_provider: TrustedProvider,
    trin_config: TrinConfig,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
    live_server_tx: tokio::sync::mpsc::Sender<bool>,
) {
    ctrlc::set_handler(move || {
        std::process::exit(1);
    })
    .expect("Error setting Ctrl-C handler.");

    let listener = TcpListener::bind(&trin_config.web3_http_address).unwrap();

    info!(url = %trin_config.web3_http_address, "HTTP JSON-RPC server listening for commands");
    std::thread::spawn(move || {
        live_server_tx.blocking_send(true).unwrap();
    });

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let trusted_provider = trusted_provider.clone();
                let portal_tx = portal_tx.clone();
                pool.execute(move || {
                    serve_http_client(stream, trusted_provider, portal_tx);
                });
            }
            Err(e) => {
                panic!("HTTP connection failed: {}", e)
            }
        };
    }
    info!("HTTP JSON-RPC server exited cleanly");
}

fn serve_ipc_client(
    rx: &mut impl Read,
    tx: &mut impl Write,
    trusted_provider: TrustedProvider,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) {
    let deser = serde_json::Deserializer::from_reader(rx);
    for obj in deser.into_iter::<JsonRequest>() {
        debug!("Got new IPC request: {:?}", obj);
        match obj {
            Ok(obj) => {
                let formatted_response = match obj.validate() {
                    Ok(_) => {
                        let result =
                            handle_request(obj, trusted_provider.clone(), portal_tx.clone());
                        match result {
                            Ok(contents) => contents.into_bytes(),
                            Err(contents) => contents.into_bytes(),
                        }
                    }
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "id": obj.id,
                        "error": format!("Unsupported trin request: {}", e),
                    })
                    .to_string()
                    .into_bytes(),
                };
                match tx.write_all(&formatted_response) {
                    Ok(_) => tx.flush().unwrap(),
                    Err(msg) => warn!("Unable to write bytes to unix stream, the requestor has likely timed out: {:?}", msg),
                }
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
    trusted_provider: TrustedProvider,
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
    let mut json_objects = deser.into_iter::<JsonRequest>();

    // Currently we assume a single JSON-RPC object within each received request.
    // Other valid JSON objects contained within the request will currently be ignored.
    let obj = json_objects.next();
    match obj {
        None => respond_with_parsing_error(stream, "No valid JSON object in request.".to_string()),
        Some(obj) => {
            let obj = match obj {
                Ok(val) => val,
                Err(msg) => {
                    respond_with_parsing_error(stream, msg.to_string());
                    return;
                }
            };
            let formatted_response = match obj.validate() {
                Ok(_) => process_http_request(obj, trusted_provider, portal_tx),
                Err(e) => format!("HTTP/1.1 400 BAD REQUEST\r\n\r\n{}", e).into_bytes(),
            };
            stream.write_all(&formatted_response).unwrap();
            stream.flush().unwrap();
        }
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
    trusted_provider: TrustedProvider,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) -> Vec<u8> {
    let result = handle_request(obj, trusted_provider, portal_tx);
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
    trusted_provider: TrustedProvider,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) -> Result<String, String> {
    let method = obj.method.as_str();
    match TrinEndpoint::from_str(method) {
        Ok(val) => dispatch_trin_request(obj, val, trusted_provider, portal_tx),
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
    trusted_provider: TrustedProvider,
    portal_tx: UnboundedSender<PortalJsonRpcRequest>,
) -> Result<String, String> {
    match endpoint {
        TrinEndpoint::TrustedProviderEndpoint(_) => {
            dispatch_trusted_http_request(obj, trusted_provider.http)
        }
        _ => dispatch_portal_request(obj, endpoint, portal_tx),
    }
}

// Handle all http requests served by the trusted provider
pub fn dispatch_trusted_http_request(
    obj: JsonRequest,
    trusted_http_client: Request,
) -> Result<String, String> {
    match proxy_to_url(&obj, trusted_http_client) {
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
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<anyhow::Result<Value>>();
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

fn proxy_to_url(request: &JsonRequest, trusted_http_client: Request) -> io::Result<Vec<u8>> {
    match trusted_http_client.send_json(ureq::json!(request)) {
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
