//use web3::{Web3, transports};
use reqwest::blocking as reqwest;
use std::sync::mpsc::channel;
use std::net;
use std::io::{self, Read, Write};
use std::os::unix;
use threadpool::ThreadPool;

// TODO: things to configure:
//  - infura project id (not just env var?)
//  - rpc endpoint port
//  - rpc endpoint type (tcp, ws, ipc)
//  - max concurrent requests (ie~ threadpool size)

pub fn launch_trin(infura_project_id: String) {
    println!("Launching with infura key: '{}'", infura_project_id);

    let pool = ThreadPool::new(2);

    //let listener = net::TcpListener::bind("127.0.0.1:8080").unwrap();
    let listener = unix::net::UnixListener::bind("/tmp/trin-jsonrpc.ipc").unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let infura_project_id = infura_project_id.clone();
        pool.execute(move || {
            let infura_url = format!("https://mainnet.infura.io:443/v3/{}", infura_project_id);
            serve_client(&mut stream, &infura_url);
        });
    }
}

fn serve_client(stream: &mut (impl Read + Write), infura_url: &String) {
    println!("Welcoming...");
    loop {
        match read_line(stream) {
            line if line.len() == 0 => break,
            request => {
                if let Err(err) = proxy_to_url(request, stream, infura_url) {
                    // TODO properly pass through the failure, and match response id with request id
                    stream.write_all(
                        b"{\"jsonrpc\":\"2.0\", \"error\": \"Infura failure\"}")
                        .unwrap();
                    //stream.write_all(err.to_string().as_bytes()).unwrap();
                }
            }
        }
    }
    println!("Clean exit");
}

fn proxy_to_url(request: Vec<u8>, out: &mut (impl Read + Write), url: &String) -> io::Result<()> {
    let client = reqwest::Client::new();
    match client.post(url).body(request).send() {
        Ok(mut response) => {
            let status = response.status();

            if status.is_success() {
                response.copy_to(out).unwrap();
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Responded with status code: {:?}", status),
                ))
            }
        },
        Err(err) => {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Request failure: {:?}", err),
            ))
        },
    }
}

fn read_line(stream: &mut (impl Read + Write)) -> Vec<u8> {
    let mut command = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(size) if size == 0 => break,  //EOF
            Ok(size) => {
                command.extend(&buffer[..size]);
                if &buffer[size-1] == &b'\n' {
                    break;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => panic!("Stream read failure: {:?}", err),
        }
    }
    command
}
