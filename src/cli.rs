//use web3::{Web3, transports};
use threadpool::ThreadPool;
use std::sync::mpsc::channel;
use std::net;
use std::io::{self, Read, Write};

// TODO: things to configure:
//  - infura project id (not just env var?)
//  - rpc endpoint port
//  - rpc endpoint type (tcp, ws, ipc)
//  - max concurrent requests (ie~ threadpool size)

pub fn launch_trin(infura_project_id: String) {
    println!("Launching with infura key: '{}'", infura_project_id);
    let infura_url = format!("https://mainnet.infura.io/v3/{}", infura_project_id);

    let pool = ThreadPool::new(2);

    let listener = net::TcpListener::bind("127.0.0.1:8080").unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        pool.execute(move || serve_client(&mut stream));
    }
}

fn serve_client(stream: &mut net::TcpStream) {
    println!("Welcoming...");
    stream.write_all(b"Welcome!").unwrap();
    loop {
        stream.write_all(b"\nInput: ").unwrap();
        match read_line(stream) {
            line if line.len() == 0 => break,
            request => {
                stream.write_all(b"Echoing: ").unwrap();
                stream.write_all(&request).unwrap();
            }
        }
    }
    println!("Clean exit");
}

fn read_line(stream: &mut net::TcpStream) -> Vec<u8> {
    let mut command = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(size) if size == 0 => break,  //EOF
            Ok(size) => {
                if &buffer[size-1] == &b'\n' {
                    let size = size - 1;
                    command.extend(&buffer[..size]);
                    break;
                } else {
                    command.extend(&buffer[..size]);
                };
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => panic!("Stream read failure: {:?}", err),
        }
    }
    command
}
