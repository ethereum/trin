# Getting Started

**Trin is currently in unstable alpha, and should not be used in production. If you run into any bugs while using Trin, please file an Issue!**

**Check out the [Release Notes](/docs/release_notes.md) to see the latest supported features.**

## Prerequisites
- Execution node, either:
    - Local node
    - [Infura](https://infura.io/) project ID
- [Rust](https://www.rust-lang.org/) installation

## Building, Testing, and Running

Note: If you use a VPN, you should disable it before running Trin.

Install dependencies (Ubuntu/Debian):

```sh
apt install libssl-dev librocksdb-dev libclang-dev pkg-config build-essential
```

Environment variables:

```sh
# Required if not using a local node ("--trusted-provider custom" flag).
export TRIN_INFURA_PROJECT_ID=<infura-project-id>

# Optional
export RUST_LOG=<error/warn/info/debug/trace>
export TRIN_DATA_PATH=<path-to-data-directory>
```

Build, test, and run:

```sh
git clone https://github.com/ethereum/trin.git
cd trin

# Build
cargo build --workspace

# Run test suite
cargo test --workspace

# Build and run test suite for an individual crate
cargo build -p trin-core
cargo test -p trin-core

# Run
cargo run
```

Note: You may also pass environment variable values in the same command as the run command. This is especially useful for setting log levels.

```sh
RUST_LOG=debug cargo run 
```

View CLI options:

```sh
cargo run -- --help
```

### Run locally

Run with the `--trusted-provider` as a local execution node (normally runs on `127.0.0.1:8545`), which can be configured with the `--trusted-provider-url` flag.

Serve portal node web3 access over a different port (such as `8547`) using the `--web3-http-address` flag. The `--web3-transport` for a local node will be over `http`
(rather than `ipc`).

```
RUST_LOG=debug cargo run -- \
    --trusted-provider custom \
    --trusted-provider-url http://127.0.0.1:8545 \
    --web3-http-address http://127.0.0.1:8547 \
    --web3-transport http \
    --discovery-port 9009 \
    --bootnodes default \
    --kb 200000 \
    --no-stun
```

### Connect to the Portal Network testnet

To immediately connect to the testnet, you can use the `--bootnodes default` argument to automatically connect with the default Trin bootnodes.

```sh
cargo run -- --bootnodes default
```

To establish a connection with a specific peer, pass in one or more bootnode ENRs. Pass the ENR as the value for the `--bootnodes` CLI flag.

```sh
cargo run -- --bootnodes <bootnode-enr> 
```

## Default data directories

- Linux/Unix: `$HOME/.local/share/trin`
- MacOS: `~/Library/Application Support/trin`
- Windows: `C:\Users\Username\AppData\Roaming\trin`

## Using Trin

In some of the following sections, we make use of the [web3.py](https://github.com/ethereum/web3.py/) library.

### Connect over IPC

In a python shell:

```py
>>> from web3 import Web3
>>> w3 = Web3(Web3.IPCProvider("/tmp/trin-jsonrpc.ipc"))
>>> w3.clientVersion
'trin 0.0.1-alpha'
>>> w3.eth.blockNumber
11870768
```

To request a custom jsonrpc endpoint, provide the endpoint and array of params. eg:
```py
>>> w3.provider.make_request("portal_historyPing", ["enr:-IS4QBz_40AQVBaqlhPIWFwVEphZqPKS3EPso1PwK01nwDMtMCcgK73FppW1C9V_BQRsvWV5QTbT1IYUR-zv8_cnIakDgmlkgnY0gmlwhKRc9_OJc2VjcDI1NmsxoQM-ccaM0TOFvYqC_RY_KhZNhEmWx8zdf6AQALhKyMVyboN1ZHCCE4w", "18446744073709551615"])
{'jsonrpc': '2.0',
 'id': 0,
 'result': {'enrSeq': '3',
  'dataRadius': '115792089237316195423570985008687907853269984665640564039457584007913129639935'}}
```

See the [JSON-RPC API docs](/docs/jsonrpc_api.md) for other standard methods that are implemented. You can use the [web3.py](https://web3py.readthedocs.io/en/stable/web3.eth.html#module-web3.eth) API to access these.

### Connect over HTTP

First launch trin using HTTP as the json-rpc transport protocol:

```sh
cargo run -- --web3-transport http
```

Then, in a python shell:

```py
>>> from web3 import Web3
>>> w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
>>> w3.clientVersion
'trin 0.0.1-alpha'
>>> w3.eth.blockNumber
11870768
```

The client version responds immediately, from the trin client. The block number is retrieved more slowly, by proxying to Infura.

To interact with trin at the lowest possible level, try netcat:

```sh
nc -U /tmp/trin-jsonrpc.ipc
{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":83}
{"jsonrpc":"2.0","id":83,"result":"0xb52258"}{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":84}
{"jsonrpc":"2.0","id":84,"result":"0xb52259"}{"jsonrpc":"2.0","id":85,"params":[],"method":"web3_clientVersion"}
{"jsonrpc":"2.0","id":"85","result":"trin 0.0.1-alpha"}
{"jsonrpc":"2.0","id":86,"params":[],"method":"discv5_nodeInfo"}
{"id":86,"jsonrpc":"2.0","result":"enr:-IS4QHK_CnCsQKT-mFTilJ5msHacIJtU91aYe8FhAd_K7G-ACO-FO2GPFOyM7kiphjXMwrNh8Y4mSbN3ufSdBQFzjikBgmlkgnY0gmlwhMCoAMKJc2VjcDI1NmsxoQNa58x56RRRcUeOegry5S4yQvLa6LKlDcbBPHL4H5Oy4oN1ZHCCIyg"}
```

For something in between, you may use `curl` to send requests to the HTTP JSON-RPC endpoint.

## Using Trin-CLI

A more detailed description of `trin-cli` is available [here](../trin-cli/README.md).

We can use Trin-CLI to initiate sending a message from one Trin client to another.

### Trin-CLI Environment

- Open a new terminal window and make sure you're in the same directory where Trin is installed.
- Make sure that you've set the required environment variables.

### View routing table

Each Trin client uses a routing table to maintain a record of members in the Portal network with whom it can communicate. At startup, your routing table should be empty (unless you've passed in the bootnode ENR's via the `--bootnodes` CLI param).

View your routing table:

```sh
cargo run -p trin-cli -- json-rpc discv5_routingTableInfo
```

View ENR information about your own Trin client:

```sh
cargo run -p trin-cli -- json-rpc discv5_nodeInfo
```

### Connect to the Portal Network testnet

You can send a message from the local node to a bootnode using JSON-RPC, automatically adding the bootnode to your routing table.

Find a [testnet bootnode ENR](https://github.com/ethereum/portal-network-specs/blob/master/testnet.md). 

Send a `PING` to the node on any of the Portal sub-networks (currently, only history and state are supported in Trin).

```sh
cargo run -p trin-cli -- json-rpc portal_historyPing --params <enr> 
```

After pinging a bootnode, you should be able to see the messages being sent and received in your node's logs. Now you can check your routing table again, where you should see the pinged bootnode (along with other nodes the bootnode shared with you). Congrats! You're now connected to the Portal Network testnet.

### Encode Content Keys

Pieces of content (data) on the Portal Network have unique identifiers that we refer to as "content keys". To request a particular piece of content, you will need the corresponding content key.

The encoding for the content key depends on the kind of content that the key refers to.

See available content keys (e.g. block header):

```sh
cargo run -p trin-cli -- encode-key -h 
```

See arguments for a specific content key:

```sh
cargo run -p trin-cli -- encode-key block-header -h
```

Example:

```sh
$ cargo run -p trin-cli -- encode-key block-body --block-hash 59834fe81c78b1838745e4ac352e455ec23cb542658cbba91a4337759f5bf3fc 
```

### Request Content

Send a `FindContent` message to a Portal Network bootnode.

```sh
cargo run -p trin-cli -- json-rpc portal_historyFindContent --params <enr>,<content-key>
```

### Setting up local metrics reporting

1. Install Docker.
2. Run Prometheus: `docker run -d -p 9090:9090 -v /absolute/path/to/trin/docs/metrics_config:/etc/prometheus prom/prometheus`. Set the correct absolute path to your copy of Trin's `docs/metrics_config/`.
3. Run Grafana: `docker run -d -p 3000:3000 -e "GF_INSTALL_PLUGINS=yesoreyeram-infinity-datasource" grafana/grafana:latest`.
4. Start your Trin process with `--enable-metrics-with-url 127.0.0.1:9100 --web3-transport http`.
	- The `--enable-metrics-with-url` parameter is the address that Trin exports metrics to, and should be equal to the port to which your Prometheus server is targeting at the bottom of `metrics_config/prometheus.yml`. 
    - The `--web-transport http` will allow Grafana to request routing table information from Trin via JSON-RPC over HTTP.
5. From the root of the Trin repo, run `cargo run -p trin-cli -- create-dashboard`. If you used different ports than detailed in the above steps, or you are not using docker, then this command's defaults will not work. Run the command with the `-h` flag to see how to provide non-default addresses or credentials. 
6. Upon successful dashboard creation, navigate to the dashboard URL that the `create-dashboard` outputs. Use `admin`/`admin` to login.

## Gotchas

- If `create-dashboard` fails with an error, the most likely reason is that it has already been run. From within the Grafana UI, delete the "json-rpc" and    "prometheus" datasources and the "trin" dashboard and re-run the command. 

- There is a limit on concurrent connections given by the threadpool. At last
  doc update, that number was 2, but will surely change. If you leave
  connections open, then new connections will block.
