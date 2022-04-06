# Getting Started

**Trin is currently in unstable alpha, and should not be used in production. If you run into any bugs while using Trin, please file an Issue!**

**Check out the [Release Notes](/docs/release_notes.md) to see the latest supported features.**

## Prerequisites
- [Infura](https://infura.io/) project ID
- [Rust](https://www.rust-lang.org/) installation

## Building, Testing, and Running

Note: If you use a VPN, you should disable it before running Trin.

Install dependencies:

```sh
apt install libssl-dev librocksdb-dev libclang-dev 
```

Environment variables:

```sh
# Required 
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
cargo run -p trin
```

Note: You may also pass environment variable values in the same command as the run command. This is especially useful for setting log levels.

```sh
RUST_LOG=debug cargo run -p trin
```

View CLI options:

```sh
cargo run -p trin -- --help
```

### Connect to the Portal Network testnet

To establish a connection with a peer, pass in one or more bootnode ENRs.

Here, we connect to one of the designated Portal Network testnet bootnodes. Find a [testnet bootnode ENR](https://github.com/ethereum/portal-network-specs/blob/master/testnet.md). 
Pass the ENR as the value for the `--bootnodes` CLI flag.

```sh
cargo run -p trin -- --bootnodes <bootnode-enr> 
```

## Default data directories

- Linux/Unix: `$HOME/.local/share/trin`
- MacOS: `~/Library/Application Support/Trin`
- Windows: `C:\Users\Username\AppData\Roaming\Trin\data`

## Using Trin

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

See the [wiki](https://eth.wiki/json-rpc/API#json-rpc-methods) for other standard methods that are implemented. You can use the [web3.py](https://web3py.readthedocs.io/en/stable/web3.eth.html#module-web3.eth) API to access these. Note that currently most of them proxy to Infura rather than requesting the data from the Portal Network.

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
cargo run -p trin-cli -- discv5_routingTableInfo
```

View ENR information about your own Trin client:

```sh
cargo run -p trin-cli -- discv5_nodeInfo
```

### Connect to the Portal Network testnet

You can send a message from the local node to a bootnode using JSON-RPC, automatically adding the bootnode to your routing table.

Find a [testnet bootnode ENR](https://github.com/ethereum/portal-network-specs/blob/master/testnet.md). 

Send a `PING` to the node on any of the Portal sub-networks (currently, only history and state are supported in Trin).

```sh
cargo run -p trin-cli -- portal_historyPing --params <bootnode-enr> 
```

After pinging a bootnode, you should be able to see the messages being sent and received in your node's logs. Now you can check your routing table again, where you should see the pinged bootnode (along with other nodes the bootnode shared with you). Congrats! You're now connected to the Portal Network testnet.

### Request Content

Send a `FindContent` message to a Portal Network bootnode.

```sh
cargo run -p trin-cli -- portal_historyFindContent --params <bootnode-enr>,<content-key>
```

### Setting up local metrics reporting

1. Install [Grafana & Prometheus](https://grafana.com/docs/grafana/latest/getting-started/getting-started-prometheus/)
2. Configure your Prometheus server to target an open port to where `prometheus_exporter` will export Trin metrics.
3. Start your Trin process with `--enable-metrics --metrics-url 127.0.0.1:9100` as flags
	- The `--metrics-url` parameter is the address for `prometheus_exporter` to export metrics to, and should be equal to the port to which your Prometheus server is targeting.
4. Navigate to the URL on which Grafana is running in your browser (probably `localhost:3000`) and login.
5. Add your Prometheus server as a Data Source, using the URL on which your Prometheus server is running.
6. Use the "Import" dashboard feature in Grafana to create your Trin dashboard, and copy and paste `metrics_dashboard.json` as the template.
7. You should now be able to see live metrics reporting for your Trin node.

## Gotchas

- There is a limit on concurrent connections given by the threadpool. At last
  doc update, that number was 2, but will surely change. If you leave
  connections open, then new connections will block.
