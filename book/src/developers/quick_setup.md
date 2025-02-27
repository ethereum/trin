# Quick setup

This is a single page that aims to cover everything required to get Trin running.

**Trin is currently in unstable alpha, and should not be used in production. If you run into any bugs while using Trin, please file an Issue!**

## Building on Debian Based Systems

### Prerequisites
- [Rust](https://www.rust-lang.org/) installation

### Building, Testing, and Running

Note: If you use a VPN, you should disable it before running Trin.

Install dependencies (Ubuntu/Debian):

```sh
apt install libclang-dev pkg-config build-essential
```

Environment variables:

```sh
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
cargo build -p trin-history
cargo test -p trin-history

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

## Building on Arch Based Systems

Before starting, update your system.

```bash
sudo pacman -Syu
```

Then, install rust.

```bash
sudo pacman -S rustup
rustup install stable
```

To check that the rust toolchain was successfully installed, run:

```bash
rustc --version
```

You should see something like:

```bash
rustc 1.85.0 (4d91de4e4 2025-02-17)
```

Next, install the required dependencies:

```bash
sudo pacman -S openssl clang pkg-config base-devel llvm git
```

Now you can build, test and run Trin!

```bash
git clone https://github.com/ethereum/trin.git
cd trin

# Build
cargo build --workspace

# Run test suite
cargo test --workspace

# Build and run test suite for an individual crate
cargo build -p trin-history
cargo test -p trin-history

# Run help
cargo run -- --help

# Run Trin with defaults
cargo run
```

## Run locally

Serve portal node web3 access over a different port (such as `8547`) using the `--web3-http-address` flag. The `--web3-transport` for a local node will be over `http`
(rather than `ipc`).

```sh
RUST_LOG=debug cargo run -- \
    --web3-http-address http://127.0.0.1:8547 \
    --web3-transport http \
    --discovery-port 9009 \
    --bootnodes default \
    --mb 200 \
    --no-stun
```

### Connect to the Portal Network mainnet

To immediately connect to the mainnet, you can use the `--bootnodes default` argument to automatically connect with the default Trin bootnodes.

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
>>> w3.client_version
'trin 0.0.1-alpha'
```

To request a custom jsonrpc endpoint, provide the endpoint and array of params. e.g.:
```py
>>> w3.provider.make_request("portal_historyPing", ["enr:-IS4QBz_40AQVBaqlhPIWFwVEphZqPKS3EPso1PwK01nwDMtMCcgK73FppW1C9V_BQRsvWV5QTbT1IYUR-zv8_cnIakDgmlkgnY0gmlwhKRc9_OJc2VjcDI1NmsxoQM-ccaM0TOFvYqC_RY_KhZNhEmWx8zdf6AQALhKyMVyboN1ZHCCE4w", "18446744073709551615"])
{'jsonrpc': '2.0',
 'id': 0,
 'result': {'enrSeq': '3',
  'dataRadius': '115792089237316195423570985008687907853269984665640564039457584007913129639935'}}
```

See the [JSON-RPC API docs](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/portal-network-specs/assembled-spec/jsonrpc/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=false&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false) for other standard methods that are implemented. You can use the [web3.py](https://web3py.readthedocs.io/en/stable/web3.eth.html#module-web3.eth) API to access these.

### Connect over HTTP

First launch trin using HTTP as the json-rpc transport protocol:

```sh
cargo run -- --web3-transport http
```

Then, in a python shell:

```py
>>> from web3 import Web3
>>> w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
>>> w3.client_version
'trin 0.0.1-alpha'
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
