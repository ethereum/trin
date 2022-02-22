# Getting Started

#### Trin is currently in unstable alpha, and should not be used in production.
#### Check out the [Release Notes](/docs/release_notes.md) to see the latest supported features.

# Pre-requisites
- You will need an [infura](https://infura.io/) id to use Trin.
- [Rust](https://www.rust-lang.org/) installed on your machine.

# Via Cargo (todo post-initial release)

# Via Source

### Install dependencies (on Ubuntu/Debian)

```sh
apt install libssl-dev librocksdb-dev libclang-dev 
```

```sh
git clone https://github.com/ethereum/trin.git
cd trin
export TRIN_INFURA_PROJECT_ID=yourinfurakey
cargo run -p trin
```

You should now see logs from Trin as it boots up and connects to the Portal Network

To run individual networks:
```sh
cargo run -p trin-state|trin-history
```

**Optional:** Custom data directory
```shell
TRIN_DATA_PATH="/your_path"
```
*Note, default data paths are:*\
Linux/Unix - `$HOME/.local/share/trin`\
MacOS - `~/Library/Application Support/Trin`\
Windows - `C:\Users\Username\AppData\Roaming\Trin\data`

# Via Docker (todo)

# Using Trin

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

### Connect over HTTP
First launch trin using HTTP as the json-rpc transport protocol:
```sh
TRIN_INFURA_PROJECT_ID="YoUr-Id-HeRe" cargo run -- --web3-transport http
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

# Using Trin-CLI (todo)
- Ping a bootnode
- View routing table
- Request content
