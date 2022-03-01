# Getting Started

#### Trin is currently in unstable alpha, and should not be used in production. If you run into any bugs while using Trin, please file an Issue!
#### Check out the [Release Notes](/docs/release_notes.md) to see the latest supported features.

# Pre-requisites
- You will need an [Infura](https://infura.io/) ID to use Trin.
- You will need [Rust](https://www.rust-lang.org/) installed on your machine.

# Via Source

### Install dependencies (on Ubuntu/Debian)

```sh
apt install libssl-dev librocksdb-dev libclang-dev 
```

```sh
git clone https://github.com/ethereum/trin.git
cd trin
export TRIN_INFURA_PROJECT_ID=yourinfurakey
RUST_LOG=debug cargo run -p trin
```

(Trin might take a couple of minutes to compile the first time you launch it.)

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

See the [wiki](https://eth.wiki/json-rpc/API#json-rpc-methods) for other standard methods that are implemented. You can use the [web3.py](https://web3py.readthedocs.io/en/stable/web3.eth.html#module-web3.eth) API to access these. Note that currently most of them proxy to Infura rather than requesting the data from the Portal Network.

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

# Using Trin-CLI
Trin needs to connect to a bootnode to join the Portal network. There are a couple of ways to do this. You can use the `--bootnodes` CLI flag to pass in bootnode ENR's, or you can send a message to a bootnode using JSON-RPC, automatically adding the bootnode to your routing table.

We can use Trin-CLI to initiate sending a message from our Trin client to another.

### Trin-CLI Environment
- Open a new terminal window and make sure you're in the same directory where Trin is installed.
- Don't forget to set the Infura environment variable: `export TRIN_INFURA_PROJECT_ID=yourinfurakey`

### View routing table
Each Trin client uses a routing table to maintain a record of members in the Portal network with whom it can communicate. At startup, your routing table should be empty (unless you've passed in the bootnode ENR's via the `--bootnodes` CLI param).

To view your routing table...
```sh
$ cargo run -p trin-cli -- discv5_routingTableInfo
```

To view ENR information about your own Trin client.
```sh
$ cargo run -p trin-cli -- discv5_nodeInfo
```

### Ping a bootnode
Send a `PING` to another node on any of the Portal Networks (currently, only history and state are supported in Trin).

##### Bootnode ENRs
```
- `enr:-IS4QJBALBigZVoKyz-NDBV8z34-pkVHU9yMxa6qXEqhCKYxOs5Psw6r5ueFOnBDOjsmgMGpC3Qjyr41By34wab1sKIBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg`
- `enr:-IS4QFm4gtstCnRtOC-MST-8AFO-eUhoNyM0u1XbXNlr4wl1O_rGr6y7zOrS3SIZrPDAge_ijFZ4e2B9eZVHhmgJtg8BgmlkgnY0gmlwhM69ZOyJc2VjcDI1NmsxoQLaI-m2CDIjpwcnUf1ESspvOctJLpIrLA8AZ4zbo_1bFIN1ZHCCIyg`
- `enr:-IS4QBE8rpfrvCZVf0RISINpHU4GM-ZmkX4y3h_WxF7YflJ-dh88a6q9_42mGVSAetfpOQqujnPE-BkDWss5qF6d45UBgmlkgnY0gmlwhJ_fCDaJc2VjcDI1NmsxoQN9rahqamBOJfj4u6yssJQJ1-EZoyAw-7HIgp1FwNUdnoN1ZHCCIyg`
```

```sh
$ cargo run -p trin-cli -- portal_historyPing --params enr:....
```

After pinging a bootnode, you should be able to see the messages being sent and received in your node's logs. Now you can check your routing table again, where you should see the pinged bootnode (along with other nodes the bootnode shared with you). Congrats! You're now connected to the Portal network.

### Request content
(todo)
