# trin
(a working name)

Trin is an Ethereum "portal": a json-rpc server with nearly instant sync, and
low CPU & storage usage.

Trin does this by making these tradeoffs:
- Trusts miners to include valid state transitions, to skip sync
- Shards state across a (new) p2p network, to reduce local storage needs

This should sound similar to a light client. It is, but with a peer-to-peer
philosophy rather than the LES client/server model, which has introduced
challenges in an altruistic environment.

## Ready for production?

LOL, not even a little bit. At the last readme update, this was simply a proxy
to Infura for all inbound requests, and doesn't validate any answers against
state roots.

Trin will proxy at least *some* requests to Infura for quite a while, but the
plan is to incrementally reduce the reliance on Infura, as more trin
functionality becomes available.

## How to use

### Install dependencies (on Ubuntu/Debian)

```sh
apt install libssl-dev librocksdb-dev libclang-dev 
```

Create an Infura account, getting a project ID. Check out the trin repository, then:

```sh
cd trin
TRIN_INFURA_PROJECT_ID="YoUr-Id-HeRe" cargo run
```

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

## CLI Options
```sh
trin 0.0.1
carver
Run an eth portal client

USAGE:
    trin [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --bootnodes <bootnodes>               One or more comma-delimited base64-encoded ENR's or multiaddr strings of
                                              peers to initially add to the local routing table [default: ]
        --discovery-port <discovery_port>     The UDP port to listen on. [default: 9000]
        --external-address <external_addr>    The public IP address and port under which this node is accessible
        --pool-size <pool_size>               max size of threadpool [default: 2]
        --unsafe-private-key <private_key>    Hex encoded 32 byte private key (considered unsafe to pass in pk as cli
                                              arg, as it's stored in terminal history - keyfile support coming soon)
        --web3-http-port <web3_http_port>     port to accept json-rpc http connections [default: 8545]
        --web3-ipc-path <web3_ipc_path>       path to json-rpc endpoint over IPC [default: /tmp/trin-jsonrpc.ipc]
        --web3-transport <web3_transport>     select transport protocol to serve json-rpc endpoint [default: ipc]
                                              [possible values: http, ipc]
```

## RPC Methods
- `discv5_nodeInfo`     Returns the ENR of the client
- `web3_clientVersion`  Returns the current version of Trin being run
- `eth_blockNumber `    Returns the current block number from the tip fo the chain (as provided by Infura at present)

## Gotchas

- There is a limit on concurrent connections given by the threadpool. At last
  doc update, that number was 2, but will surely change. If you leave
  connections open, then new connections will block.
- Error handling is pretty close to non-existent.
- This project may never be updated. If this repo is looking stale, you might
  try [asking the Trinity team](https://gitter.im/ethereum/trinity) to find out
  what spiritual successor exists, if any.
