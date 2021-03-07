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

Create an Infura account, getting a project ID. Check out the trin repository, then:

```sh
cd trin
TRIN_INFURA_PROJECT_ID="YoUr-Id-HeRe" cargo run
```

## CLI Options
```sh
USAGE:
    trin [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -e, --endpoint <endpoint>      http port [default: 7878]
    -s, --pool-size <pool_size>    max size of threadpool [default: 2]
    -p, --protocol <protocol>      select transport protocol [default: http]
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
In a python shell:
```py
>>> from web3 import Web3
>>> w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7878"))
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
{"jsonrpc":"2.0","id":"85","result":"trin 0.0.1-alpha"}^C
```

## Gotchas

- There is a limit on concurrent connections given by the threadpool. At last
  doc update, that number was 2, but will surely change. If you leave
  connections open, then new connections will block.
- Error handling is pretty close to non-existent.
- This project may never be updated. If this repo is looking stale, you might
  try [asking the Trinity team](https://gitter.im/ethereum/trinity) to find out
  what spiritual successor exists, if any.
