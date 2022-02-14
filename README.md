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

## Repository Structure

The portal protocol is a collection of networks. Trin needs to connect to all of them.

The repository is structured as follows:

- `trin/`: The main entry point to run a holistic Ethereum portal client
- `trin-history/`: The chain history network
- `trin-state/`: The state network

## Ready for production?

LOL, not even a little bit. At the last readme update, this was simply a proxy
to Infura for all inbound requests, and doesn't validate any answers against
state roots.

Trin will proxy at least *some* requests to Infura for quite a while, but the
plan is to incrementally reduce the reliance on Infura, as more trin
functionality becomes available.

## How to use Trin

Checkout out the [Getting Started](/docs/getting_started.md) guide to quickly get up and running with Trin.

## CLI Options
```sh
trin 0.0.1
carver
Run an eth portal client

USAGE:
    trin [OPTIONS]

FLAGS:
        --enable-metrics    Enable prometheus metrics reporting (requires --metrics-url)
    -h, --help              Prints help information
        --internal-ip       (For testing purposes) Use local ip address rather than external via STUN.
    -V, --version           Prints version information

OPTIONS:
        --bootnodes <bootnodes>               One or more comma-delimited base64-encoded ENR's or multiaddr strings of
                                              peers to initially add to the local routing table [default: ]
        --discovery-port <discovery_port>     The UDP port to listen on. [default: 9000]
        --external-address <external_addr>    The public IP address and port under which this node is accessible
        --kb <kb>                             Maximum number of kilobytes of total data to store in the DB
                                              [default: 100000]
        --metrics-url <metrics-url>           URL for prometheus server
        --networks <networks>...              Comma-separated list of which portal subnetworks to activate
                                              [default: history,state]
        --pool-size <pool_size>               max size of threadpool [default: 2]
        --unsafe-private-key <private_key>    Hex encoded 32 byte private key (considered unsafe to pass in pk as cli
                                              arg, as it's stored in terminal history - keyfile support coming soon)
        --web3-http-address <web3-http-address>    address to accept json-rpc http connections [default: 127.0.0.1:8545]
        --web3-ipc-path <web3_ipc_path>       path to json-rpc endpoint over IPC [default: /tmp/trin-jsonrpc.ipc]
        --web3-transport <web3_transport>     select transport protocol to serve json-rpc endpoint [default: ipc]
                                              [possible values: http, ipc]
```

## Custom RPC Methods
- `discv5_nodeInfo`             Returns the ENR of the client
- `discv5_routingTableInfo`     Returns the list of discovery peers that have recently been available

See the [wiki](https://eth.wiki/json-rpc/API#json-rpc-methods) for other standard methods that are implemented. Currently, most of them proxy to Infura.

## Want to help?

Want to file a bug, contribute some code, or improve documentation? Excellent! Read up on our
guidelines for [contributing](/docs/contributing.md),
then check out issues that are labeled
[Good First Issue](https://github.com/ethereum/trin/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22).

## Gotchas

- There is a limit on concurrent connections given by the threadpool. At last
  doc update, that number was 2, but will surely change. If you leave
  connections open, then new connections will block.
