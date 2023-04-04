# Startup

Configuration occurs at startup via flags:

```sh
cargo run -p trin -- --flag1 value --flag2 value
```
Backslashes allow flags to be on new lines for easier reading.
```sh
cargo run -p trin -- \
    --flag1 value \
    --flag2 value \
    --flag3 value1,value2 \
```

## Flags

For the most up to date flags run:

```sh
cargo run -p trin -- --help
```
### Bootnodes

Trin automatically connects to the Portal Network bootnodes.
Use the `--bootnodes` cli flag to connect to a specific node
or to none.

### Control disk use

Trin can be tuned to control how much disk space is used:

|Selected size|Data acess|Network contribution|
|-|-|-|
|Smaller|Slower|Less|
|Larger|Faster|More|

See the `--kb` flag.

### Sub-Protocols

Trin can connect to different sub-protocols to have access to
different types of data. One more more can be selected, but be aware
that not all sub-protocols are ready:

- Execution State Network
- Execution History Network
- Execution Transaction Gossip Network
- Execution Canonical Indices Network

### Networking configuration

Optionally one can specify Trin's network proprties:
- What sort of network connections (HTPP vs IPC)
- Port answering Ethereum-related queries
- Port for connecting to other nodes

These types of flags have defaults.

### Connect to a full node

During development of the Portal Network, some parts of the network
are not yet available. A connection to a full (Execution) node allows
Trin to use that node when necessary.

For example: If the state network is not live, state data requests
to Trin will be forwarded to the full node.

If a node is not provided, Trin requires connection to Infura, and will
ask for an Infura key upon startup. See the `--trusted-provider` flag for more.
