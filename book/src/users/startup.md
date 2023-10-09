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

See the `--mb` flag.


### Private Key management

Trin requires a private key to configure a node's identity. Upon startup,
Trin will automatically generate a random private key that will be re-used
every time Trin is restarted. The only exceptions are if...
- User supplies a private key via the `--unsafe-private-key` flag, in which
  case that private key will be used to create the node's identity.
- User deletes the `TRIN_DATA_DIR` or changes the `TRIN_DATA_DIR`. In which 
  case a new private key will be randomly generated and used.

### Sub-Protocols

Trin can connect to different sub-protocols to have access to
different types of data. One more more can be selected, but be aware
that not all sub-protocols are ready:

- Execution State Network
- Execution History Network
- Execution Transaction Gossip Network
- Execution Canonical Indices Network

### Networking configuration

Optionally one can specify Trin's network properties:
- What sort of network connections (HTTP vs IPC)
- Port answering Ethereum-related queries
- Port for connecting to other nodes

These types of flags have defaults.
