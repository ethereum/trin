# Running Trin

Configuration occurs at startup via standard flags. Launch trin with 5GB of storage space like this:

```text
trin --mb 5000
```

For the [full list of flags](cli.md), run:

```text
trin --help
```

## Data storage limits

When setting a storage usage limit, here's how to think about the tradeoffs:

|Storage size|Data access|Network contribution|
|-|-|-|
|Smaller|Slower|Less|
|Larger|Faster|More|


## Select which networks to join

Eventually, by default, trin will connect to all Portal Networks. Each network stores different types of data. Some examples are the consensus-layer network for confirming the latest headers, and several execution-layer networks like:

- **History Network** - blocks & receipts
- **State Network** - account info
- **Transaction Gossip Network** - mempool
- **Canonical Indices Network** - tx lookups

For now, only the history network is on by default, because the others are still under active development. At the moment, the state network has only the first one million blocks of state data.

To try out state access, you can turn it on like this:

```text
trin --mb 5000 --portal-subnetworks beacon,history,state
```

Note that to access state, you must also run with history enabled, in order to validate peer responses.

## Advanced flags

The following flags all have reasonable defaults and most people won't need to touch them:

### Bootnodes

Trin automatically connects to some standard Portal Network bootnodes.
Use the `--bootnodes` cli flag to connect to a specific node
or to none.

### Private Key management

Trin requires a private key to configure a node's identity. Upon startup,
Trin will automatically generate a random private key that will be re-used
every time Trin is restarted. The only exceptions are if...
- User supplies a private key via the `--unsafe-private-key` flag, in which
  case that private key will be used to create the node's identity.
- User deletes the `TRIN_DATA_DIR` or changes the `TRIN_DATA_DIR`. In which 
  case a new private key will be randomly generated and used.

### Networking configuration

Optionally one can specify Trin's network properties:
- What sort of connection to query with (HTTP vs IPC)
- Port answering Ethereum-related queries
- Port for connecting to other nodes
