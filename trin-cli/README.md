# trin-cli

A little utility for running JSON-RPC commands against trin nodes.

```sh
$ cargo run -p trin-cli -- json-rpc discv5_routingTableInfo
Attempting RPC. endpoint=discv5_routingTableInfo file=/tmp/trin-jsonrpc.ipc
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "buckets": [],
    "localKey": "0x0d2a..f3f5"
  }
}
```

### To send a parameter, use the `--params` flag. To use multiple parameters, enter them as a comma-separated string.
```sh
$ cargo run -p trin-cli -- json-rpc portal_statePing --params enr:....
```

### If you have multiple nodes running you can manually select which one you communicate with:

```sh
$ cargo run -p trin-cli -- json-rpc discv5_routingTableInfo --ipc /tmp/trin-jsonrpc-2.ipc
```

### To use trin-cli to encode content keys:
Check out the `Encode Content Keys` section of the [Getting Started docs](../docs/getting_started.md#encode-content-keys).
