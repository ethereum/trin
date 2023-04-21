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

### View routing table

Each Trin client uses a routing table to maintain a record of members in the Portal network with whom it can communicate. At startup, your routing table should be empty (unless you've passed in the bootnode ENR's via the `--bootnodes` CLI param).

View your routing table:

```sh
cargo run -p trin-cli -- json-rpc discv5_routingTableInfo
```

View ENR information about your own Trin client:

```sh
cargo run -p trin-cli -- json-rpc discv5_nodeInfo
```

### Connect to the Portal Network testnet

You can send a message from the local node to a bootnode using JSON-RPC, automatically adding the bootnode to your routing table.

Find a [testnet bootnode ENR](https://github.com/ethereum/portal-network-specs/blob/master/testnet.md).

Send a `PING` to the node on any of the Portal sub-networks (currently, only history and state are supported in Trin).

```sh
cargo run -p trin-cli -- json-rpc portal_historyPing --params <enr>
```

After pinging a bootnode, you should be able to see the messages being sent and received in your node's logs. Now you can check your routing table again, where you should see the pinged bootnode (along with other nodes the bootnode shared with you). Congrats! You're now connected to the Portal Network testnet.

### Encode Content Keys

Pieces of content (data) on the Portal Network have unique identifiers that we refer to as "content keys". To request a particular piece of content, you will need the corresponding content key.

The encoding for the content key depends on the kind of content that the key refers to.

See available content keys (e.g. block header):

```sh
cargo run -p trin-cli -- encode-key -h
```

See arguments for a specific content key:

```sh
cargo run -p trin-cli -- encode-key block-header -h
```

Example:

```sh
$ cargo run -p trin-cli -- encode-key block-body --block-hash 59834fe81c78b1838745e4ac352e455ec23cb542658cbba91a4337759f5bf3fc
```

### Request Content

Send a `FindContent` message to a Portal Network bootnode.

```sh
cargo run -p trin-cli -- json-rpc portal_historyFindContent --params <enr>,<content-key>
```

### Setting up local metrics reporting

1. Install Docker.
2. Run Prometheus, note that you MUST manually set the absolute path to your copy of Trin's `docs/metrics_config/`:
```sh
docker run -p 9090:9090 -v /**absolute/path/to/trin/docs/metrics_config**:/etc/prometheus --add-host=host.docker.internal:host-gateway prom/prometheus
```
3. Run Grafana:
```sh
docker run -p 3000:3000 -e "GF_INSTALL_PLUGINS=yesoreyeram-infinity-datasource" --add-host=host.docker.internal:host-gateway grafana/grafana:latest
```
4. Start your Trin process with:
```sh
cargo run -p trin -- --enable-metrics-with-url 0.0.0.0:9100 --web3-http-address http://0.0.0.0:8545 --web3-transport http
```
  - The addresses must be bound to 0.0.0.0, because 127.0.0.1 only allows internal requests to
    complete, and requests from docker instances are considered external.
  - The `--enable-metrics-with-url` parameter is the address that Trin exports metrics to, and should be equal to the port to which your Prometheus server is targeting at the bottom of `metrics_config/prometheus.yml`
  - The `--web-transport http` will allow Grafana to request routing table information from Trin via JSON-RPC over HTTP
5. From the root of the Trin repo, run `cargo run -p trin-cli -- create-dashboard`. If you used different ports than detailed in the above steps, or you are not using docker, then this command's defaults will not work. Run the command with the `-h` flag to see how to provide non-default addresses or credentials.
6. Upon successful dashboard creation, navigate to the dashboard URL that the `create-dashboard` outputs. Use `admin`/`admin` to login.

## Gotchas

- If `create-dashboard` fails with an error, the most likely reason is that it has already been run. From within the Grafana UI, delete the "json-rpc" and    "prometheus" datasources and the "trin" dashboard and re-run the command.

- There is a limit on concurrent connections given by the threadpool. At last
  doc update, that number was 2, but will surely change. If you leave
  connections open, then new connections will block.
