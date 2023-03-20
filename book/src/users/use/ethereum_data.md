# Ethereum data

Trin is designed to eventually serve the JSON-RPC methods that an Ethereum full node would
provide. This includes methods the start with the `eth_` namespace.

Here is an example of making an `eth_blockNumber` request to a node serving over HTTP to get
the latest block number.
```json
{"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id":1}
```
## HTTP

```sh
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id":1}' localhost:8545 | jq
```
## IPC

```sh
echo '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | nc -U /tmp/trin-jsonrpc.ipc | jq
```
