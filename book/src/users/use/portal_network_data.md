# Portal network data

There are methods for requesting data that are specific to:
- Each sub-protocol (history, state, etc.)
    - `portal_history*`
    - `portal_state*`
- Discovery protocol
    - `discv5_*`

See the Portal Network JSON-RPC specification
[here](https://github.com/ethereum/portal-network-specs/tree/master/jsonrpc)
for a comprehensive and interactive view of specific methods available.

## Designing a Query
One can identify data by its "content key". The following queries ask Trin to speak with
peers, looking for a particular piece of data.

Let us request the block body for block 16624561
- Block hash: `0xd27f5e55d88b447788667b3d72cca66b7c944160f68f0a62aaf02aa7e4b2af17`
- Selector for a block body: `0x01` (defined in Portal Network spec under the History sub-protocol).
- Content key: `0x01d27f5e55d88b447788667b3d72cca66b7c944160f68f0a62aaf02aa7e4b2af17`
- Request: `portal_historyRecursiveFindContent`, which accepts a content key as a parameter

```json
{"jsonrpc":"2.0","method":"portal_historyRecursiveFindContent","params":["0x01d27f5e55d88b447788667b3d72cca66b7c944160f68f0a62aaf02aa7e4b2af17"],"id":1}
```
## HTTP

```sh
curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"portal_historyRecursiveFindContent","params":["0x01d27f5e55d88b447788667b3d72cca66b7c944160f68f0a62aaf02aa7e4b2af17"],"id":1}' http://localhost:8545 | jq
```

## IPC

```sh
echo '{"jsonrpc":"2.0","method":"portal_historyRecursiveFindContent","params":["0x01d27f5e55d88b447788667b3d72cca66b7c944160f68f0a62aaf02aa7e4b2af17"],"id":1}' | nc -U /tmp/trin-jsonrpc.ipc | jq
```