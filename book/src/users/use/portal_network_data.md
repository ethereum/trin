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

Let us request the block body for block 21,000,000.
- Block hash: `0xf5e1d15a3e380006bd271e73c8eeed75fafc3ae6942b16f63c21361079bba709`
- Selector for a block body: `0x01` (defined in Portal Network spec under the History sub-protocol).
- Content key: `0x01f5e1d15a3e380006bd271e73c8eeed75fafc3ae6942b16f63c21361079bba709`
- Request: `portal_historyGetContent`, which accepts a content key as a parameter

```json
{"jsonrpc":"2.0","method":"portal_historyGetContent","params":["0x01f5e1d15a3e380006bd271e73c8eeed75fafc3ae6942b16f63c21361079bba709"],"id":1}
```

## IPC

```sh
echo '{"jsonrpc":"2.0","method":"portal_historyGetContent","params":["0x01f5e1d15a3e380006bd271e73c8eeed75fafc3ae6942b16f63c21361079bba709"],"id":1}' | nc -U /tmp/trin-jsonrpc.ipc | jq
```

## HTTP

If you have started Trin with `--web3-transport http`, you can query it over HTTP from any computer that can reach that port.

```sh
curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"portal_historyGetContent","params":["0x01f5e1d15a3e380006bd271e73c8eeed75fafc3ae6942b16f63c21361079bba709"],"id":1}' http://localhost:8545 | jq
```
