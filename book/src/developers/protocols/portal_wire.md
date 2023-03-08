# Portal wire protocol

The Portal Wire protocol ([spec](https://github.com/ethereum/portal-network-specs/blob/master/portal-wire-protocol.md)) is a variant of the discovery (Discv5) wire protocol ([spec](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md)).

This means that the basic protocol is the same, but there are custom portal-specific messages.


## Protocol ID
Nodes identify each other by a protocol ID.

- `0x50..` Portal Network
    -  `0x500A` portal state sub-protocol.
    -  `0x500B` portal history sub-protocol.
    - Etc.
- `0x....` Other networks (Ethereum execution, Ethreum consensus chain, others.)

## Messages
Messages the define the portal sub-protocols are:
- `TALKREQ` (talk requests). These have a request ID.
- `TALKRESP` (talk responses). These refer to the reqest ID being responded to.

Messages contain data that is an SSZ union. This means that the message contains
one of the possible message content types, and that the type will be specified.
```py
# Python
message = Union[ping, pong, find_nodes, nodes, find_content, content, offer, accept]
```
## Message encoding

The SSZ Union encoding means that each component has a selector (`PING 0x00, PONG 0x01, FIND_NODES 0x02, ...`).
That way, different clients on the network can listen to messages on the right protocol
and correctly decode them.

For example, receiving a message and seeing that the first byte is `0x02` indicates that the
message contains a `FIND_NODES` type of content.

## Message data

Each message has specific data that is sent. For example, a `find_content` message component will have the content that is being sought. The details of these can be found in the spec.

## Additional API exposure

The above message definitions are sufficient for a Trin node to participate in the network.

However, as Trin is a JSON-RPC server (serving Ethereum-related requests like `eth_getBlockNumber`)
it also exposes the wire methods. This is not strictly required by the Portal Network specification,
but is very useful.

Messages that are wire responses are not exposed, as they are not requests.

## Relationship to JSON-RPC

The following table shows the wire definition, purpose and how it is exposed for querying via
the JSON-RPC server.

Recall that each Trin can serve multiple sub-protocols simultaneously. Hence, the
following table is for the History sub-protocol (`0x500A` in Discovery-terms), and
JSON-RPC methods start with `portal_history*`.

|message|SSZ union message selector|purpose|JSON-RPC|
|-|-|-|-|
|ping|`0x01`|"Are you alive?"|`portal_historyPing`|
|pong|`0x02`|"I'm alive"|None|
|find_nodes|`0x03`|"Give me peers at specific distances x, y & z"|`portal_historyFindNodes`|
|nodes|`0x04`|"Response to findnodes"|None|
|find_content|`0x05`|"I want content x, or peers who might have it"|`portal_historyFindContent`|
|content|`0x06`|"Here is content x, or peers who might have it."|None|
|offer|`0x07`|"I have content x, y & z, would you like any of them?"|`portal_historyOffer`|
|accept|`0x08`|"Yes please, I would like x, y & z"|None|
