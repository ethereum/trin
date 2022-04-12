# JSON-RPC API

This is a document for all JSON-RPC API endpoints currently supported by Trin. Trin plans to eventually support the entire [Portal Network JSON-RPC API](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/portal-network-specs/assembled-spec/jsonrpc/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=false&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false) and [Ethereum JSON-RPC API](https://eth.wiki/json-rpc/API#json-rpc-methods).

## Currently supported endpoints

### Portal Network
The specification for these endpoints can be found [here](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/portal-network-specs/assembled-spec/jsonrpc/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=false&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false).

- `discv5_nodeInfo`
- `discv5_routingTableInfo`
- `portal_historyFindContent`
- `portal_stateFindContent`
- `portal_historyFindNodes`
- `portal_stateFindNodes`
- `portal_historyOffer`
- `portal_stateOffer`
- `portal_historyStore`
- `portal_stateStore`
- `portal_historyPing`
- `portal_statePing`

### Ethereum endpoints
The specification for these endpoints can be found [here](https://eth.wiki/json-rpc/API#json-rpc-methods).

- [`eth_blockNumber`](https://eth.wiki/json-rpc/API#eth_blocknumber)
	- This endpoint is currently proxied to Infura, and not served by the Portal Network.
- [`eth_getBlockByHash`](https://eth.wiki/json-rpc/API#eth_getblockbyhash)
	- This endpoint relies on fetching block headers from the Portal Network, so all blocks may not be available until the Portal Network stabilizes.
- [`eth_getBlockByNumber`](https://eth.wiki/json-rpc/API#eth_getblockbynumber)
	- This endpoint relies on the master accumulator to lookup the block hash. Since the master accumulator was frozen at the merge block, only pre-merge blocks are currently supported.
- [`web3_clientVersion`](https://eth.wiki/json-rpc/API#web3_clientversion)

### Custom Trin JSON-RPC endpoints
- [`portal_historyRadius`](#portal_historyRadius)
- [`portal_stateRadius`](#portal_stateRadius)
- [`portal_historyLocalContent`](#portal_historyLocalContent) 
- [`portal_stateLocalContent`](#portal_stateLocalContent)
- [`portal_historyRecursiveFindContent`](#portal_historyRecursiveFindContent)

# History Overlay Network

## `portal_historyRadius`
Returns the current data storage radius being used for the History network.

### Parameters
`None`

### Returns
- Data storage radius.

#### Example
```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "18446744073709551615"
}
```

## `portal_historyLocalContent`
Attempts to look up content key in Trin node's local db.

### Parameters
- `content_key`: Target content key.

### Returns
- Hex-encoded content value.

#### Example
```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
	  "content": "0xf90217a06add1c183f1194eb132ca8079197c7f2bc43f644f96bf5ab00a93aa4be499360a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942a65aca4d5fc5b5c859090a6c34d164135398226a05ae233f6377f0671c612ec2a8bd15c20e428094f2fafc79bead9c55a989294dda064183d9f805f4aecbf532de75e6ad276dc281ba90947ff706beeaecc14eec6f5a059cf53b2f956a914b8360ea6fe271ebe7b10461c736eb16eb1a4121ba3abbb85b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000860710895564a08309a92a832fefd882520884565fc3be98d783010302844765746887676f312e352e31856c696e7578a0c5e99c6e90fbdee5650ff9b6dd41198655872ba32f810de58acb193a954e15898840f1ce50d18d7fdc"
  }
}
```

## `portal_historyRecursiveFindContent`
This method is for development purposes and unstable. It's not fully recursive, but will perform a single lookup in the Trin client's routing table to find a peer close to the content key, and then request the content value from the found peer. 

### Parameters
- `content_key`: Target block header content key.

### Returns
- Block header

#### Example
```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "author": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
    "base_fee_per_gas": null,
    "difficulty": "0x710895564a0",
    "extra_data": "0xd783010302844765746887676f312e352e31856c696e7578",
    "gas_limit": "0x2fefd8",
    "gas_used": "0x5208",
    "log_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "mix_hash": "0xc5e99c6e90fbdee5650ff9b6dd41198655872ba32f810de58acb193a954e1589",
    "nonce": 4679748334323072988,
    "number": 633130,
    "parent_hash": "0x6add1c183f1194eb132ca8079197c7f2bc43f644f96bf5ab00a93aa4be499360",
    "receipts_root": "0x59cf53b2f956a914b8360ea6fe271ebe7b10461c736eb16eb1a4121ba3abbb85",
    "state_root": "0x5ae233f6377f0671c612ec2a8bd15c20e428094f2fafc79bead9c55a989294dd",
    "timestamp": 1449116606,
    "transactions_root": "0x64183d9f805f4aecbf532de75e6ad276dc281ba90947ff706beeaecc14eec6f5",
    "uncles_hash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
  }
}
```

# State Overlay Network

## `portal_stateRadius`
Returns the current data storage radius being used for the State network.

### Parameters
`None`

### Returns
- Data storage radius.

#### Example
```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "18446744073709551615"
}
```

## `portal_stateLocalContent`
Attempts to look up content key in Trin node's local db.

### Parameters
- `content_key`: Target content key.

### Returns
- Hex-encoded content value.

#### Example
```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
	  "content": "0x0217a06ebc43f644f96bf5ab00a93aa4be499360a01dcc4de8dec75d0a142fd40d49347942a65aca4d5fc5b5c859090a6c34d164135398226a05ae233f6377f0671c612ec2a8bd15c20e428094f2fafc79bead9c55a989294dda064183d9f805f4aecbf532de75e6ad276dc281ba90947ff706beeaecc14eec6f5a059cf53b2f956a914b8360ea6fe271ebe7b10461c736eb16eb1a4121ba3abbb85b90110895564a08309a92a832fefd882520884565fc3be98d783010302844765746887676f312e352e31856c696e7578a0c5e99c6e90fbdee5650ff9b6dd41198655872ba32f810de58acb193a954e15898840f1ce50d18d7fdc"
  }
}
```
