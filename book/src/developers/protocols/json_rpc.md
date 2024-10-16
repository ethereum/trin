# JSON-RPC

This is a document for all JSON-RPC API endpoints currently supported by Trin. Trin plans to eventually support the entire [Portal Network JSON-RPC API](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/portal-network-specs/assembled-spec/jsonrpc/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=false&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false) and [Ethereum JSON-RPC API](https://eth.wiki/json-rpc/API#json-rpc-methods).


## Currently supported endpoints

### Portal Network
The specification for these endpoints can be found [here](https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/portal-network-specs/assembled-spec/jsonrpc/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=false&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false).

- `discv5_nodeInfo`
- `discv5_routingTableInfo`
- `portal_historyFindContent`
- `portal_historyFindNodes`
- `portal_historyGossip`
- `portal_historyLocalContent`
- `portal_historyPing`
- `portal_historyOffer`
- `portal_historyGetContent`
- `portal_historyStore`
- `portal_stateFindContent`
- `portal_stateFindNodes`
- `portal_stateLocalContent`
- `portal_stateGossip`
- `portal_stateOffer`
- `portal_stateStore`
- `portal_statePing`

### Custom Trin JSON-RPC endpoints
The following endpoints are not part of the Portal Network specification and are defined
in subsequent sections:
- [`portal_historyRadius`](#portal_historyradius)
- [`portal_historyTraceGetContent`](#portal_historytracegetcontent)
- [`portal_paginateLocalContentKeys`](#portal_paginatelocalcontentkeys)
- [`portal_stateRadius`](#portal_stateradius)

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

## `portal_historyTraceGetContent`
Same as `portal_historyGetContent`, but will also return a "route" with the content. The "route" contains all of the ENR's contacted during the lookup, and their respective distance to the target content. If the content is available in local storage, the route will contain an empty array.

### Parameters
- `content_key`: Target content key.

### Returns
- Target content value, or `0x` if the content was not found.
- Network ENRs traversed to find the target content along with their base-2 log distance from the content. If the target content was found in local storage, this will be an empty array.

#### Example
```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
	  "content": "0xf90217a06add1c183f1194eb132ca8079197c7f2bc43f644f96bf5ab00a93aa4be499360a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942a65aca4d5fc5b5c859090a6c34d164135398226a05ae233f6377f0671c612ec2a8bd15c20e428094f2fafc79bead9c55a989294dda064183d9f805f4aecbf532de75e6ad276dc281ba90947ff706beeaecc14eec6f5a059cf53b2f956a914b8360ea6fe271ebe7b10461c736eb16eb1a4121ba3abbb85b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000860710895564a08309a92a832fefd882520884565fc3be98d783010302844765746887676f312e352e31856c696e7578a0c5e99c6e90fbdee5650ff9b6dd41198655872ba32f810de58acb193a954e15898840f1ce50d18d7fdc",
	  "route": [{
            "enr": "enr:-IS4QFoKx0TNU0i-O2Bg7qf4Ohypb14-jb7Osuotnm74UVgfXjF4ohvk55ijI_UiOyStfLjpWUZsjugayK-k8WFxhzkBgmlkgnY0gmlwhISdQv2Jc2VjcDI1NmsxoQOuY9X8mZHUYbjqVTV4dXA4LYZarOIxnhcAqb40vMU9-YN1ZHCCZoU",
            "distance": 256
	  }]
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


# General

## `portal_paginateLocalContentKeys`
Return a paginated list of all of the content keys (from every subnetwork) currently available in local storage.

### Parameters
- `offset`: The number of records that need to be skipped.
- `limit`: Number of entries to return.

### Returns
- `content_keys`: List of content keys.
- `total_entries`: Total number of content keys in local storage.

#### Example
```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "content_keys": ["0x0055b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb286"],
    "total_entries": 1
  }
}
```
