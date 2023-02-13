# Making queries

If you want to manually query trin, the following patterns can be used, depending on whether
Trin was started with `--web3-transport` as `http` or `ipc`.

## Query form
A query for JSON-RPC has the following form for a call to `"methodname"` that accepts two
parameters: `parameter_one` and `parameter_two`.

Query:
```json
{
    "jsonrpc": "2.0",
    "method": "<methodname>",
    "params": ["<parameter_one>", "<parameter_two>"],
    "id":1
}
```
Usually passed on one line:
```json
{"jsonrpc":"2.0","method":"<methodname>","params":["<parameter_one>", "<parameter_two>"],"id":1}
```

## HTTP transport

Command for `query` (above) to HTTP server on `port`:
```sh
curl -X POST -H "Content-Type: application/json" -d '<query>' localhost:<port> | jq
```
## IPC transport

Command for `query` (above) to IPC server with socket file located at `/path/to/ipc`:
```sh
echo '<query>' | nc -U </path/to/ipc> | jq
```

## Response

If the data is not in the network the following response is expected:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x"
}
```
