# Building Queries

If you want to manually query trin, the following patterns can be used, depending on whether
Trin was started with `--web3-transport` as `http` or `ipc`. It defaults to `ipc`.

Whatever the transport, the JSON-RPC format is the same.

## Query form
A query for JSON-RPC has the following form for a call to `methodname` that accepts two
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
Succinctly written:
```json
{"jsonrpc":"2.0","method":"<methodname>","params":["<parameter_one>", "<parameter_two>"],"id":1}
```

In following pages, we'll cover a couple specific examples of queries.

## IPC transport

By default, Trin listens on a Unix domain socket file at `/tmp/trin-jsonrpc.ipc`. This means that you can only access the data from the local machine.

Example command for `query` (above) to IPC server with socket file located at `/tmp/trin-jsonrpc.ipc`:
```sh
echo '<query>' | nc -U /tmp/trin-jsonrpc.ipc | jq
```

## HTTP transport

If you started Trin with `--web3-transport http`, you can query it over HTTP.

Command for `query` (above) to HTTP server on it's default port (8545):
```sh
curl -X POST -H "Content-Type: application/json" -d '<query>' localhost:8545 | jq
```

## Response

The "id" will match the request. The result is the data you requested. Alternatively, it may return an error message.

An example successful response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x1234"
}
```
