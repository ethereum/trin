# trin
(a working name)

Trin is an Ethereum "portal": a json-rpc server with nearly instant sync, and
low CPU & storage usage.

Trin does this by making these tradeoffs:
- Trusts miners to include valid state transitions, to skip sync
- Shards state across a (new) p2p network, to reduce local storage needs

This should sound similar to a light client. It is, but with a peer-to-peer
philosophy rather than the LES client/server model, which has introduced
challenges in an altruistic environment.

## Ready for production?

LOL, not even a little bit. At the last readme update, this was simply a proxy
to Infura for all inbound requests, and doesn't validate any answers against
state roots.

Trin will proxy at least *some* requests to Infura for quite a while, but the
plan is to incrementally reduce the reliance on Infura, as more trin
functionality becomes available.

## How to use

Create an Infura account, getting a project ID. Check out the git repository, then:

```sh
cd trin
TRIN_INFURA_PROJECT_ID="<YoUr-Id-HeRe>" cargo run
```

In another shell:
```sh
nc localhost 8080
```

You can interact with trin by using netcat to enter a json-formatted request
after the "Input:" and then a newline, like:
```
Welcome!
Input: {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":83}
{"jsonrpc":"2.0","id":83,"result":"0xb4bc97"}
Input: {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":84}
{"jsonrpc":"2.0","id":84,"result":"0xb4bc98"}
Input: ^C
```

## Gotchas

- This doesn't actually accept inbound json-rpc connections yet, it only serves
  a bare TCP connection, and reads input line by line.
- There is a limit on concurrent connections given by the threadpool. At last
  doc update, that number was 2, but will surely change. If you leave
  connections open, then new connections will block.
- Error handling is pretty close to non-existent.
- This project may never be updated. If this repo is looking stale, you might
  try [asking the Trinity team](https://gitter.im/ethereum/trinity) to find out
  what spiritual successor exists, if any.
