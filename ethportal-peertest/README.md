# ethportal-peertest

Run a portal network node that you want to test and pass node's Enr as a target node argument.

```sh
cd ethportal-peertest

RUST_LOG=debug cargo run -p ethportal-peertest -- --target-node enr:-IS4QBDHCSMoYoC5UziAwKSyTmMPrhMaEpaE52L8DDAkipqvZQe9fgLy2wVuuEJwO9l1KsYrRoFGCsNjylbd0CDNw60BgmlkgnY0gmlwhMCoXUSJc2VjcDI1NmsxoQJPAZUFErHK1DZYRTLjk3SCNgye9sS-MxoQI-gLiUdwc4N1ZHCCIyk
```

If you are running it on a local network you will likely want to manually give it a port
to use and advertise:

```sh
RUST_LOG=debug cargo run -p ethportal-peertest -- --external-address 127.0.0.1:4568 --listen-port 4568 --target-node $ENR
```

## Transport selection
Running the test harness will by default test all jsonrpc endpoints over IPC to the target node. To make sure these pass, please make sure that the target node is running with `--web3-transport ipc`. To test jsonrpc over http, use the `--target-transport http` cli argument for the harness, and make sure the target node is running with `--web3-transport http`. Ideally, both transport methods are tested before PRs.

