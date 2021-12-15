# ethportal-peertest

Run a portal network node that you want to test and pass the node's IPC path to the json-rpc server for testing.

# An example, with trin

To start, launch trin:
```sh
RUST_LOG=debug TRIN_INFURA_PROJECT_ID=0 cargo run -p trin -- --internal-ip --web3-ipc-path /tmp/ethportal-peertest-target.ipc
```

Finally, launch the peertester:
```sh
RUST_LOG=debug cargo run -p ethportal-peertest -- --target-ipc-path /tmp/ethportal-peertest-target.ipc
```

Note that the `--web3-ipc-path` and `--target-ipc-path` flags in trin and peertest are optional, because they default to the same thing. They are added for clarity, to assist in testing other clients that have different IPC path defaults.

# Target Node Config

## IP Address
The test harness will spawn at least one node, using an internal IP. In order to support devp2p communication between the nodes, launch your target node with `--internal-ip` also.

## Transport selection
Running the test harness will by default test all jsonrpc endpoints over IPC to the target node. To make sure these pass, please make sure that the target node is running with `--web3-transport ipc`. To test jsonrpc over http, use the `--target-transport http` cli argument for the harness, and make sure the target node is running with `--web3-transport http`. Ideally, both transport methods are tested before PRs.
