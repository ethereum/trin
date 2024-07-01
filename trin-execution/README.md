# Trin Execution

Trin execution has it's origins in trying to gossip all of Ethereum's Merkle Patrica archival state onto the Portal State Network. To do this we execute all of the blocks to the head of the chain. If we can execute to the head of the chain, as a byproduct we just built an Ethereum Execution Layer client.

## Priorities

Currently the main priority is executing to the head of the chain so we can gossip all of Ethereum's state data. After we achieve this goal we can open Trin Execution as an Execution layer client. Trin Execution is the first execution layer client being built without relying on devp2p.


## How to run
```bash
cargo run -p trin-execution
```

### Want to get a trace of the EVM's execution?
EVM traces are useful for debugging as they will give you the trace of every opcode executed during a transaction. Traces will be saved in Trin Execution's working directory, under the `evm_traces` folder

The tracer we use is from [EIP-3155](https://eips.ethereum.org/EIPS/eip-3155)

#### To trace all blocks
```bash
cargo run -p trin-execution -- --block-to-trace=all
```

#### To trace a specific block by block number
```bash
cargo run -p trin-execution -- --block-to-trace=block:<block_number>
```
