# Trin Execution

Trin execution has it's origins in trying to gossip all of Ethereum's Merkle Patrica archival state onto the Portal State Network. To do this we execute all of the blocks to the head of the chain. If we can execute to the head of the chain, as a byproduct we just built an Ethereum Execution Layer client.

## Priorities

Currently the main priority is executing to the head of the chain so we can gossip all of Ethereum's state data. After we achieve this goal we can open Trin Execution as an Execution layer client. Trin Execution is the first execution layer client being built without relying on devp2p.
