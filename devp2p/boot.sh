#!/bin/bash

# start up target client, ie, the node you want to test
cargo run -p trin-state &
echo "LAUNCHING TARGET CLIENT (and grabbing ENR)"

# grab the ENR of this node
test_node_enr=$(python ipc_calls.py | cut -b 40-222)

# Run the devp2p testing suite, which starts up a dummy node. Pass the ENR
# obtained previously as a cmdln argument to connect the nodes.
echo "STARTING DUMMY NODE & RUNNING TESTS..."
TRIN_DATA_PATH="/tmp/devp2p" RUST_LOG=debug cargo run -p devp2p -- --target_node $test_node_enr | grep devp2p
