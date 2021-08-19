# devp2p

Run a portal network node that you want to test and pass node's Enr as a target node.

## Running tests
To test a target client against a dummy peer, do:
```sh
cd devp2p

./boot.sh
```
This runs a shell script which:
1. Starts up the test client (currently, it just runs: `cargo run -p trin-state`)
2. Grabs the test client's ENR
3. Runs the portal network testing suite, which starts up a dummy node 
and passes the test client ENR to connect the nodes.