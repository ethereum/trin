# devp2p

Run a portal network node that you want to test and pass node's Enr as a target node.

```sh
cd devp2p

TRIN_DATA_PATH="/tmp/devp2p" RUST_LOG=debug cargo run -p devp2p -- --target_node enr:-IS4QBDHCSMoYoC5UziAwKSyTmMPrhMaEpaE52L8DDAkipqvZQe9fgLy2wVuuEJwO9l1KsYrRoFGCsNjylbd0CDNw60BgmlkgnY0gmlwhMCoXUSJc2VjcDI1NmsxoQJPAZUFErHK1DZYRTLjk3SCNgye9sS-MxoQI-gLiUdwc4N1ZHCCIyk

```