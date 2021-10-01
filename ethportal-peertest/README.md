# ethportal-peertest

Run a portal network node that you want to test and pass node's Enr as a target node argument.

```sh
cd ethportal-peertest

RUST_LOG=debug cargo run -p ethportal-peertest -- --target_node enr:-IS4QBDHCSMoYoC5UziAwKSyTmMPrhMaEpaE52L8DDAkipqvZQe9fgLy2wVuuEJwO9l1KsYrRoFGCsNjylbd0CDNw60BgmlkgnY0gmlwhMCoXUSJc2VjcDI1NmsxoQJPAZUFErHK1DZYRTLjk3SCNgye9sS-MxoQI-gLiUdwc4N1ZHCCIyk

```