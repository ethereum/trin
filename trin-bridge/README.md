# Trin-Bridge
Process to feed the portal network by gossiping data retrieved from a trusted provider. Currently, this is only compatible with `Trin`, but it is intended to be client-agnostic, at some point.

ex.
```
cargo run -p trin-bridge -- --node-count 1 --executable-path ./target/debug/trin --epoch-accumulator-path ./portal-accumulators trin
```
