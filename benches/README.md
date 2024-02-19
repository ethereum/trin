# Trin Benchmarks

## Usage
It will run the normal criterion benchmark.
```
cargo bench criterion
```

It will generate a flamegraph report without running any criterion analysis.
> **NOTE**: The flamegraph will also include the setup in the benchmarks, unlike just running the normal benchmarks which excludes the setup for the tests in the benchmark
```
cargo bench -- --profile-time=<amount of seconds to benchmark for>
```
Flamegraph reports can be find at `target/criterion/<name-of-benchmark>/profile/flamegraph.svg` 