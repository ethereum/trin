# Trin Bench
Trin bench is for testing Trin performance and being able to recreate situations reliably to verify if performance improvements or regressions happen

## To run benchmark with Trin
```sh
make bench-trin
```

## To run benchmark with Trin and generate flamegraphs
```sh
make bench-trin-perf
```

## Clean results
```sh
make clean
```

## View the results

The results such as logs can be viewed in the generate `logs` folder

`trin_benchmark.log` will contain the logs of the bench mark coordinator

`data_sender` and `data_receiver` is the data directory
`data_sender.log` and `data_receiver.log` are the logs of the portal clients
if perf mode is ran the portal client will be profiled and flamegraphs will be generated `data_sender.svg` and `data_receiver.svg`

The `past_runs` directory archives the logs and flamegraphs of previous runs
