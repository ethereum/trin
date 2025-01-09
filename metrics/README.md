# Trin Metrics

You can run this docker compose file it will run
- prometheus
- grafana
- setup the metrics dashboard

Metrics are useful for telling how Trin is performing.

The default username and password is `admin`.

### How to run
```sh
docker compose up
```

### View the dashboard at
http://localhost:3000/d/trin-metrics/trin-metrics

***WARNING***: don't forget to run `Trin` with metric exporting on!

**Example**
```bash
cargo run -p trin -- --enable-metrics-with-url 0.0.0.0:9100 --web3-http-address http://0.0.0.0:8545 --web3-transport http
```
