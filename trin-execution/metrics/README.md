# Trin Execution Metrics

You can run this docker compose file it will run
- prometheus 
- grafana
- setup the metrics page

Metrics are useful for telling how Trin Execution is performing and what is slow.

The default username and password is `admin`.

### How to run
```sh
docker compose up
```

### View the dashboard at
http://localhost:3000

***WARNING***: don't forget to run `Trin Execution` with metric exporting on!

**Example**
```bash
cargo run -p trin-execution  -- --ephemeral --enable-metrics-with-url=127.0.0.1:9091
```
