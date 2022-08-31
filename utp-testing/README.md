# uTP testing infrastructure

Testing infrastructure which enables to test uTP implementation over different
network conditions on local machine.

Highly based on tools developed to test QUIC protocol:

[quic-interop-runner](https://github.com/marten-seemann/quic-interop-runner)

[quic-network-simulator](https://github.com/marten-seemann/quic-network-simulator)

## Prerequisities

- Machine with docker and docker-compose installed
- trin set-up to run `cargo build -p utp-testing --release`
- Load ip6table_filter kernel module:
```shell
sudo apt install -y kmod
sudo modprobe ip6table_filter
```

## How it works

Test setup uses docker compose to start 3 docker containers:
- client - which is instance of uTP test app
- server - which is instance of uTP test app
- sim - which is instance with ns3 network simulator with several pre-compiled scenarios

The networking is setup in such way that network traffic is routed from client to server
and server to client thorugh sim which decideds what to do with flowing packets

Explanation from [quic-network-simulator](https://github.com/marten-seemann/quic-network-simulator):

```
The framework uses two networks on the host machine: `leftnet` (IPv4
193.167.0.0/24, IPv6 fd00:cafe:cafe:0::/64) and `rightnet` (IPv4
193.167.100.0/24, IPv6 fd00:cafe:cafe:100::/64). `leftnet` is connected to the
client docker image, and `rightnet` is connected to the server. The ns-3
simulation sits in the middle and forwards packets between `leftnet` and
`rightnet`
```

## Practicalities

To run integration testing scenarios with different network conditions

```
1. cd trin/
2. docker build -t test-utp --build-arg REPO_URL={repo-url} --build-arg BRANCH_NAME={branch-name} utp-testing/docker
3. SCENARIO="scenario_details" docker-compose -f utp_testing/docker/docker-compose.yml up

For example:
SCENARIO="drop-rate --delay=15ms --bandwidth=10Mbps --queue=25 --rate_to_client=0 --rate_to_server=0" docker-compose -f utp-testing/docker/docker-compose.yml up
would start `drop-rate` scenario with specified delay, bandwith, and different drop rates

4. cargo build -p utp-testing --release
5. ./target/release/utp-test-suite
```

All scenarios are specified in: [scenarios](https://github.com/marten-seemann/quic-network-simulator/tree/master/sim/scenarios)
