# Linux

## Trin on Ubuntu

These steps are for setting up a Trin node as a service on Ubuntu.

## Installation
```sh
$ sudo apt install libssl-dev librocksdb-dev libclang-dev pkg-config build-essentials
```
Install Trin:
> Tip: If you intend to submit code changes to trin, first fork the repo and
then clone that url.
```sh
$ cd ~
$ git clone https://github.com/ethereum/trin.git
$ cd trin
$ cargo build --workspace --release
```
Now the executable is located in `trin/target/release` and can be called by systemd.
Move that binary to the standard location for binaries:
```sh
$ sudo cp -a ~/trin/target/release/trin /usr/local/bin/trin
```
> Tip: If you make changes to these steps, keep a record for future reference.

Make a new user for the Trin service:
```sh
$ sudo useradd --no-create-home --shell /bin/false trin
```
Make a directory for Trin data and give the Trin user permission to access it:
```sh
$ sudo mkdir -p /var/lib/trin
$ sudo chown -R trin:trin /var/lib/trin
```
Check that the binary works:
```sh
$ /usr/local/bin/trin --version
```
Example response:
```sh
> Launching trin
> trin 0.0.1
```
## Configuration
Before setting up the service, look at the flags that can be set when starting Trin:
```sh
$ /usr/local/bin/trin --help
```
Some selected flags are described below.

### Optional flag for database size
`--mb 200`. Trin lets you control how much storage the node takes up (e.g., 200MB). The default is
100 megabytes and can be changed.

### Optional flag for no connection to external server

`--no-stun`. A third party server connection is configured by default to assist in testing.
This is a Session Traversal Utilities for NAT (STUN) server and may be disabled
a flag. The docs state: "Do not use STUN to determine an external IP. Leaves
ENR entry for IP blank. Some users report better connections over VPN."

### Optional flags for conflicting nodes

The discovery and JSON-RPC ports may conflict with an existing an Ethereum client
on the same machine.

`--discovery-port <port>`. If an Ethereum consensus client is already running, it may be using
the default port 9000.

`--web3-http-address <ip_address>:<port>`. If an Ethereum execution client is already running, it may be using the default port 8545. The localhost IP address (127.0.0.1) is recommended here.

`--web3-transport http`. If a new http port is specified using `--web3-http-address` (as above),
the transport must also be changed to http from the default (ipc).

To pick a new port, select a number in the range 1024–49151 and
test if it is in use (no response indicates it is ok to use):

```sh
$ sudo ss -tulpn | grep ':9009'
```

## Create the node service

Create a service to run the Trin node:
```sh
$ sudo nano /etc/systemd/system/trin.service
```
Paste the following, modifying flags as appropriate:
> Tip: Note that backslash is needed if starting a flag on a new line.
```sh
[Unit]
Description=Trin Portal Network client
After=network.target
Wants=network.target
[Service]
User=trin
Group=trin
Type=simple
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/trin \
    --discovery-port 9009 \
    --web3-http-address 127.0.0.1:8547 \
    --web3-transport http \
    --bootnodes default \
    --mb 200 \
    --no-stun
[Install]
WantedBy=default.target
```
CTRL-X then CTRL-Y to exit and save.

## Add environment variables

The environment variables are going in a different file so they
are not accidentally copy-pasted to public places. Create the `override.conf`
file, which will be placed in a new `trin.service.d` directory beside
the `trin.service` file:
```sh
$ sudo systemctl edit trin
```
Open the file:
```sh
$ sudo nano /etc/systemd/system/trin.service.d/override.conf
```
Paste the following, replace the Infura ID with your own.
> Tip: The 'info' level of logs is a good starting value.
```sh
[Service]
# (required unless the '--trusted-provider' is set to 'local')
Environment="TRIN_INFURA_PROJECT_ID=<infura-project-id>"
# (optional) Rust log level: <error/warn/info/debug/trace>
Environment="RUST_LOG=info"
# (optional) This flag sets the data directory to the location we created earlier.
Environment="TRIN_DATA_PATH=/var/lib/trin"
```
## Configure firewall

Ensure that the discovery port (custom or default 9000) is not blocked by the firewall:
```sh
$ sudo ufw allow 9009
```
Check the configuration:
```sh
$ sudo ufw status numbered
```
> Tip: use `sudo ufw delete <number>` to remove a particular rule.

## Start the service

Start the Trin node service and enable it to start on reboot:
```sh
$ sudo systemctl daemon-reload
$ sudo systemctl start trin
$ sudo systemctl status trin
$ sudo systemctl enable trin
```
Follow Trin's logs:
```sh
$ sudo journalctl -fu trin
```
CTRL-C to to exit.

Logs can be searched for an "exact phrase":
```sh
$ grep "trin" /var/log/syslog | grep "exact phrase"
```
To stop Trin and disable it from starting on reboot:
```sh
$ sudo systemctl stop trin
$ sudo systemctl disable trin
```
## Code changes

> Tip: Use a unique discovery-port or disable the Trin service prior to running a second
`cargo`-based instance of Trin.

See [getting started](getting_started.md) notes for more tips including setting environment
variables during testing.
```sh
$ cargo test --workspace
$ cargo run -- --discovery-port 9009 \
    --web3-http-address 127.0.0.1:8547 \
    --web3-transport http \
    --bootnodes default \
    --mb 200 \
    --no-stun
```

To get upstream updates, sync your fork with upstream on Github. To move any changes
from the codebase to the service, rebuild and move the binary as before:

```sh
$ git pull
$ cd trin
$ cargo build --workspace --release
$ sudo systemctl stop trin
$ sudo cp -a ~/trin/target/release/trin /usr/local/bin/trin
```
Restart the service to use the new binary:
```sh
$ sudo systemctl daemon-reload
$ sudo systemctl start trin
```
