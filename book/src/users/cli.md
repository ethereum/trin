# All Command Line Flags

> See our guide on [how to run trin](startup.md) for the most common flags.

Below is the current list of all command line flags.

Note that these flags may change over time, so run `trin --help` to get the most up-to-date information for your version.

```text
Usage: trin [OPTIONS] [COMMAND]

Commands:
  create-dashboard  
  help              Print this message or the help of the given subcommand(s)

Options:
      --web3-transport <WEB3_TRANSPORT>
          select transport protocol to serve json-rpc endpoint [default: ipc]
      --web3-http-address <WEB3_HTTP_ADDRESS>
          address to accept json-rpc http connections [default: http://127.0.0.1:8545/]
      --web3-ipc-path <WEB3_IPC_PATH>
          path to json-rpc endpoint over IPC [default: /tmp/trin-jsonrpc.ipc]
      --discovery-port <DISCOVERY_PORT>
          The UDP port to listen on. [default: 9009]
      --bootnodes <BOOTNODES>
          One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to initially add to the local routing table [default: default]
      --external-address <EXTERNAL_ADDR>
          (Only use this if you are behind a NAT) The address which will be advertised to peers (in an ENR). Changing it does not change which port or address trin binds to. Port number is required, ex: 127.0.0.1:9001
      --no-stun
          Do not use STUN to determine an external IP. Leaves ENR entry for IP blank. Some users report better connections over VPN.
      --no-upnp
          Do not use UPnP to determine an external port.
      --unsafe-private-key <PRIVATE_KEY>
          Hex encoded 32 byte private key (with 0x prefix) (considered unsafe as it's stored in terminal history - keyfile support coming soon)
      --trusted-block-root <TRUSTED_BLOCK_ROOT>
          Hex encoded block root from a trusted checkpoint
      --network <NETWORK>
          Choose mainnet or angelfood [default: mainnet]
      --portal-subnetworks <PORTAL_SUBNETWORKS>
          Comma-separated list of which portal subnetworks to activate [default: history]
      --storage.total <storage.total>
          Maximum storage capacity (in megabytes), shared between enabled subnetworks [default: 1000]
      --storage.beacon <storage.beacon>
          Maximum storage capacity (in megabytes) used by beacon subnetwork
      --storage.history <storage.history>
          Maximum storage capacity (in megabytes) used by history subnetwork
      --storage.state <storage.state>
          Maximum storage capacity (in megabytes) used by state subnetwork
      --enable-metrics-with-url <ENABLE_METRICS_WITH_URL>
          Enable prometheus metrics reporting (provide local IP/Port from which your Prometheus server is configured to fetch metrics)
      --data-dir <DATA_DIR>
          The directory for storing application data. If used together with --ephemeral, new child directory will be created. Can be alternatively set via TRIN_DATA_PATH env variable.
  -e, --ephemeral
          Use new data directory, located in OS temporary directory. If used together with --data-dir, new directory will be created there instead.
      --disable-poke
          Disables the poke mechanism, which propagates content at the end of a successful content query. Disabling is useful for network analysis purposes.
      --ws
          Used to enable WebSocket rpc.
      --ws-port <WS_PORT>
          The WebSocket port to listen on. [default: 8546]
      --utp-transfer-limit <UTP_TRANSFER_LIMIT>
          The limit of max background uTP transfers for any given channel (inbound or outbound) for each subnetwork [default: 50]
  -h, --help
          Print help (see more with '--help')
  -V, --version
          Print version
```
