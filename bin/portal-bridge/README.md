# Portal-Bridge

Process to feed the portal network by gossiping data retrieved from a trusted provider. This is only compatible with `Trin` clients.

ex.
```sh
cargo run -p portal-bridge --release -- --mode e2hs --e2hs-range 100000-2000000
```

## Providers

`Portal-Bridge` currently supports 3 types of providers...

- PandaOps (default provider for both execution and consensus layers)
  - This provider is not publicly accessible. If you don't have access, then you must use another option.
- Infura (execution layer only)
  - Running the bridge in `backfill` mode will hit the daily threshold for a free infura account fairly quickly.
  - To bridge "history" network data from Infura, use the following flag.
	- eg. `--el-provider https://mainnet.infura.io/v3/insert-api-key-here`
- Local Client (execution &/or consensus via URL)
  - This option has not been thoroughly tested against all possible providers, if you are unable to connect to a local client please open an issue.
  - To bridge "beacon" network data, specify the URL for your Consensus client.
	- eg. `--cl-provider http://localhost:8551`

### Bridge modes

#### History Network E2HS Bridge

- `"--mode e2hs --e2hs-range 100-200"`: gossip a block range from #100 to #200 (inclusive) using `E2HS` files as the data source
- `"--mode e2hs --e2hs-range 1000-10000 --e2hs-randomize"`: randomize the order in which epochs from block range are gossiped

#### Beacon Subnetwork

- `"--mode latest"`: follow the head of the chain and gossip latest blocks

#### State Subnetwork

- `"--mode single:r50-100"`: backfill, gossips state diffs for blocks in #50-#100 range (inclusive)
- `"--mode snapshot:1000000"`: gossips a state snapshot at the respective block, in this example the state snapshot at block 1,000,000 will be gossiped. This mode is only used for the State Network.


### Subnetwork configuration

You can specify the `--portal-subnetwork` flag for which network to run the bridge for
- `"--portal-subnetwork history"`: Default value. Run the bridge for the history network.
- `"--portal-subnetwork beacon"`: Run the bridge for the beacon network.
- `"--portal-subnetwork state"`: Run the bridge for the state network.
Any pre-required subnetworks will automatically be enabled
