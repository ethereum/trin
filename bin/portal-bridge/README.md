# Portal-Bridge

Process to feed the portal network by gossiping data retrieved from a trusted provider. This is only compatible with `Trin` clients.

ex.
```sh
git clone https://github.com/ethereum/portal-accumulators.git
cargo run -p portal-bridge -- --executable-path ./target/debug/trin --epoch-accumulator-path ./portal-accumulators
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

#### History Subnetwork

- `"--mode latest"`: follow the head of the chain and gossip latest blocks
- `"--mode test:/path/to/test_data.json"`: gossip content keys & values found in test file.
- `"--mode backfill:b100"`: start backfill at block #100
- `"--mode backfill:e100"`: start backfill at epoch #100
- `"--mode backfill:r10-12"`: backfill a block range from #10 to #12 (inclusive)
- `"--mode single:b100"`: gossip a single block #100
- `"--mode single:e100"`: gossip a single epoch #100
- `"--mode fourfours`: will randomly select era1 files from `era1.ethportal.net` and gossip them
- `"--mode fourfours:random_epoch"`: will randomly select a single era1 file from `era1.ethportal.net` and then gossip it
- `"--mode fourfours:random_epoch:100"`: will randomly select a single era1 file from `era1.ethportal.net` that represents an epoch number greater than the floor provided and then gossip it
- `"--mode fourfours:e600`: will select era1 file 600 from `era1.ethportal.net` and gossip it
- `"--mode fourfours:r100-200`: will gossip a block range from an era1 file, range must be from the same epoch
- `"--mode fourfours:hunter:10:50`: sample size = 10, threshold = 50
    - will randomly select era1 files from `era1.ethportal.net` and gossip them after performing rfc lookups given the sample size. if the threshold is **not** met, the era1 file will be gossiped.
    - before gossiping a individual piece of content, the bridge will perform a lookup to see if the content is already in the portal network. If it is, the content will not be gossiped.
- `"--mode fourfours:single_hunter:10:50`: sample size = 10, threshold = 50
    - same as the above hunter mode, but it will only gossip a single era1 file before exiting
#### Beacon Subnetwork

- `"--mode latest"`: follow the head of the chain and gossip latest blocks
- `"--mode test:/path/to/test_data.json"`: gossip content keys & values found in test file.

#### State Subnetwork

- `"--mode single:b100"`: backfill, always beginning from block #0 until the specified block (#100)
- `"--mode single:r50-100"`: backfill, gossips state diffs for blocks in #50-#100 range (inclusive)
- `"--mode snapshot:1000000"`: gossips a state snapshot at the respective block, in this example the state snapshot at block 1,000,000 will be gossiped. This mode is only used for the State Network.


### Subnetwork configuration

You can specify the `--portal-subnetworks` flag for which network to run the bridge for
- `"--portal-subnetworks history"`: Default value. Run the bridge for the history network.
- `"--portal-subnetworks beacon"`: Run the bridge for the beacon network.
- `"--portal-subnetworks history,beacon"`: Run the bridge for the history & beacon network.
`  "--portal-subnetworks state"`: Run the bridge for the state network.
    - Currently, the `"state"` network can only be run by itself!

### Test File example

```json
[{
	"content_key": "0x006251d65b8a8668efabe2f89c96a5b6332d83b3bbe585089ea6b2ab9b6754f5e9",
	"content_value": "0x0800000023020000f90218a00409be8253ad6ac0eb2056bc94194c6ccb83c74f4292c40c82e2dc8203bdc759a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942a65aca4d5fc5b5c859090a6c34d164135398226a0afbf9bfd23008e8df44a83bb51ade45b993b3253fbce69cf7cec5d628eca6d45a0a7120e4bd136c0b6bdb0fa4990649f8c34d10d180dbd5ad6d03502ae92d32308a0d78aa953fedc7f7c112b2686d0b2b7e37eba716dd1f5d74ef3c8a37005f35215b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000004000000000000000000040000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000860b69dd9d66ce830f424a832fefd88303a68c8456bfb4e398d783010303844765746887676f312e352e31856c696e7578a0e962efb883f91286e4fc6fd12989a70f24c174bd087f472528137c4134af0a1a88e857c5acc15dd827cead98e305c70563000000000000000000000000000000000000000000000000be1b4a7a57f5316eea09c5e3e349141c46c1cb43664a815d28644cd74f282ca122360456d89447c0d586a8f5490922ea86b20e056879d64d87d104c14c0e594a6d800f67f5331ee2e511dc20e169c644b3df0f4c6b7c1717fc29d4844050b74044b506bf91edd14825aaec4f36fc5ad97b9eed9773aa2df15f80dff21eb668e24d61c29c3fda0fb425078a0479c5ea375ff95ad7780d0cdc87012009fd4a3dd003b06c7a28d6188e6be50ac544548cc7e3ee6cd07a8129f5c6d4d494b62ee8d96d26d0875bc87b56be0bf3e45846c0e3773abfccc239fdab29640b4e2aef297efcc6cb89b00a2566221cb4197ece3f66c24ea89969bd16265a74910aaf08d775116191117416b8799d0984f452a6fba19623442a7f199ef1627f1ae7295963a67db5534a292f98edbfb419ed85756abe76cd2d2bff8eb9b848b1e7b80b8274bbc469a36dce58b48ae57be6312bca843463ac45c54122a9f3fa9dca124b0fd50bce300708549c77b81b031278b9d193464f5e4b14769f6018055a457a577c508e811bcf55b297df3509f3db7e66ec68451e25acfbf935200e246f71e3c48240d00020000000000000000000000000000000000000000000000000000000000000"
}]
```
