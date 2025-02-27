# ethportal-api

> **Warning!**
> This crate is experimental! Do not rely on it in a production setting.

This crate contains definitions for various Portal Network JSON-RPC APIs using [jsonrpsee](https://github.com/paritytech/jsonrpsee) framework.

## Client usage example
Enable `client` feature of `ethportal-api` crate.

```rust,no_run
use ethportal_api::jsonrpsee::http_client::HttpClientBuilder;
use ethportal_api::{
    HistoryContentValue, HistoryContentKey, HistoryNetworkApiClient, Web3ApiClient,
};

#[tokio::main]
async fn main() {
    // Connect to a local node JSON-RPC
    let client = HttpClientBuilder::default()
        .build("http://localhost:8545")
        .unwrap();

    // Call web3_clientVersion endpoint
    let client_version = client.client_version().await.unwrap();
    println!("Current client version is {client_version}");

    let content_key_json =
        r#""0x00cb5cab7266694daa0d28cbf40496c08dd30bf732c41e0455e7ad389c10d79f4f""#;
    let content_value_json = r#""0x0800000022020000f90217a08e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942a65aca4d5fc5b5c859090a6c34d164135398226a07dd4aabb93795feba9866821c0c7d6a992eda7fbdd412ea0f715059f9654ef23a0c61c50a0a2800ddc5e9984af4e6668de96aee1584179b3141f458ffa7d4ecec6a0b873ddefdb56d448343d13b188241a4919b2de10cccea2ea573acf8dbc839befb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000860b6b4bbd735f830f4241832fefd88252088456bfb41a98d783010303844765746887676f312e352e31856c696e7578a0d5332614a151dd917b84fc5ff62580d7099edb7c37e0ac843d873de978d50352889112b8c2b377fbe8c971eaaa41600563000000000000000000000000000000000000000000000000629f9dbe275316ef21073133b8ecec062a44e20201be7b24a22c56db91df336f0c71aaaec1b3526027a54b15387ef014fcd18bb46e90e05657b46418fd326e785392c40ec6d38f000042798fee52ed833ff376b1d5a95dc7c2356dc8d8d02e30b704e9ee8e4d712920a18fd4e8833a7979a14e5b972d4b27958dcfa5187e3aa14d61c29c3fda0fb425078a0479c5ea375ff95ad7780d0cdc87012009fd4a3dd003b06c7a28d6188e6be50ac544548cc7e3ee6cd07a8129f5c6d4d494b62ee8d96d26d0875bc87b56be0bf3e45846c0e3773abfccc239fdab29640b4e2aef297efcc6cb89b00a2566221cb4197ece3f66c24ea89969bd16265a74910aaf08d775116191117416b8799d0984f452a6fba19623442a7f199ef1627f1ae7295963a67db5534a292f98edbfb419ed85756abe76cd2d2bff8eb9b848b1e7b80b8274bbc469a36dce58b48ae57be6312bca843463ac45c54122a9f3fa9dca124b0fd50bce300708549c77b81b031278b9d193464f5e4b14769f6018055a457a577c508e811bcf55b297df3509f3db7e66ec68451e25acfbf935200e246f71e3c48240d00020000000000000000000000000000000000000000000000000000000000000""#;

    // Deserialise to a portal history content key type from a hex string
    let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();
    let content_value: HistoryContentValue = serde_json::from_str(content_value_json).unwrap();

    // Store content to remote node, call portal_historyStore endpoint
    let result: bool = client
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();
    assert!(result);

    // Call portal_historyLocalContent endpoint and deserialize to `HistoryContentValue::BlockHeaderWithProof` type
    let result: HistoryContentValue = client.local_content(content_key).await.unwrap();
    assert_eq!(result, content_value);
}
```

## Types

A variety of types are published in the `types` module. For now, types go into
this module if either 1) they are used by multiple crates, or 2) it's part of
the ethportal-api type signatures. Importantly, ethportal-api shouldn't have
andy dependencies on other crates in the workspace. It's a goal to be able to
publish ethportal-api without also publishing any other supporting crates.

Especially during this experimental period, the types are subject to change, as
many of them are used internally by trin. When ethportal-api becomes
production-ready, the types will follow semantic versioning as usual: any
incompatible change will be introduced with a major version increase.

Utilities used throughout trin are still generally kept in trin-utils, unless
they are used by ethportal-api. Then they are published into ethportal-api,
like the hex utilities.

## License
The entire code within this repository is licensed under the [GNU General Public License v3.0](./LICENSE)
