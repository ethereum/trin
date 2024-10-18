# Ethereum data

Trin is designed to serve the JSON-RPC methods that an Ethereum full node would
provide. This includes methods the start with the `eth_` namespace. Note that not every method is implemented yet.

Here are some methods that are available:

## Get Block By Number

Here is an example of making an `eth_getBlockByNumber` request to a node, to load the block details for block 20,987,654. (In hexadecimal representation, this number is `0x1403f06`.)
```json
{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x1403f06", false], "id": 1}
```
### IPC

By default, trin serves the JSON-RPC methods over an IPC socket. The default location on Linux is `/tmp/trin-jsonrpc.ipc`.

Make the request in your shell with this one-liner:
```sh
BLOCK_NUM=20987654; echo '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x'$(printf "%x" $BLOCK_NUM)'", false],"id":1}' | nc -U /tmp/trin-jsonrpc.ipc | jq
```

Note the following steps in the one-liner above:
 - Convert the block number from decimal to hexadecimal using `printf`
 - Send the request to trin using `nc`
 - format the response with `jq` (optional, for pretty printing)

### HTTP

Trin can also serve the JSON-RPC methods over HTTP. It needs to be activated with the flag `--web3-transport http`. The default port is 8545.

```sh
BLOCK_NUM=20987654; curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x'$(printf "%x" $BLOCK_NUM)'", false],"id":1}' localhost:8545 | jq
```

## Call a contract function

To read data out of a contract, use the `eth_call` method.

The data needed to make this call is well populated in the Portal Network for the first 1 million blocks, and is being expanded over time. To activate contract storage access, connect to the Portal state network by running trin with the flag `--portal-subnetworks state,history`.

Calling a contract fuction usually involves enough formatting that it's helpful to use a tool to build the request, like Web3.py.

Below is an example of [one of the earliest contracts posted to Ethereum](https://medium.com/etherscan-blog/an-archeological-trip-across-early-ethereum-contracts-232b0de33f8#2187), which allows you to write "graffiti" on the chain.

### Calling Contract with Python

The following python code reads the graffiti from entry 7 in the contract. We read this data (ie~ call this contract fuction) as it was available in block 1,000,000, which has the hash [`0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e`](https://etherscan.io/address/0x6e38A457C722C6011B2dfa06d49240e797844d66#code).

```python
from web3 import Web3

# Connect to trin
w3 = Web3(Web3.IPCProvider('/tmp/trin-jsonrpc.ipc'))

# Generate the contract interface
contract = w3.eth.contract(
    address='0x6e38A457C722C6011B2dfa06d49240e797844d66',
    abi='[{"constant":false,"inputs":[],"name":"number_of_claims","outputs":[{"name":"result","type":"uint256"}],"type":"function"},{"constant":true,"inputs":[{"name":"","type":"uint256"}],"name":"claims","outputs":[{"name":"claimant","type":"address"},{"name":"message","type":"string"},{"name":"block_number","type":"uint256"}],"type":"function"},{"constant":false,"inputs":[{"name":"message","type":"string"}],"name":"claim","outputs":[],"type":"function"}]'
)

# Call the contract function
claim = contract.functions.claims(7).call(block_identifier='0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e')

print(f"claim graffiti: {claim}")
```

When running this python script, you should see the output:
> claim graffiti: ['0xFb7Bc66a002762e28545eA0a7fc970d381863C42', 'Satisfy Values through Friendship and Ponies!', 50655]

This tells you that the `0xFb7Bc66a002762e28545eA0a7fc970d381863C42` address made the claim, shows you what they wrote, and shows which block number they made the claim in (50,655).

### Call contract without Web3

Without a tool like Web3.py, you can build the JSON-RPC request manually. Here is an example of calling the same contract function as above manually:

```sh
echo '{"jsonrpc": "2.0", "method": "eth_call", "params": [{"to": "0x6e38A457C722C6011B2dfa06d49240e797844d66", "data": "0xa888c2cd0000000000000000000000000000000000000000000000000000000000000007"}, "0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e"], "id": 1}' | nc -U /tmp/trin-jsonrpc.ipc | jq
```

Which outputs:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x000000000000000000000000fb7bc66a002762e28545ea0a7fc970d381863c420000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000c5df000000000000000000000000000000000000000000000000000000000000002d536174697366792056616c756573207468726f75676820467269656e647368697020616e6420506f6e6965732100000000000000000000000000000000000000"
}
```

Decoding the result is left as an exercise to the reader.
