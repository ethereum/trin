# Quickstart

Trin runs on Linux, MacOS, and Windows. There are two ways to run it: download a binary executable, or install it from source.

## Download an executable

The github repository hosts the binaries. Download the latest release for your platform from the [releases page](https://github.com/ethereum/trin/releases).

Extract the compressed file to get the `trin` executable.

### Extraction on Linux / MacOS

The binary is compressed in a tarball, so first we need to extract it.

For example, to extract version 0.1.0:

```sh
tar -xzvf trin-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
```

You now have a `trin` executable in the current directory.

## Run trin

Launch the executable with 2GB local disk space:
```sh
trin --mb 2000
```

## Load a block from Ethereum history

Print the block data at height 20,987,654:

```sh
BLOCK_NUM=20987654; echo '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x'$(printf "%x" $BLOCK_NUM)'", false],"id":1}' | nc -U /tmp/trin-jsonrpc.ipc | jq
```

For a deeper understanding of how to interact with Ethereum, like invoking a contract function, see the [Ethereum data](../users/use/ethereum_data.md) section.

## Alternatively, install from source

To get the very latest updates, install from source. This path is intended for power users and developers, who want access to the very latest code.

There are platform-specific [build instructions](../developers/contributing/build_instructions.md).
