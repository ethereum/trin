# Workspaces

Trin is a package that can be run:
```sh
cargo run -p trin
```

The trin repository is composed of workspaces that are used by the main Trin package.
Their relationship is outlined below.

## `trin`

Code for the `trin` package is located in `./src`.

This crate is responsible for the operation of the Trin node functionality.

- Startup with different configurations via command line arguments
- Starting threads for different important functions such as uTP, Discovery & JSON-RPC.
- These threads perform tasks such as listening for peers or requests from a user.

## `trin-core`

This crate is responsible for the code that defines the main functions and data structures required for the operation of a Trin node. This includes code for:

- Interacting with and managing peers
- Determining content to store and share
- Database management
- Ethereum related data structures

## `trin-history`

This crate is responsible for the History sub-protocol. This means interacting with peers
to retrieve and distribute the following:
- Block headers
- Block bodies
- Block receipts

Additionally, it is also responsible for the header accumulator, a structure which provides a
mechanism to determine whether a given block hash is part of the canonical set of block hashes.

The crate uses the `ethportal-api` crate to represent the main data type in this crate: the
`HistoryContentKey`. This struct implements the OverlayContentKey trait, which allows it to
be treated as a member of the broader family of `OverlayContentKey`s.

## `trin-state`

> This crate exists mostly as a stub for future work.

This crate is equivalent in function to the `trin-history` crate, but instead is responsible
for the State sub-protocol.

This means that it is responsible for:
- The state of all accounts.
- The state of all contracts.
- The bytecode of all contracts.

Data in the state network is represented as a tries (tree structures). The network uses proofs
against these tries to allow Trin nodes to verify the correctness of data.

## `ethportal-api`

This crate seeks to expose the data structures in the Portal Network specification.
This includes features such as derived SSZ encoding and convenience functions.

The crate defines traits that may be used across different sub-protocols. For
example, the `OverlayContentKey` may be implemented for content on both the History and State
sub-protocols. Thus a function can accept content from both networks via `T: OverlayContentKey`.

```rs,no_run
fn handles_content_keys<T: OverlayContentKey>(key: T) {
    // Snip
}
```
The crate will evolve to provide the types required for the other sub-protocols.

## `rpc`

This crate contains implementations of `ethportal-api` jsonrpsee server API traits in Trin and interface for running the JSON-RPC server.

## `utp-testing`

Trin uses Micro Transport Protocol (uTP) a UDP based protocol similar to the BitTorrent protocol.
This crate can be used to set up clients and servers to test the protocol on a single machine.

## `ethportal-peertest` (for deprecation)

This crate is marked for deprecation and was previously used for automated peer testing in CI.
Now that a multi-client network exists, peer testing happens there.