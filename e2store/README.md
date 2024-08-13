# E2store

E2store is a format originally developed by Nimbus as a framework for building other storage formats. More information can be found here https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md


# What formats does this Crate support
- e2store
- era
- era1

## What is era?
era is a format for storing beacon chain data more information can be found here https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md#era-files

## What is era1?

era1 is a format for storing all of Ethereum's pre merge blocks. It contains block headers, block bodies, and receipts for pre-merge block history which ranges block 0-15537394

## What is the difference between `e2store/memory.rs` and `e2store/stream.rs`

`e2store/memory.rs` provides an api to load a full e2store file such as `.era`/`.era1` and manipulate it in memory. For smaller e2store files this approach works well. The issue comes when dealing with e2store files of much greater size loading the whole file into memory at once often isn't possible. This is where `e2store/stream.rs` comes in where you can stream the data you need from a e2store file as you need it. This will be required in `.era2` a format for storing full flat state snapshots.
