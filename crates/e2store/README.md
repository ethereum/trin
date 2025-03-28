# E2store

E2store is a format originally developed by Nimbus as a framework for building other storage formats. More information can be found here https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md


# What formats does this Crate support
- e2store
- era
- era1
- e2ss
- e2hs

## What is era?
era is a format for storing beacon chain data more information can be found here https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md#era-files

## What is era1?

era1 is a format for storing all of Ethereum's pre merge blocks. It contains block headers, block bodies, and receipts for pre-merge block history which ranges block 0-15537394

## What is e2ss?

e2ss is an abbreviation for `e2-state-snapshot`

e2ss is a format made to store full flat state snapshots, one of our first uses of this will be using to bootstrap Portal State Network bridges. Unlike `.era`/`.era1` e2ss files will only store 1 block's worth of state per file. The reason for this choice is a snapshot of the state is quite large.

TODO: Add chart of snapshot size at every million block interval.

### E2SS analysis tool

Analysis tool that reads e2ss file and prints basic stats about it can be run with:

```bash
cargo run -p e2store --bin e2ss-stats --features e2ss-stats-binary -- <path>
```

## What is the difference between `e2store/memory.rs` and `e2store/stream.rs`

`e2store/memory.rs` provides an api to load a full e2store file such as `.era`/`.era1` and manipulate it in memory. For smaller e2store files this approach works well. The issue comes when dealing with e2store files of much greater size loading the whole file into memory at once often isn't possible. This is where `e2store/stream.rs` comes in where you can stream the data you need from a e2store file as you need it. This is required for `.e2ss` format for storing full flat state snapshots.
