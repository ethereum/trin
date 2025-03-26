# E2HS Writer

## What?
A WIP CLI program to generate [E2HS](https://github.com/eth-clients/e2store-format-specs/blob/main/formats/e2hs.md) files. 

## Data Sources
- Pre-Merge: The program will use era1 files to source data.
- Post-Merge: The program will use a combination of era files (headers / bodies) and a live provider (receipts) which can be configured via cli flags (defaults to pandaops). 

## How?

```
$ cargo run -p e2hs-writer -- --target-dir <target-dir> --epoch <epoch> --el-provider <provider-url>
```
