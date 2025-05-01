# E2HS Writer

## What?
A WIP CLI program to generate [E2HS](https://github.com/eth-clients/e2store-format-specs/blob/main/formats/e2hs.md) files. 


## Mode: `single-generator`
Generates a single E2HS file for a given period.

#### Data Sources
- Pre-Merge: The program will use era1 files to source data.
- Post-Merge: The program will use a combination of era files (headers / bodies) and a live provider (receipts) which can be configured via cli flags (defaults to pandaops). 

#### How to run Single Generator?

```sh
$ cargo run -p e2hs-writer --release -- single-generator --target-dir <target-dir> --period <period> --el-provider <provider-url>
```

## Mode: `head-generator`
Head Generator maintains a s3 bucket of E2HS files at the head of the chain, Head Generator will backfill the last 3 months of E2HS files if some files are missing. Head Generator will exit earlier if the backfill is longer then 3 months. It is recommended to use Single Generator if more then 3 months of E2HS files must be generated as the Single Generator is more efficient for generating individual files.

#### Data Sources
- Execution Layer JSON-RPC: used to get receipts.
- Consensus Layer Beacon API: used to get Beacon Blocks and the Beacon State, which can be used to derive `HeaderWithProof` and bodies.


#### Data Sources
- Pre-Merge: The program will use era1 files to source data.
- Post-Merge: The program will use a combination of era files (headers / bodies) and a live provider (receipts) which can be configured via cli flags (defaults to pandaops). 


#### How to run Head Generator?

```sh
$ cargo run -p e2hs-writer --release -- head-generator --el-provider <el-provider-url> --cl-provider <cl-provider-url> --s3-bucket <bucket-name>
```
