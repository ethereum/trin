# SSZ

The Simple Serialize (SSZ) protocol ([spec](https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md)) is used to ensure that data sent to peers is interpreted unambiguously.

It is used in two main ways:
- Encoding: from rich data (struct, enum) to bytes (`Vec<u8>`).
- Decoding: from bytes (`Vec<u8>`) to rich data (struct, enum).

The encoded data is not self-describing, so you have to know what sort of data you
are expecting. Hence, the data type descriptions in the Portal Network spec.

Encoded data can only be interpreted in one way. Additionally, encoded data
can also be used in Merkle proofs efficiently.

## Types

The following is a quick overview of major composite types used. See the spec for
basic types (e.g., bits, bools, unsigned integers).

|Type|Description|Note|
|-|-|-|
|List|Holds variable number of a specified item|Specify max number|
|Vector|Holds specific number of a specified item|Specify number|
|Container|Holds many different specified items| Items are spaced into 32 byte partitions|
|Union|Holds one of many different specified items| Item kind is specified using a prepended selector byte|

Each type can hold any of the other types, so a Containter can hold a List
and a Union, and the Union can hold another Container, etc.
Anything that is put into one of the types above must itself be SSZ-able

## Implementations

The `ssz` crate does a lot of the work by providing `Encode` and `Decode` methods that
can be derived.
```rs,no_run
#[derive(Clone, Debug, Decode, Encode, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum HistoryContentKey {
    BlockHeaderWithProof(BlockHeader),
    BlockBody(BlockBody),
    BlockReceipts(BlockReceipts),
    EpochAccumulator(EpochAccumulator),
}
```
The spec defines a content key for the History sub-protocol as:
```py
block_header_key = Container(block_hash: Bytes32)
selector         = 0x00
content_key      = selector + SSZ.serialize(block_header_key)
```
The inclusion of the selector is handled by implementing `serde::Serialize` for
the enum, and including the appending the appropriate selector byte.

That is, the hex string ready to be serialized into bytes for a block header would be
```sh
# Header, body or receipts
"0x<selector byte><block hash>"
# Header specifically
"0x00<block hash>"
# Serialize to bytes
[0x00, ...]
```
## Merkle proofs

The Epoch Accumulator uses SSZ encoding. This allows for Merkle proofs to be made
for arbitrary historical blocks against the accumulator.