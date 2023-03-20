# Users

The following are users who are well-suited to using Trin.

## Laptop wallet user

A user has a laptop that frequently is turned off. When
they want to transact, they can turn on Trin and connect their
wallet to it.

*Benefit*: Wallet use without reliance on third party wallet APIs.

## Desktop wallet user

A user has a desktop that usually on, but most of the disk is used for other things.
When they want to transact, their wallet is already connected to their portal node.

*Benefit*: Wallet use without reliance on third party wallet APIs. Contributes to
network health without using entire disk.

## Protocol experimentation

A researcher looking to explore the Ethereum protocol, testing out
specific aspects and perhaps making experimental changes to the protocol.

*Benefit*: Spin up a node and play around quickly and with low cost.

## Single board computer hobbyist

A raspberry pi 3, or similarly-sized computer with could contribute
to network health.

Currently a raspberry pi 4 can run a full node, with consensus
and execution clients, however this is a bit tight and requires a ~2TB SSD.

*Benefit*: Learn about Ethereum, get node access and provide the
network with additional robustness.

## Mobile user

Trin is not currently configured to run on mobile, however this is plausibly
a viable and interesting use case. A trin node could run as a background
task with configurable limits on disk, CPU and bandwidth use.

*Benefit*: Wallet use without reliance on third party wallet APIs. Contributes to
network health.

## Unsuitable users

There are situations where Trin is estimated to not be a good node choice:
- Time-critical chain tip data. Likely that data distribution may not be fast enough for these
    use cases, however testing may show otherwise.
    - Consensus participation. Beacon chain staking with a Consensus client with Portal Network node as Execution client.
    - Block builder. Serving blocks to beacon chain validator nodes via MEV-boost
- Data analysis requiring state at historical blocks. Trin is not an archive node and does not
    expose `trace_`* or` debug_`* endpoints.
