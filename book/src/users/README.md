# Use Cases

The following are examples of people who will be well-suited to using a Portal Network client, like Trin.

> All of these examples are speculative about the future. The most plausible users today are the [Protocol Researcher](#protocol-researcher) and [Client Developer](#client-developer).

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

## Protocol researcher

A researcher looking to explore the Ethereum protocol, testing out
specific aspects and perhaps making experimental changes to the protocol.

*Benefit*: Spin up a node and play around quickly and with low cost.

## Client developer

Ethereum clients are resource-intensive. Developers of those clients can update
their client to use Portal Network data and reduce the local burden of their
client.

*Benefit*: Reduce resource usage of an Ethereum client.

## Single board computer hobbyist

A raspberry pi 3, or similarly-sized computer with could contribute
to network health.

Currently a raspberry pi 4 can run a full node, with consensus
and execution clients, however this is a bit tight and requires a ~2TB SSD.

*Benefit*: Learn about Ethereum, get node access and provide the
network with additional robustness.

## Mobile user

Trin is not currently configured to run on mobile, however this is plausibly
a viable and interesting use case for the future. There are a number of
challenges to address first. Mobile does not typically support backrgound use
of apps, and the battery life of a mobile device is a concern. So one challenge
is how to make the mobile clients contribute back to the network in a way that
is not too burdensome on the device.

*Benefit*: Wallet use without reliance on third party wallet APIs.

## Unsuitable users

There are situations where Trin is estimated to not be a good node choice:
- Very speedy historical state access. It's possible to retrieve old state, but don't expect sub-second contract reads on state as viewed from a historical block.
- Building blocks locally, as a block producer. Random access to the full state and transaction pool is not supported at the speed needed to build competitive blocks.
  - We remain hopeful that in the future, you could use an externally-generated block (like one provided by MEV-boost) so that you can act as a validater using a standard Consensus client, with Trin as the Execution client. This probably depends on a future where state witnesses are bundled with the block sent to you by the producer.
