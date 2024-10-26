# Portal vs Standard Clients

This page is not trying to be an unbiased comparison. Obviously we think Portal is cool. Below is why we think so. Of course, we still identify known drawbacks of using the Portal Network.

## What are standard clients?

These are also known as Execution Layer clients. The [top three by usage](https://clientdiversity.org/) are Geth, Nethermind, and Besu. There are more great ones out there.

You would use standard clients if you want to stake ether, or access on-chain contracts or generate transactions without using a third-party service.

## Standard client challenges

In general, the following are challenges with all standard clients:

- First-time sync: can take days or more
- High storage needs: 2 Terabytes or more
- Connectivity sensitivity: going offline overnight means spending a while to catch up
- Non-trivial CPU usage: you'll notice it running on your laptop

## Portal benefits

In contrast, Portal Network was designed to overcome these challenges. For example:

### Sync

First-time sync is very fast. You can be up and running in minutes.

All Portal needs to do is download data for the Consensus Layer to identify the tip of the chain signed by stakers. The client can then validate all past Execution Layer data.

### Storage

The amount you store is fully configurable. You could run with 10 MB, if you want.

You will help yourself and the network by storing more, like 1-100 Gigabytes. That means you'll get faster local requests and you'll be able to serve more data to others. But it is fully your choice.

### Connectivity

Going offline and coming back online is no big deal. You'll be able to sync up again quickly.

### CPU

Portal is designed to be very light on CPU. The goal is to make it so you can run it on a Raspberry Pi, or even forget that it's running on your laptop, because it's so light.

Since we're still in early days, users may experience some fluctuations in CPU usage. We will continue to optimize!

## Joint Benefits of Portal & Standard Clients

Some things are great about standard clients, so Portal keeps those features, like:

### Standard JSON-RPC Endpoint

Portal clients can act as a server for Ethereum data. They do this by hosting the standardized JSON-RPC endpoint. Portal clients are a drop-in replacement for you Web3 script or wallet.

Note that not every endpoint is supported in Portal clients yet, but coverage is expanding over time.

### Fully-validated

Whenever Portal clients request data from a peer, they also generate internal cryptographic proofs that the provided content matches the canonical chain.

This happens recursively until the source of consensus. For example, if you request contract storage, Portal clients will:
1. generate merkle proofs back to the state root
2. verify the state root against a header
3. verify that the header was signed/attested by Ethereum stakers

### Privacy

There is no single third party that collects every request you make about the Ethereum network.

An individual peer knows if you request data from them, but they don't know what your original RPC query is.

## Portal Drawbacks

There are some drawbacks to using Portal clients. Here are some known ones:

### Latency

When making a request that requires many different pieces of data under the hood, that requires many network round trips. This can be slow. Reading data out of a contract might take many seconds, instead of milliseconds.

### Partial view

The essense of Portal is that you only store a small slice of the total data.

There are some use cases that involve seeing all the data in the network at once. For those, it will often be better to just load a standard client and have all the data locally for analysis.

*Caveat:* There are still some cases that it might be faster to use Portal, even if you need a wide spread of data. You might be able to enumerate every account on the network faster than it takes a standard client to sync up from scratch, for example.

### Offline access

A Portal client is not very useful while offline. Clients depends on requesting missing data from peers. In contrast, standard clients that are offline can still serve all data up until their latest sync point.

### Uptime

The primary Ethereum network is maniacal about uptime. If you run a standard client, and have an internet connection, you will be getting network updates.

There are more opportunities for downtime or lag in Portal clients. You might expect something more like 99.5% uptime. *(No promises, just a guess. Of course we will aim higher)*
