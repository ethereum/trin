# Discovery

## Node Discovery Protocol v5 (Discv5)

A protocol ([spec](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md)) for nodes to identify each other. There are three main capabilities:
- Sample (walk the network to find nodes)
- Search (locate nodes interested in a specific topic)
- Update (navigate when a peer updates their details, such as IP address)

Discovery is a high level protocol that is further defined with the Discovery wire protocol.

## Discovery (Discv5) wire protocol

An application-level protocol ([spec](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md)) for nodes using Discv5. It describes the structure and logic of different
messages sent between nodes.

Some important properties of the protocol are:
- UDP based scheme (tolerant to packet loss compared with TCP)
    - The Portal Network uses a variant of UDP called uTP that is more friendly for larger
    packets.
- Message encryption (ENRs are used to encrypt data with the recipients public key)
- Protocol differentiation (allow nodes to avoid unrelated networks)
- Message types (for finding peers, establishing connections, requesting specific things)
- Flexible request/types types (for sub-protocols to use custom messages)

## Ethereum Node Records (ENR)

A data format ([spec](https://github.com/ethereum/devp2p/blob/master/enr.md)) that allows nodes to know the identity and important information about
peers. This includes data like IP address and ports.

Nodes generate a private key for the purpose of node discovery. This is used to sign
the ENR to prevent impersonation. Peers can encrypt messages for each other using the ENR.

The private key is unrelated to private keys used to sign Ethereum transactions.
