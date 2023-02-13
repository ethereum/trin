# uTP

The Dicv5 protocol normally uses UDP packets, however this has some limitations
in packet size. The Portal Network uses Micro Transport Protocol (uTP)
([spec](https://github.com/ethereum/portal-network-specs/blob/master/discv5-utp.md))
to avoid this problem.

uTP is similar to the BitTorrent protocol and provides a way to send ordered packets.

Once two peers have agreed to send data via messages in the Portal Wire protocol (E.g., via
an `OFFER` and `ACCEPT`) sequence, the peers can then open communication on the uTP
sub-protocol. Inside this protocol they can send the data to each other, following the
uTP protocol until the data transfer is complete.

First, a sub-protocol is used:
- History sub-protocol (arrange data transfer, but don't start sending)
- State sub-protocol (arrange data transfer, but don't start sending)
- ...

Second, once data transfer is arranged, peers switch to the uTP protocol to start the
data transfer. uTP uses the relevant sub-protocol (E.g., History Discv5 overlay,
State Discv5 overlay) as transport. 

By providing an ID for the content that they are transferring, the two peers
can easily switch from one protocol to the uTP protocol and complete the specified transfer.
