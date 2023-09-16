# Kademlia

A protocol for finding content that is distributed amongst peers.

## Overview

### You know who should have what
Each node is responsible for having some content. Exactly what
content they have is determined by the ID of the node. Nodes have
peers, and know the IDs of their peers. Hence, nodes know what data
their peers *should* have.

### You know if you're close

Each node has a way of determining how close data is to an ID.

For example, you might say "I only have data that starts with five 0s".
If you see data with four zeros, you recognise that it is close. Closer
than no zeros.
```ignore
# ID
00000...
# Close data
00001...
# Far away data
11111...
```

### Nodes prefer similar nodes

Nodes prefer peers who have data that is close to theirs. Hence
if you are looking for a piece of data, you can look through your
peers, find the closest one and ask them. That peer will have
contacts that are similar, and so you can ask them to check with their peers.

Hence, network requests can "head in the right direction".

### Visualization

Animations of the protocol can be seen [here](https://kelseyc18.github.io/kademlia_vis/basics/1/)

## Use

### Full database

When Trin is full and a new piece of data is to be stored, the content is
stored, and then other data is deleted until the storage is at the targed size.

This involves repeatedly removing the content with the furthest ID from the node ID until
the database is below the target.

## Deep dive

A map is a data structure that stores `<key, value>` pairs and allows two fundamental operations: `PUT(key, value)` to add or update a value under a specific key and `GET(key)` to retrieve the value associated with a particular key. This makes maps highly useful for quickly retrieving specific values.

A Distributed Hash Table (DHT), on the other hand, is a more sophisticated structure that extends the functionality of maps to a distributed system. In a DHT, data is dispersed across multiple nodes (computers) in a network.

To function effectively, a DHT system must meet two critical criteria:
- **Scalability**. As more nodes join the network, the DHT should distribute the data evenly across them to maintain balance and efficiency.
- **Fault Tolerance**. In case a node leaves the network or fails, the system should ensure continued access to the data that the unavailable node previously held.

In DHTs, data assignment to nodes typically works like this:

- Generate a unique key for each piece of data, typically using a hash function: `Key = hash(data)`.
- Assign a unique ID to each participating node in the network.
- Assign each key to the node with the 'closest' ID based on a certain metric.

In this context, the `PUT` and `GET` operations involve finding the node that is 'closest' to a key to store the corresponding value or retrieve it. However, how do we find the 'closest' node to a given key in a distributed system?

The answer depends on how we visualize and implement the DHT: as a hash ring or as a binary tree. 

A Chord DHT represents the system as a circular hash table (or hash ring), where each node is assigned a position on the ring based on its ID, and each key is assigned to the node that is its successor on the ring.

In contrast, a Kademlia DHT represents the system as a binary tree, with the node ID determining its position in the tree. This tree-based approach helps in efficient routing and searching for nodes in large networks.


### Kademlia

![kademlia](https://codethechange.stanford.edu/guides/_images/fig7.png "kademlia")
"[111 wants to perform GET(011)](https://codethechange.stanford.edu/guides/guide_kademlia.html#id9)" by [Drew Gregory](https://github.com/DrewGregory), Jose Francisco, Ben Heller, and Zarah Tesfai is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

In Kademlia, 'distance' is defined using the XOR operator, applied to the IDs (interpreted as non-negative integers) of two nodes, or between a node ID and a key. Essentially, the 'closest' node to a key in Kademlia is the one with the smallest XOR result when the key is XORed with the node's ID.

Having established the rules for how keys are assigned to nodes, we need to define the process for nodes to discover keys stored on other nodes. This task involves striking a balance between the number of other nodes' addresses that each node needs to store (referred to as its 'routing table') and the time it takes to locate a particular key in the network.

#### Static Network

In a network where nodes are neither joining nor leaving, one efficient way to manage the discovery of keys is through the use of 'k-buckets'. 

In Kademlia, each node maintains a set of k-buckets, where each bucket corresponds to a specific range of distances from the node. Each k-bucket stores the contact information of up to `k` other nodes in the network, which fall within the bucket's corresponding distance range. The 'k' in k-buckets refers to this limit on the number of entries in each bucket.

Even with this structure, it's not guaranteed that every node will have information on every other node in the network. There will be situations where a node needs to perform a `GET` operation on a key but does not know which other node holds that key. 

In such a case, the node will consult its k-buckets and contact the known node that is 'closest' to the desired key (according to the XOR distance metric). This contacted node can then either provide the requested data, if it holds it, or help the requester by forwarding the request to another node that is 'closer' to the key.


#### Dynamic Network

In a dynamic network where nodes can join or leave at any time, Kademlia uses 'k-buckets' in a slightly different way. Here, `k` is typically chosen to be a number representing nodes that are extremely unlikely to leave the network within a certain time frame (say an hour). Each k-bucket can then store information about up to `k` other nodes.

##### Node Lookup Procedure
1. Find the `k` closest nodes to a given key in your routing table (using XOR metric).
2. Continue the following steps until responses are received from all the `k` closest nodes:
   a. Query these `k` closest nodes for their own `k` closest nodes.
   b. Update your list of the `k` closest nodes based on the new information received.

In case a node leaves the network and cannot respond to queries, it will be replaced in the k-buckets of other nodes, thus maintaining the network's robustness.

##### Bucket Refresh Procedure
To refill a k-bucket after nodes have left, the system performs 'bucket refreshes'. These involve executing lookups on random IDs within the k-bucket's ID range, helping discover active nodes in that range.

##### Node Join Procedure
When a new node `j` joins the network, it must initially know the ID and IP address of at least one other node `c`. The new node then performs the following steps:
1. Execute a lookup for its own ID to discover the closest known nodes to itself.
2. Perform bucket refreshes for all k-buckets, guided by the closest known nodes.
As part of these procedures, other nodes in the network will become aware of `j` and can add it to their k-buckets if they have room.

Moreover, whenever a node learns about a new node that's closer to any of the keys it stores, it can proactively move those keys to the new node by issuing `PUT` requests. This helps ensure that keys are optimally distributed in the network.

##### Kademlia RPCs
Kademlia defines four Remote Procedure Calls (RPCs) for nodes to interact:

- `PING`: Checks if a node is online.
- `STORE`: Instructs a node to store a `<key, value>` pair.
- `FIND_NODE`: Takes a 160-bit key and returns information about the `k` closest nodes to that key.
- `FIND_VALUE`: Similar to `FIND_NODE` but returns the stored value if the key is found, else returns the `k` closest nodes to the key.

