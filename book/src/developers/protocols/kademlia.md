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