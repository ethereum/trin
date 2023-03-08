# Archive nodes

A Portal Network node is not an archival node. This page explores the reason for this
and some considerations on the topic.

An archive node is one that can know the history at a certain block in the past.

A non-archive node has this information until a block is 128 blocks old. After this
point the data is forgotten.

## Old state
Archive nodes store old states

- What was the balance of token x at block y?
- What was in storage slot x at block y?

## Old traces
Archive nodes store old traces. This means that they can re-execute old
transactions and show everything that the EVM did.

- What events were emitted during transaction x?
- How much gas did transaction x use?

## Requirements
Consider an archive node that is going to trace the 100th transaction in an old
block.

- The transaction may call a contract, which may in turn call another contract (etc., ). The state of the contracts must be known (balance, nonce, bytecode, storage)
- The transaction may reference the hash of a preceeding block (up to depth of 256 blocks)
- The transaction may modify state that has already been modified in in the preceeding 99
transactions.

## Would an Archive sub-protocol be of use?

### Not for sequential data analysis
Archival nodes are great for data science because they allow traversing a large number
of sequential blocks and tracking changes over time.

A portal node would not be suited for this activity because it requires sequential blocks
rather than posession of data based on the nodes ID. Hence a Portal Node has a disperse subset of
content and would need to ask peers for data for sequential blocks. Asking for all sequential
blocks would cause an infeasible burden on peers.

### Possibly for personal wallet history

A user with access to an index of address appearances (such as the Unchained Index)
could make queries about their historical transactions. This could be for a wallet,
multisig contract or any contract.

After retrieving the traces for these transactions, they could be used to create a
display of activity. E.g., A graph of token balances changing over time, or a log
of on-chain activity (trades, loans, transfers, NFT activity).

## Could an Archive sub-protocol exist?

It is not impossible. However, the goal of the Portal Network is to provide the
function of a non-tracing node. Some considerations are explored below.

### Intra-block state

To trace the last transaction in a block, all preceeding transaction final states
must be known. Hence single request for a transaction trace could result in requiring
many transactions in a single block to be obtained. This applies to popular contracts
that appear frequently in a block (e.g., exchanges, and popular tokens).

Consequence of a request for a transaction at the end of a block involving popular contracts:
- It would be very slow to get a response
- It could be used as a denial of service (DoS) attack on the network. For instance,
by finding the final transactions in blocks and requesting them from different nodes.

### Nested contract calls

A contract could start a chain of nested calls to other contracts. If a node
does not have the state of these contracts, it would have to request them.
Hence, the time to trace such a transaction would be very slow. Every nested
call would take the time that a single Portal Network request takes.

Consequences of a request for a transaction with deeply nested contract calls:
- It would be very slow to get a response
- It could be used as a denial of service (DoS) attack on the network. For instance,
by finding many nested transactions and requesting them from different nodes.

### Duplication of data

If Archive was a sub-protocol there may be some data that is required to be duplicated
on the History or State sub-protocols. This implies that the sub-protocol is inefficient
with respect to disk space but may not be a significant problem.

### Medium-sized portal nodes

There is a always a moderate amount of interest in archive nodes, for many parties
find historical Ethereum data valuable. As archive nodes require minimum ~2TB
of storage, many people choose not to run one.

Perhaps there is a large enough appetite to run a "medium-sized portal archive node",
such that many users contribute ~100GB.
In this scenario, the DoS attacks are reduced as these medium-sized nodes would
cause less amplification of network traffic.

### Appetite for lags

If the desire for the results of an archive node are large enough, applications
and users could be tolerant of slow lookup times. For example, a wallet connected to a
portal archive node could display current wallet state quickly, but under a "history" tab could show: "performing deep search... Estimated time 24 hours". Once the information has been retrieved
it could then be stored for fast access.
