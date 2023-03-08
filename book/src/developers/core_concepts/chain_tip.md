# Chain tip

A Trin node can serve information about the chain tip, such as the latest
block number. A Trin node knows about the beacon chain protocol that is
creating the chain tip.

By listening to activity on the beacon chain
network, it can follow the activities of members of the sync committee. If a certain fraction
of the sync committee have signed off on a certain beacon block, the Trin node can
be confident that this is likely to be the chain tip.

Beacon blocks contain references to Ethereum blocks, and so the node can see the tip of the
Execution chain.