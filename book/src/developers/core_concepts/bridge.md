# Bridge

Blocks are produced by Ethereum Execution clients which use a different
network to Portal Network nodes. A Bridge node is responsible for taking data
from the external network and passing it to the Portal Network.

```mermaid
flowchart LR
    eth[Ethereum Execution node]-->bridge[Portal Network Bridge node]
    bridge-->portal[Portal network node]
```
This operates as follows:
```mermaid
sequenceDiagram
    Bridge-->>Execution: eth_getBlock
    Execution-->>Bridge: block
    Bridge-->>Portal: block
```
Currently the bridge functionality exists as a separate python application
with plans to implement in Trin.