# Finding peers

If a peer is in a network behind a NAT (Network Address Translation) table, the process for
finding a peer is more complicated.

These diagrams are indended as a rough-guide.

## Non-NAT simple case

The bootnode can gossip to Charlie who can then directly contact Alice.

```mermaid
sequenceDiagram
    Alice IP1 PORT1-->>Bootnode: Hello (ENR with no IP)
    Bootnode-->>Alice IP1 PORT1: Hi, I notice your address is <IP1>:<PORT1>
    Alice IP1 PORT1-->>Alice IP1 PORT1: Updates ENR (<IP1>:<PORT1>)
    Bootnode-->>Charlie: Meet Alice (ENR with <IP1>:<PORT1>)
    Charlie->>Alice IP1 PORT1: Hello Alice at <IP1>:<PORT1>
    Alice IP1 PORT1->>Charlie: Hello (ENR <IP1>:<PORT1>)
```

## NAT problem

The bootnode can gossip to Charlie, but Charlie is a stranger from the NAT's perspective.
It doesn't know who on the internal network is the recipient.

- The NAT remembers who it has spoken to.
- Messages from the bootnode are expected.
- Messages from Charlie are not expected, and its not clear who they are for. Perhaps
the smart fridge?

```mermaid
sequenceDiagram
    Alice IP1 PORT1-->>NAT IP2 PORT2: Hello bootnode (ENR with no IP)
    Note right of NAT IP2 PORT2: Stores Bootnode
    NAT IP2 PORT2-->>NAT IP2 PORT2: Maps from internal IP
    NAT IP2 PORT2-->>Bootnode: Hello bootnode (ENR with no IP)
    Bootnode-->>NAT IP2 PORT2: Hi, I notice your address is <IP2>:<PORT2>
    NAT IP2 PORT2-->>NAT IP2 PORT2: Maps to internal IP
    NAT IP2 PORT2-->>Alice IP1 PORT1: Hi, I notice your address is <IP2>:<PORT2>
    Alice IP1 PORT1-->>Alice IP1 PORT1: Updates ENR (<IP2>:<PORT2>)
    Alice IP1 PORT1-->>NAT IP2 PORT2: Thanks bootnode (ENR with <IP2>:<PORT2>)
    NAT IP2 PORT2-->>Bootnode: Thanks boodnode (ENR with <IP2>:<PORT2>)
    Bootnode-->>Charlie: Meet Alice (ENR with <IP2>:<PORT2>)
    Charlie->>NAT IP2 PORT2: Hello Alice at <IP2>:<PORT2>
    Note right of NAT IP2 PORT2: No map on record. Who is this for?
    Note right of Charlie: Hmm Alice didn't respond.
```

## The NAT solution

If Alice knows she is behind a NAT, she can pass a message which goes:

"I'm behind a NAT. Send your requests via peers and I'll reach out to you."

- The bootnode gossips to Charlie
- Charlie sees "NAT" in Alices ENR
- Charlie asks the bootnode to introduce him to Alice
- Alice reaches out to Charlie
- The NAT now has a mapping for Charlie-Alice messages.

### Part 1: NAT detection

Alice can suspect that she is behind a NAT probabalitically.
If 2 minutes after connecting with a bootnode, no strangers (like Charlie)
have reached out, a NAT is likely.

```mermaid
sequenceDiagram
    Alice IP1 PORT1-->>NAT IP2 PORT2: Hello bootnode (ENR with no IP)
    Note right of NAT IP2 PORT2: Stores Bootnode
    NAT IP2 PORT2-->>NAT IP2 PORT2: Maps from internal IP
    NAT IP2 PORT2-->>Bootnode: Hello bootnode (ENR with no IP)
    Bootnode-->>NAT IP2 PORT2: Hi, I notice your address is <IP2>:<PORT2>
    NAT IP2 PORT2-->>NAT IP2 PORT2: Maps to internal IP
    NAT IP2 PORT2-->>Alice IP1 PORT1: Hi, I notice your address is <IP2>:<PORT2>
    Alice IP1 PORT1-->>Alice IP1 PORT1: Updates ENR (<IP2>:<PORT2>)
    Alice IP1 PORT1-->>NAT IP2 PORT2: Thanks bootnode (ENR with <IP2>:<PORT2>)
    NAT IP2 PORT2-->>Bootnode: Thanks boodnode (ENR with <IP2>:<PORT2>)
    Note right of Alice IP1 PORT1: ... Hmm no strangers. Must be a NAT.

```

### Part 2: NAT communication

Alice can put "NAT" in her ENR. Now when Charlie tries to get in touch,
he knows to go via a peer.

Continued from above, skipping Charlie's failed attempt to contact Alice directly.

```mermaid
sequenceDiagram
    Note right of Alice IP1 PORT1: ... Hmm no strangers. Must be a NAT.
    Alice IP1 PORT1-->>NAT IP2 PORT2: Update: NAT (ENR with NAT <IP2>:<PORT2>)
    NAT IP2 PORT2-->>Bootnode: Update: NAT (ENR with NAT <IP2>:<PORT2>)
    Bootnode-->>Charlie: Meet Alice (ENR with NAT <IP2>:<PORT2>)
    Charlie->>Bootnode: Hello Alice (From Charlie ENR(<charlie>))
    Note right of Bootnode: To Alice via Bootnode
    Bootnode->>NAT IP2 PORT2: Hello Alice (From Charlie ENR(<charlie>))
    NAT IP2 PORT2-->>NAT IP2 PORT2: Maps to internal IP
    NAT IP2 PORT2-->>Alice IP1 PORT1:  Hello Alice (From Charlie ENR(<charlie>))
    Alice IP1 PORT1-->>NAT IP2 PORT2: Hello Charlie (ENR with NAT <IP2>:<PORT2>)
    Note right of NAT IP2 PORT2: Stores Charlie
    NAT IP2 PORT2-->>NAT IP2 PORT2: Maps from internal IP
    NAT IP2 PORT2-->>Charlie: Hello Charlie (ENR with NAT <IP2>:<PORT2>)
    Charlie-->>NAT IP2 PORT2: Hi Alice
    NAT IP2 PORT2-->>NAT IP2 PORT2: Maps to internal IP
    Note right of NAT IP2 PORT2: Finally has a mapping for Charlie!
    NAT IP2 PORT2-->>Alice IP1 PORT1: Hello Alice
```