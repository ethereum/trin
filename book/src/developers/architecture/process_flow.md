# Process flow

The following main threads are spawned when Trin is started via `./src/main.rs`.

```mermaid
stateDiagram-v2
    trin: trin

    state trin {
        utplistner: UTP listner
        subprotocolhandler: sub-protocol handler
        subprotocolnetworktask: sub-protocol network task
        portaleventshandler: portal events handler
        jsonrpcserver: JSON-RPC server

        main() --> utplistner
        main() --> subprotocolhandler
        main() --> subprotocolnetworktask
        main() --> portaleventshandler
        main() --> jsonrpcserver

    }

```
Where for each sub-protocol implemented (History, State, Etc.,), a new thread is started.

Here are some of the major components of trin-core that are called on startup within `./trin-core/src/lib.rs`.

```mermaid
stateDiagram-v2
    trincore: trin-core
    collection: configs and services

    state trin {
        main() --> from_cli()
        from_cli() --> run_trin()
        run_trin() --> discovery()
        run_trin() --> utp_listener()
        run_trin() --> header_oracle()
        run_trin() --> portalnet_config
        run_trin() --> storage_config

    }

    state trincore {
        portalnet_config --> collection
        storage_config --> collection
        discovery() --> collection
        header_oracle() --> collection
        utp_listener() --> collection


        state portalnet {
            portalnet_config
            storage_config
            discovery()
        }
        state utp {
            utp_listener()
        }
        state validation {
            header_oracle()
        }
    }
```

Once the initial collection of important configs and services have
been aggregated, they are passed to the crates for each sub-protocol (`trin-history` shown here). The received data structures are then
used to start the JSON-RPC server.

An events listener awaits network activity that can be actioned.
```mermaid
stateDiagram-v2
    trincore: trin-core
    trinhistory: trin-history
    jsonrpchistory: JSON-RPC History details
    historyhandler: History handler
    collection: configs and services

    state trin {
        collection --> initialize_history_network()
        collection --> HistoryRequestHandler
        initialize_history_network() --> jsonrpchistory
        jsonrpchistory --> launch_jsonrpc_server()
        HistoryRequestHandler --> historyhandler
        collection --> events()
        historyhandler --> events()
    }

    state trincore {
        state portalnet {
            events()
        }

    }
    state trinhistory {
        initialize_history_network()
        state jsonrpc {
            HistoryRequestHandler
        }
    }
    state rpc {
        launch_jsonrpc_server()
    }
```

Then `./trin-core/portalnet/events.rs` is handles events at the level of the Portal Wire Protocol.
These are defined messages that are compliant with the Discv5 protocol, and specific
to the Portal Network.