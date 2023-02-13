# Logging

- All logging should be done with the `log` library and not `println!()` statements.
- Appropriate log levels (`debug`, `warn`, `info`, etc.) should be used with respect to their content.
- Log statements should be declarative, useful, succinct and formatted for readability.

Bad:
```sh
Oct 25 23:42:11.079 DEBUG trin_core::portalnet::events: Got discv5 event TalkRequest(TalkRequest { id: RequestId([226, 151, 109, 239, 115, 223, 116, 109]), node_address: NodeAddress { socket_addr: 127.0.0.1:4568, node_id: NodeId { raw: [5, 208, 240, 167, 153, 116, 216, 224, 160, 101, 80, 229, 154, 206, 113, 239, 182, 109, 181, 137, 16, 96, 251, 63, 85, 223, 235, 208, 3, 242, 175, 11] } }, protocol: [115, 116, 97, 116, 101], body: [1, 1, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0], sender: Some(UnboundedSender { chan: Tx { inner: Chan { tx: Tx { block_tail: 0x55c4fe611290, tail_position: 1 }, semaphore: 0, rx_waker: AtomicWaker, tx_count: 2, rx_fields: "..." } } }) })
```

Good:
```sh
Oct 25 23:43:02.373 DEBUG trin_core::portalnet::overlay: Received Ping(enr_seq=1, radius=18446744073709551615)
```
