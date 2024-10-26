# Access trin from different computer

If you want to run Trin on one computer and access it from another, launch the trin node with an HTTP transport instead of a default IPC tranport:

```sh
trin --web3-transport http
```

This endpoint is unprotected. Anyone can make requests to your trin node. (This is why the default is IPC)

You probably want to restrict access to your trin node. One way to do that is to firewall off the trin port, and use SSH port forwarding.

## SSH port forwarding

Assuming you can SSH into the computer running Trin, you can forward the HTTP port to your local machine, with:

```sh
ssh -N -L 8545:127.0.0.1:8545 username@trin-host-computer
```

Now you can query the trin node from your local machine at `http://localhost:8545`, as described in [Building Queries](../use/making_queries.md).
