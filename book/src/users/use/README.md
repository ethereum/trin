# Use

Once Trin is running, it will be serving Ethereum data in response to requests.
This can be accessed by other programs, such as a wallet in a web browser.

Once Trin is running, another program will be able to communicate with Trin as it
would any other Ethereum node.

Additionally, commands can be made in the terminal to test functionality.
See sections below for more detail.

## Access from different computer

If Trin is started on `host` computer by `user`, serving data over HTTP `port`
then the following command can be issued on another computer to send requests to Trin
and receive responses:
```sh
ssh -N -L <port>:127.0.0.1:<port> <user>@<host>
```
For example:
```sh
ssh -N -L 8545:127.0.0.1:8545 username@mycomputer
```
Accessing Trin from another computer using IPC is not covered here.
