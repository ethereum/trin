# Testing

Testing occurs at different levels of abstraction.

## Unit testing

Unit tests are for checking individual data structures and methods.
These tests are included within each workspace, at the bottom the file that contains the
code being tested. Tests are run by CI tasks on pull requests to the Trin repository.

## Integration testing

Tests that involve testing different parts of a crate at the same time are included in a `/tests`
directory within the relevant module or crate. They are also run by CI tasks on pull
requests to the Trin repository.

## Network simulation

The `test-utp` crate is part of continuous integration (CI). This sets up
client and server infrastructure on a single machine to test data streaming with
simulated packet loss.

## Hive

Hive testing runs Trin as a node and challenges it in a peer to peer environment. This
involves creating a docker image with the Trin binary and passing it to Hive.

Hive itself is a fork of Ethereum hive testing and exists as `portal-hive`, an
external repository ([here](https://github.com/ogenev/portal-hive)). It can be started with docker images of other clients for cross-client testing.
The nodes are started, fed a small amount of data and then challenged with RPC requests
related to that data.

Testing is automated, using docker configurations in the Trin repository to build test Trin
and other clients at a regular cadence. Results of the latest test are displayed
at [https://portal-hive.ethdevops.io/](https://portal-hive.ethdevops.io/).
