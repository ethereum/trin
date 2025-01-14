#!/bin/bash
set -e

# Set up the routing needed for the simulation.
/setup.sh

echo "Client params: $CLIENT_PARAMS"

./bin/utp-test-app $CLIENT_PARAMS
