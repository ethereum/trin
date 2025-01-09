## Run [ethereum/consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests)

`ethereum/consensus-spec-tests` test data is important for testing our types, but the test data is very large which makes it not feasible to host it in our repository, this has lead to us under testing new types when new forks ship, and adding thousands of lines of test data and copy pasting almost identical tests with a few variables renamed.

To solve the first problem we will have a Makefile which will download the test data and run the tests, then to reduce code duplication we can write macros as most tests are identical, for more niche test cases it might make sense to write some traditional test cases as well.

### Running the tests

All the tests in this crate are behind a feature flag `ef-tests` as they require the test data to be downloaded for the tests to run

To run the tests it is as simple as running `make test`, this will download all required files then run the tests
```bash
make test
```

### Cleaning up test data

This will delete all the previously downloaded test data
```bash
make clean
```

## Outline of the crate structure
### src
The source of this crate will contain helper types and macros for our tests

### tests
All the tests the `ef-tests` crates run will be located in the `tests` folder

## what kinds of data types are being tested?

Currently we are testing all the Consensus Specification types we have implemented, every fork some Beacon Chain types are updated, so we can easily
add the new types to be tested.

In the future we may also test `ethereum/execution-test-specs`

## how to add tests in future forks & make sure that they're tested

Currently the main testing we are doing is the `ssz_static` tests which test
- ssz encode
- ssz decode
- merkle root calculation

Testing these is as easy as adding `test_consensus_type!(SignedBeaconBlockDeneb, ForkName::Deneb);` and passing in the type and an enum for the network upgrade into the macro and it will generate tests for you.

For testing more niche test cases it might not make sense to write a macro and in that case we can just write a traditional test case
