# select build image
FROM rust:1.81.0 AS builder

# create a new empty shell project
RUN USER=root cargo new --bin trin-execution
WORKDIR /trin

# Docker build command *SHOULD* include --build-arg GIT_HASH=...
# eg. --build-arg GIT_HASH=$(git rev-parse HEAD)
ARG GIT_HASH=unknown
ENV GIT_HASH=$GIT_HASH

RUN apt-get update && apt-get install clang -y

# copy over manifests and source to build image
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./e2store ./e2store
COPY ./ethportal-api ./ethportal-api
COPY ./ethportal-peertest ./ethportal-peertest
COPY ./light-client ./light-client
COPY ./portalnet ./portalnet
COPY ./portal-bridge ./portal-bridge
COPY ./rpc ./rpc
COPY ./src ./src 
COPY ./trin-beacon ./trin-beacon
COPY ./trin-evm ./trin-evm
COPY ./trin-execution ./trin-execution
COPY ./trin-history ./trin-history
COPY ./trin-metrics ./trin-metrics
COPY ./trin-state ./trin-state
COPY ./trin-storage ./trin-storage
COPY ./trin-utils ./trin-utils
COPY ./trin-validation ./trin-validation 
COPY ./utp-testing ./utp-testing

# build for release
RUN cargo build -p trin-execution --release

# final base
FROM ubuntu:22.04

# copy build artifacts from build stage
COPY --from=builder /trin/target/release/trin-execution /usr/bin/

ENV RUST_LOG=debug

ENTRYPOINT ["/usr/bin/trin-execution"]
