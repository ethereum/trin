# select build image
FROM rust:1.79.0 AS builder

# create a new empty shell project
RUN USER=root cargo new --bin trin
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
COPY ./portalnet ./portalnet
COPY ./light-client ./light-client
COPY ./rpc ./rpc
COPY ./src ./src 
COPY ./trin-beacon ./trin-beacon
COPY ./trin-execution ./trin-execution
COPY ./portal-bridge ./portal-bridge
COPY ./trin-history ./trin-history
COPY ./trin-metrics ./trin-metrics
COPY ./trin-state ./trin-state
COPY ./trin-storage ./trin-storage
COPY ./trin-utils ./trin-utils
COPY ./trin-validation ./trin-validation 
COPY ./utp-testing ./utp-testing

# build for release
RUN cargo build -p trin --release

# final base
FROM ubuntu:22.04

# copy build artifacts from build stage
COPY --from=builder /trin/target/release/trin /usr/bin/
COPY --from=builder /trin/target/release/poll_latest /usr/bin/
COPY --from=builder /trin/target/release/sample_range /usr/bin/

ENV RUST_LOG=debug

ENTRYPOINT ["/usr/bin/trin"]
