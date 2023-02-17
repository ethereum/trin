# select build image
FROM rust:1.66.1 AS builder

# create a new empty shell project
RUN USER=root cargo new --bin trin
WORKDIR /trin

RUN apt-get update && apt-get install clang -y

# copy over manifests and source to build image
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./src ./src 
COPY ./trin-cli ./trin-cli
COPY ./trin-core ./trin-core 
COPY ./trin-history ./trin-history 
COPY ./trin-state ./trin-state 
COPY ./ethportal-peertest ./ethportal-peertest 
COPY ./ethportal-api ./ethportal-api

# build for release
RUN cargo build -p trin -p trin-cli --release

# final base
FROM ubuntu:22.04

# copy default merge master acc to expected location
RUN mkdir -p /trin/trin-core/src/assets
COPY --from=builder /trin/trin-core/src/assets/merge_macc.bin ./trin/trin-core/src/assets/merge_macc.bin
# copy build artifacts from build stage
COPY --from=builder /trin/target/release/trin /usr/bin/
COPY --from=builder /trin/target/release/trin-cli /usr/bin/
COPY --from=builder /trin/target/release/purge_db /usr/bin/

ENV RUST_LOG=debug

ENTRYPOINT ["/usr/bin/trin"]
