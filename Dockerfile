# select build image
FROM rust as builder

# create a new empty shell project
RUN USER=root cargo new --bin trin
WORKDIR /trin

RUN apt-get update && apt-get install clang -y
RUN rustup component add rustfmt

# copy over manifests and source to build image
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./src ./src 
COPY ./trin-core ./trin-core 
COPY ./trin-history ./trin-history 
COPY ./trin-state ./trin-state 
COPY ./ethportal-peertest ./ethportal-peertest 

# build for release
RUN cargo build --release

# final base
FROM rust

# copy build artifact from build stage
COPY --from=builder /trin/target/release/trin .

ENV RUST_LOG=debug

ENTRYPOINT ["./trin"]
