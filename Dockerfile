# select build image
FROM rust:1.62 AS builder

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
COPY ./mainnetMM ./mainnetMM 
COPY ./utp-testing ./utp-testing 

# build for release
RUN cargo build --all --release

# final base
FROM rust:1.62

# copy build artifacts from build stage
# rename trin executable to enable mkdir /trin
COPY --from=builder /trin/target/release/trin ./trin-main
COPY --from=builder /trin/target/release/trin-cli .
COPY --from=builder /trin/target/release/seed-database .
# copy default merge master acc to expected location
RUN mkdir -p /trin/trin-core/src/assets
COPY --from=builder /trin/trin-core/src/assets/merge_macc.bin ./trin/trin-core/src/assets/merge_macc.bin

# These steps copy the mainnet chain header seed data into container
# This data is too large to be kept inside trin-source code
# It must be downloaded separately and moved to the correct location
# https://www.dropbox.com/s/y5n36ztppltgs7x/mainnetMM.zip?dl=0
RUN mkdir /mainnetMM
COPY --from=builder /trin/mainnetMM ./mainnetMM

ENV RUST_LOG=debug

ENTRYPOINT ["./trin-main"]
