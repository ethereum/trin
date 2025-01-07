FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

RUN apt-get update && apt-get install clang -y

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
# Copy over all project folders specified in the .dockerignore
COPY . .
RUN cargo build --release --locked --bin trin

# We do not need the Rust toolchain to run the binary!
FROM ubuntu AS runtime
WORKDIR /app

# copy build artifacts from build stage
COPY --from=builder /app/target/release/trin /usr/bin/
COPY --from=builder /app/target/release/poll_latest /usr/bin/
COPY --from=builder /app/target/release/purge_invalid_history_content /usr/bin/
COPY --from=builder /app/target/release/sample_range /usr/bin/

ENV RUST_LOG=debug

ENTRYPOINT ["/usr/bin/trin"]
