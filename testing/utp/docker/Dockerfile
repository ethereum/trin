FROM rust:1.85.0-bullseye AS builder

RUN apt-get update \
 && apt-get install clang -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ARG BRANCH_NAME=master
ARG REPO_URL="https://github.com/ethereum/trin.git"

RUN git clone $REPO_URL \
 && cd trin \
 && git checkout ${BRANCH_NAME} --

WORKDIR /trin

RUN cargo build -p utp-testing --release

RUN mv target/release/utp-test-app /bin/

FROM debian:bullseye-slim AS deploy

RUN apt-get update \
 && apt-get install -y ethtool net-tools \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /bin/utp-test-app /bin/utp-test-app

ENV RUST_LOG=TRACE

COPY setup.sh .
RUN chmod +x setup.sh

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
