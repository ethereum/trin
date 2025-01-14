FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y ethtool net-tools \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY ./utp-test-app /bin/utp-test-app

ENV RUST_LOG=debug

COPY setup.sh .
RUN chmod +x setup.sh

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
