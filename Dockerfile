FROM rust:1.56

RUN set -eux; \
    apt-get update; \
    apt-get install -y libacl1-dev;
