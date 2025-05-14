FROM gcr.io/distroless/static-debian12

COPY --chmod=0755 target/x86_64-alpine-linux-musl/release/laurel /usr/bin/laurel
COPY etc/laurel/config.toml /etc/laurel/config.toml

ENTRYPOINT ["/usr/bin/laurel"]
CMD ["--config", "/etc/laurel/config.toml"]
