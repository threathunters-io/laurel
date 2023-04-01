FROM gcr.io/distroless/static-debian11

COPY laurel /usr/bin/laurel
COPY etc/laurel/config.toml /etc/laurel/config.toml
ENTRYPOINT ["/usr/bin/laurel"]
CMD ["--config", "/etc/laurel/config.toml"]
