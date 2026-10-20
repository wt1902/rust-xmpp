FROM rust:1.99.1-slim AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/rust-xmpp /usr/local/bin/rust-xmpp
RUN ln -s /usr/local/bin/rust-xmpp /usr/local/bin/prosodyctl
COPY scripts/docker-entrypoint.sh /usr/local/bin/rust-xmpp-entrypoint
RUN chmod 0755 /usr/local/bin/rust-xmpp-entrypoint
WORKDIR /work
ENTRYPOINT ["rust-xmpp-entrypoint"]
CMD ["serve", "/etc/prosody/prosody.cfg.lua", "--experimental"]
