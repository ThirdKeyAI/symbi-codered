# Plan F: rust-sandbox for poc_forge reproducer scripts.
FROM rust:1-slim

ENV CARGO_TERM_COLOR=never \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Pre-seed Cargo manifest with common deps so the sandbox doesn't need network.
COPY Cargo.toml.seed /tmp/Cargo.toml
RUN mkdir -p /tmp/src \
    && echo 'fn main(){}' > /tmp/src/main.rs \
    && (cargo build --manifest-path /tmp/Cargo.toml --offline 2>/dev/null \
        || cargo build --manifest-path /tmp/Cargo.toml)

COPY run-reproducer.py /usr/local/bin/run-reproducer
RUN chmod +x /usr/local/bin/run-reproducer

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
