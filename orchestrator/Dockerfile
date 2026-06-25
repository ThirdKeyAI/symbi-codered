# =============================================================================
# symbi-codered orchestrator image
#
# Bundles:
#   - codered CLI (our workspace, release build)
#   - symbi 1.14.1 binary (Symbiont runtime, with Cedar feature)
#   - tree-sitter grammars (loaded; used in Plan B)
#   - local bge-small embedding model (downloaded at first run; cached)
#
# Plan A: image boots, runs `codered tools validate`, runs an audit-stub
# against a dummy repo, exits 0. No phase agents wired yet.
# =============================================================================

# ----- Stage 1: build our workspace -----
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake protobuf-compiler libprotobuf-dev git \
    && rm -rf /var/lib/apt/lists/*

# symbi-runtime is pulled from crates.io (see workspace Cargo.toml) — no sibling
# checkout needed; cargo fetches it during the build below.
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY db ./db

# -j2 to match the global build-parallelism convention
RUN cargo build --release -j2 --bin codered

# ----- Stage 2: fetch the symbi binary (pinned) -----
FROM debian:bookworm-slim AS symbi-fetch

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG SYMBI_VERSION=1.14.1
# Note: when 1.14.1 release artifact name differs, update this URL.
RUN curl -sSfL "https://github.com/thirdkeyai/symbiont/releases/download/v${SYMBI_VERSION}/symbi-v${SYMBI_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
    | tar xz -C /tmp/ \
    && install -m 0755 /tmp/symbi /usr/local/bin/symbi

# ----- Stage 3: runtime -----
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="symbi-codered-orchestrator"
LABEL org.opencontainers.image.description="Governed AI source-code auditor (orchestrator)"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/thirdkeyai/symbi-codered"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 jq git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder      /build/target/release/codered  /usr/local/bin/codered
COPY --from=symbi-fetch  /usr/local/bin/symbi           /usr/local/bin/symbi

# Project files
WORKDIR /opt/codered
COPY symbi.toml                  ./
COPY toolclad.toml               ./
COPY agents/                     ./agents/
COPY tools/                      ./tools/
COPY policies/                   ./policies/
COPY .symbiont/                  ./.symbiont/
COPY orchestrator/entrypoint.sh  /usr/local/bin/entrypoint

RUN chmod +x /usr/local/bin/entrypoint

# Workspace for audits: bind-mount your target repo here as read-only
WORKDIR /audit
VOLUME ["/audit"]

ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["--help"]
