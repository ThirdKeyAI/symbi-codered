# symbi-codered Rust scanner sidecar.
#
# Bundles: cargo-audit, clippy (security selects), semgrep (rust ruleset).
# Long-running container; the orchestrator invokes scanners via `docker exec`.
FROM rust:1.90-slim

LABEL org.opencontainers.image.title="symbi-codered-scanner-rust"
LABEL org.opencontainers.image.description="Rust scanner sidecar (cargo-audit + clippy + semgrep)"
LABEL org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    CARGO_TERM_COLOR=never

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git jq \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Python venv for semgrep (PEP 668: system Python is externally-managed in
# Debian-derived images). The runner shebangs `python3` and we put venv on
# PATH so `semgrep` resolves.
RUN python3 -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir "semgrep>=1.90,<2.0"
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# Pre-warm semgrep
RUN semgrep --version

# cargo-audit pinned to current upstream major (0.22).
RUN cargo install cargo-audit@0.22.1

# clippy is shipped via rustup component (rust:1.90-slim already has rustup).
RUN rustup component add clippy

# Bake offline semgrep ruleset into the image: sidecar runs with
# network_mode: none at runtime, so --config auto cannot reach the
# Semgrep registry. The runner uses --config /opt/semgrep-rules/rust
# (falling back to /opt/semgrep-rules if the rust subdir is absent).
# Strip non-rule directories (stats/, template/, scripts/) and the
# test fixture .yml files that semgrep would reject as missing the
# top-level `rules:` key.
RUN git clone --depth=1 https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules \
    && rm -rf /opt/semgrep-rules/.git \
              /opt/semgrep-rules/stats \
              /opt/semgrep-rules/template \
              /opt/semgrep-rules/scripts \
              /opt/semgrep-rules/.github \
              /opt/semgrep-rules/libsonnet \
    && find /opt/semgrep-rules -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -delete \
    && find /opt/semgrep-rules -name '*.test.yaml' -delete \
    && find /opt/semgrep-rules -name '*.test.yml' -delete \
    && find /opt/semgrep-rules -type d \( \
            -name 'correctness' -o -name 'maintainability' \
         -o -name 'best-practice' -o -name 'style' \
         -o -name 'performance' -o -name 'compatibility' \
       \) -prune -exec rm -rf {} +

# Bake initial copy of compromised-packages-check; see scanners/python/Dockerfile
# for the refresh contract.
RUN git clone --depth=1 https://github.com/jaschadub/compromised-packages-check.git /opt/compromised-packages-check \
    && rm -rf /opt/compromised-packages-check/.git

COPY scanner-runner.py /usr/local/bin/scanner-runner
RUN chmod +x /usr/local/bin/scanner-runner

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

WORKDIR /repo
ENTRYPOINT ["/usr/local/bin/entrypoint"]
