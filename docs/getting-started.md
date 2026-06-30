# Getting Started

## Prerequisites

- Docker + Docker Compose
- Rust toolchain (stable)
- An LLM API key — `ANTHROPIC_API_KEY` by default. OpenAI / OpenRouter, or AWS Bedrock via an OpenAI-compatible gateway, are also supported (see `.env.example`).

## Install

```bash
git clone https://github.com/ThirdKeyAI/symbi-codered && cd symbi-codered
cp .env.example .env   # set ANTHROPIC_API_KEY (and SYMBIONT_*)

# Build the CLI:
cargo build -j2 -p symbi-codered-cli --release
```

The core depends on the [Symbiont](https://github.com/ThirdKeyAI/Symbiont) runtime (`symbi-runtime`), pulled from crates.io — no extra setup required.

## Bring up the scanner sidecars

Each language scanner and sandbox runs as a Docker Compose service. They build on first `up`:

```bash
CODERED_TARGET=/path/to/target/repo docker compose up -d \
  python-scanner rust-scanner typescript-scanner go-scanner java-scanner php-scanner \
  python-sandbox rust-sandbox typescript-sandbox go-sandbox php-sandbox
```

Each sidecar is optional. If `rust-scanner` isn't up, the rust jobs bump `scanner_errors` and the rest of the pipeline continues — useful for fast iteration on a single-language target:

```bash
docker compose up -d python-scanner python-sandbox
codered hunt --engagement <eid>   # Rust/TS/Go jobs gracefully error, Python flow completes
```

## Run the pipeline

```bash
# 1. Map the repo (capture the engagement_id printed to stdout):
./target/release/codered carto /path/to/target/repo

# 2. Sign a threat model (sources, sinks, scope):
./target/release/codered specifier --engagement <eid> --target /path/to/target/repo

# 3. Run the hunt (scanners → taint → LLM agents → poc → advocate → reflector):
./target/release/codered hunt --engagement <eid>

# 4. Render outputs:
./target/release/codered report --engagement <eid>
```

Outputs land in `reports/<eid>/`:

```
findings.sarif
report.md
engagement-seed.json   # Ed25519-signed, Cedar-filtered
```

A fully wired audit on a Rust + TypeScript repo takes ~5–15 minutes wall-clock and ~$1–$10 in tokens, depending on finding volume.

## Independent devil's advocate

By default `devils_advocate` mirrors the generation model. To break the confirmation-bias loop, point the rebuttal pass at an independent model with its own fallback chain:

```bash
codered hunt --engagement <eid> \
  --advocate-provider openrouter \
  --advocate-model openai/gpt-4.1 \
  --advocate-fallback minimax/minimax-m2
```

A startup warning fires if the advocate ends up mirroring the generation tier.

## Next steps

- [Architecture](architecture.md) — how the pieces fit together
- [Pipeline Stages](pipeline-stages.md) — what each stage produces
- [CLI Reference](cli-reference.md) — every subcommand
