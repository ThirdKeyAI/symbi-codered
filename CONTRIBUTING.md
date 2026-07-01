# Contributing to symbi-codered

Thanks for your interest in contributing! This file covers the essentials for
building, testing, and submitting changes. For architecture and design
background, see the [documentation site](https://codered.symbiont.dev) and
[`docs/`](docs/).

## Prerequisites

- **Rust** (stable) — the analysis engine and CLI are a Cargo workspace
- **protoc** (`protobuf-compiler` + `libprotobuf-dev`) — required by a
  transitive dependency (lance-encoding via lancedb)
- **Docker + Docker Compose** — for the per-language scanner and sandbox
  sidecars

## Build + test

```bash
cargo build  -j2 --workspace
cargo test   -j2 --workspace --all-targets
cargo clippy -j2 --workspace --all-targets -- -D warnings
```

Please run clippy with `-D warnings` before opening a PR — CI enforces it.

## Scope

This repository is the **open-source core** (engine + CLI) under Apache-2.0.
The multi-tenant client portal is a separate enterprise offering and is not part
of this tree; PRs should target the core.

## Adding scanners / languages / sandboxes

The extension points are documented in the docs:

- [Adding a new scanner](https://codered.symbiont.dev/language-coverage/#adding-a-new-scanner)
- [Adding a new language](https://codered.symbiont.dev/language-coverage/#adding-a-new-language)

A new language sandbox reproducer follows the pattern in `scanners/<lang>-sandbox/`
(Dockerfile + `entrypoint.sh` + Python `run-reproducer.py`); the PHP and Java
sandboxes are the reference implementations.

## Submitting changes

1. Fork and branch from `main`.
2. Keep the change focused; add or update tests covering it.
3. Update `docs/` if you change the CLI surface, features, or APIs.
4. Add a `CHANGELOG.md` entry under `## [Unreleased]` for user-visible changes.
5. Open a PR and fill out the template.

## Security

Do **not** open public issues for vulnerabilities. Follow the coordinated
disclosure process in [SECURITY.md](SECURITY.md).
