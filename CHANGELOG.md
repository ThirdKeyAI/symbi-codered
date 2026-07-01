# Changelog

All notable changes to symbi-codered are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Java sandbox reproducer** — `poc_forge` now runs Java PoCs in a
  network-isolated JDK 21 sandbox using single-file source mode
  (`java Repro.java`, no compile step) with `sqlite-jdbc` on the classpath for
  in-process SQLite repros. Closes the previously-deferred Java gap; Java PoCs
  no longer fall back to citation-grade evidence. New `hunt
  --java-sandbox-container` flag and `java-sandbox` compose service.
- `CONTRIBUTING.md`, issue templates, and a pull-request template.

### Changed
- **OSS sync publishes only git-tracked files.** The public-mirror sync now
  enumerates git-tracked files per allowlisted directory instead of copying the
  tree as-is, so untracked/scratch content can no longer leak to the public repo.
- Promoted `examples/guard_check.rs` from a throwaway to a tracked example.

### Fixed
- Documentation accuracy: the IaC sidecar ships in `docker-compose.yml` (was
  described as not-yet-included); corrected the `symbi-redteam` link and clone
  URL; added `php-sandbox`/`java-sandbox`/`iac-scanner` to the quick-start;
  documented `GRC_TOKEN` and `OPENROUTER_API_KEY` in `.env.example`.

## [1.1.0] - 2026-06-30

First public release of the open-source core under Apache-2.0.

### Added
- **PHP language support** — tree-sitter parsing, dataflow/taint, symbols, and
  SAST via semgrep + progpilot + compromised-packages, plus a network-isolated
  PHP 8.3 CLI sandbox reproducer (pdo_sqlite).
- **Documentation site** (zensical) at https://codered.symbiont.dev.
- **AWS Bedrock inference** via an OpenAI-compatible gateway.

### Changed
- Open-sourced the analysis engine and CLI under Apache-2.0; the multi-tenant
  client portal is feature-gated as a separate enterprise offering.
- Hardened adjudication: witness-gated devil's-advocate rebuttal, an independent
  non-mirroring advocate model (`--advocate-*`), and an `inconclusive`
  `poc_status` so a reproducer that could not run is not treated as a disproof.

## [1.0.0] - 2026-06-06

### Added
- First tagged release: multi-language analysis pipeline
  (Python / Rust / Go / TypeScript / Java static path) with evidence-grade
  adjudication, cartographer → specifier → static_hunter → taint → pattern_scout
  → chain_builder → poc_forge → devils_advocate → reflector, Cedar policy gates,
  a hash-chained audit journal, and Ed25519-signed threat models and handoffs.
