# Changelog

All notable changes to symbi-codered are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Selectable model profiles** — `codered hunt --model-profile <name>`
  (`CODERED_MODEL_PROFILE` env) picks the generation model without recompiling:
  `fable5` (default), `opus`, `sonnet`, or a local `ollama-qwen` example. Each
  profile bundles its fallback chain + rough list pricing; the cost report and
  advocate mirror-detection follow the selected profile. A fully custom chain
  can be set via `CODERED_GENERATION_PROVIDER`/`_MODEL`/`_FALLBACK` (overrides
  the preset). The universal optimizations (tool_choice, temperature, context
  budget) stay on for every profile. Also added to the standalone `advocate`
  command for correct mirror-detection.
- **Java sandbox reproducer** — `poc_forge` now runs Java PoCs in a
  network-isolated JDK 21 sandbox using single-file source mode
  (`java Repro.java`, no compile step) with `sqlite-jdbc` on the classpath for
  in-process SQLite repros. Closes the previously-deferred Java gap; Java PoCs
  no longer fall back to citation-grade evidence. New `hunt
  --java-sandbox-container` flag and `java-sandbox` compose service.
- `CONTRIBUTING.md`, issue templates, and a pull-request template.

### Changed
- **Default LLM is now Fable 5.** The finding-generation chain leads with
  `claude-fable-5` (→ OpenRouter Opus 4.8 overload path → Sonnet 4.6 degraded);
  `detect_tier` env defaults refreshed to Sonnet 4.6; token-cost estimates
  relabeled to Fable 5 list pricing.
- **`poc_forge` and `devils_advocate` LoopConfig** now set `tool_choice: Any`,
  `temperature: 0.0`, and a 120K context budget (previously inherited weaker
  defaults) — fixes the "0 verdicts" prose-only termination, avoids a
  `temperature` 400 on Fable 5/Opus, and stops early context truncation.
- **OSS sync publishes only git-tracked files.** The public-mirror sync now
  enumerates git-tracked files per allowlisted directory instead of copying the
  tree as-is, so untracked/scratch content can no longer leak to the public repo.
- Promoted `examples/guard_check.rs` from a throwaway to a tracked example.

### Fixed
- **`hypothesis_repl` verdict is now a native `emit_verdict` tool-call** instead
  of substring-matching free text — removes the negation-blind misparse
  ("not refuted… reproduced" → refuted) that could corrupt hypothesis-grounded
  findings, and wires the previously-ignored `budget_iterations`.
- **`orga::with_provider_and_model` openrouter branch** now hides competing API
  keys, so an OpenRouter tier with no OpenRouter key fails cleanly instead of
  silently falling through to the wrong provider.
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
