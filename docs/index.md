# symbi-codered

**Governed AI source-code auditor.** Multi-language SAST + LLM-driven reasoning + sandboxed PoC validation + devil's-advocate rebuttal, with an evidence chain you can audit.

Produces SARIF + Markdown + a signed `engagement-seed.json` handoff that downstream consumers (e.g. [symbi-redteam](https://github.com/ThirdKeyAI/symbi-redteam)) can ingest to drive exploit validation.

## What it is, in one paragraph

Run `codered hunt` against a repo. Static analyzers (semgrep, bandit, clippy, gosec, eslint, checkov, trivy, …) produce raw findings. A tree-sitter dataflow extractor builds `dataflow_edges`; a mechanical taint tracer walks them. Four LLM agents — `pattern_scout`, `chain_builder`, `poc_forge`, `devils_advocate` — then reason over the evidence: pattern_scout composes citation-gated findings, chain_builder maps them onto the seven-stage Agent Kill Chain, poc_forge synthesizes reproducer scripts that run in network-isolated sandboxes, and devils_advocate runs an inverted-prompt rebuttal pass (optionally on an independent, non-mirroring model). A `reflector` agent distills the engagement into reusable knowledge triples. Every step is Cedar-policy-gated, hash-chained in an audit journal, and signed with a per-engagement Ed25519 key. `codered report` then emits SARIF, Markdown, and an Ed25519-signed JSON handoff.

## Why it's different

Most code scanners stop at "here is a risky-looking pattern." codered treats a raw finding as a *hypothesis* and makes it earn promotion to a reported finding:

- **Citation-gated** — no finding is stored without a structural witness (analyzer output, code reference, or a reachability hypothesis). Enforced by Cedar, not convention.
- **Reachability, not shapes** — a mechanical taint tracer walks real dataflow edges from source to sink. A finding must cite that path.
- **Sandboxed proof** — `poc_forge` writes a reproducer and runs it in a network-isolated container; the result (`reproduced` / `refuted` / `inconclusive`) is recorded.
- **Adversarial review** — a read-only `devils_advocate` tries to *refute* each finding, optionally on an independent model, and can only suppress one if it cites a structural witness of its own.
- **Auditable** — every tool call and policy decision is hash-chained and signed. You can prove the journal wasn't edited after the fact.

## Core capabilities

| Capability | What it does |
|-----------|-------------|
| **Multi-language SAST** | Per-language scanner sidecars (semgrep, bandit, clippy, gosec, eslint, checkov, trivy, progpilot, …) |
| **Dataflow + taint** | tree-sitter dataflow extraction + mechanical BFS taint tracer (no LLM) producing source→sink chains |
| **LLM reasoning** | Citation-gated `pattern_scout`, kill-chain `chain_builder`, reproducer `poc_forge`, rebuttal `devils_advocate`, `reflector` |
| **Sandboxed PoC** | LLM-synthesized reproducers run in `network_mode: none`, read-only `/repo`, time-boxed containers |
| **Cedar governance** | Policy gates at every finding/advocate/poc/triple/seed write |
| **Tamper-evident audit** | SHA-256 hash-chained journal; `audit::verify_chain` proves no tampering |
| **Signed handoff** | Ed25519-signed, Cedar-filtered `engagement-seed.json` for downstream red-team tooling |

## Get started

- [Getting Started](getting-started.md) — install, configure, run your first audit
- [Architecture](architecture.md) — the pipeline and the trust substrate
- [Pipeline Stages](pipeline-stages.md) — what each of the nine stages does
- [Language Coverage](language-coverage.md) — what's supported today
- [Governance & Trust](governance.md) — Cedar policies, audit journal, signing
- [CLI Reference](cli-reference.md) — the `codered` subcommands

## License

The codered **core** — the analysis engine and CLI plus the `agents/`, `policies/`, `tools/`, and `scanners/` definitions — is licensed under the [Apache License 2.0](https://github.com/ThirdKeyAI/symbi-codered/blob/main/LICENSE). Copyright © ThirdKey.

Some additional features, including the multi-tenant **client portal**, are a separate **enterprise** offering and are **not** covered by this license. Contact ThirdKey for enterprise licensing.
