# Pipeline Stages

The hunt runs nine stages, then `codered report` renders the outputs. Stages 1–4 are deterministic (no LLM); stages 5–9 are LLM-driven but every write is Cedar-gated.

| # | Stage | Type | Output |
|---|-------|------|--------|
| 1 | `cartographer` | tree-sitter | `repo_facts`, `symbol_index`, `routes`, `dataflow_edges`, code-chunk LanceDB index |
| 2 | `specifier` | canonical JSON + Ed25519 | `threat_models` row (sources, sinks, scope, signature) |
| 3 | `static_hunter` | docker exec into sidecars | `findings` rows with `Citation::Analyzer` per scanner |
| 4 | `taint_tracer` | mechanical BFS (no LLM) | `taint_chains` rows (source→sink paths) |
| 5 | `pattern_scout` | LLM (Symbiont ORGA loop) | `findings` rows with `Citation::Code` / `Citation::Hypothesis` |
| 6 | `chain_builder` | LLM | `attack_chains` rows mapping to the 7-stage Agent Kill Chain |
| 7 | `poc_forge` | LLM + language-specific sandbox | `findings.poc_status` ∈ {reproduced, refuted, inconclusive, reproduced_by_citation} |
| 8 | `devils_advocate` | LLM (inverted prompt, read-only, witness-gated) | `findings.advocate_verdict` ∈ {confirmed, rebutted, uncertain} |
| 9 | `reflector` | LLM | `knowledge_triples` rows (cross-engagement recall substrate) |

Followed by `codered report` (deterministic Rust; no LLM), which renders SARIF + Markdown + the signed seed.

## Taint, in context

A *source* is where untrusted input enters (HTTP params, request bodies, CLI args, env, file reads); a *sink* is an operation that's dangerous with untrusted input (SQL query, shell exec, file path, deserializer, HTML output).

The `taint_tracer` does a mechanical BFS over the cartographer's `dataflow_edges` from each source to each sink the specifier pinned. An unsanitized source→sink path becomes a `TaintChain` (SQLi, command injection, path traversal, SSRF, XSS, …). Those chains are the structural *witness* a finding must cite: reachability proof, not just a risky-looking code shape.

## poc_status and advocate_verdict

Two fields capture how much a finding earned its place:

- **`poc_status`** — `reproduced` (the sandbox ran the PoC and it worked), `refuted` (it ran and didn't), `inconclusive` (the reproducer could not run — explicitly *not* a disproof), or `reproduced_by_citation` (citation-grade evidence where no sandbox exists for the language).
- **`advocate_verdict`** — `confirmed`, `rebutted` (only if the rebuttal cites a structural witness), or `uncertain`.

The `inconclusive` state exists so that "the reproducer could not run" is never silently treated as a disproof. Likewise, a rebuttal is witness-bound: suppressing a finding is as evidence-bound as creating one.
