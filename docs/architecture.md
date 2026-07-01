# Architecture

codered is a staged pipeline over a trust substrate. The pipeline turns a target repo into an auditable set of findings; the substrate guarantees that every step is policy-gated, recorded, and signed.

```mermaid
flowchart TD
    repo[("target repo")]
    cli["codered CLI"]
    journal[("audit_journal<br/>hash-chained")]

    cli --> carto["1 — cartographer<br/>tree-sitter facts +<br/>dataflow_edges"]
    carto --> spec["2 — specifier<br/>signed threat model<br/>(Ed25519)"]
    spec --> stat["3 — static_hunter<br/>per-language scanners"]

    stat --> py["python-scanner<br/>(semgrep, bandit,<br/>pip-audit, ruff)"]
    stat --> rs["rust-scanner<br/>(cargo-audit, clippy,<br/>semgrep)"]
    stat --> ts["typescript-scanner<br/>(eslint, npm-audit,<br/>semgrep)"]
    stat --> go["go-scanner<br/>(gosec, govulncheck,<br/>staticcheck)"]
    stat --> jv["java-scanner<br/>(semgrep,<br/>compromised-pkgs)"]
    stat --> php["php-scanner<br/>(semgrep, progpilot,<br/>compromised-pkgs)"]
    stat --> iac["iac-scanner<br/>(checkov, trivy)"]

    stat --> taint["4 — taint_tracer<br/>BFS over<br/>dataflow_edges"]
    taint --> scout["5 — pattern_scout<br/>citation-gated<br/>LLM reasoning"]
    scout -. uncertain claims .-> hrepl["hypothesis_repl<br/>(sub-context)"]
    scout --> chain["6 — chain_builder<br/>kill-chain<br/>clustering (LLM)"]
    chain --> poc["7 — poc_forge<br/>LLM-synthesized<br/>reproducers"]

    poc --> sb_py["python-sandbox"]
    poc --> sb_rs["rust-sandbox"]
    poc --> sb_ts["typescript-sandbox"]
    poc --> sb_go["go-sandbox"]
    poc --> sb_php["php-sandbox"]
    poc --> sb_java["java-sandbox"]

    poc --> adv["8 — devils_advocate<br/>inverted-prompt rebuttal<br/>(LLM, witness-gated,<br/>optional non-mirroring model)"]
    adv --> refl["9 — reflector<br/>knowledge_triples<br/>(LLM)"]

    refl --> report["codered report"]
    report --> sarif["findings.sarif"]
    report --> md["report.md"]
    report --> seed["engagement-seed.json<br/>(Ed25519-signed,<br/>Cedar-filtered)"]

    cli -. every action .-> journal
    repo --> carto
```

## Trust substrate

Orthogonal to the pipeline, these guarantees hold at every stage:

- **Cedar policy gates** at every `store_finding`, `advocate_finding`, `mark_poc_status`, `write_knowledge_triple`, `emit_to_seed`. Policies live in [`policies/`](https://github.com/ThirdKeyAI/symbi-codered/tree/main/policies).
- **Hash-chained audit journal** (`.symbiont/audit/audit.jsonl`) — every tool invocation and Cedar decision is recorded; `audit::verify_chain` proves no tampering.
- **Per-engagement Ed25519 keypair** (`.symbiont/keys/<eng>.{priv,pub}`) — the specifier signs the threat model; the reporter signs the engagement-seed.
- **Witness/lawyer rule** (`policies/citation.cedar`) — no finding can be stored without a `Citation::{Analyzer,Code,Hypothesis}`; structurally enforced via attr-bearing Cedar entities.
- **Read-only devil's advocate** (`policies/tool-authorization.cedar`) — a Cedar `forbid` rule prevents `devils_advocate` from ever calling `store_finding`.
- **Witnessed rebuttal** (`policies/advocate.cedar`) — symmetric with citation.cedar: a rebuttal can only *suppress* a finding if it cites a structural witness (envelope / sanitizer / closed-set / constant-caller).
- **Network-isolated sandboxes** for poc_forge — `network_mode: none`, read-only `/repo`, time-boxed per script.

See [Governance & Trust](governance.md) for the policy details and [Pipeline Stages](pipeline-stages.md) for what each stage produces.
