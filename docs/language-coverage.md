# Language Coverage

| Language | Parsing | Dataflow + taint | SAST scanners | Sandboxed reproducer |
|----------|:-------:|:----------------:|:-------------:|:--------------------:|
| Python | ✅ | ✅ | semgrep, bandit, pip-audit, ruff | ✅ |
| Rust | ✅ | ✅ | cargo-audit, clippy, semgrep | ✅ |
| TypeScript / JavaScript | ✅ | ✅ | eslint, npm-audit, semgrep | ✅ |
| Go | ✅ | ✅ | gosec, govulncheck, staticcheck | ✅ |
| Java | ✅ | ✅ | semgrep, compromised-packages | ✅ |
| PHP | ✅ | ✅ | semgrep, progpilot, compromised-packages | ✅ |
| IaC (Terraform / K8s / Dockerfile / GH-Actions) | n/a | n/a | checkov, trivy | n/a |

Java and PHP each ship the full static path (tree-sitter parsing, dataflow extraction, taint, symbols, semgrep SAST; PHP also adds progpilot and compromised-packages) and a sandbox reproducer: PHP on PHP 8.3 CLI + pdo_sqlite, Java on JDK 21 single-file source mode (`java Repro.java`, no compile step) with sqlite-jdbc on the classpath for in-process SQLite repros.

The IaC sidecar (checkov + trivy) is wired into the cartographer's language detection and the static_hunter JOBS table (container `symbi-codered-scanner-iac`); its Dockerfile lives in `scanners/iac/` and the `iac-scanner` service ships in `docker-compose.yml` — bring it up alongside the others to exercise it.

## Adding a new scanner

1. Drop a Dockerfile + `scanner-runner.py` in `scanners/<name>/`
2. Add a service to `docker-compose.yml`
3. Add an output parser at `crates/symbi-codered-tools/src/scanner_parsers/<name>.rs`
4. Add a ToolClad manifest at `tools/<name>.clad.toml` + bump `toolclad_load` count
5. Add a `ScannerJob` entry in `crates/symbi-codered-tools/src/static_hunter.rs`

## Adding a new language

Same as adding a scanner, plus:

6. Add the language to `SupportedLanguage` in `crates/symbi-codered-tools/src/tree_sitter_loader.rs`
7. (optional) Extend `dataflow.rs` with `extract_<lang>_edges`
8. Add per-language source/sink defaults to `crates/symbi-codered-tools/src/specifier.rs`
9. Add a per-language sandbox in `scanners/<lang>-sandbox/` and wire poc_forge dispatch
