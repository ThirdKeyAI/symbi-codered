use symbi_codered_core::toolclad;

#[test]
fn all_native_manifests_parse() {
    let manifests = toolclad::parse_dir("../../tools").expect("tools/ must load");
    assert_eq!(manifests.len(), 37, "expected 37 manifests, got {}", manifests.len());

    let names: Vec<_> = manifests.iter().map(|(_p, m)| m.tool.name.as_str()).collect();
    let expected = [
        "repo_overview", "dependency_graph", "find_symbol", "read_symbol",
        "read_context", "route_map", "grep_semantic", "recall_journal",
        "pin_threat_model",
        "semgrep", "bandit", "pip_audit", "ruff_security",
        "taint_trace",
        // Plan D Task 15: pattern_scout read-only query tools
        "query_threat_model", "query_findings", "query_taint_chains",
        "read_context_range",
        // Plan D Task 18: hypothesis_repl sub-context primitive
        "hypothesis_repl",
        // Plan D Task 22: chain_builder write tool
        "build_attack_chain",
        // Plan E Task 3: confirmation bias write tools
        "advocate_finding", "mark_poc_status",
        // Plan E Task 9: poc_forge sandbox bridge
        "run_reproducer",
        // Plan F Group 1: Rust scanner manifests
        "cargo_audit", "clippy_security", "semgrep_rust",
        // Plan F Group 2: TypeScript scanner manifests
        "eslint_security", "npm_audit", "semgrep_ts",
        // Plan F Group 3: Go scanner manifests
        "gosec", "govulncheck", "staticcheck",
        // Plan G Group 1: reflector write tool
        "write_knowledge_triple",
        // IaC + supply-chain scanner manifests
        "checkov", "tfsec", "trivy", "compromised_packages",
    ];
    for e in expected {
        assert!(names.contains(&e), "missing manifest {e}; got {names:?}");
    }
}
