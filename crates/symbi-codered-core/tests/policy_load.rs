use symbi_codered_core::policy::PolicyEngine;

#[test]
fn all_policy_files_in_repo_load() {
    // Test resolves `policies/` relative to the workspace root, which is
    // cargo's CWD when running tests.
    let engine = PolicyEngine::from_dir("../../policies").expect("policies/ must load");
    let _ = engine;
}
