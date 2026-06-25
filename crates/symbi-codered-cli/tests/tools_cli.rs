use std::process::Command;

fn codered() -> Command {
    let bin = env!("CARGO_BIN_EXE_codered");
    Command::new(bin)
}

#[test]
fn tools_list_succeeds_on_workspace_tools_dir() {
    let out = codered()
        .current_dir("../..")
        .args(["tools", "list"])
        .output()
        .unwrap();
    assert!(out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in ["repo_overview", "dependency_graph", "find_symbol", "read_symbol",
                 "read_context", "route_map", "grep_semantic", "recall_journal"] {
        assert!(stdout.contains(name), "expected {name} listed; got:\n{stdout}");
    }
}

#[test]
fn tools_validate_succeeds_on_workspace_tools_dir() {
    let out = codered()
        .current_dir("../..")
        .args(["tools", "validate"])
        .output()
        .unwrap();
    assert!(out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));
}
