//! Plan F end-to-end: carto → specifier → hunt against tests/fixtures/java-servlet-vuln.
//!
//! Asserts the Java multilang pipeline (semgrep scanner + tree-sitter-java
//! dataflow + taint_tracer) produces:
//!   - >=1 finding with tool_origin = semgrep
//!   - >=1 dataflow_edge row touching a .java file
//!   - >=1 taint_chain row linking a getParameter source to an executeQuery sink
//!   - audit journal verifies
//!
//! Requires:
//!   - java-scanner sidecar running (`docker compose up -d java-scanner`)
//!   - ANTHROPIC_API_KEY set
//!
//! Run with: cargo test -j2 -p symbi-codered-cli --test plan_f_java_e2e -- --ignored

use rusqlite::Connection;
use std::process::Command;
use tempfile::TempDir;

fn fixture_path() -> std::path::PathBuf {
    let mut p = std::env::current_dir().unwrap();
    p.pop();
    p.pop();
    p.push("tests/fixtures/java-servlet-vuln");
    p
}

#[test]
#[ignore]
fn plan_f_java_servlet_vuln_produces_semgrep_findings_dataflow_and_taint_chain() {
    let work = TempDir::new().unwrap();
    let db = work.path().join("codered.db");
    let lance = work.path().join("lance");
    let journal = work.path().join("audit.jsonl");
    let evidence = work.path().join("evidence");
    let fixture = fixture_path();
    assert!(fixture.exists(), "fixture missing at {}", fixture.display());

    let policies = {
        let mut p = std::env::current_dir().unwrap();
        p.pop();
        p.pop();
        p.push("policies");
        p
    };
    assert!(
        policies.exists(),
        "policies dir missing at {}",
        policies.display()
    );

    let bin = env!("CARGO_BIN_EXE_codered");

    let out = Command::new(bin)
        .args([
            "carto",
            fixture.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--lance",
            lance.to_str().unwrap(),
            "--journal",
            journal.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "carto failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let engagement = stdout
        .lines()
        .find(|l| l.starts_with("engagement_id:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("engagement_id printed by carto")
        .to_string();

    let out = Command::new(bin)
        .args([
            "specifier",
            "--engagement",
            &engagement,
            "--target",
            fixture.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--journal",
            journal.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "specifier failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(bin)
        .args([
            "hunt",
            "--engagement",
            &engagement,
            "--db",
            db.to_str().unwrap(),
            "--journal",
            journal.to_str().unwrap(),
            "--evidence-dir",
            evidence.to_str().unwrap(),
            "--policies",
            policies.to_str().unwrap(),
        ])
        .current_dir(&fixture)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "hunt failed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let conn = Connection::open(&db).unwrap();

    let n_scanner: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM findings \
             WHERE engagement_id = ?1 \
               AND tool_origin = 'semgrep'",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        n_scanner >= 1,
        "expected >=1 finding from semgrep, got {n_scanner}"
    );

    let n_java_dataflow: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM dataflow_edges \
             WHERE engagement_id = ?1 AND file_path LIKE '%.java'",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        n_java_dataflow >= 1,
        "expected >=1 dataflow_edge row for .java files, got {n_java_dataflow}"
    );

    let n_taint_chain: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM taint_chains \
             WHERE engagement_id = ?1 \
               AND chain_json LIKE '%getParameter%' \
               AND chain_json LIKE '%executeQuery%'",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        n_taint_chain >= 1,
        "expected >=1 taint_chain linking getParameter -> executeQuery, got {n_taint_chain}"
    );

    symbi_codered_core::audit::verify_chain(&journal).expect("journal chain validates");
}
