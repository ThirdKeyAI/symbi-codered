//! Plan D end-to-end: carto → specifier → hunt → assert chain artifacts.
//!
//! Requires:
//!   - python-scanner sidecar running (`docker compose up -d python-scanner`)
//!   - ANTHROPIC_API_KEY set
//!
//! Run with: cargo test -j2 -p symbi-codered-cli --test chain_e2e -- --ignored

use rusqlite::Connection;
use std::process::Command;
use tempfile::TempDir;

fn fixture_path() -> std::path::PathBuf {
    let mut p = std::env::current_dir().unwrap();
    p.pop();
    p.pop();
    p.push("tests/fixtures/python-flask-vuln");
    p
}

#[test]
#[ignore]
fn chain_e2e_produces_taint_pattern_chain_artifacts() {
    let work = TempDir::new().unwrap();
    let db = work.path().join("codered.db");
    let lance = work.path().join("lance");
    let journal = work.path().join("audit.jsonl");
    let evidence = work.path().join("evidence");
    let fixture = fixture_path();
    assert!(fixture.exists(), "fixture missing at {}", fixture.display());

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
        "specifier: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // pattern_scout uses `target_repo = PathBuf::from(".")`, so the
    // executor's read_context_range resolves files relative to cwd. Run
    // `hunt` from the fixture root so those host-side reads succeed.
    //
    // Because cwd changes, the default `--policies policies` no longer
    // resolves to the codered repo's policies/ dir; pass it explicitly
    // as an absolute path derived from the test's starting cwd
    // (crates/symbi-codered-cli) walked up to the repo root.
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

    let n_dataflow: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM dataflow_edges WHERE engagement_id = ?1",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(n_dataflow >= 1, "dataflow_edges: {n_dataflow}");

    let n_taint: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM taint_chains WHERE engagement_id = ?1",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(n_taint >= 1, "taint_chains: {n_taint}");

    let n_scout: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND tool_origin = 'pattern_scout'",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(n_scout >= 1, "pattern_scout findings: {n_scout}");

    let n_with_code: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM finding_citations c \
             JOIN findings f ON f.id = c.finding_id \
             WHERE f.engagement_id = ?1 AND f.tool_origin = 'pattern_scout' \
               AND c.citation_type = 'code'",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        n_with_code >= 1,
        "pattern_scout findings with Citation::Code: {n_with_code}"
    );

    let n_chains: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attack_chains WHERE engagement_id = ?1",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(n_chains >= 1, "attack_chains: {n_chains}");

    symbi_codered_core::audit::verify_chain(&journal).expect("journal chain validates");
}
