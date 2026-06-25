//! Plan E end-to-end: carto → specifier → hunt → assert poc + advocate artifacts.
//!
//! Requires:
//!   - python-scanner sidecar running (`docker compose up -d python-scanner`)
//!   - python-sandbox sidecar running (`docker compose up -d python-sandbox`)
//!   - ANTHROPIC_API_KEY set
//!
//! Run with: cargo test -j2 -p symbi-codered-cli --test plan_e_e2e -- --ignored

use rusqlite::Connection;
use std::process::Command;
use tempfile::TempDir;

#[test]
#[ignore]
fn plan_e_produces_poc_and_advocate_artifacts() {
    let work = TempDir::new().unwrap();
    let db = work.path().join("codered.db");
    let lance = work.path().join("lance");
    let journal = work.path().join("audit.jsonl");
    let evidence = work.path().join("evidence");
    let fixture = {
        let mut p = std::env::current_dir().unwrap();
        p.pop();
        p.pop();
        p.push("tests/fixtures/python-flask-vuln");
        p
    };
    let policies = {
        let mut p = std::env::current_dir().unwrap();
        p.pop();
        p.pop();
        p.push("policies");
        p
    };
    assert!(fixture.exists(), "fixture missing");
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
        "carto: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let engagement = stdout
        .lines()
        .find(|l| l.starts_with("engagement_id:"))
        .and_then(|l| l.split_whitespace().last())
        .unwrap()
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

    let out = Command::new(bin)
        .current_dir(&fixture)
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
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "hunt: stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    let conn = Connection::open(&db).unwrap();
    let n_reproduced: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND poc_status = 'reproduced'",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        n_reproduced >= 1,
        "expected >=1 reproduced finding, got {n_reproduced}"
    );

    let n_confirmed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND advocate_verdict = 'confirmed'",
            rusqlite::params![engagement],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        n_confirmed >= 1,
        "expected >=1 confirmed finding, got {n_confirmed}"
    );

    let n_advocate_findings: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE tool_origin = 'devils_advocate'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n_advocate_findings, 0,
        "devils_advocate must NOT be able to create findings"
    );

    symbi_codered_core::audit::verify_chain(&journal).expect("journal verifies");
}
