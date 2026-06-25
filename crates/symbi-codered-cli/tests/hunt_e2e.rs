//! End-to-end: cartographer → specifier → static_hunter on python-flask-vuln.
//!
//! Requires:
//!   1. The python-scanner sidecar to be running and reachable as
//!      `symbi-codered-scanner-python`. Start with:
//!      `docker compose up -d python-scanner`
//!   2. The fixture repo bind-mounted at /repo inside the sidecar.
//!
//! Run with: cargo test -j2 -p symbi-codered-cli --test hunt_e2e -- --ignored

use rusqlite::Connection;
use std::process::Command;
use tempfile::TempDir;

fn fixture_path() -> std::path::PathBuf {
    let mut p = std::env::current_dir().unwrap();
    p.pop(); p.pop();
    p.push("tests/fixtures/python-flask-vuln");
    p
}

#[test]
#[ignore]
fn carto_specifier_hunt_produces_sqli_finding_with_citation() {
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
            "carto", fixture.to_str().unwrap(),
            "--db",      db.to_str().unwrap(),
            "--lance",   lance.to_str().unwrap(),
            "--journal", journal.to_str().unwrap(),
        ])
        .output().expect("carto");
    assert!(out.status.success(), "carto failed: {}",
        String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let engagement_id = stdout
        .lines().find(|l| l.starts_with("engagement_id:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("engagement_id printed by carto")
        .to_string();

    let out = Command::new(bin)
        .args([
            "specifier",
            "--engagement", &engagement_id,
            "--target",     fixture.to_str().unwrap(),
            "--db",         db.to_str().unwrap(),
            "--journal",    journal.to_str().unwrap(),
        ])
        .output().expect("specifier");
    assert!(out.status.success(), "specifier failed: {}",
        String::from_utf8_lossy(&out.stderr));

    let out = Command::new(bin)
        .args([
            "hunt",
            "--engagement",   &engagement_id,
            "--db",           db.to_str().unwrap(),
            "--journal",      journal.to_str().unwrap(),
            "--evidence-dir", evidence.to_str().unwrap(),
        ])
        .output().expect("hunt");
    assert!(out.status.success(),
        "hunt failed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));

    let conn = Connection::open(&db).unwrap();
    let n_findings: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1",
        rusqlite::params![engagement_id], |r| r.get(0),
    ).unwrap();
    assert!(n_findings >= 1, "expected at least 1 finding, got {n_findings}");

    let n_without_specifier: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND specifier_hash IS NULL",
        rusqlite::params![engagement_id], |r| r.get(0),
    ).unwrap();
    assert_eq!(n_without_specifier, 0,
        "every finding must have a specifier_hash");

    let n_findings_without_cite: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings f \
         WHERE f.engagement_id = ?1 \
         AND NOT EXISTS (SELECT 1 FROM finding_citations c WHERE c.finding_id = f.id)",
        rusqlite::params![engagement_id], |r| r.get(0),
    ).unwrap();
    assert_eq!(n_findings_without_cite, 0,
        "every finding must have a citation row");

    let n_sqli: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND cwe = 'CWE-89'",
        rusqlite::params![engagement_id], |r| r.get(0),
    ).unwrap();
    assert!(n_sqli >= 1, "expected at least 1 CWE-89 finding, got {n_sqli}");

    let n_entries = symbi_codered_core::audit::verify_chain(&journal)
        .expect("journal chain validates");
    assert!(n_entries >= 7, "expected at least 7 journal entries, got {n_entries}");
}
