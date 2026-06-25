//! End-to-end test for the cartographer phase.
//!
//! Builds the `codered` binary, runs `codered carto` against the
//! python-flask-vuln fixture, and asserts the SQLite DB has the expected
//! rows for languages, frameworks, package_managers, dependencies, routes,
//! and symbols.
//!
//! NOTE: this test invokes the LocalEmbedder, which downloads ~130 MB
//! on first run. It is `#[ignore]`d by default; run with:
//!   cargo test -j2 -p symbi-codered-cli --test carto_e2e -- --ignored

use rusqlite::Connection;
use std::process::Command;
use tempfile::TempDir;

fn fixture_path() -> std::path::PathBuf {
    let mut p = std::env::current_dir().unwrap();
    p.pop(); p.pop(); // crates/symbi-codered-cli -> repo root
    p.push("tests/fixtures/python-flask-vuln");
    p
}

#[test]
#[ignore]
fn carto_e2e_on_python_flask_fixture() {
    let work = TempDir::new().unwrap();
    let db = work.path().join("codered.db");
    let lance = work.path().join("lance");
    let journal = work.path().join("audit.jsonl");
    let fixture = fixture_path();
    assert!(fixture.exists(), "fixture missing at {}", fixture.display());

    let bin = env!("CARGO_BIN_EXE_codered");
    let out = Command::new(bin)
        .args([
            "carto",
            fixture.to_str().unwrap(),
            "--db",      db.to_str().unwrap(),
            "--lance",   lance.to_str().unwrap(),
            "--journal", journal.to_str().unwrap(),
        ])
        .output()
        .expect("running codered carto");
    assert!(out.status.success(),
        "carto failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));

    let conn = Connection::open(&db).expect("opening db");

    let langs: Vec<String> = conn.prepare(
        "SELECT json FROM repo_facts WHERE kind = 'language'"
    ).unwrap()
        .query_map([], |r| r.get::<_, String>(0)).unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let lang_blob = langs.join(",");
    assert!(lang_blob.contains("\"python\""), "languages missing python: {lang_blob}");
    assert!(lang_blob.contains("\"toml\""), "languages missing toml: {lang_blob}");

    let fws: Vec<String> = conn.prepare(
        "SELECT json FROM repo_facts WHERE kind = 'framework'"
    ).unwrap()
        .query_map([], |r| r.get::<_, String>(0)).unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert!(fws.iter().any(|j| j.contains("\"flask\"")),
        "frameworks missing flask: {fws:?}");

    let pms: Vec<String> = conn.prepare(
        "SELECT json FROM repo_facts WHERE kind = 'package_manager'"
    ).unwrap()
        .query_map([], |r| r.get::<_, String>(0)).unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert!(pms.iter().any(|j| j.contains("\"pip\"")),
        "package_managers missing pip: {pms:?}");

    let eps: Vec<String> = conn.prepare(
        "SELECT json FROM repo_facts WHERE kind = 'entrypoint'"
    ).unwrap()
        .query_map([], |r| r.get::<_, String>(0)).unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert!(eps.iter().any(|j| j.contains("app/__init__.py")),
        "entrypoints missing app/__init__.py: {eps:?}");

    let deps: Vec<String> = conn.prepare(
        "SELECT json FROM repo_facts WHERE kind = 'dependency'"
    ).unwrap()
        .query_map([], |r| r.get::<_, String>(0)).unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let dep_blob = deps.join("|");
    assert!(dep_blob.contains("\"name\":\"flask\""), "deps missing flask: {dep_blob}");
    assert!(dep_blob.contains("\"name\":\"sqlalchemy\""), "deps missing sqlalchemy: {dep_blob}");

    let n_routes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM routes", [], |r| r.get(0),
    ).unwrap();
    assert!(n_routes >= 4, "expected at least 4 routes, got {n_routes}");

    let symbol_names: Vec<String> = conn.prepare(
        "SELECT name FROM symbol_index"
    ).unwrap()
        .query_map([], |r| r.get::<_, String>(0)).unwrap()
        .filter_map(|r| r.ok())
        .collect();
    for expected in ["list_users", "create_user", "dashboard", "delete_user", "query"] {
        assert!(symbol_names.contains(&expected.to_string()),
            "symbol {expected} missing; got: {symbol_names:?}");
    }

    let n_entries = symbi_codered_core::audit::verify_chain(&journal)
        .expect("journal chain validates");
    assert!(n_entries >= 5, "expected at least 5 journal entries, got {n_entries}");

    let n_edges: i64 = conn.query_row(
        "SELECT COUNT(*) FROM dataflow_edges WHERE engagement_id = (SELECT id FROM engagements LIMIT 1)",
        [], |r| r.get(0),
    ).unwrap();
    assert!(n_edges >= 1, "expected at least 1 dataflow edge, got {n_edges}");
}
