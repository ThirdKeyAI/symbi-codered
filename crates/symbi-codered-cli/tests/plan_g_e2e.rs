//! Plan G end-to-end: carto → specifier → hunt → report → assert SARIF + MD + signed seed.
//!
//! Requires:
//!   - python-scanner sidecar running (`docker compose up -d python-scanner`)
//!   - python-sandbox sidecar running (`docker compose up -d python-sandbox`)
//!   - ANTHROPIC_API_KEY set
//!
//! Run with: cargo test -j2 -p symbi-codered-cli --test plan_g_e2e -- --ignored

use std::process::Command;
use tempfile::TempDir;

#[test]
#[ignore]
fn plan_g_produces_sarif_md_seed() {
    let work = TempDir::new().unwrap();
    let db = work.path().join("codered.db");
    let lance = work.path().join("lance");
    let journal = work.path().join("audit.jsonl");
    let evidence = work.path().join("evidence");
    let reports = work.path().join("reports");
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

    // 1. carto
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

    // 2. specifier
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

    // 3. hunt (current_dir → fixture so pattern_scout's PathBuf::from(".") + signing keys resolve)
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
        "hunt: stderr={}\nstdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    // 4. report (NEW — Plan G)
    // Run from fixture so .symbiont/keys/<eng>.priv resolves (specifier wrote it there)
    let out = Command::new(bin)
        .current_dir(&fixture)
        .args([
            "report",
            "--engagement",
            &engagement,
            "--db",
            db.to_str().unwrap(),
            "--journal",
            journal.to_str().unwrap(),
            "--policies",
            policies.to_str().unwrap(),
            "--output-dir",
            reports.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "report: stderr={}\nstdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    // Assertions on output files
    let outdir = reports.join(&engagement);
    let sarif_path = outdir.join("findings.sarif");
    let md_path = outdir.join("report.md");
    let seed_path = outdir.join("engagement-seed.json");
    assert!(sarif_path.exists(), "missing {}", sarif_path.display());
    assert!(md_path.exists(), "missing {}", md_path.display());
    assert!(seed_path.exists(), "missing {}", seed_path.display());

    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_eq!(sarif["version"].as_str().unwrap(), "2.1.0");

    let md = std::fs::read_to_string(&md_path).unwrap();
    assert!(
        md.contains("# symbi-codered Engagement Report"),
        "report.md missing header; got: {md}"
    );

    let seed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&seed_path).unwrap()).unwrap();
    let sig = seed["signature"].as_str().expect("seed.signature missing");
    assert_eq!(
        sig.len(),
        128,
        "signature should be 64-byte Ed25519 hex (128 chars), got {}: {sig:?}",
        sig.len()
    );
    assert!(
        seed["findings"].is_array(),
        "seed.findings should be an array"
    );

    symbi_codered_core::audit::verify_chain(&journal).expect("journal verifies");
}
