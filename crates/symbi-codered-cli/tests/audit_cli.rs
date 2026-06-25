use std::process::Command;
use tempfile::TempDir;

#[test]
fn audit_creates_engagement_row_and_journal_entry() {
    let work = TempDir::new().unwrap();
    let target = work.path().join("repo");
    std::fs::create_dir(&target).unwrap();

    let db = work.path().join("codered.db");
    let journal = work.path().join("audit.jsonl");

    let bin = env!("CARGO_BIN_EXE_codered");
    let out = Command::new(bin)
        .args([
            "audit",
            target.to_str().unwrap(),
            "--db", db.to_str().unwrap(),
            "--journal", journal.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(),
        "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let journal_text = std::fs::read_to_string(&journal).unwrap();
    assert!(journal_text.contains("create_engagement"),
        "journal missing entry: {journal_text}");
    assert!(db.exists(), "db file not created");
}
