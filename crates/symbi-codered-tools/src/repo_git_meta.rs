//! Capture the target repo's git provenance (remote URL + HEAD commit) at
//! cartographer time and persist it as `repo_facts` rows so the downstream
//! viewer can deep-link finding locations to source on github/gitlab/gitea.
//!
//! Both calls are best-effort: non-git targets (or repos without an `origin`
//! remote) simply yield `None` and no rows are written. The stored json shape
//! mirrors the other `repo_facts` rows (`{"name": ...}` / `{"path": ...}`):
//! here we use `{"value": "<remote-or-sha>"}` and read it back the same way
//! in the web crate's `query::git_meta`.

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;
use symbi_codered_core::db;
use uuid::Uuid;

/// `repo_facts.kind` for the captured `git remote get-url origin`.
pub const KIND_GIT_REMOTE: &str = "git_remote";
/// `repo_facts.kind` for the captured `git rev-parse HEAD`.
pub const KIND_GIT_COMMIT: &str = "git_commit";

/// Best-effort capture of `(origin remote url, HEAD commit sha)` from a target
/// directory. Tolerates non-git targets: any failure (missing git, not a repo,
/// no `origin`, detached/empty) yields `None` for that component.
pub fn git_capture(target: &Path) -> (Option<String>, Option<String>) {
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(target)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };
    (
        run(&["remote", "get-url", "origin"]),
        run(&["rev-parse", "HEAD"]),
    )
}

/// Persist captured git provenance as `repo_facts` rows. Only writes a row when
/// the corresponding value is `Some`. The json shape is `{"value": "..."}`.
pub fn store_git_meta(
    conn: &Connection,
    engagement_id: Uuid,
    remote: Option<&str>,
    commit: Option<&str>,
) -> Result<()> {
    if let Some(remote) = remote {
        db::insert_repo_fact(
            conn,
            engagement_id,
            KIND_GIT_REMOTE,
            &serde_json::json!({ "value": remote }).to_string(),
        )?;
    }
    if let Some(commit) = commit {
        db::insert_repo_fact(
            conn,
            engagement_id,
            KIND_GIT_COMMIT,
            &serde_json::json!({ "value": commit }).to_string(),
        )?;
    }
    Ok(())
}

/// Convenience: capture from `target` and persist in one call (used by carto).
pub fn capture_and_store(conn: &Connection, engagement_id: Uuid, target: &Path) -> Result<()> {
    let (remote, commit) = git_capture(target);
    store_git_meta(conn, engagement_id, remote.as_deref(), commit.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbi_codered_core::db as db_;
    use symbi_evidence_schema::Engagement;
    use tempfile::TempDir;

    fn fresh_db() -> (TempDir, Connection, Uuid) {
        let dir = TempDir::new().unwrap();
        let conn = db_::init_db(dir.path().join("test.db").to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        let id = e.id;
        db_::insert_engagement(&conn, &e).unwrap();
        (dir, conn, id)
    }

    fn git(repo: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("running git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        git(p, &["init", "-q"]);
        git(p, &["config", "user.email", "t@example.com"]);
        git(p, &["config", "user.name", "t"]);
        git(p, &["config", "commit.gpgsign", "false"]);
        git(p, &["remote", "add", "origin", "https://github.com/o/r.git"]);
        std::fs::write(p.join("README.md"), "hi").unwrap();
        git(p, &["add", "."]);
        git(p, &["commit", "-q", "-m", "init"]);
        dir
    }

    #[test]
    fn git_capture_reads_remote_and_head() {
        let repo = init_repo();
        let (remote, commit) = git_capture(repo.path());
        assert_eq!(remote.as_deref(), Some("https://github.com/o/r.git"));
        let sha = commit.expect("HEAD commit present");
        assert_eq!(sha.len(), 40, "expected full sha, got {sha:?}");
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn git_capture_tolerates_non_git_target() {
        let dir = TempDir::new().unwrap();
        let (remote, commit) = git_capture(dir.path());
        assert_eq!(remote, None);
        assert_eq!(commit, None);
    }

    #[test]
    fn carto_stores_both_repo_facts_rows() {
        let repo = init_repo();
        let (_dir, conn, id) = fresh_db();

        capture_and_store(&conn, id, repo.path()).unwrap();

        let remotes = db_::list_repo_facts(&conn, id, KIND_GIT_REMOTE).unwrap();
        let commits = db_::list_repo_facts(&conn, id, KIND_GIT_COMMIT).unwrap();
        assert_eq!(remotes.len(), 1, "expected one git_remote row: {remotes:?}");
        assert_eq!(commits.len(), 1, "expected one git_commit row: {commits:?}");
        assert!(
            remotes[0].contains("https://github.com/o/r.git"),
            "remote json: {}",
            remotes[0]
        );
        // Stored json shape is {"value": "..."}.
        let v: serde_json::Value = serde_json::from_str(&remotes[0]).unwrap();
        assert_eq!(v["value"], "https://github.com/o/r.git");
    }

    #[test]
    fn store_git_meta_skips_none_values() {
        let (_dir, conn, id) = fresh_db();
        store_git_meta(&conn, id, None, Some("deadbeef")).unwrap();
        assert!(db_::list_repo_facts(&conn, id, KIND_GIT_REMOTE)
            .unwrap()
            .is_empty());
        let commits = db_::list_repo_facts(&conn, id, KIND_GIT_COMMIT).unwrap();
        assert_eq!(commits.len(), 1);
        assert!(commits[0].contains("deadbeef"));
    }
}
