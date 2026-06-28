//! poc_forge — sandboxed minimal reproducer attempts.
//!
//! Plan E Tasks 11 + 12. Same shape as [`crate::devils_advocate`] /
//! [`crate::chain_builder`]: an ORGA runner ([`run`]) backed by an
//! [`ActionExecutor`] ([`PocForgeExecutor`]).
//!
//! The LLM is given four tools:
//! - `query_findings`     — list eligible candidates for PoC attempts
//!   (CWE-89/78/22/94/79, `status = 'open'`, `poc_status IS NULL`)
//! - `read_context_range` — read raw source lines from the target repo
//!   (path-traversal guarded against the engagement's target_repo root)
//! - `run_reproducer`     — ship a Python script to the python-sandbox
//!   sidecar and capture stdout/stderr/verdict
//! - `mark_poc_status`    — write `reproduced` / `refuted` onto the
//!   finding's `poc_status` column and append an audit-journal entry
//!
//! Sandbox guarantees (enforced by the sidecar, not this crate):
//! read-only `/repo`, no network, 30s default timeout. The LLM is told
//! to print `REPRODUCED` on success and `REFUTED` on a credible negative.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use symbi_codered_core::orga::CoderedOrga;

use symbi_runtime::reasoning::conversation::ConversationMessage;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::LoopConfig;
use symbi_runtime::reasoning::Conversation;
use symbi_runtime::types::AgentId;

pub mod executor;
pub use executor::PocForgeExecutor;

/// Inputs handed to [`run`] from the CLI / orchestrator layer.
///
/// One sandbox container name per supported language. The executor's
/// `run_reproducer` dispatches to the right container by either the
/// LLM-supplied `language` arg or by inferring it from the finding's
/// file extension (`.py` / `.rs` / `.ts` / `.tsx` / `.js` / `.jsx` /
/// `.mjs` / `.cjs` / `.go` / `.php`).
pub struct PocInput {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
    pub target_repo: PathBuf,
    /// Default / python sandbox container name.
    pub sandbox_container: String,
    /// Rust sandbox container name (Plan F).
    pub rust_sandbox_container: String,
    /// TypeScript / JavaScript sandbox container name (Plan F).
    pub typescript_sandbox_container: String,
    /// Go sandbox container name (Plan F).
    pub go_sandbox_container: String,
    /// PHP sandbox container name.
    pub php_sandbox_container: String,
}

/// Counters reported back after the loop terminates.
pub struct PocSummary {
    /// Number of `mark_poc_status` calls with status = "reproduced".
    pub reproduced: usize,
    /// Number of `mark_poc_status` calls with status = "refuted".
    pub refuted: usize,
    /// Number of `mark_poc_status` calls with status = "inconclusive" — the
    /// reproducer could not run, so the finding is neither proven nor disproven.
    pub inconclusive: usize,
    /// Number of `run_reproducer` invocations (irrespective of verdict).
    pub scripts_run: usize,
    /// Number of `ProposedAction::ToolCall` actions seen by the executor.
    pub tool_calls: usize,
    /// LLM input tokens consumed across the entire loop.
    pub tokens_in: u32,
    /// LLM output tokens generated across the entire loop.
    pub tokens_out: u32,
    /// Number of ORGA iterations executed before termination.
    pub iterations: u32,
}

/// Run poc_forge end-to-end for a single engagement.
///
/// Builds the [`PocForgeExecutor`], wraps it in a [`CoderedOrga`],
/// seeds the conversation with the reproducer system prompt, and runs
/// the ORGA loop. Returns the per-run counters from the executor
/// regardless of how the loop terminated; the caller inspects the
/// journal / logs for the `LoopResult` details.
///
/// Returns `Err` if [`CoderedOrga::new`] cannot find an LLM API key.
pub async fn run(input: PocInput) -> Result<PocSummary> {
    let executor = Arc::new(PocForgeExecutor::new(
        input.engagement_id,
        input.db_path,
        input.journal_path,
        input.target_repo,
        input.sandbox_container,
        input.rust_sandbox_container,
        input.typescript_sandbox_container,
        input.go_sandbox_container,
        input.php_sandbox_container,
    ));
    let executor_for_orga: Arc<dyn ActionExecutor> = executor.clone();
    let orga = CoderedOrga::new(executor_for_orga)
        .context("building CoderedOrga for poc_forge")?;

    let conversation = build_conversation(input.engagement_id);
    let config = LoopConfig {
        tool_definitions: crate::tool_defs::poc_forge(),
        max_iterations: 60,
        max_total_tokens: 400_000,
        timeout: std::time::Duration::from_secs(900),
        ..LoopConfig::default()
    };
    let agent_id = AgentId::new();

    let result = orga.run(agent_id, conversation, config).await;
    let mut s = executor.summary();
    s.tokens_in = result.total_usage.prompt_tokens;
    s.tokens_out = result.total_usage.completion_tokens;
    s.iterations = result.iterations;
    Ok(s)
}

/// Seed conversation: a system prompt that enumerates the four tools
/// and the sandbox contract, plus an opening user turn pointing the
/// agent at the current engagement.
fn build_conversation(engagement_id: Uuid) -> Conversation {
    let system = format!(
        "You are poc_forge. Your job is to DEMONSTRATE actual exploitation \
         of each candidate finding, not merely confirm the vulnerable pattern \
         exists. A finding is REPRODUCED only when your script triggers the \
         vulnerable behavior end-to-end and prints REPRODUCED. If you cannot \
         construct an exploit (e.g., the sink isn't reachable, the input is \
         sanitized, the surrounding code mitigates the issue), mark it \
         REFUTED.\n\n\
         WHAT COUNTS AS REPRODUCED (per CWE class):\n\
         - CWE-89 (SQL injection): construct a payload that changes the SQL \
           semantics (e.g., extracts a row via UNION, bypasses an auth WHERE), \
           run the actual code path or instantiate the actual sink (e.g., \
           sqlite3 with the same query template), observe the difference.\n\
         - CWE-78 (OS command injection): construct an input that runs a \
           NEW command via the sink (e.g., subprocess.run with shell=True \
           and `; echo PWNED`), and verify the side-channel.\n\
         - CWE-22 (path traversal): construct an input containing `../` \
           sequences and confirm the resolved path escapes the intended \
           root (verify via os.path.realpath or os.path.commonpath).\n\
         - CWE-94 (code injection): construct an input that the eval/exec \
           sink turns into executable code (e.g., `__import__('os').system`), \
           confirm the executed branch ran.\n\
         - CWE-79 (XSS): construct an input containing `<script>` and pass it \
           through the actual rendering path; verify the output contains the \
           unescaped tag. SIMPLY checking 'template literal interpolation \
           exists' is NOT reproduction — you must demonstrate the unescaped \
           render.\n\n\
         REPRODUCED FAILURE MODES (do NOT mark reproduced):\n\
         - Script only prints the vulnerable line / file content.\n\
         - Script only describes the vulnerability in prose.\n\
         - Script imports the module but never reaches the sink with attacker-\n  \
           controlled input.\n\
         - Sandbox times out / errors out before the sink is ever tested.\n\
         STATUS CHOICE (critical — do not conflate a non-test with a disproof):\n\
         - reproduced: the script RAN and the exploit fired (sentinel printed).\n\
         - refuted: the script RAN TO COMPLETION and the exploit did NOT fire — \
           a genuine disproof. Only when run_reproducer actually executed the \
           exploit path (clean exit, no env error).\n\
         - inconclusive: the reproducer COULD NOT run — compile/sandbox error, \
           timeout, missing sandbox, or a non-zero exit before the sink was \
           tested. The exploit was NOT tested: neither proven nor disproven, the \
           finding stays in play for a human. run_reproducer returns a \
           `suggested_status` — use it. NEVER mark an environmental failure \
           `refuted` (the executor refuses it); that would drop a real finding \
           on a non-test.\n\n\
         Sandboxes (read-only /repo, no network, 30s timeout):\n\
         - python: Python 3.12 with Flask/SQLAlchemy/requests pre-installed.\n\
         - rust:   rustc 1.85 + cargo, pre-seeded Cargo.toml with \
           axum/tokio/sqlx/serde/reqwest.\n\
         - typescript: node 22 + tsx, pre-installed \
           express/axios/sqlite3/lodash. First line `// @lang js` selects \
           plain `node` instead of `tsx`.\n\
         - go: go 1.24 with lib/pq pre-fetched.\n\
         - php: PHP 8.3 CLI with PDO + pdo_sqlite (stand up an in-process \
           SQLite DB for SQLi/RCE repros; no network).\n\
         The `language` arg on run_reproducer routes the script to the right \
         sandbox. If omitted, language is inferred from the finding's file \
         extension. Always match the script's language to the finding's \
         source language.\n\n\
         TOOLS:\n\
         - query_findings(page=0, page_size=30) — paginated candidate list. \
           Iterate while has_more=true.\n\
         - read_context_range(file_path, line_start, line_end) — fetch source\n\
         - run_reproducer(script, timeout_seconds?, language?, finding_id?) — \
           ship to sandbox (language auto-inferred from finding_id if absent)\n\
         - mark_poc_status(finding_id, status) — status in reproduced|refuted|inconclusive|reproduced_by_citation. Pass run_reproducer's suggested_status; refuted needs a clean run that disproved the exploit, inconclusive for env/compile/timeout failures.\n\
         - emit_source_proof(finding_id, claim, citations[]) — TIER-B PoC: \
           prove a finding by citing source ranges instead of running an \
           exploit. Each citation gives {{file_path, line_start, line_end, \
           expected_substring, role}}; the executor verifies the substring \
           is still present at that range. Use for findings that cannot \
           fit a 30-second sandbox: authz bypass, missing-auth chains \
           (taint_chains tagged 'unguarded'), multi-service flows.\n\n\
         CANDIDATE PRIORITY: query_findings returns the chain-aware \
         pattern_scout findings (ids like `F-pattern-scout-*`) FIRST, ahead \
         of raw scanner hits (`F-bandit-*`, `F-semgrep-*`). Spend your budget \
         there first — they are deduplicated, reachability-reasoned, and \
         usually in production service code. In particular, do NOT exhaust \
         your iterations on near-duplicate scanner findings before attempting \
         every scout-sourced injection candidate (CWE-89/78/94) at least \
         once.\n\
         WORKFLOW: query_findings(page=0). For each candidate, choose ONE \
         strategy:\n\
         - TIER-A (sandbox exploit) — for CWE-78/89/22/94/79 where the \
           sink fits in a script. Synthesize the exploit, run it, mark \
           reproduced or refuted.\n\
         - TIER-B (source-citation proof) — for authz bypass / unguarded \
           taint chains / multi-service flows. Read the relevant files, \
           draft a structured claim, and emit_source_proof with at least \
           two citations (sink AND unguarded_handler OR safe_sibling). \
           The proof gets verified against current disk state.\n\
         If a Tier-A first script fails, iterate once or twice; if you \
         still can't trigger the sink AND the bug fits Tier-B, switch \
         strategies rather than marking refuted.\n\
         Engagement: {engagement_id}."
    );
    let user = format!(
        "Begin reproducing findings for engagement {engagement_id}."
    );

    let mut c = Conversation::new();
    c.push(ConversationMessage::system(system));
    c.push(ConversationMessage::user(user));
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check on the seed conversation: system + user turns, all
    /// four tools named in the system prompt, and the engagement id
    /// surfaces in both turns.
    #[test]
    fn build_conversation_seeds_system_and_user_turns() {
        let eid = Uuid::new_v4();
        let conv = build_conversation(eid);
        let messages = conv.messages();
        assert_eq!(messages.len(), 2);

        let sys = &messages[0];
        assert!(matches!(
            sys.role,
            symbi_runtime::reasoning::conversation::MessageRole::System
        ));
        for tool in [
            "query_findings",
            "read_context_range",
            "run_reproducer",
            "mark_poc_status",
        ] {
            assert!(
                sys.content.contains(tool),
                "system prompt missing tool: {tool}"
            );
        }
        for verdict in ["reproduced", "refuted"] {
            assert!(
                sys.content.contains(verdict),
                "system prompt missing verdict: {verdict}"
            );
        }
        assert!(sys.content.contains(&eid.to_string()));

        let user = &messages[1];
        assert!(matches!(
            user.role,
            symbi_runtime::reasoning::conversation::MessageRole::User
        ));
        assert!(user.content.contains(&eid.to_string()));
    }

    /// The runner errors out cleanly when no LLM API key is set —
    /// `CoderedOrga::new` is the source of that error, and we just
    /// propagate. We don't need to mutate env here; this test only
    /// proves the `PocInput` shape is usable.
    #[test]
    fn poc_input_constructs() {
        let _input = PocInput {
            engagement_id: Uuid::new_v4(),
            db_path: PathBuf::from("/tmp/codered.db"),
            journal_path: PathBuf::from("/tmp/codered.journal"),
            target_repo: PathBuf::from("/tmp/repo"),
            sandbox_container: "python-sandbox".to_string(),
            rust_sandbox_container: "rust-sandbox".to_string(),
            typescript_sandbox_container: "typescript-sandbox".to_string(),
            go_sandbox_container: "go-sandbox".to_string(),
            php_sandbox_container: "php-sandbox".to_string(),
        };
    }
}
