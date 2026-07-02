//! pattern_scout — the LLM-reasoning agent.
//!
//! Runs through Symbiont's `ReasoningLoopRunner` (the ORGA loop), wrapped by
//! [`CoderedOrga`]. Reads cartographer facts, static_hunter findings, and
//! taint chains for a single engagement, then composes new `Finding` rows
//! whose every claim cites a witness (`Citation::Analyzer`,
//! `Citation::Code`, or `Citation::Hypothesis`).
//!
//! ## Status
//!
//! Plan D Task 16 implements the runner scaffold and a **stub** executor
//! (see [`executor::PatternScoutExecutor`]). Every tool call currently
//! returns an error observation. Task 17 wires the real dispatchers
//! against `crate::pattern_scout_tools` and adds the Cedar gate around
//! `store_finding`.
//!
//! ## System prompt
//!
//! The system prompt tells the agent its tool inventory and the
//! citation-grounding contract. Note: the tool list uses
//! `read_context_range` (the range-slicer added in Task 15) rather than
//! `read_context` — the latter name is already taken by the cartographer's
//! enclosing-function tool and would collide here.
//!
//! [`CoderedOrga`]: symbi_codered_core::orga::CoderedOrga

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use symbi_codered_core::policy::PolicyEngine;
use symbi_runtime::reasoning::conversation::ConversationMessage;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::LoopConfig;
use symbi_runtime::reasoning::Conversation;
use symbi_runtime::types::AgentId;

pub mod executor;
pub use executor::PatternScoutExecutor;

/// Inputs handed to [`run`] from the CLI / orchestrator layer.
pub struct ScoutInput {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
    pub target_repo: PathBuf,
    pub policy: Arc<PolicyEngine>,
}

/// Counters reported back after the loop terminates.
///
/// `denied_by_cedar` will remain `0` in the Task 16 stub — the Cedar gate
/// around `store_finding` lands in Task 17.
pub struct ScoutSummary {
    pub findings_inserted: usize,
    pub denied_by_cedar: usize,
    pub tool_calls: usize,
    pub tokens_in: u32,
    pub tokens_out: u32,
    pub iterations: u32,
}

/// Run pattern_scout end-to-end for a single engagement.
///
/// Builds the [`PatternScoutExecutor`], constructs a [`CoderedOrga`]
/// around it, seeds the conversation with the system prompt + initial
/// user instruction, and runs the ORGA loop. Returns the per-run
/// counters from the executor regardless of how the loop terminated;
/// the caller is expected to inspect logs / the journal for the
/// `LoopResult` details.
///
/// Returns `Err` if [`CoderedOrga::new`] cannot find an LLM API key in
/// the environment.
pub async fn run(input: ScoutInput) -> Result<ScoutSummary> {
    let executor = Arc::new(PatternScoutExecutor::new(
        input.engagement_id,
        input.db_path.clone(),
        input.journal_path.clone(),
        input.target_repo.clone(),
        input.policy.clone(),
    ));

    let executor_for_orga: Arc<dyn ActionExecutor> = executor.clone();

    let conversation = build_conversation(input.engagement_id);
    // Bumped budget for real-repo workloads + comparative-reading
    // workflow. The scout is now expected to crawl sibling functions and
    // look for inconsistent guard usage (authz-bypass pattern), which
    // takes more iters than its prior "skim findings" behavior.
    //
    // tool_choice = Any forces the LLM to call a tool every turn. Without
    // this, long system prompts let the model respond with planning text on
    // turn 1 and the loop terminates at iter 0. The agent terminates by
    // hitting max_iterations / max_total_tokens or by Cedar denying a
    // store_finding attempt; never by a stray "DONE" text response.
    let config = LoopConfig {
        tool_definitions: crate::tool_defs::pattern_scout(),
        tool_choice: Some(symbi_runtime::reasoning::inference::ToolChoice::Any),
        // Fable 5 (like Opus) rejects an explicit `temperature`. The runtime's
        // build_anthropic_body skips the field when temperature is 0.0; setting
        // it here forces the omit path. Applies to every tier in the chain.
        temperature: 0.0,
        // Fable 5 has a large (≥1M) input window, but the runtime's context
        // manager caps "claude" at 200K and the default budget is only 32K,
        // which truncated the conversation almost every iteration on a real
        // engagement (scout lost earlier query results and re-read). 120K leaves
        // headroom for the ~16K output + framing while retaining far more
        // cross-file context. Cost scales with ACTUAL tokens, not the ceiling,
        // so this only matters when the conversation genuinely grows.
        context_token_budget: 120_000,
        max_iterations: 100,
        max_total_tokens: 600_000,
        timeout: std::time::Duration::from_secs(1500),
        ..LoopConfig::default()
    };
    let agent_id = AgentId::new();

    // Pattern_scout composes findings via cross-file reasoning — Fable 5
    // first. Fallback chain: Anthropic Fable 5 → OpenRouter Opus 4.8 (different
    // infrastructure pool when Anthropic-direct is overloaded) →
    // Anthropic Sonnet 4.6 (always-running degraded tier).
    let result = symbi_codered_core::orga::run_with_fallback(
        executor_for_orga,
        agent_id,
        conversation,
        config,
        symbi_codered_core::orga::GENERATION_CHAIN,
    )
    .await
    .context("running pattern_scout with the generation fallback chain")?;
    let mut s = executor.summary();
    s.tokens_in = result.total_usage.prompt_tokens;
    s.tokens_out = result.total_usage.completion_tokens;
    s.iterations = result.iterations;
    Ok(s)
}

/// Build pattern_scout's seed conversation: a system prompt that names the
/// tool inventory + the citation-grounding contract, plus an opening user
/// turn that points the agent at the current engagement.
fn build_conversation(engagement_id: Uuid) -> Conversation {
    let system = format!(
        "You are pattern_scout for engagement {engagement_id}. Your job is \
         to EMIT store_finding calls, grounded in citations. You are NOT \
         here to read findings indefinitely.\n\n\
         TOOLS:\n\
         - query_threat_model() — sources/sinks/scope/guards\n\
         - query_taint_chains() — source→sink paths; rows with \
           sanitizers_seen=[\"unguarded\"] are missing-auth candidates\n\
         - query_findings(page=0, page_size=30, compact=true, tool_origin?)\n\
         - query_finding_detail(finding_id)\n\
         - read_context_range(file_path, line_start, line_end)\n\
         - hypothesis_repl(hypothesis_text)\n\
         - store_finding(severity, file_path, line_start, line_end, title, \
                          description, citations[]) — your goal\n\n\
         OUTPUT QUOTA — this is the success metric:\n\
         A run with 5 imperfect store_finding calls beats a run with 0 \
         perfect ones. Aim to call store_finding at least every 3 read \
         operations. If you find yourself reading a fifth file without \
         storing a finding, you are stuck — pick your strongest candidate \
         and store_finding now.\n\n\
         PRIORITY TARGETS (look here FIRST):\n\
         1. UNGUARDED TAINT CHAINS IN PRODUCTION CODE — query_taint_chains \
            returns unguarded chains first, AND within those, production-path \
            sinks (web-service/, services/, jobs/, cmd/, rust/<svc>/) before \
            dev-tooling. SPEND YOUR BUDGET ON THE PRODUCTION ONES. A chain \
            whose sink is a gRPC/HTTP handler or a DB query in a service is \
            high-value; read the sink + 1-2 siblings, and if a sibling applies \
            an org/owner guard and this one does not, store_finding with \
            severity=high, CWE-285 (Authorization Bypass), citing BOTH.\n\
         2. DEPRIORITIZE DEV-TOOLING CHAINS — chains whose sink is in \
            scripts/, notebooks/, */tests/, fixtures, or a generated mock \
            (*_mock.*, *_test.*, mocks/) are almost always CLI-argparse-driven \
            operator tooling or test scaffolding where the 'source' is a local \
            CLI arg or a fake, not a remote attacker — and the code is never \
            reachable in production. These are a known false-positive class. \
            Do NOT spend more than one finding on the entire dev-tooling \
            category; if you must record one, mark it severity=low. Your \
            scarce iterations belong on production sinks.\n\
         3. COMPARATIVE READING — when you find an interesting Select-by-ID \
            data-layer function, check whether its caller (the handler) \
            applies an authz check. If neither does, you have a cross-tenant \
            bypass; store it at severity=high.\n\n\
         RHYTHM:\n\
         1. query_threat_model() then query_taint_chains().\n\
         2. For the first unguarded chain: read_context_range on the sink \
            function, store_finding immediately with what you have.\n\
         3. Continue paginating findings (query_findings page=N) and \
            storing — never let 3 consecutive iterations pass without a \
            store_finding call.\n\n\
         EVERY citation must be one of analyzer|code|hypothesis. A code \
         citation needs file_path + line range matching what you read."
    );
    let user = format!(
        "Call query_threat_model() now. After you have its response, then \
         call query_taint_chains() and query_findings(page=0). Engagement \
         id is {engagement_id}. Do not respond with text only — your \
         response must contain a tool_use block."
    );

    let mut c = Conversation::new();
    c.push(ConversationMessage::system(system));
    c.push(ConversationMessage::user(user));
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn stub_policy() -> Arc<PolicyEngine> {
        let dir = TempDir::new().unwrap();
        Arc::new(PolicyEngine::from_dir(dir.path()).unwrap())
    }

    /// Sanity check: the seed conversation has exactly the system + user
    /// turns we expect, and the system prompt names every tool from the
    /// .symbi capability list (using `read_context_range`, not the
    /// cartographer's `read_context`).
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
            "query_threat_model",
            "query_findings",
            "query_taint_chains",
            "read_context_range",
            "hypothesis_repl",
            "store_finding",
        ] {
            assert!(
                sys.content.contains(tool),
                "system prompt missing tool: {tool}"
            );
        }
        // The system prompt must NOT name the cartographer's `read_context`
        // tool (collision risk). `read_context_range` substring trivially
        // contains "read_context", so we check the cartographer name is
        // absent only as a whole-word.
        assert!(!sys.content.contains("read_context,"));
        assert!(!sys.content.contains("read_context ")); // followed by space
        // Engagement id should appear in both turns.
        assert!(sys.content.contains(&eid.to_string()));

        let user = &messages[1];
        assert!(matches!(
            user.role,
            symbi_runtime::reasoning::conversation::MessageRole::User
        ));
        assert!(user.content.contains(&eid.to_string()));
    }

    /// The runner errors out cleanly when no LLM API key is set —
    /// `CoderedOrga::new` is the source of that error and we just propagate.
    /// We don't need to mutate env here; the policy stub + no-key case is
    /// covered upstream in `CoderedOrga::new`'s own test, and running the
    /// real ORGA loop is deferred to Task 24's e2e test. This test only
    /// proves the wiring compiles + the `ScoutInput` shape is usable.
    #[test]
    fn scout_input_constructs() {
        let _input = ScoutInput {
            engagement_id: Uuid::new_v4(),
            db_path: PathBuf::from("/tmp/codered.db"),
            journal_path: PathBuf::from("/tmp/codered.journal"),
            target_repo: PathBuf::from("/tmp/repo"),
            policy: stub_policy(),
        };
    }
}
