//! devils_advocate — inverted-prompt rebuttal pass over an engagement's
//! existing findings.
//!
//! Plan E Tasks 5 + 6. Same shape as [`crate::chain_builder`]: an ORGA
//! runner ([`run`]) backed by an [`ActionExecutor`]
//! ([`DevilsAdvocateExecutor`]). The LLM is given two tools —
//! `query_findings` and `advocate_finding` — and is asked to argue why
//! each finding is WRONG. The runner does NOT permit `store_finding`
//! from the devils_advocate principal; that gate is enforced by the
//! Cedar policy attached to the agent's `.symbi` manifest, not by this
//! executor.
//!
//! Each `advocate_finding` call writes the agent's verdict
//! (`confirmed` / `rebutted` / `uncertain`) to the finding's
//! `advocate_verdict` column via
//! [`symbi_codered_core::db::set_advocate_verdict`] and appends a
//! `devils_advocate` permit entry to the hash-chained audit journal.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use symbi_codered_core::orga::CoderedOrga;
use symbi_codered_core::orga::FallbackTier;
use symbi_codered_core::policy::PolicyEngine;

use symbi_runtime::reasoning::conversation::ConversationMessage;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::LoopConfig;
use symbi_runtime::reasoning::loop_types::LoopResult;
use symbi_runtime::reasoning::Conversation;
use symbi_runtime::types::AgentId;

pub mod executor;
pub use executor::DevilsAdvocateExecutor;

/// Inputs handed to [`run`] from the CLI / orchestrator layer.
pub struct AdvocateInput {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
    /// Repo root the advocate may read source from (path-escape guarded) so it
    /// can verify caller/sink context before confirming. `codered hunt` runs
    /// from the target-repo root, so ".".
    pub target_repo: PathBuf,
    /// Resolved (provider, model) fallback chain for the advocate's OWN model,
    /// enabling a non-mirroring reviewer. Empty => env-default single-tier
    /// (legacy behavior). Resolved by the CLI from --advocate-* flags / env.
    pub model_chain: Vec<(String, String)>,
    /// Lowest severity the advocate should adjudicate ("critical", "high",
    /// "medium", "low"). `None` = no floor (every severity). Applied at the
    /// SQL layer inside [`crate::pattern_scout_tools::query_findings_prioritized`].
    pub severity_min: Option<String>,
    /// ORGA loop iteration cap. `None` = default (60). Bump when running a
    /// thorough validation pass.
    pub max_iterations: Option<u32>,
    /// ORGA loop total-token cap. `None` = default (400_000). Bump
    /// alongside `max_iterations` so the loop doesn't get terminated for
    /// token reasons before it exhausts iterations.
    pub max_total_tokens: Option<u32>,
    /// Cedar engine that gates `advocate_finding` — a `rebutted` verdict is
    /// authorized through `advocate.cedar`'s witness rule. Loaded from the same
    /// `--policies` dir as the rest of the pipeline.
    pub policy: Arc<PolicyEngine>,
}

/// Counters reported back after the loop terminates.
pub struct AdvocateSummary {
    /// Number of `advocate_finding` calls with verdict = "confirmed".
    pub confirmed: usize,
    /// Number of `advocate_finding` calls with verdict = "rebutted".
    pub rebutted: usize,
    /// Number of `advocate_finding` calls with verdict = "uncertain".
    pub uncertain: usize,
    /// Number of `ProposedAction::ToolCall` actions seen by the executor.
    pub tool_calls: usize,
    /// Number of `rebutted` verdicts denied by Cedar for lacking a witness.
    pub rebuttals_denied: usize,
    /// LLM input tokens consumed across the entire loop.
    pub tokens_in: u32,
    /// LLM output tokens generated across the entire loop.
    pub tokens_out: u32,
    /// Number of ORGA iterations executed before termination.
    pub iterations: u32,
}

/// True when tiers DID construct but every one of them made no progress
/// (overloaded / quota / model unavailable), which `run_with_fallback`
/// surfaces as an empty `LoopResult`. The total construction-failure case
/// (no API key for any provider) is now an `Err` from `run_with_fallback`,
/// propagated by the `?` above this call — it never reaches here.
fn all_tiers_unusable(r: &LoopResult) -> bool {
    r.iterations == 0 && r.total_usage.prompt_tokens == 0
}

/// Run devils_advocate end-to-end for a single engagement.
///
/// Builds the [`DevilsAdvocateExecutor`], wraps it in a [`CoderedOrga`],
/// seeds the conversation with the inverted-prompt system message, and
/// runs the ORGA loop. Returns the per-run counters from the executor
/// regardless of how the loop terminated; the caller inspects the
/// journal / logs for the `LoopResult` details.
///
/// Returns `Err` if [`CoderedOrga::new`] cannot find an LLM API key.
pub async fn run(input: AdvocateInput) -> Result<AdvocateSummary> {
    let executor = Arc::new(DevilsAdvocateExecutor::new_with_severity_floor(
        input.engagement_id,
        input.db_path,
        input.journal_path,
        input.target_repo,
        input.severity_min.clone(),
        input.policy,
    ));
    let executor_for_orga: Arc<dyn ActionExecutor> = executor.clone();

    let conversation = build_conversation(input.engagement_id, input.severity_min.as_deref());
    let config = LoopConfig {
        tool_definitions: crate::tool_defs::devils_advocate(),
        // tool_choice = Any forces a tool call every turn so the advocate can't
        // answer in prose and never call advocate_finding — the root cause of
        // the observed "0 verdicts" behavior on less tool-compliant models.
        tool_choice: Some(symbi_runtime::reasoning::inference::ToolChoice::Any),
        // Fable 5 / Opus reject an explicit `temperature`; 0.0 hits the runtime's
        // omit path. A stochastic skeptic is undesirable — keep it deterministic.
        temperature: 0.0,
        // Match the generation stages' 120K budget; the advocate reads findings +
        // evidence and would truncate early at the 32K default.
        context_token_budget: 120_000,
        max_iterations: input.max_iterations.unwrap_or(60),
        max_total_tokens: input.max_total_tokens.unwrap_or(400_000),
        timeout: std::time::Duration::from_secs(1500),
        ..LoopConfig::default()
    };
    let agent_id = AgentId::new();

    let result = if input.model_chain.is_empty() {
        // Legacy path: env-default provider/model, single attempt.
        let orga = CoderedOrga::new(executor_for_orga)
            .context("building CoderedOrga for devils_advocate")?;
        orga.run(agent_id, conversation, config).await
    } else {
        // Independent-reviewer path: run the resolved (provider, model) chain.
        let chain: Vec<FallbackTier> = input
            .model_chain
            .iter()
            .map(|(p, m)| (p.as_str(), m.as_str()))
            .collect();
        let r = symbi_codered_core::orga::run_with_fallback(
            executor_for_orga,
            agent_id,
            conversation,
            config,
            &chain,
        )
        .await?;
        if all_tiers_unusable(&r) {
            let tiers: Vec<String> =
                input.model_chain.iter().map(|(p, m)| format!("{p}:{m}")).collect();
            anyhow::bail!(
                "no usable advocate model (all tiers failed to construct or were unavailable): [{}]",
                tiers.join(", ")
            );
        }
        r
    };
    let mut s = executor.summary();
    s.tokens_in = result.total_usage.prompt_tokens;
    s.tokens_out = result.total_usage.completion_tokens;
    s.iterations = result.iterations;
    Ok(s)
}

/// Seed conversation: a system prompt that frames the agent as an
/// adversarial reviewer, plus an opening user turn pointing at the
/// engagement.
fn build_conversation(engagement_id: Uuid, severity_min: Option<&str>) -> Conversation {
    let scope_note = match severity_min {
        Some(s) => format!(
            "\n\nSCOPE: You are running a FOCUSED validation pass — findings \
             are pre-filtered to severity >= {s}. There is no value in \
             rebutting low-effort findings here; spend your iter budget \
             scrutinizing each one carefully."
        ),
        None => String::new(),
    };
    let system = format!(
        "You are devils_advocate. You will see a list of security findings \
         for engagement {engagement_id}. For each finding, your job is to \
         argue why it is WRONG — false positive, unreachable code, \
         mitigated by surrounding logic, etc. If you cannot construct a \
         credible rebuttal, the finding is CONFIRMED. If your rebuttal \
         succeeds, the finding is REBUTTED. If you genuinely cannot tell, \
         mark it UNCERTAIN.{scope_note}\n\n\
         TOOLS:\n\
         - query_findings(page=0, page_size=30, tool_origin?: string) — paginated. \
           Returns {{findings, page, page_size, total, returned, has_more}}.\n\
         - read_context_range(file_path, line_start, line_end) — read source \
           from the target repo. USE IT: a finding's description is the author's \
           claim, not evidence. Open the sink AND its callers before you confirm.\n\
         - advocate_finding(finding_id, verdict, reason?, witness?)\n\n\
         For each finding, call advocate_finding(finding_id, verdict, ...) \
         where verdict is exactly one of: \"confirmed\", \"rebutted\", \"uncertain\".\n\
         ASYMMETRIC COST — suppression is WITNESS-GATED by Cedar: a \"rebutted\" \
         verdict REQUIRES (a) a non-empty `reason` arguing the rebuttal AND (b) a \
         `witness` array naming at least one recognized kind: \
         {{\"type\":\"envelope\",\"ref\":<a read_context_range envelope id you \
         read>}}, or \"sanitizer\" (a named sanitizer that neutralizes the sink), \
         or \"closed_set\" (the value is a closed set of literals), or \
         \"constant_caller\" (every caller passes a constant). WITHOUT a witness, \
         the rebuttal is DENIED by policy and the finding is NOT dropped — so a \
         finding can never be suppressed on an unwitnessed claim. Confirming or \
         marking uncertain keeps the finding in play and needs neither. Dropping a \
         finding always costs more than keeping it.\n\n\
         WORKFLOW (IMPORTANT — full coverage):\n\
         1. Call query_findings(page=0).\n\
         2. NOTE the `returned` count in the response — call it N.\n\
         3. You MUST emit EXACTLY N advocate_finding tool calls, one per \
            id in the returned list, before doing anything else. Do not \
            summarize. Do not say \"DONE\" yet. Do not output narrative \
            between calls. The page is not complete until every id has \
            a verdict.\n\
         4. After all N calls, if has_more=true call query_findings(page+1) \
            and repeat from step 2. If has_more=false, only THEN say \"DONE\".\n\n\
         ANTI-SHORTCUT RULE: It is a hard failure to stop the loop while \
         findings remain unadjudicated. \"This pattern looks similar to \
         the previous one\" is NOT a substitute for an advocate_finding \
         call — each finding gets its own verdict, even if the reason \
         field reuses earlier reasoning verbatim.\n\n\
         CALLER-CONTEXT CHECK (cuts BOTH ways — use read_context_range): For \
         any CWE-78/89/22/94/79 finding whose exploitability depends on a \
         value being attacker-controlled, READ the code before you rule. \
         Specifically:\n\
         - To REBUT a 'trusted input' defence: identify the enclosing \
           function and what calls it. If it's a gRPC/HTTP handler entry \
           point, inputs ARE attacker-controlled and the rebuttal fails.\n\
         - To CONFIRM an injection finding, verify the tainted value is \
           actually reachable from untrusted input. Open the sink, then open \
           its callers/registration. If every caller passes a CONSTANT or a \
           value from a CLOSED SET of literals (e.g. a dispatch table of \
           {{\"YEAR\",\"MONTH\",...}}), the value is NOT attacker-controlled — \
           REBUT it (this is the api_filter EXTRACT/`field` shape). A \
           description that hedges ('IF any caller path lets request input \
           dictate X' / 'for future refactors') is describing a LATENT issue, \
           not a demonstrated one — do not CONFIRM on conditional language.\n\
         - DON'T TRUST LABELS: a finding may already carry poc_status or a \
           prior verdict. Those are claims, not proof. If poc_status says \
           'reproduced' but no reproducing input is evident in the code you \
           read, treat reachability as unproven and mark UNCERTAIN rather than \
           confirming on the label.\n\
         - If you cannot verify either way after reading, mark UNCERTAIN — \
           let a human resolve. Never CONFIRM what you could not read.\n\n\
         Do NOT try to query all findings at once — the response would be too large \
         to fit in context. Do NOT invent findings; you cannot (the policy gate \
         prevents store_finding from your principal)."
    );
    let user = format!(
        "Begin the rebuttal pass for engagement {engagement_id}."
    );

    let mut c = Conversation::new();
    c.push(ConversationMessage::system(system));
    c.push(ConversationMessage::user(user));
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check on the seed conversation: system + user turns, both
    /// tools and all three verdicts named in the system prompt, and the
    /// engagement id surfaces in both turns.
    #[test]
    fn build_conversation_seeds_system_and_user_turns() {
        let eid = Uuid::new_v4();
        let conv = build_conversation(eid, None);
        let messages = conv.messages();
        assert_eq!(messages.len(), 2);

        let sys = &messages[0];
        assert!(matches!(
            sys.role,
            symbi_runtime::reasoning::conversation::MessageRole::System
        ));
        for tool in ["query_findings", "advocate_finding"] {
            assert!(
                sys.content.contains(tool),
                "system prompt missing tool: {tool}"
            );
        }
        for verdict in ["confirmed", "rebutted", "uncertain"] {
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
    /// proves the `AdvocateInput` shape is usable.
    #[test]
    fn advocate_input_constructs() {
        let pdir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            pdir.path().join("p.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();
        let _input = AdvocateInput {
            engagement_id: Uuid::new_v4(),
            db_path: PathBuf::from("/tmp/codered.db"),
            journal_path: PathBuf::from("/tmp/codered.journal"),
            target_repo: PathBuf::from("."),
            model_chain: Vec::new(),
            severity_min: None,
            max_iterations: None,
            max_total_tokens: None,
            policy: Arc::new(PolicyEngine::from_dir(pdir.path()).unwrap()),
        };
    }

    /// The scope note only appears when severity_min is set.
    #[test]
    fn build_conversation_includes_scope_note_when_severity_min_set() {
        let eid = Uuid::new_v4();
        let with_floor = build_conversation(eid, Some("high"));
        let without = build_conversation(eid, None);
        assert!(with_floor.messages()[0].content.contains("severity >= high"));
        assert!(!without.messages()[0].content.contains("severity >= "));
    }

    /// A zero-value `LoopResult` (no iterations, no prompt tokens) is what
    /// `run_with_fallback` returns when tiers constructed but all made no
    /// progress (overloaded / quota) — and `all_tiers_unusable` must flag it;
    /// any progress (iterations or prompt tokens) flips it usable. The
    /// total construction-failure case is an `Err`, not this empty result.
    /// `LoopResult` does not implement `Default`, so build the zero value from
    /// its fields explicitly.
    fn zero_loop_result() -> LoopResult {
        LoopResult {
            output: String::new(),
            iterations: 0,
            total_usage: Default::default(),
            termination_reason:
                symbi_runtime::reasoning::loop_types::TerminationReason::Completed,
            duration: std::time::Duration::from_secs(0),
            conversation: Conversation::new(),
        }
    }

    #[test]
    fn all_tiers_unusable_detects_zero_progress() {
        let mut r = zero_loop_result();
        assert!(
            super::all_tiers_unusable(&r),
            "default (0 iters, 0 tokens) is unusable"
        );
        r.iterations = 1;
        assert!(!super::all_tiers_unusable(&r), "any progress is usable");

        // Second conjunct: prompt tokens were consumed even though the loop
        // recorded 0 iterations. The tier DID call inference, so this is
        // usable progress — `all_tiers_unusable` must return false.
        let mut r = zero_loop_result();
        r.total_usage.prompt_tokens = 1;
        assert!(
            !super::all_tiers_unusable(&r),
            "prompt tokens consumed (even at 0 iterations) is usable"
        );
    }
}
