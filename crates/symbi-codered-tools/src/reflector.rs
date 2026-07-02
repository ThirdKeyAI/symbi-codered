//! reflector — end-of-engagement cross-phase knowledge distillation.
//!
//! Plan G Task 4. Same shape as [`crate::chain_builder`] /
//! [`crate::devils_advocate`]: an ORGA runner ([`run`]) backed by an
//! [`ActionExecutor`] ([`ReflectorExecutor`]). The LLM is given five
//! read-only query tools plus a single write tool — `write_knowledge_triple` —
//! and is asked to distill the most useful 5-15 reusable knowledge triples
//! a future engagement could surface via `recall_knowledge_by_subject`.
//!
//! The runner does NOT permit `store_finding` from the reflector principal;
//! that gate is enforced by the Cedar `reflector-forbids-store-finding`
//! policy attached to the agent's `.symbi` manifest, not by this executor.
//!
//! Each `write_knowledge_triple` call inserts one
//! [`symbi_codered_core::db::KnowledgeTriple`] row with `source_phase =
//! "reflector"` and appends a `reflector` permit entry to the hash-chained
//! audit journal.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;


use symbi_runtime::reasoning::conversation::ConversationMessage;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::LoopConfig;
use symbi_runtime::reasoning::Conversation;
use symbi_runtime::types::AgentId;

pub mod executor;
pub use executor::ReflectorExecutor;

/// Inputs handed to [`run`] from the CLI / orchestrator layer.
pub struct ReflectInput {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
}

/// Counters reported back after the loop terminates.
pub struct ReflectSummary {
    /// Number of successful `write_knowledge_triple` calls (one row per call).
    pub triples_written: usize,
    /// Number of `ProposedAction::ToolCall` actions seen by the executor.
    pub tool_calls: usize,
    /// LLM input tokens consumed across the entire loop.
    pub tokens_in: u32,
    /// LLM output tokens generated across the entire loop.
    pub tokens_out: u32,
    /// Number of ORGA iterations executed before termination.
    pub iterations: u32,
}

/// Run reflector end-to-end for a single engagement.
///
/// Builds the [`ReflectorExecutor`], wraps it in a [`CoderedOrga`],
/// seeds the conversation with the distillation system prompt, and runs
/// the ORGA loop. Returns the per-run counters from the executor
/// regardless of how the loop terminated; the caller inspects the
/// journal / logs for the `LoopResult` details.
///
/// Returns `Err` if [`CoderedOrga::new`] cannot find an LLM API key.
pub async fn run(input: ReflectInput) -> Result<ReflectSummary> {
    let executor = Arc::new(ReflectorExecutor::new(
        input.engagement_id,
        input.db_path,
        input.journal_path,
    ));
    let executor_for_orga: Arc<dyn ActionExecutor> = executor.clone();

    let conversation = build_conversation(input.engagement_id);
    // Bumped budget so the reflector can crawl enough surface to spot
    // architectural patterns, not just per-finding observations.
    // tool_choice = Any forces tool_use every turn.
    let config = LoopConfig {
        tool_definitions: crate::tool_defs::reflector(),
        tool_choice: Some(symbi_runtime::reasoning::inference::ToolChoice::Any),
        // Fable 5 (like Opus) rejects `temperature`; omit by setting 0.0.
        temperature: 0.0,
        // 120K context window (see pattern_scout for rationale).
        context_token_budget: 120_000,
        max_iterations: 100,
        max_total_tokens: 600_000,
        timeout: std::time::Duration::from_secs(1500),
        ..LoopConfig::default()
    };
    let agent_id = AgentId::new();

    // Reflector synthesizes cross-phase patterns. Anthropic Fable 5 →
    // OpenRouter Opus 4.8 → Anthropic Sonnet 4.6.
    let result = symbi_codered_core::orga::run_with_fallback(
        executor_for_orga,
        agent_id,
        conversation,
        config,
        symbi_codered_core::orga::GENERATION_CHAIN,
    )
    .await
    .context("running reflector with the generation fallback chain")?;
    let mut s = executor.summary();
    s.tokens_in = result.total_usage.prompt_tokens;
    s.tokens_out = result.total_usage.completion_tokens;
    s.iterations = result.iterations;
    Ok(s)
}

/// Seed conversation per spec §5.2: frame the agent as the cross-phase
/// distiller and enumerate the read tools + the single write tool.
fn build_conversation(engagement_id: Uuid) -> Conversation {
    let system = format!(
        "You are reflector for engagement {engagement_id} (just completed). \
         Your job is to EMIT write_knowledge_triple calls capturing \
         reusable patterns. You are NOT here to read findings indefinitely.\n\n\
         TRIPLE SHAPE: (subject, predicate, object, confidence, rationale). \
         Predicates are free-form but should be reusable across engagements: \
         `is_taint_source_for`, `mitigates`, `commonly_misused_via`, \
         `prefers_pattern`, `false_positive_class`, \
         `has_inconsistent_authz_pattern`, `cwe_typical_for_language`.\n\n\
         TOOLS:\n\
         - query_findings(page=0, page_size=30, compact=true)\n\
         - query_finding_detail(finding_id)\n\
         - query_taint_chains() — chains tagged unguarded are missing-auth signal\n\
         - query_attack_chains(page=0, page_size=30)\n\
         - write_knowledge_triple(subject, predicate, object, confidence?, rationale?)\n\n\
         OUTPUT QUOTA: aim for 5-15 triples per engagement. After your \
         first read pass (query_findings page=0 + query_taint_chains + \
         query_attack_chains page=0), call write_knowledge_triple at least \
         3 times before doing any more reads. A run with 5 imperfect triples \
         is far more useful than a run with 0 perfect ones.\n\n\
         TARGET PATTERN TYPES (write triples capturing these, not per-finding observations):\n\
         - Dominant code-shape — what KIND of code produced the dominant \
           finding class (e.g., subject=\"dev tooling subprocess.run calls\", \
           predicate=\"commonly_misused_via\", object=\"non-literal argv\").\n\
         - Sibling-function inconsistency — when one function applies a \
           guard and a neighbor does not (subject=package, \
           predicate=\"has_inconsistent_authz_pattern\", object=function pair).\n\
         - Cross-language pattern when multiple languages are in scope.\n\
         - False-positive class — patterns the advocate consistently rebutted.\n\n\
         You are READ-ONLY on findings and chains. Your only write is \
         write_knowledge_triple."
    );
    let user = format!(
        "Call query_findings(page=0, compact=true) now. Then proceed to \
         query_taint_chains() and query_attack_chains(page=0). Engagement \
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

    /// Sanity check on the seed conversation: system + user turns, all five
    /// tools and key predicate terms named in the system prompt, and the
    /// engagement id surfaces in both turns.
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
            "query_finding_detail",
            "query_taint_chains",
            "query_attack_chains",
            "write_knowledge_triple",
        ] {
            assert!(
                sys.content.contains(tool),
                "system prompt missing tool: {tool}"
            );
        }
        for pred in ["is_taint_source_for", "false_positive_class"] {
            assert!(
                sys.content.contains(pred),
                "system prompt missing predicate hint: {pred}"
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
    /// proves the `ReflectInput` shape is usable.
    #[test]
    fn reflect_input_constructs() {
        let _input = ReflectInput {
            engagement_id: Uuid::new_v4(),
            db_path: PathBuf::from("/tmp/codered.db"),
            journal_path: PathBuf::from("/tmp/codered.journal"),
        };
    }
}
