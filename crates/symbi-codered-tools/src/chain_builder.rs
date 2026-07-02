//! chain_builder — maps findings + taint chains onto the seven-stage
//! Agent Kill Chain graph.
//!
//! Plan D Task 21. Same shape as [`crate::pattern_scout`]: an ORGA runner
//! ([`run`]) backed by an [`ActionExecutor`] ([`ChainBuilderExecutor`]).
//! The LLM is given three tools — `query_findings`, `query_taint_chains`,
//! and `build_attack_chain` — and is asked to cluster the engagement's
//! findings into chains whose nodes name one of the seven kill-chain
//! stages defined in [`symbi_evidence_schema::attack_chain::KillChainStage`].
//!
//! The stages here are AGENT-attack stages, NOT MITRE ATT&CK:
//!
//! - `surface_mapping`        — initial reconnaissance / API enumeration
//! - `tool_subversion`        — abusing tool access (dangerous tool params)
//! - `instruction_injection`  — prompt injection / context poisoning
//! - `reasoning_capture`      — coercing the agent's reasoning loop
//! - `gate_evasion`           — bypassing policy / Cedar gates
//! - `privileged_action`      — executing high-impact actions
//! - `audit_evasion`          — covering tracks / suppressing audit logs
//!
//! Every `build_attack_chain` call writes one or more `attack_chains` rows
//! (one node per `finding_id`), linked in order via `next_chain_id`. The
//! agent has NO free-form-claim path; its only act is to cluster and label.

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
pub use executor::ChainBuilderExecutor;

/// Inputs handed to [`run`] from the CLI / orchestrator layer.
pub struct ChainInput {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
}

/// Counters reported back after the loop terminates.
pub struct ChainSummary {
    /// Number of successful `build_attack_chain` calls. One call may
    /// write multiple `attack_chains` rows (one per finding in the chain).
    pub chains_built: usize,
    /// Total `attack_chains` rows inserted across all chains.
    pub nodes_inserted: usize,
    /// Number of `ProposedAction::ToolCall` actions seen by the executor.
    pub tool_calls: usize,
    /// LLM input tokens consumed across the entire loop.
    pub tokens_in: u32,
    /// LLM output tokens generated across the entire loop.
    pub tokens_out: u32,
    /// Number of ORGA iterations executed before termination.
    pub iterations: u32,
}

/// Run chain_builder end-to-end for a single engagement.
///
/// Builds the [`ChainBuilderExecutor`], wraps it in a [`CoderedOrga`],
/// seeds the conversation with the kill-chain system prompt, and runs
/// the ORGA loop. Returns the per-run counters from the executor
/// regardless of how the loop terminated; the caller inspects the
/// journal / logs for the `LoopResult` details.
///
/// Returns `Err` if [`CoderedOrga::new`] cannot find an LLM API key.
pub async fn run(input: ChainInput) -> Result<ChainSummary> {
    let executor = Arc::new(ChainBuilderExecutor::new(
        input.engagement_id,
        input.db_path,
        input.journal_path,
    ));
    let executor_for_orga: Arc<dyn ActionExecutor> = executor.clone();

    let conversation = build_conversation(input.engagement_id);
    let config = LoopConfig {
        tool_definitions: crate::tool_defs::chain_builder(),
        // Force tool_use every turn — chain_builder is iterate-until-done.
        tool_choice: Some(symbi_runtime::reasoning::inference::ToolChoice::Any),
        // Fable 5 (like Opus) rejects `temperature`; omit by setting 0.0.
        temperature: 0.0,
        // 120K context window (see pattern_scout for rationale).
        context_token_budget: 120_000,
        max_iterations: 60,
        max_total_tokens: 400_000,
        timeout: std::time::Duration::from_secs(900),
        ..LoopConfig::default()
    };
    let agent_id = AgentId::new();

    // Chain_builder stitches findings + taint chains into multi-hop
    // attack narratives. Anthropic Fable 5 → OpenRouter Opus 4.8 → Sonnet 4.6.
    let result = symbi_codered_core::orga::run_with_fallback(
        executor_for_orga,
        agent_id,
        conversation,
        config,
        symbi_codered_core::orga::GENERATION_CHAIN,
    )
    .await
    .context("running chain_builder with the generation fallback chain")?;
    let mut s = executor.summary();
    s.tokens_in = result.total_usage.prompt_tokens;
    s.tokens_out = result.total_usage.completion_tokens;
    s.iterations = result.iterations;
    Ok(s)
}

/// Seed conversation: a system prompt that enumerates the three tools and
/// the seven kill-chain stages, plus an opening user turn pointing the
/// agent at the current engagement.
fn build_conversation(engagement_id: Uuid) -> Conversation {
    let system = format!(
        "You are chain_builder. Given engagement {engagement_id}'s findings \
         and taint chains, group them into attack chains mapping to the \
         seven-stage Agent Kill Chain.\n\n\
         STAGES (use these literal snake_case names):\n\
         - surface_mapping        — initial recon / API surface enumeration\n\
         - tool_subversion        — abusing tool access (dangerous tool params)\n\
         - instruction_injection  — prompt injection / context poisoning\n\
         - reasoning_capture      — coercing the agent's reasoning loop\n\
         - gate_evasion           — bypassing policy / Cedar gates\n\
         - privileged_action      — executing high-impact actions\n\
         - audit_evasion          — covering tracks / suppressing audit logs\n\n\
         TOOLS:\n\
         - query_findings(page=0, page_size=30, tool_origin?: string)\n\
         - query_taint_chains() — list taint chains for this engagement\n\
         - build_attack_chain(stage: string, finding_ids: string[], rationale?: string)\n\n\
         OUTPUT QUOTA — this is the success metric:\n\
         Your job is NOT to read findings; it is to EMIT chain calls. After \
         your first read (query_findings page=0 + query_taint_chains), you \
         must call build_attack_chain on your first plausible cluster — even \
         if you'd prefer to read more. Then continue paginating and emitting. \
         A run that emits 10 imperfect chain calls is better than a run that \
         reads all 60 pages and emits zero.\n\n\
         RHYTHM (this is the literal pattern to follow):\n\
         1. query_findings(page=0) + query_taint_chains() — these are your only \
            'read' calls before the first write.\n\
         2. IMMEDIATELY call build_attack_chain on the most coherent 2-5 finding \
            cluster you can see — pick a stage, pass the finding_ids, give a \
            one-sentence rationale.\n\
         3. query_findings(page=1) — read.\n\
         4. build_attack_chain on the next cluster — write.\n\
         5. Continue alternating read/write until has_more=false on findings.\n\n\
         Never call more than two consecutive read tools without an intervening \
         build_attack_chain. If you find yourself wanting to read 'just one more \
         page,' call build_attack_chain instead with whatever cluster is freshest.\n\n\
         No free-form claims — your only act is clustering and labeling existing findings."
    );
    let user = format!(
        "Build attack chains for engagement {engagement_id}. Start by \
         querying the existing findings and taint chains."
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
    /// seven stages and all three tools named in the system prompt, and
    /// the engagement id surfaces in both turns.
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
        for stage in [
            "surface_mapping",
            "tool_subversion",
            "instruction_injection",
            "reasoning_capture",
            "gate_evasion",
            "privileged_action",
            "audit_evasion",
        ] {
            assert!(
                sys.content.contains(stage),
                "system prompt missing stage: {stage}"
            );
        }
        for tool in ["query_findings", "query_taint_chains", "build_attack_chain"] {
            assert!(
                sys.content.contains(tool),
                "system prompt missing tool: {tool}"
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
    /// proves the `ChainInput` shape is usable.
    #[test]
    fn chain_input_constructs() {
        let _input = ChainInput {
            engagement_id: Uuid::new_v4(),
            db_path: PathBuf::from("/tmp/codered.db"),
            journal_path: PathBuf::from("/tmp/codered.journal"),
        };
    }
}
