//! hypothesis_repl — fresh-context prove-or-kill sub-agent.
//!
//! Spawned from pattern_scout (or any other Plan D reasoning agent) when it
//! needs to verify or refute a single, well-scoped hypothesis without
//! polluting the parent reasoning trace. The sub-agent runs in its own
//! [`CoderedOrga`] loop with a tightly scoped system prompt and a stub
//! [`ReplExecutor`] that returns error observations for any tool call —
//! Plan D intentionally gives the sub-agent no live tool surface, mirroring
//! the .symbi capability list (`read_context_range`, `query_findings`) but
//! leaving the wire-up to Plan E. The LLM is expected to respond in plain
//! text with one of `REPRODUCED`, `REFUTED`, or `UNCERTAIN`.
//!
//! ## Outputs
//!
//! On success the runner persists a transcript [`EvidenceEnvelope`] to
//! `evidence_dir` and returns its `envelope_id`. pattern_scout uses that id
//! as the `Citation::Hypothesis::intended_poc` pointer when it later calls
//! `store_finding` with a hypothesis-grounded claim.
//!
//! ## Verdict parsing
//!
//! We lowercase the LoopResult `output` and match on substring rather than
//! exact equality — the LLM follows the verdict word with a short
//! justification paragraph, and lowercasing is the cheapest way to absorb
//! casing drift across providers.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use symbi_codered_core::orga::CoderedOrga;
use symbi_evidence_schema::evidence::EvidenceEnvelope;

use symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry;
use symbi_runtime::reasoning::conversation::{Conversation, ConversationMessage};
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::{LoopConfig, Observation, ProposedAction};
use symbi_runtime::types::AgentId;

/// Verdict the sub-agent reaches about a hypothesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The hypothesis was demonstrated (witness produced).
    Reproduced,
    /// The hypothesis was contradicted by evidence.
    Refuted,
    /// Insufficient evidence either way — pattern_scout should not cite it.
    Uncertain,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Reproduced => "reproduced",
            Verdict::Refuted => "refuted",
            Verdict::Uncertain => "uncertain",
        }
    }
}

/// Inputs to a single hypothesis_repl invocation.
pub struct ReplInput {
    pub engagement_id: Uuid,
    pub hypothesis_text: String,
    pub budget_iterations: u32,
    pub evidence_dir: PathBuf,
}

/// Outputs surfaced back to the calling agent (e.g. pattern_scout).
pub struct ReplOutput {
    pub verdict: Verdict,
    pub transcript_envelope_id: String,
}

/// Stub executor for the sub-agent. Records the names of any tools the LLM
/// tries to call (so the transcript carries a faint trail of what it
/// wanted) and surfaces every call as an error observation. Plan E may
/// replace this with a real dispatcher for `read_context_range` /
/// `query_findings`.
struct ReplExecutor {
    transcript: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ActionExecutor for ReplExecutor {
    async fn execute_actions(
        &self,
        actions: &[ProposedAction],
        _config: &LoopConfig,
        _circuit_breakers: &CircuitBreakerRegistry,
    ) -> Vec<Observation> {
        actions
            .iter()
            .filter_map(|a| match a {
                ProposedAction::ToolCall {
                    call_id,
                    name,
                    arguments: _,
                } => {
                    self.transcript
                        .lock()
                        .expect("hypothesis_repl transcript mutex poisoned")
                        .push(format!("tool: {name}"));
                    Some(
                        Observation::tool_error(
                            name.clone(),
                            "hypothesis_repl sub-agent has no tools enabled in Plan D"
                                .to_string(),
                        )
                        .with_call_id(call_id.clone()),
                    )
                }
                _ => None,
            })
            .collect()
    }
}

/// Run a hypothesis_repl sub-context to verdict.
///
/// Returns `Err` if [`CoderedOrga::new`] cannot find an LLM API key, if the
/// evidence directory cannot be created, or if writing the transcript
/// envelope fails. All other failures (including tool-call denials inside
/// the sub-conversation) are observed by the LLM and collapse to an
/// `Uncertain` verdict.
pub async fn run(input: ReplInput) -> Result<ReplOutput> {
    let executor = Arc::new(ReplExecutor {
        transcript: Mutex::new(Vec::new()),
    });
    let executor_for_orga: Arc<dyn ActionExecutor> = executor.clone();
    let orga = CoderedOrga::new(executor_for_orga)
        .context("building CoderedOrga for hypothesis_repl")?;

    let system = format!(
        "You are a focused, skeptical verifier. The user gives you ONE \
         hypothesis. Reply with exactly one of: REPRODUCED, REFUTED, UNCERTAIN, \
         followed by a one-paragraph justification. No tool calls are needed. \
         Budget: {} iterations.",
        input.budget_iterations,
    );
    let mut conv = Conversation::new();
    conv.push(ConversationMessage::system(system));
    conv.push(ConversationMessage::user(input.hypothesis_text.clone()));

    let cfg = LoopConfig::default();
    let agent_id = AgentId::new();
    let result = orga.run(agent_id, conv, cfg).await;
    let text = result.output.to_lowercase();
    let verdict = parse_verdict(&text);

    // Persist the transcript as an EvidenceEnvelope so the parent agent can
    // cite it via Citation::Hypothesis::intended_poc. The scan_id mirrors
    // static_hunter's "<prefix>-<engagement[:8]>" convention.
    let transcript = executor
        .transcript
        .lock()
        .expect("hypothesis_repl transcript mutex poisoned")
        .join("\n");
    let body = format!(
        "hypothesis: {}\n\nresponse:\n{}\n\ntranscript:\n{}",
        input.hypothesis_text, result.output, transcript
    );
    let envelope = EvidenceEnvelope {
        scan_id: format!("H-{}", &input.engagement_id.simple().to_string()[..8]),
        tool: "hypothesis_repl".into(),
        content_type: "text/plain".into(),
        bytes: body.into_bytes(),
    };
    let envelope_id = envelope.envelope_id();
    std::fs::create_dir_all(&input.evidence_dir)
        .context("creating hypothesis_repl evidence dir")?;
    std::fs::write(
        input.evidence_dir.join(format!("{envelope_id}.txt")),
        &envelope.bytes,
    )
    .context("writing hypothesis_repl transcript envelope")?;

    Ok(ReplOutput {
        verdict,
        transcript_envelope_id: envelope_id,
    })
}

/// Parse the LLM's verdict from a pre-lowercased response. Order matters:
/// `refuted` is checked before `reproduced` so an LLM that prefixes its
/// justification with "refuted, NOT reproduced" still maps to `Refuted`.
/// Default is `Uncertain`, which the parent agent treats as "do not cite".
fn parse_verdict(lowercased: &str) -> Verdict {
    if lowercased.contains("refuted") {
        Verdict::Refuted
    } else if lowercased.contains("reproduced") {
        Verdict::Reproduced
    } else {
        Verdict::Uncertain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_as_str_matches_serialized_form() {
        assert_eq!(Verdict::Reproduced.as_str(), "reproduced");
        assert_eq!(Verdict::Refuted.as_str(), "refuted");
        assert_eq!(Verdict::Uncertain.as_str(), "uncertain");
    }

    #[test]
    fn parse_verdict_handles_each_keyword() {
        assert_eq!(parse_verdict("reproduced — see line 42"), Verdict::Reproduced);
        assert_eq!(parse_verdict("refuted because the input is sanitized"), Verdict::Refuted);
        assert_eq!(parse_verdict("uncertain, need more context"), Verdict::Uncertain);
        // No keyword → uncertain.
        assert_eq!(parse_verdict("i don't know"), Verdict::Uncertain);
    }

    #[test]
    fn parse_verdict_prefers_refuted_when_both_present() {
        // The LLM sometimes writes "refuted (not reproduced)" — refuted wins.
        assert_eq!(
            parse_verdict("refuted, not reproduced by the trace"),
            Verdict::Refuted
        );
    }

    /// Stub executor produces one error observation per tool call and
    /// preserves the call_id so the loop can correlate the result back to
    /// the originating tool_use block.
    #[tokio::test]
    async fn repl_executor_errors_on_tool_calls() {
        let exec = ReplExecutor {
            transcript: Mutex::new(Vec::new()),
        };
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "read_context_range".into(),
            arguments: "{}".into(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert_eq!(obs.len(), 1);
        assert!(obs[0].is_error);
        assert!(obs[0].content.contains("no tools enabled"));
        assert_eq!(obs[0].call_id.as_deref(), Some("c1"));
        assert_eq!(
            exec.transcript.lock().unwrap().as_slice(),
            &["tool: read_context_range".to_string()]
        );
    }

    /// Non-tool actions (Respond/Terminate) produce no observations,
    /// mirroring the `DefaultActionExecutor` and pattern_scout convention.
    #[tokio::test]
    async fn repl_executor_ignores_non_tool_actions() {
        let exec = ReplExecutor {
            transcript: Mutex::new(Vec::new()),
        };
        let actions = vec![ProposedAction::Terminate {
            reason: "done".into(),
            output: "REPRODUCED — direct call to eval".into(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(obs.is_empty());
        assert!(exec.transcript.lock().unwrap().is_empty());
    }
}
