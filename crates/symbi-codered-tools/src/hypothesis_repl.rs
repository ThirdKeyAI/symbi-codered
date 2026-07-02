//! hypothesis_repl — fresh-context prove-or-kill sub-agent.
//!
//! Spawned from pattern_scout (or any other Plan D reasoning agent) when it
//! needs to verify or refute a single, well-scoped hypothesis without
//! polluting the parent reasoning trace. The sub-agent runs in its own
//! [`CoderedOrga`] loop with a tightly scoped system prompt and a
//! [`ReplExecutor`] that exposes exactly one tool — `emit_verdict` — and
//! errors on anything else. Plan D intentionally gives the sub-agent no live
//! investigative surface (`read_context_range`, `query_findings`); wiring
//! those in is left to Plan E, at which point `tool_choice` would relax from
//! the forced `emit_verdict` to `Any`.
//!
//! ## Outputs
//!
//! On success the runner persists a transcript [`EvidenceEnvelope`] to
//! `evidence_dir` and returns its `envelope_id`. pattern_scout uses that id
//! as the `Citation::Hypothesis::intended_poc` pointer when it later calls
//! `store_finding` with a hypothesis-grounded claim.
//!
//! ## Verdict extraction
//!
//! The verdict is read from a native `emit_verdict` tool call (a
//! schema-constrained enum), not by substring-matching free text. The loop
//! forces the tool via `ToolChoice::Tool { name: "emit_verdict" }`, so a
//! prose-only answer can't slip through and a word like "reproduced"
//! appearing inside the model's reasoning can't flip the verdict. If the
//! model never emits a valid verdict, the result defaults to `Uncertain`,
//! which the parent agent treats as "do not cite".

use anyhow::{Context, Result};
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use symbi_codered_core::orga::CoderedOrga;
use symbi_evidence_schema::evidence::EvidenceEnvelope;

use symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry;
use symbi_runtime::reasoning::conversation::{Conversation, ConversationMessage};
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::inference::{ToolChoice, ToolDefinition};
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

/// Map the `emit_verdict` enum string to a [`Verdict`]. Unknown values return
/// `None` so the executor can surface a tool error rather than silently
/// coercing to a verdict.
fn verdict_from_str(s: &str) -> Option<Verdict> {
    match s.to_ascii_lowercase().as_str() {
        "reproduced" => Some(Verdict::Reproduced),
        "refuted" => Some(Verdict::Refuted),
        "uncertain" => Some(Verdict::Uncertain),
        _ => None,
    }
}

/// The single tool the sub-agent may call. A schema-constrained enum verdict
/// plus a free-text justification captured into the transcript envelope.
fn emit_verdict_tool() -> ToolDefinition {
    ToolDefinition {
        name: "emit_verdict".to_string(),
        description: "Record your final verdict on the hypothesis. Call this exactly once. \
             reproduced = the hypothesis is demonstrated; refuted = contradicted by evidence; \
             uncertain = insufficient evidence (the parent agent will not cite it)."
            .to_string(),
        parameters: json!({
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["reproduced", "refuted", "uncertain"]},
                "justification": {"type": "string", "description": "One-paragraph justification."}
            },
            "required": ["verdict", "justification"]
        }),
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

/// Executor for the sub-agent. Handles the `emit_verdict` tool (capturing the
/// first valid verdict) and surfaces every other tool call as an error
/// observation. Records a faint trail of activity into `transcript`. Plan E
/// may extend this with a real `read_context_range` / `query_findings`
/// dispatcher.
struct ReplExecutor {
    transcript: Mutex<Vec<String>>,
    /// First valid verdict the model emitted, if any. First-wins so a
    /// forced re-call on a later turn can't overwrite the initial answer.
    verdict: Mutex<Option<Verdict>>,
}

impl ReplExecutor {
    fn new() -> Self {
        Self {
            transcript: Mutex::new(Vec::new()),
            verdict: Mutex::new(None),
        }
    }

    fn handle_emit_verdict(&self, call_id: &str, arguments: &str) -> Observation {
        let args: serde_json::Value =
            serde_json::from_str(arguments).unwrap_or(serde_json::Value::Null);
        let parsed = args
            .get("verdict")
            .and_then(|v| v.as_str())
            .and_then(verdict_from_str);
        let justification = args
            .get("justification")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        match parsed {
            Some(verdict) => {
                self.transcript
                    .lock()
                    .expect("hypothesis_repl transcript mutex poisoned")
                    .push(format!("verdict: {} — {justification}", verdict.as_str()));
                let mut slot = self
                    .verdict
                    .lock()
                    .expect("hypothesis_repl verdict mutex poisoned");
                if slot.is_none() {
                    *slot = Some(verdict);
                }
                Observation::tool_result("emit_verdict".to_string(), "verdict recorded".to_string())
                    .with_call_id(call_id.to_string())
            }
            None => Observation::tool_error(
                "emit_verdict".to_string(),
                "verdict must be one of: reproduced | refuted | uncertain".to_string(),
            )
            .with_call_id(call_id.to_string()),
        }
    }
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
                    arguments,
                } if name == "emit_verdict" => {
                    Some(self.handle_emit_verdict(call_id, arguments))
                }
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
                            "hypothesis_repl sub-agent exposes only emit_verdict in Plan D"
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
/// envelope fails. All other failures (including a model that never emits a
/// valid verdict) collapse to an `Uncertain` verdict.
pub async fn run(input: ReplInput) -> Result<ReplOutput> {
    let executor = Arc::new(ReplExecutor::new());
    let executor_for_orga: Arc<dyn ActionExecutor> = executor.clone();
    let orga = CoderedOrga::new(executor_for_orga)
        .context("building CoderedOrga for hypothesis_repl")?;

    let system = "You are a focused, skeptical verifier. The user gives you ONE hypothesis \
         about a code-security claim. Reason about it briefly, then record your conclusion by \
         calling the `emit_verdict` tool exactly once (reproduced / refuted / uncertain) with a \
         one-paragraph justification."
        .to_string();
    let mut conv = Conversation::new();
    conv.push(ConversationMessage::system(system));
    conv.push(ConversationMessage::user(input.hypothesis_text.clone()));

    let cfg = LoopConfig {
        tool_definitions: vec![emit_verdict_tool()],
        // Force the verdict tool so a prose-only turn can't terminate the loop
        // without recording a verdict (the historic freeform-parse failure).
        tool_choice: Some(ToolChoice::Tool {
            name: "emit_verdict".to_string(),
        }),
        // Fable 5 / Opus reject an explicit `temperature`; 0.0 hits the omit path.
        temperature: 0.0,
        // Honor the caller's budget (previously accepted but never wired into
        // the loop). With no investigative tools this is effectively single-shot.
        max_iterations: input.budget_iterations.max(1),
        ..LoopConfig::default()
    };
    let agent_id = AgentId::new();
    let result = orga.run(agent_id, conv, cfg).await;
    let verdict = executor
        .verdict
        .lock()
        .expect("hypothesis_repl verdict mutex poisoned")
        .clone()
        .unwrap_or(Verdict::Uncertain);

    // Persist the transcript as an EvidenceEnvelope so the parent agent can
    // cite it via Citation::Hypothesis::intended_poc. The scan_id mirrors
    // static_hunter's "<prefix>-<engagement[:8]>" convention.
    let transcript = executor
        .transcript
        .lock()
        .expect("hypothesis_repl transcript mutex poisoned")
        .join("\n");
    let body = format!(
        "hypothesis: {}\n\nverdict: {}\n\nresponse:\n{}\n\ntranscript:\n{}",
        input.hypothesis_text,
        verdict.as_str(),
        result.output,
        transcript
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
    fn verdict_from_str_maps_known_and_rejects_unknown() {
        assert_eq!(verdict_from_str("reproduced"), Some(Verdict::Reproduced));
        assert_eq!(verdict_from_str("REFUTED"), Some(Verdict::Refuted));
        assert_eq!(verdict_from_str("uncertain"), Some(Verdict::Uncertain));
        assert_eq!(verdict_from_str("maybe"), None);
        // Substring of a verdict word must NOT match (the old freeform bug).
        assert_eq!(verdict_from_str("not refuted"), None);
    }

    /// `emit_verdict` captures the first valid verdict and returns a success
    /// observation correlated by call_id.
    #[tokio::test]
    async fn repl_executor_captures_emit_verdict() {
        let exec = ReplExecutor::new();
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "emit_verdict".into(),
            arguments: r#"{"verdict":"refuted","justification":"input is sanitized"}"#.into(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].is_error);
        assert_eq!(obs[0].call_id.as_deref(), Some("c1"));
        assert_eq!(*exec.verdict.lock().unwrap(), Some(Verdict::Refuted));
    }

    /// An invalid verdict value is a tool error and captures nothing.
    #[tokio::test]
    async fn repl_executor_rejects_invalid_verdict() {
        let exec = ReplExecutor::new();
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "emit_verdict".into(),
            arguments: r#"{"verdict":"maybe","justification":"x"}"#.into(),
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
        assert!(exec.verdict.lock().unwrap().is_none());
    }

    /// A non-emit_verdict tool call produces one error observation and
    /// preserves the call_id so the loop can correlate the result.
    #[tokio::test]
    async fn repl_executor_errors_on_other_tool_calls() {
        let exec = ReplExecutor::new();
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
        assert!(obs[0].content.contains("only emit_verdict"));
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
        let exec = ReplExecutor::new();
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
