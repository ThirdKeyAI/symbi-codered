//! Plan D smoke test: confirm `CoderedOrga` successfully runs one turn
//! through Symbiont's `ReasoningLoopRunner` against the real Anthropic API.
//!
//! Run with:
//!
//! ```bash
//! ANTHROPIC_API_KEY=sk-... cargo test -j2 -p symbi-codered-core \
//!   --test orga_smoke -- --ignored
//! ```
//!
//! Ignored by default because it makes a live network call.

use std::sync::Arc;

use async_trait::async_trait;
use symbi_codered_core::orga::CoderedOrga;
use symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry;
use symbi_runtime::reasoning::conversation::ConversationMessage;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::{LoopConfig, Observation, ProposedAction};
use symbi_runtime::reasoning::Conversation;
use symbi_runtime::types::AgentId;

/// Tool-less executor: the smoke test deliberately uses a system prompt
/// that should drive the LLM to `Respond` immediately, so no tool calls
/// are expected. If the LLM does attempt a tool call, we return an empty
/// observation set — and the fail-closed `DefaultPolicyGate` inside
/// `CoderedOrga` would have denied it anyway.
struct NoopExecutor;

#[async_trait]
impl ActionExecutor for NoopExecutor {
    async fn execute_actions(
        &self,
        _actions: &[ProposedAction],
        _config: &LoopConfig,
        _circuit_breakers: &CircuitBreakerRegistry,
    ) -> Vec<Observation> {
        Vec::new()
    }
}

#[tokio::test]
#[ignore]
async fn orga_runs_one_turn_against_real_anthropic_api() {
    let executor: Arc<dyn ActionExecutor> = Arc::new(NoopExecutor);
    let orga = CoderedOrga::new(executor).expect("build CoderedOrga from env");

    let mut conv = Conversation::new();
    conv.push(ConversationMessage::system(
        "You are a helpful assistant. Reply with exactly the word 'pong' \
         and nothing else.",
    ));
    conv.push(ConversationMessage::user("ping"));

    let cfg = LoopConfig::default();
    let result = orga.run(AgentId::new(), conv, cfg).await;

    assert!(
        result.output.to_lowercase().contains("pong"),
        "expected 'pong' in response, got: {:?} (termination: {:?})",
        result.output,
        result.termination_reason
    );
}
