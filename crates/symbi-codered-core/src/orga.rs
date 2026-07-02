//! codered's wrapper around Symbiont's `ReasoningLoopRunner` (the ORGA loop).
//!
//! This wrapper bakes in the policy-relevant defaults for codered:
//!
//! * **Inference provider:** [`CloudInferenceProvider::from_env`], which
//!   walks `OPENROUTER_API_KEY` → `OPENAI_API_KEY` → `ANTHROPIC_API_KEY` and
//!   builds an `LlmClient` for the first one it finds. Anthropic is the
//!   documented path for Plan D's pattern_scout / chain_builder /
//!   hypothesis_repl agents, but operators can override via env.
//! * **Policy gate:** [`DefaultPolicyGate::new`] (fail-closed). Plan E may
//!   swap this for a Cedar-backed gate that delegates to codered's
//!   [`crate::policy::PolicyEngine`].
//! * **Action executor:** caller-supplied. The builder takes an
//!   `Arc<dyn ActionExecutor>` so each codered agent can plug its own tool
//!   registry in.
//! * **Journal / context manager / circuit breakers:** Symbiont's defaults
//!   ([`BufferedJournal`], [`DefaultContextManager`],
//!   [`CircuitBreakerRegistry::default`]). Later tasks may swap the journal
//!   for a sink that appends to codered's audit journal.
//!
//! The wrapper is intentionally thin: it constructs the runner and forwards
//! [`run`](CoderedOrga::run). Tool registration and conversation seeding
//! belong to the calling agent.
//!
//! [`BufferedJournal`]: symbi_runtime::reasoning::loop_types::BufferedJournal
//! [`DefaultContextManager`]: symbi_runtime::reasoning::context_manager::DefaultContextManager
//! [`CircuitBreakerRegistry::default`]: symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry

use anyhow::{anyhow, Result};
use std::sync::Arc;

use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::inference::InferenceProvider;
use symbi_runtime::reasoning::loop_types::{LoopConfig, LoopResult};
use symbi_runtime::reasoning::policy_bridge::DefaultPolicyGate;
use symbi_runtime::reasoning::providers::cloud::CloudInferenceProvider;
use symbi_runtime::reasoning::reasoning_loop::ReasoningLoopRunner;
use symbi_runtime::reasoning::Conversation;
use symbi_runtime::types::AgentId;

/// Thin wrapper around Symbiont's [`ReasoningLoopRunner`] configured for
/// codered's agents. See the module docs for the policy decisions baked in.
pub struct CoderedOrga {
    runner: ReasoningLoopRunner,
}

impl CoderedOrga {
    /// Build a runner from environment-derived credentials.
    ///
    /// Returns an error if no supported LLM API key is present in the
    /// environment. `CloudInferenceProvider::from_env` checks
    /// `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, then `ANTHROPIC_API_KEY` —
    /// for Plan D agents, `ANTHROPIC_API_KEY` is the documented happy path.
    pub fn new(executor: Arc<dyn ActionExecutor>) -> Result<Self> {
        let provider: Arc<dyn InferenceProvider> = Arc::new(
            CloudInferenceProvider::from_env().ok_or_else(|| {
                anyhow!(
                    "no LLM API key found in environment; \
                     set ANTHROPIC_API_KEY (preferred for codered) \
                     or OPENAI_API_KEY / OPENROUTER_API_KEY"
                )
            })?,
        );

        Ok(Self::with_provider(provider, executor))
    }

    /// Build a runner with a specific Anthropic model. Stages that need
    /// deep cross-file reasoning (pattern_scout, chain_builder, reflector,
    /// poc_forge Tier B) should request Opus; mechanical / pattern-match
    /// stages (poc_forge Tier A, devils_advocate) stay on Sonnet for cost.
    ///
    /// Implementation: symbi-runtime's `LlmClient::from_env` reads
    /// `ANTHROPIC_MODEL` to pick the model. We mutate that env var for the
    /// duration of the provider construction and restore it afterward, so
    /// callers don't have to manage the env themselves. A process-wide
    /// mutex serializes the env mutation across concurrent constructions.
    pub fn with_model(model: &str, executor: Arc<dyn ActionExecutor>) -> Result<Self> {
        Self::with_provider_and_model("anthropic", model, executor)
    }

    /// Build a runner for a specific (provider, model) combination.
    /// Provider must be `"anthropic"`, `"openrouter"`, or `"openai"`.
    /// The function temporarily mutates env so symbi-runtime's
    /// `LlmClient::from_env` resolves the right provider+model regardless
    /// of which API keys are present. All other keys are hidden during
    /// construction so the first-match precedence doesn't fall through to
    /// the wrong provider.
    ///
    /// Used by [`run_with_fallback`] to route between Anthropic-direct
    /// and OpenRouter when the primary provider hits an
    /// `overloaded_error` 503.
    pub fn with_provider_and_model(
        provider: &str,
        model: &str,
        executor: Arc<dyn ActionExecutor>,
    ) -> Result<Self> {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Snapshot every env var we may mutate so restoration is exact.
        let keys = [
            "OPENROUTER_API_KEY",
            "OPENROUTER_MODEL",
            "OPENAI_API_KEY",
            "CHAT_MODEL",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_MODEL",
        ];
        let snapshot: Vec<(&str, Option<String>)> = keys
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();

        // Hide every API key except the one we want, then set the
        // corresponding model. LlmClient::from_env checks
        // OpenRouter → OpenAI → Anthropic in that order; hiding the
        // others guarantees the right branch fires.
        match provider {
            "anthropic" => {
                std::env::remove_var("OPENROUTER_API_KEY");
                std::env::remove_var("OPENAI_API_KEY");
                std::env::set_var("ANTHROPIC_MODEL", model);
            }
            "openrouter" => {
                // Hide the competing keys so that if OPENROUTER_API_KEY is
                // absent, from_env returns None (clean "no usable key" error +
                // fallback skip) instead of silently falling through to
                // Anthropic/OpenAI and constructing the wrong provider.
                std::env::remove_var("OPENAI_API_KEY");
                std::env::remove_var("ANTHROPIC_API_KEY");
                std::env::set_var("OPENROUTER_MODEL", model);
            }
            "openai" => {
                std::env::remove_var("OPENROUTER_API_KEY");
                std::env::remove_var("ANTHROPIC_API_KEY");
                std::env::set_var("CHAT_MODEL", model);
            }
            other => {
                // Restore before erroring so we don't leak the mutated state.
                for (k, v) in snapshot {
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                }
                return Err(anyhow!(
                    "unknown provider {other:?}; expected anthropic|openrouter|openai"
                ));
            }
        }

        let provider_opt = CloudInferenceProvider::from_env();

        // Restore all env vars regardless of construction outcome.
        for (k, v) in snapshot {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }

        let inference: Arc<dyn InferenceProvider> = Arc::new(provider_opt.ok_or_else(|| {
            anyhow!(
                "no LLM API key found for provider {provider:?}; \
                 set the matching API key env var \
                 (ANTHROPIC_API_KEY / OPENROUTER_API_KEY / OPENAI_API_KEY)"
            )
        })?);
        Ok(Self::with_provider(inference, executor))
    }

    /// Build a runner with a caller-supplied inference provider.
    ///
    /// Useful for tests (stub provider) and for callers that want to
    /// resolve API keys from a `SecretStore` via
    /// [`CloudInferenceProvider::from_env_or_secrets`] before handing the
    /// provider over.
    pub fn with_provider(
        provider: Arc<dyn InferenceProvider>,
        executor: Arc<dyn ActionExecutor>,
    ) -> Self {
        // Symbiont's DefaultPolicyGate is fail-closed for ToolCall/Delegate
        // by design. codered's policy enforcement happens INSIDE each
        // executor (via PolicyEngine::evaluate_with_attrs) rather than at
        // the gate, so for now we opt into permissive mode here. A proper
        // Cedar-backed ReasoningPolicyGate that delegates to codered's
        // PolicyEngine is Plan F (or later) work.
        let permissive = std::env::var("SYMBI_INSECURE_ALLOW_ALL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let gate = if permissive {
            tracing::warn!(
                "CoderedOrga: using DefaultPolicyGate::permissive_for_dev_only — \
                 tool dispatch enforcement relies on executor-side Cedar checks. \
                 Set SYMBI_INSECURE_ALLOW_ALL=0 to switch to the fail-closed gate."
            );
            DefaultPolicyGate::permissive_for_dev_only()
        } else {
            DefaultPolicyGate::new()
        };
        let runner = ReasoningLoopRunner::builder()
            .provider(provider)
            .executor(executor)
            .policy_gate(Arc::new(gate))
            .build();
        Self { runner }
    }

    /// Run the reasoning loop. See [`ReasoningLoopRunner::run`] for
    /// termination semantics.
    pub async fn run(
        &self,
        agent_id: AgentId,
        conversation: Conversation,
        config: LoopConfig,
    ) -> LoopResult {
        self.runner.run(agent_id, conversation, config).await
    }
}

/// One tier in a fallback chain: (provider, model). Provider must be one
/// of the strings accepted by [`CoderedOrga::with_provider_and_model`].
pub type FallbackTier<'a> = (&'a str, &'a str);

/// The model chain the finding-GENERATION stages (pattern_scout, chain_builder,
/// reflector) run on. Single source of truth so mirror detection knows what the
/// advocate must NOT mirror. Tier 0 is the generation reference.
pub const GENERATION_CHAIN: &[FallbackTier<'static>] = &[
    ("anthropic", "claude-fable-5"),
    ("openrouter", "anthropic/claude-opus-4.8"),
    ("anthropic", "claude-sonnet-4-6"),
];

/// A selectable generation-model preset. Bundles the genuinely model-varying
/// knobs — the fallback chain and rough list pricing — so `codered hunt
/// --model-profile <name>` can switch the whole generator without recompiling.
/// The model-agnostic optimizations (tool_choice=Any, temperature omit, 120K
/// context budget) stay on for every profile and are NOT gated here.
pub struct ModelProfile {
    pub name: &'static str,
    /// Generation fallback chain; tier 0 is the generation reference used by
    /// advocate mirror-detection.
    pub chain: &'static [FallbackTier<'static>],
    /// Rough USD-per-million-token list price, for the cost signal only.
    pub cost_in_per_mtok: f64,
    pub cost_out_per_mtok: f64,
}

/// Default: Fable 5 lead, OpenRouter Opus 4.8 overload path, Sonnet 4.6 degraded.
pub const PROFILE_FABLE5: ModelProfile = ModelProfile {
    name: "fable5",
    chain: GENERATION_CHAIN,
    cost_in_per_mtok: 10.0,
    cost_out_per_mtok: 50.0,
};

/// Opus 4.8 lead — for the deepest cross-file reasoning at higher cost.
pub const PROFILE_OPUS: ModelProfile = ModelProfile {
    name: "opus",
    chain: &[
        ("anthropic", "claude-opus-4-8"),
        ("openrouter", "anthropic/claude-opus-4.8"),
        ("anthropic", "claude-sonnet-4-6"),
    ],
    cost_in_per_mtok: 15.0,
    cost_out_per_mtok: 75.0,
};

/// Sonnet 4.6 lead — cheapest, for high-volume or budget-constrained runs.
pub const PROFILE_SONNET: ModelProfile = ModelProfile {
    name: "sonnet",
    chain: &[
        ("anthropic", "claude-sonnet-4-6"),
        ("openrouter", "anthropic/claude-sonnet-4-6"),
    ],
    cost_in_per_mtok: 3.0,
    cost_out_per_mtok: 15.0,
};

/// Example: a fully-local run against Ollama serving a Qwen coder model
/// through its OpenAI-compatible API. No per-token cost. Requires:
///   OPENAI_BASE_URL=http://<ollama-host>:11434/v1
///   OPENAI_API_KEY=ollama            # any non-empty token; Ollama ignores it
///   plus `ollama pull qwen2.5-coder:32b` (or edit the model below).
/// Note: the runtime's OpenAI-path SSRF guard may reject private/link-local
/// hosts — allowlist the Ollama host if the connection is refused.
pub const PROFILE_OLLAMA_QWEN: ModelProfile = ModelProfile {
    name: "ollama-qwen",
    chain: &[("openai", "qwen2.5-coder:32b")],
    cost_in_per_mtok: 0.0,
    cost_out_per_mtok: 0.0,
};

/// All selectable profiles, in listing order. First entry is the default.
pub const MODEL_PROFILES: &[&ModelProfile] =
    &[&PROFILE_FABLE5, &PROFILE_OPUS, &PROFILE_SONNET, &PROFILE_OLLAMA_QWEN];

/// The profile used when none is requested.
pub const DEFAULT_PROFILE: &ModelProfile = &PROFILE_FABLE5;

/// Resolve a profile by name (case-insensitive). `None` for an unknown name so
/// the CLI can list the valid choices.
pub fn profile_by_name(name: &str) -> Option<&'static ModelProfile> {
    let n = name.trim().to_ascii_lowercase();
    MODEL_PROFILES.iter().copied().find(|p| p.name == n)
}

/// Comma-separated list of valid profile names, for error messages.
pub fn profile_names() -> String {
    MODEL_PROFILES
        .iter()
        .map(|p| p.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The resolved generation config for a run: an owned (provider, model) chain
/// plus its cost basis and a human label. Produced from a preset profile and/or
/// the `CODERED_GENERATION_*` env override.
pub struct ResolvedGeneration {
    pub chain: Vec<(String, String)>,
    pub cost_in_per_mtok: f64,
    pub cost_out_per_mtok: f64,
    pub label: String,
}

/// Parse a comma-separated `provider:model` tier list, e.g.
/// `"openrouter:anthropic/claude-opus-4.8,anthropic:claude-sonnet-4-6"`.
/// Splits each tier on its FIRST `:` so model names may contain colons
/// (e.g. Ollama's `qwen2.5-coder:32b`). Malformed tiers are skipped.
pub fn parse_tiers(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(|t| {
            let (p, m) = t.trim().split_once(':')?;
            if p.is_empty() || m.is_empty() {
                return None;
            }
            Some((p.to_string(), m.to_string()))
        })
        .collect()
}

/// Resolve the generation model config. Precedence (highest first):
///   1. `CODERED_GENERATION_PROVIDER` + `CODERED_GENERATION_MODEL`
///      (+ optional `CODERED_GENERATION_FALLBACK`) → a custom chain, priced
///      against the named/default preset as a rough basis.
///   2. `profile_flag` (e.g. from `--model-profile`).
///   3. `CODERED_MODEL_PROFILE` env.
///   4. [`DEFAULT_PROFILE`].
///
/// Returns `Err` (with the valid names) if the requested profile is unknown.
pub fn resolve_generation(profile_flag: Option<&str>) -> Result<ResolvedGeneration> {
    let name = profile_flag
        .map(str::to_string)
        .or_else(|| std::env::var("CODERED_MODEL_PROFILE").ok())
        .unwrap_or_else(|| DEFAULT_PROFILE.name.to_string());
    let profile = profile_by_name(&name).ok_or_else(|| {
        anyhow!("unknown model profile {name:?}; valid: {}", profile_names())
    })?;

    // Raw env override replaces the chain; the preset's price is kept as the
    // rough cost basis (a custom model's true price is unknown here).
    let gen_provider = std::env::var("CODERED_GENERATION_PROVIDER").ok();
    let gen_model = std::env::var("CODERED_GENERATION_MODEL").ok();
    if let (Some(p), Some(m)) = (gen_provider.as_deref(), gen_model.as_deref()) {
        if !p.is_empty() && !m.is_empty() {
            let mut chain = vec![(p.to_string(), m.to_string())];
            if let Ok(fb) = std::env::var("CODERED_GENERATION_FALLBACK") {
                chain.extend(parse_tiers(&fb));
            }
            return Ok(ResolvedGeneration {
                chain,
                cost_in_per_mtok: profile.cost_in_per_mtok,
                cost_out_per_mtok: profile.cost_out_per_mtok,
                label: format!("custom:{p}:{m}"),
            });
        }
    }

    Ok(ResolvedGeneration {
        chain: profile
            .chain
            .iter()
            .map(|(p, m)| (p.to_string(), m.to_string()))
            .collect(),
        cost_in_per_mtok: profile.cost_in_per_mtok,
        cost_out_per_mtok: profile.cost_out_per_mtok,
        label: profile.name.to_string(),
    })
}

/// Provider-independent model identity, so aliases collapse to one family:
/// drops a routing prefix (`anthropic/claude-opus-4.7` -> `claude-opus-4.7`)
/// and normalizes version punctuation (`.` -> `-`), lowercased. Used only for
/// mirror detection. Provider is intentionally not part of the identity — the
/// model string already names the family across providers.
pub fn canonical_model_id(model: &str) -> String {
    let lower = model.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    base.replace('.', "-")
}

/// Indices of advocate tiers whose model is the same family as the generation
/// reference (`GENERATION_CHAIN[0]`). A non-empty result means the advocate
/// would partly mirror the generator — the caller warns but never blocks.
pub fn mirroring_tiers(tiers: &[(String, String)]) -> Vec<usize> {
    mirroring_tiers_for(GENERATION_CHAIN[0].1, tiers)
}

/// Like [`mirroring_tiers`] but against an explicit generation reference model,
/// so mirror-detection tracks the selected `--model-profile` rather than the
/// hardcoded default.
pub fn mirroring_tiers_for(gen_model: &str, tiers: &[(String, String)]) -> Vec<usize> {
    let gen = canonical_model_id(gen_model);
    tiers
        .iter()
        .enumerate()
        .filter(|(_, (_, model))| canonical_model_id(model) == gen)
        .map(|(i, _)| i)
        .collect()
}

/// Pure provider/model detection, parameterized over a key lookup so it can be
/// unit-tested without mutating the process environment. Mirrors
/// `CloudInferenceProvider::from_env`'s order and documented defaults.
pub(crate) fn detect_tier(get: impl Fn(&str) -> Option<String>) -> Option<(String, String)> {
    if get("OPENROUTER_API_KEY").is_some() {
        let model = get("OPENROUTER_MODEL").unwrap_or_else(|| "anthropic/claude-sonnet-4-6".to_string());
        return Some(("openrouter".to_string(), model));
    }
    if get("OPENAI_API_KEY").is_some() {
        let model = get("CHAT_MODEL").unwrap_or_else(|| "gpt-4o".to_string());
        return Some(("openai".to_string(), model));
    }
    if get("ANTHROPIC_API_KEY").is_some() {
        let model = get("ANTHROPIC_MODEL").unwrap_or_else(|| "claude-sonnet-4-6".to_string());
        return Some(("anthropic".to_string(), model));
    }
    None
}

/// Best-effort: the `(provider, model)` an unconfigured stage would resolve to
/// from the current environment. Used only to decide whether to warn that the
/// default advocate mirrors the generator; never used to run.
pub fn detect_env_default_tier() -> Option<(String, String)> {
    detect_tier(|k| std::env::var(k).ok())
}

/// Run a reasoning loop against a chain of (provider, model) tiers. On
/// each tier, if the loop terminates at iteration 0 with zero prompt
/// tokens consumed (the signature of a 503/overload/unavailable response
/// rejecting the first inference call), move to the next tier. The
/// first tier that produces progress — or, if all tiers fail, the last
/// LoopResult — is returned.
///
/// Typical chain for reasoning-heavy stages (pattern_scout / chain_builder
/// / reflector):
///
///   1. ("anthropic", "claude-fable-5")             — preferred, lowest latency
///   2. ("openrouter", "anthropic/claude-opus-4.8") — Anthropic-overloaded path (different pool)
///   3. ("anthropic", "claude-sonnet-4-6")          — quality-degraded but always running
///
/// The conversation is cloned per attempt so the next tier gets a fresh
/// seed; configs are cloned the same way. Tiers that fail to construct
/// (missing API key for the provider) are skipped with a warning rather
/// than aborting the whole chain — same shape as an overloaded_error.
pub async fn run_with_fallback(
    executor: Arc<dyn ActionExecutor>,
    agent_id: AgentId,
    conversation: Conversation,
    config: LoopConfig,
    chain: &[FallbackTier<'_>],
) -> Result<LoopResult> {
    if chain.is_empty() {
        return Err(anyhow!("fallback chain is empty"));
    }

    let mut last_result: Option<LoopResult> = None;
    for (idx, (provider, model)) in chain.iter().enumerate() {
        let conv = conversation.clone();
        let cfg = config.clone();
        let orga = match CoderedOrga::with_provider_and_model(provider, model, executor.clone()) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(
                    tier = idx,
                    provider = provider,
                    model = model,
                    error = %e,
                    "fallback tier could not construct provider; skipping"
                );
                continue;
            }
        };
        // Each tier needs its own agent_id — the runtime tracks usage per
        // agent and reusing the id across tiers conflates token counters.
        // AgentId is Copy.
        let aid = if idx == 0 { agent_id } else { AgentId::new() };
        let result = orga.run(aid, conv, cfg).await;
        let made_no_progress =
            result.iterations == 0 && result.total_usage.prompt_tokens == 0;
        if !made_no_progress {
            if idx > 0 {
                tracing::info!(
                    tier = idx,
                    provider = provider,
                    model = model,
                    "fallback tier produced progress"
                );
            }
            return Ok(result);
        }
        tracing::warn!(
            tier = idx,
            provider = provider,
            model = model,
            "tier produced 0 iterations and 0 prompt tokens — \
             trying next tier (likely overloaded_error / quota / model unavailable)"
        );
        last_result = Some(result);
    }

    // Every tier either failed to construct or ran without progress. If at least
    // one tier RAN (produced an empty result), surface it so the caller can do
    // zero-progress accounting. If NONE constructed (e.g. no API key for any
    // provider in the chain), there is nothing to return — fail loudly rather
    // than panic.
    match last_result {
        Some(r) => Ok(r),
        None => {
            let tiers: Vec<String> = chain.iter().map(|(p, m)| format!("{p}:{m}")).collect();
            Err(anyhow!(
                "all fallback tiers failed to construct (no usable provider/API key for: [{}])",
                tiers.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use symbi_runtime::reasoning::executor::DefaultActionExecutor;

    /// Serializes any test in this module that mutates process-global LLM
    /// env vars. Cargo runs tests in parallel by default, so without this
    /// guard a future env-touching test could race with
    /// `new_errors_without_api_key` and produce flaky failures.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// `CoderedOrga::new` must fail loudly when no LLM API key is in the
    /// environment, rather than silently constructing a runner with no
    /// usable provider.
    #[test]
    fn new_errors_without_api_key() {
        // Recover from a poisoned mutex: we only hold the lock for env
        // munging, so prior panics can't have left the env in a worse state
        // than this test is about to scrub anyway.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Save and clear all known LLM env vars so the test is deterministic
        // even when run in a shell that has one set.
        let keys = ["OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"];
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for (k, _) in &saved {
            // Tests share process env; we restore below before the assertion
            // so a failure can't leak state into other tests.
            std::env::remove_var(k);
        }

        let executor: Arc<dyn ActionExecutor> = Arc::new(DefaultActionExecutor::default());
        let result = CoderedOrga::new(executor);

        // Restore env before asserting.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }

        assert!(result.is_err(), "expected error when no API key is set");
    }

    /// When EVERY tier fails to construct (no API key for any provider in the
    /// chain), `run_with_fallback` must return a clean `Err` rather than
    /// panicking on `last_result.expect(...)`. We scrub all LLM env vars so
    /// every `with_provider_and_model` call fails to find a key; no tier ever
    /// runs, so the executor is never invoked (a no-op `DefaultActionExecutor`
    /// is fine) and no network/keys are required.
    // The env must stay scrubbed for the whole `run_with_fallback` future, since
    // each tier's `with_provider_and_model` reads it during the awaited call. We
    // hold the sync `ENV_LOCK` across the await deliberately to serialize against
    // the other env-mutating test in this module; an async Mutex wouldn't help —
    // the contention is with a non-async test, and the critical section is the
    // process-global env, not awaited I/O.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn run_with_fallback_errors_when_no_tier_constructs() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let keys = [
            "OPENROUTER_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ];
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }

        let executor: Arc<dyn ActionExecutor> = Arc::new(DefaultActionExecutor::default());
        let chain: &[FallbackTier] = &[
            ("anthropic", "claude-opus-4-7"),
            ("openrouter", "anthropic/claude-opus-4.7"),
        ];
        let result = run_with_fallback(
            executor,
            AgentId::new(),
            Conversation::new(),
            LoopConfig::default(),
            chain,
        )
        .await;

        // Restore env before asserting so a failure can't leak state.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }

        let err = result.expect_err("expected Err when no tier can construct");
        assert!(
            err.to_string().contains("all fallback tiers failed to construct"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn generation_chain_is_the_known_fable_first_chain() {
        assert_eq!(
            super::GENERATION_CHAIN,
            &[
                ("anthropic", "claude-fable-5"),
                ("openrouter", "anthropic/claude-opus-4.8"),
                ("anthropic", "claude-sonnet-4-6"),
            ]
        );
    }

    #[test]
    fn canonical_model_id_normalizes_aliases() {
        use super::canonical_model_id;
        // OpenRouter routing prefix + dotted version collapse to the bare family.
        assert_eq!(canonical_model_id("anthropic/claude-opus-4.7"), "claude-opus-4-7");
        assert_eq!(canonical_model_id("claude-opus-4-7"), "claude-opus-4-7");
        // A genuinely different model stays distinct.
        assert_eq!(canonical_model_id("gpt-4o"), "gpt-4o");
        assert_ne!(canonical_model_id("gpt-4o"), canonical_model_id("claude-opus-4-7"));
    }

    #[test]
    fn mirroring_tiers_flags_only_generator_matches() {
        use super::mirroring_tiers;
        let chain = vec![
            ("openai".to_string(), "gpt-4o".to_string()),                       // independent
            ("openrouter".to_string(), "anthropic/claude-fable-5".to_string()), // MIRROR (alias)
            ("anthropic".to_string(), "claude-fable-5".to_string()),            // MIRROR (direct)
        ];
        assert_eq!(mirroring_tiers(&chain), vec![1, 2]);

        let independent = vec![("openai".to_string(), "gpt-4o".to_string())];
        assert!(mirroring_tiers(&independent).is_empty());
    }

    #[test]
    fn detect_tier_follows_provider_precedence_and_defaults() {
        use super::detect_tier;
        use std::collections::HashMap;
        let mk = |pairs: &[(&str, &str)]| {
            let m: HashMap<String, String> =
                pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            move |k: &str| m.get(k).cloned()
        };
        // OpenRouter wins; its model override is honored.
        assert_eq!(
            detect_tier(mk(&[("OPENROUTER_API_KEY", "x"), ("OPENROUTER_MODEL", "google/gemini-2.5-pro")])),
            Some(("openrouter".to_string(), "google/gemini-2.5-pro".to_string()))
        );
        // OpenAI default model.
        assert_eq!(
            detect_tier(mk(&[("OPENAI_API_KEY", "x")])),
            Some(("openai".to_string(), "gpt-4o".to_string()))
        );
        // Anthropic default model.
        assert_eq!(
            detect_tier(mk(&[("ANTHROPIC_API_KEY", "x")])),
            Some(("anthropic".to_string(), "claude-sonnet-4-6".to_string()))
        );
        // No key -> None.
        assert_eq!(detect_tier(mk(&[])), None);
    }

    #[test]
    fn profile_lookup_and_defaults() {
        use super::{profile_by_name, DEFAULT_PROFILE, PROFILE_FABLE5};
        assert_eq!(profile_by_name("fable5").unwrap().name, "fable5");
        assert_eq!(profile_by_name("OPUS").unwrap().name, "opus"); // case-insensitive
        assert_eq!(profile_by_name(" sonnet ").unwrap().name, "sonnet"); // trimmed
        assert_eq!(profile_by_name("ollama-qwen").unwrap().name, "ollama-qwen");
        assert!(profile_by_name("gpt7").is_none());
        assert_eq!(DEFAULT_PROFILE.name, "fable5");
        // The default profile's chain IS the generation chain.
        assert_eq!(PROFILE_FABLE5.chain, super::GENERATION_CHAIN);
    }

    #[test]
    fn mirroring_tiers_for_uses_explicit_reference() {
        use super::mirroring_tiers_for;
        let chain = vec![
            ("openai".to_string(), "gpt-4o".to_string()),
            ("anthropic".to_string(), "claude-opus-4-8".to_string()),
        ];
        // Against an opus generator, the opus tier mirrors; gpt does not.
        assert_eq!(mirroring_tiers_for("claude-opus-4-8", &chain), vec![1]);
        // Against a fable-5 generator, nothing in this chain mirrors.
        assert!(mirroring_tiers_for("claude-fable-5", &chain).is_empty());
    }

    #[test]
    fn parse_tiers_splits_on_first_colon() {
        use super::parse_tiers;
        // Ollama-style model names contain a colon — must split on the first only.
        assert_eq!(
            parse_tiers("openai:qwen2.5-coder:32b,anthropic:claude-sonnet-4-6"),
            vec![
                ("openai".to_string(), "qwen2.5-coder:32b".to_string()),
                ("anthropic".to_string(), "claude-sonnet-4-6".to_string()),
            ]
        );
        // Malformed tiers are skipped.
        assert!(parse_tiers("garbage, ,").is_empty());
    }

    #[test]
    fn resolve_generation_defaults_to_fable5() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let keys = [
            "CODERED_MODEL_PROFILE",
            "CODERED_GENERATION_PROVIDER",
            "CODERED_GENERATION_MODEL",
            "CODERED_GENERATION_FALLBACK",
        ];
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }

        let default = super::resolve_generation(None).unwrap();
        let opus = super::resolve_generation(Some("opus")).unwrap();
        let unknown = super::resolve_generation(Some("nope"));

        // Env override takes precedence over the preset when set.
        std::env::set_var("CODERED_GENERATION_PROVIDER", "openai");
        std::env::set_var("CODERED_GENERATION_MODEL", "qwen2.5-coder:32b");
        let custom = super::resolve_generation(Some("opus")).unwrap();

        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }

        assert_eq!(default.label, "fable5");
        assert_eq!(default.chain[0].1, "claude-fable-5");
        assert_eq!(opus.chain[0].1, "claude-opus-4-8");
        assert!(unknown.is_err());
        assert_eq!(custom.label, "custom:openai:qwen2.5-coder:32b");
        assert_eq!(custom.chain[0], ("openai".to_string(), "qwen2.5-coder:32b".to_string()));
    }
}
