//! Resolve the devils_advocate model chain from CLI flags + env, and parse
//! `provider:model` fallback tiers. Pure + unit-tested; the command layer feeds
//! it flag/env values and runs the resulting chain.

use anyhow::{bail, Result};

const PROVIDERS: [&str; 3] = ["anthropic", "openai", "openrouter"];

/// Default model for an OpenRouter advocate when `--advocate-model` is omitted.
/// gemini-2.5-pro is non-Anthropic (so it won't mirror the Opus generation
/// tier) and drives the advocate's `query_findings`/`advocate_finding` tools
/// reliably — unlike gpt-5.x via OpenRouter, which was observed to answer in
/// prose and emit zero verdicts.
const DEFAULT_OPENROUTER_ADVOCATE_MODEL: &str = "google/gemini-2.5-pro";

/// Raw advocate model inputs from one source (flags, or env). All optional.
#[derive(Default, Clone)]
pub struct AdvModelInput {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub fallback: Option<String>,
}

/// Parse one `provider:model` fallback tier. `model` may contain `/` and `:`.
pub fn parse_tier_token(tok: &str) -> Result<(String, String)> {
    let (prov, model) = tok
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid advocate tier {tok:?}: expected provider:model"))?;
    let prov = prov.trim().to_ascii_lowercase();
    let model = model.trim().to_string();
    if !PROVIDERS.contains(&prov.as_str()) {
        bail!("unknown provider {prov:?} in advocate tier {tok:?}; expected one of {PROVIDERS:?}");
    }
    if model.is_empty() {
        bail!("empty model in advocate tier {tok:?}");
    }
    Ok((prov, model))
}

/// Flags override env per field. Returns the resolved `(provider, model)` run
/// chain: `[primary] ++ fallback` when a primary is configured, else empty
/// (legacy: the advocate uses the env-default single-tier path).
pub fn resolve_advocate_chain(flags: AdvModelInput, env: AdvModelInput) -> Result<Vec<(String, String)>> {
    let provider = flags.provider.or(env.provider);
    let model = flags.model.or(env.model);
    let fallback = flags.fallback.or(env.fallback);

    let primary = match (provider, model) {
        (Some(p), Some(m)) => {
            let p = p.trim().to_ascii_lowercase();
            if !PROVIDERS.contains(&p.as_str()) {
                bail!("unknown --advocate-provider {p:?}; expected one of {PROVIDERS:?}");
            }
            Some((p, m.trim().to_string()))
        }
        // Provider given without a model: openrouter gets a sensible default
        // (gemini-2.5-pro); other providers still require an explicit model.
        (Some(p), None) => {
            let p = p.trim().to_ascii_lowercase();
            if p == "openrouter" {
                Some((p, DEFAULT_OPENROUTER_ADVOCATE_MODEL.to_string()))
            } else if PROVIDERS.contains(&p.as_str()) {
                bail!("--advocate-provider {p:?} requires --advocate-model (no built-in default)");
            } else {
                bail!("unknown --advocate-provider {p:?}; expected one of {PROVIDERS:?}");
            }
        }
        (None, None) => None,
        (None, Some(_)) => bail!("--advocate-model requires --advocate-provider"),
    };

    let fallback_tiers: Vec<(String, String)> = match fallback {
        Some(f) if !f.trim().is_empty() => f
            .split(',')
            .map(|t| parse_tier_token(t.trim()))
            .collect::<Result<_>>()?,
        _ => Vec::new(),
    };

    match primary {
        Some(p) => {
            let mut chain = vec![p];
            chain.extend(fallback_tiers);
            Ok(chain)
        }
        None => {
            if !fallback_tiers.is_empty() {
                bail!("--advocate-fallback requires --advocate-provider/--advocate-model");
            }
            Ok(Vec::new())
        }
    }
}

/// Resolve the advocate model chain from flags + env, emit mirror warnings
/// (warn-only, never blocks), and return the chain for `AdvocateInput.model_chain`.
pub fn resolve_and_warn_advocate_chain(
    flags: AdvModelInput,
    env: AdvModelInput,
    gen_model: &str,
) -> Result<Vec<(String, String)>> {
    let model_chain = resolve_advocate_chain(flags, env)?;

    // Mirror check: the run chain if configured, else the env-default tier (so
    // the default, silently-mirroring advocate is still warned about). Keyed off
    // the actual generation model (the selected --model-profile), not a constant.
    let check: Vec<(String, String)> = if model_chain.is_empty() {
        symbi_codered_core::orga::detect_env_default_tier().into_iter().collect()
    } else {
        model_chain.clone()
    };
    for idx in symbi_codered_core::orga::mirroring_tiers_for(gen_model, &check) {
        let (p, m) = &check[idx];
        if model_chain.is_empty() {
            tracing::warn!(
                "advocate is using the generation model {p}:{m}; pass \
                 --advocate-provider/--advocate-model for an independent review"
            );
        } else {
            // 1-based tier numbering for human-facing logs.
            tracing::warn!(
                "advocate tier {} ({p}:{m}) mirrors the generation model; \
                 independence is not guaranteed for that tier",
                idx + 1
            );
        }
    }
    Ok(model_chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inp(p: Option<&str>, m: Option<&str>, f: Option<&str>) -> AdvModelInput {
        AdvModelInput {
            provider: p.map(String::from),
            model: m.map(String::from),
            fallback: f.map(String::from),
        }
    }

    #[test]
    fn flags_override_env() {
        let chain = resolve_advocate_chain(
            inp(Some("openai"), Some("gpt-4o"), None),
            inp(Some("anthropic"), Some("claude-opus-4-7"), None),
        )
        .unwrap();
        assert_eq!(chain, vec![("openai".to_string(), "gpt-4o".to_string())]);
    }

    #[test]
    fn env_used_when_flags_absent() {
        let chain = resolve_advocate_chain(
            AdvModelInput::default(),
            inp(Some("openrouter"), Some("google/gemini-2.5-pro"), None),
        )
        .unwrap();
        assert_eq!(chain, vec![("openrouter".to_string(), "google/gemini-2.5-pro".to_string())]);
    }

    #[test]
    fn neither_set_is_empty_legacy_chain() {
        let chain = resolve_advocate_chain(AdvModelInput::default(), AdvModelInput::default()).unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn primary_plus_fallback_builds_full_chain() {
        let chain = resolve_advocate_chain(
            inp(Some("openai"), Some("gpt-4o"), Some("openrouter:google/gemini-2.5-pro,anthropic:claude-opus-4-7")),
            AdvModelInput::default(),
        )
        .unwrap();
        assert_eq!(
            chain,
            vec![
                ("openai".to_string(), "gpt-4o".to_string()),
                ("openrouter".to_string(), "google/gemini-2.5-pro".to_string()),
                ("anthropic".to_string(), "claude-opus-4-7".to_string()),
            ]
        );
    }

    #[test]
    fn partial_primary_errors() {
        assert!(resolve_advocate_chain(inp(Some("openai"), None, None), AdvModelInput::default()).is_err());
    }

    #[test]
    fn openrouter_without_model_defaults_to_gemini() {
        let chain =
            resolve_advocate_chain(inp(Some("openrouter"), None, None), AdvModelInput::default())
                .unwrap();
        assert_eq!(
            chain,
            vec![("openrouter".to_string(), super::DEFAULT_OPENROUTER_ADVOCATE_MODEL.to_string())]
        );
    }

    #[test]
    fn model_without_provider_errors() {
        assert!(resolve_advocate_chain(inp(None, Some("gpt-4o"), None), AdvModelInput::default()).is_err());
    }

    #[test]
    fn fallback_without_primary_errors() {
        assert!(resolve_advocate_chain(
            inp(None, None, Some("openai:gpt-4o")),
            AdvModelInput::default()
        )
        .is_err());
    }

    #[test]
    fn unknown_provider_token_errors() {
        assert!(parse_tier_token("groq:llama-3").is_err());
    }

    #[test]
    fn tier_token_allows_slash_and_colon_in_model() {
        assert_eq!(
            parse_tier_token("openrouter:openai/gpt-4o:nitro").unwrap(),
            ("openrouter".to_string(), "openai/gpt-4o:nitro".to_string())
        );
    }
}
