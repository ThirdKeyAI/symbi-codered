//! Markdown engagement report renderer. Plain `String::push_str` templating —
//! no `tera` / `handlebars` / `askama` dependency. Plan G spec §5.5.
//!
//! Sections produced (in order):
//!   - Title
//!   - Executive Summary (overall + advocate + PoC counters)
//!   - Attack Chains (per stage / finding_id)
//!   - Findings by Severity (Critical → Info subsections, per-finding cards)
//!   - Methodology (boilerplate)
//!   - Reproducibility (specifier_hash + signature verification hint)
//!
//! The renderer is deterministic: callers may rely on identical input
//! producing identical output (the only floating data is `signed_at`, which
//! the caller supplies as a pre-formatted string).

use std::fmt::Write as _;

use symbi_codered_core::db::KnowledgeTriple;
use symbi_evidence_schema::finding::{AdvocateVerdict, PocStatus, Severity};
use symbi_evidence_schema::{AttackChainNode, Finding};

/// Render the engagement report markdown.
pub fn render(
    engagement_id: &str,
    specifier_hash: &str,
    signed_at: &str,
    findings: &[Finding],
    attack_chains: &[AttackChainNode],
    knowledge_triples: &[KnowledgeTriple],
) -> String {
    let mut out = String::new();
    out.push_str("# symbi-codered Engagement Report\n\n");

    render_exec_summary(
        &mut out,
        engagement_id,
        specifier_hash,
        signed_at,
        findings,
        knowledge_triples,
    );
    render_attack_chains(&mut out, attack_chains);
    render_findings_by_severity(&mut out, findings);
    render_methodology(&mut out);
    render_reproducibility(&mut out, engagement_id, specifier_hash);

    out
}

fn render_exec_summary(
    out: &mut String,
    engagement_id: &str,
    specifier_hash: &str,
    signed_at: &str,
    findings: &[Finding],
    knowledge_triples: &[KnowledgeTriple],
) {
    let total = findings.len();
    let confirmed = findings
        .iter()
        .filter(|f| f.advocate_verdict == Some(AdvocateVerdict::Confirmed))
        .count();
    let rebutted = findings
        .iter()
        .filter(|f| f.advocate_verdict == Some(AdvocateVerdict::Rebutted))
        .count();
    let uncertain = findings
        .iter()
        .filter(|f| f.advocate_verdict == Some(AdvocateVerdict::Uncertain))
        .count();
    let reproduced = findings
        .iter()
        .filter(|f| f.poc_status == Some(PocStatus::Reproduced))
        .count();
    let refuted = findings
        .iter()
        .filter(|f| f.poc_status == Some(PocStatus::Refuted))
        .count();

    out.push_str("## Executive Summary\n\n");
    let _ = writeln!(out, "- **engagement_id:** `{engagement_id}`");
    let _ = writeln!(out, "- **specifier_hash:** `{specifier_hash}`");
    let _ = writeln!(out, "- **signed_at:** {signed_at}");
    let _ = writeln!(
        out,
        "- **findings:** {total} total ({confirmed} confirmed, {rebutted} rebutted, {uncertain} uncertain)"
    );
    let _ = writeln!(
        out,
        "- **PoC results:** {reproduced} reproduced, {refuted} refuted"
    );
    let _ = writeln!(
        out,
        "- **knowledge_triples distilled:** {}",
        knowledge_triples.len()
    );
    out.push('\n');
}

fn render_attack_chains(out: &mut String, chains: &[AttackChainNode]) {
    out.push_str("## Attack Chains\n\n");
    if chains.is_empty() {
        out.push_str("_No attack chains recorded._\n\n");
        return;
    }
    for c in chains {
        let stage = serde_json::to_string(&c.stage)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let _ = writeln!(out, "### {} — `{}`", c.id, stage);
        if let Some(fid) = &c.finding_id {
            let _ = writeln!(out, "- finding: `{fid}`");
        }
        if let Some(eid) = &c.evidence_id {
            let _ = writeln!(out, "- evidence: `{eid}`");
        }
        if let Some(next) = &c.next_chain_id {
            let _ = writeln!(out, "- next: `{next}`");
        }
        let _ = writeln!(out, "- rationale: {}", c.rationale);
        out.push('\n');
    }
}

fn render_findings_by_severity(out: &mut String, findings: &[Finding]) {
    out.push_str("## Findings by Severity\n\n");
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let bucket: Vec<&Finding> =
            findings.iter().filter(|f| f.severity == sev).collect();
        if bucket.is_empty() {
            continue;
        }
        let label = severity_label(sev);
        let _ = writeln!(out, "### {label}\n");
        for f in bucket {
            render_finding_card(out, f);
        }
    }
}

fn render_finding_card(out: &mut String, f: &Finding) {
    let _ = writeln!(out, "#### `{}` — {}", f.id, f.title);
    let _ = writeln!(
        out,
        "- **location:** `{}:{}-{}`",
        f.file_path, f.line_start, f.line_end
    );
    if let Some(cwe) = &f.cwe {
        let _ = writeln!(out, "- **CWE:** {cwe}");
    }
    if let Some(owasp) = &f.owasp {
        let _ = writeln!(out, "- **OWASP:** {owasp}");
    }
    let _ = writeln!(
        out,
        "- **advocate_verdict:** {}",
        f.advocate_verdict
            .as_ref()
            .map(advocate_label)
            .unwrap_or("(none)")
    );
    let _ = writeln!(
        out,
        "- **poc_status:** {}",
        f.poc_status.as_ref().map(poc_label).unwrap_or("(none)")
    );
    if let Some(t) = &f.tool_origin {
        let _ = writeln!(out, "- **tool_origin:** {t}");
    }
    let _ = writeln!(out, "- **evidence_envelope_id:** `{}`", f.evidence_envelope_id);
    let _ = writeln!(out, "\n{}\n", f.description);
}

fn render_methodology(out: &mut String) {
    out.push_str("## Methodology\n\n");
    out.push_str(
        "The engagement was driven by the symbi-codered pipeline. Stages, in order:\n\n",
    );
    out.push_str("1. **cartographer** — pure-fact repo enumeration (languages, routes, symbols, dependencies).\n");
    out.push_str("2. **specifier** — pins + Ed25519-signs a threat model (scope, sources, sinks).\n");
    out.push_str("3. **static_hunter** — runs sandboxed analyzers (semgrep / bandit / pip_audit / ruff_security / etc.), Cedar-gated, citation-attached.\n");
    out.push_str("4. **taint_tracer** — mechanical source→sink chain enumeration over the dataflow graph.\n");
    out.push_str("5. **pattern_scout** — LLM agent under ORGA loop; emits hypothesised findings with mandatory citations.\n");
    out.push_str("6. **chain_builder** — LLM agent that stitches findings + taint chains into attack chains.\n");
    out.push_str("7. **poc_forge** — LLM agent that builds + executes minimal reproducers inside a sandbox sidecar.\n");
    out.push_str("8. **devils_advocate** — LLM agent that rebuts each finding; confirms / rebuts / marks uncertain.\n");
    out.push_str("9. **reflector** — LLM agent that distils cross-phase knowledge_triples for future engagements.\n");
    out.push_str("10. **reporter** — this deterministic module; emits SARIF + Markdown + Cedar-filtered engagement-seed.json.\n\n");
}

fn render_reproducibility(out: &mut String, engagement_id: &str, specifier_hash: &str) {
    out.push_str("## Reproducibility\n\n");
    let _ = writeln!(out, "- **specifier_hash:** `{specifier_hash}`");
    let _ = writeln!(
        out,
        "- **engagement_seed signature:** verify with `ed25519-dalek` against `.symbiont/keys/{engagement_id}.pub` over the canonical JSON of `engagement-seed.json` with the `signature` field stripped."
    );
    out.push_str("- **pipeline reproducer:**\n\n");
    out.push_str("```\n");
    out.push_str("codered carto      --target <repo>\n");
    out.push_str("codered specifier  --engagement <id> --target <repo>\n");
    out.push_str("codered hunt       --engagement <id>\n");
    let _ = writeln!(out, "codered report     --engagement {engagement_id}");
    out.push_str("```\n");
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn advocate_label(v: &AdvocateVerdict) -> &'static str {
    match v {
        AdvocateVerdict::Confirmed => "confirmed",
        AdvocateVerdict::Rebutted => "rebutted",
        AdvocateVerdict::Uncertain => "uncertain",
    }
}

fn poc_label(p: &PocStatus) -> &'static str {
    match p {
        PocStatus::Hypothesis => "hypothesis",
        PocStatus::PocAttempted => "poc_attempted",
        PocStatus::Reproduced => "reproduced",
        PocStatus::Refuted => "refuted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use symbi_codered_core::db::KnowledgeTriple as DbKt;
    use symbi_evidence_schema::finding::{Confidence, Phase, Status};
    use symbi_evidence_schema::KillChainStage;
    use uuid::Uuid;

    fn sample_finding() -> Finding {
        Finding {
            id: "F-pattern-scout-0001".into(),
            engagement_id: Uuid::nil(),
            phase: Phase::Sast,
            severity: Severity::High,
            confidence: Confidence::High,
            cwe: Some("CWE-89".into()),
            owasp: Some("A03:2021".into()),
            file_path: "app/users.py".into(),
            line_start: 88,
            line_end: 92,
            title: "SQL injection via sort parameter".into(),
            description: "Untrusted sort reaches cursor.execute".into(),
            reachable: Some(true),
            exploitable: None,
            evidence_envelope_id: "S-001-semgrep-dead".into(),
            status: Status::Open,
            rank_score: Some(0.9),
            specifier_hash: Some("abc123".into()),
            advocate_verdict: Some(AdvocateVerdict::Confirmed),
            tool_origin: Some("semgrep".into()),
            poc_status: Some(PocStatus::Reproduced),
            created_at: Utc::now(),
        }
    }

    fn sample_chain() -> AttackChainNode {
        AttackChainNode {
            id: "AC-0001".into(),
            engagement_id: Uuid::nil(),
            stage: KillChainStage::SurfaceMapping,
            finding_id: Some("F-pattern-scout-0001".into()),
            evidence_id: None,
            next_chain_id: Some("AC-0002".into()),
            rationale: "Surface enumerated".into(),
            created_at: Utc::now(),
        }
    }

    fn sample_triple() -> DbKt {
        DbKt {
            id: "KT-0001".into(),
            engagement_id: Uuid::nil(),
            subject: "flask.request.args".into(),
            predicate: "is_taint_source_for".into(),
            object: "subprocess.Popen".into(),
            confidence: Some(0.9),
            rationale: Some("seen in 3 chains".into()),
            source_phase: "reflector".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn renders_top_level_sections() {
        let md = render(
            "eng-1",
            "spec-hash",
            "2026-05-25T00:00:00Z",
            &[sample_finding()],
            &[sample_chain()],
            &[sample_triple()],
        );
        assert!(md.contains("# symbi-codered Engagement Report"));
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("## Attack Chains"));
        assert!(md.contains("## Findings by Severity"));
        assert!(md.contains("## Methodology"));
        assert!(md.contains("## Reproducibility"));
    }

    #[test]
    fn exec_summary_counts_advocate_and_poc() {
        let md = render(
            "eng-1",
            "spec-hash",
            "2026-05-25T00:00:00Z",
            &[sample_finding()],
            &[],
            &[],
        );
        assert!(md.contains("1 total"));
        assert!(md.contains("1 confirmed"));
        assert!(md.contains("1 reproduced"));
    }

    #[test]
    fn finding_id_appears_in_severity_section() {
        let md = render(
            "eng-1",
            "spec-hash",
            "2026-05-25T00:00:00Z",
            &[sample_finding()],
            &[],
            &[],
        );
        assert!(md.contains("### High"));
        assert!(md.contains("F-pattern-scout-0001"));
        assert!(md.contains("CWE-89"));
    }

    #[test]
    fn attack_chain_id_and_stage_render() {
        let md = render(
            "eng-1",
            "spec-hash",
            "2026-05-25T00:00:00Z",
            &[],
            &[sample_chain()],
            &[],
        );
        assert!(md.contains("AC-0001"));
        assert!(md.contains("surface_mapping"));
    }

    #[test]
    fn empty_chains_render_placeholder_text() {
        let md = render("eng-1", "spec-hash", "now", &[], &[], &[]);
        assert!(md.contains("_No attack chains recorded._"));
    }
}
