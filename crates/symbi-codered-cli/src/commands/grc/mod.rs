//! `codered export-grc` — push a signed engagement seed to a GRC platform as
//! Risk Register entries, mapped to compliance controls.
//!
//! codered stays taxonomy-only (CWE/OWASP). This adapter reads the
//! already-signed `engagement-seed.json`, verifies its Ed25519 signature,
//! maps each finding's CWE to control IDs in NIST 800-53 / OWASP ASVS / SOC2 /
//! ISO 27001 via an embedded, SME-curatable crosswalk ([`crosswalk.json`]),
//! and POSTs one Risk Register entry per finding.
//!
//! Two platforms are supported behind a common [`Target`] abstraction:
//!   - **gapps**: `POST /api/v1/projects/<pid>/risks`, `token` header.
//!   - **comp** (Comp AI): `POST /api/v1/risks`, `x-api-key` header; the org is
//!     derived from the key, so no project id is needed.
//!
//! A finding is evidence of a control *deficiency*, never an attestation, so
//! everything lands in the Risk Register. Only confirmed / reproduced findings
//! are present in the seed; unmapped CWEs are logged, never silently dropped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

/// Embedded CWE -> control crosswalk. Edit `crosswalk.json` to refine.
const CROSSWALK_JSON: &str = include_str!("crosswalk.json");

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Target {
    /// gapps (Flask GRC): project-scoped risks, `token` header.
    Gapps,
    /// Comp AI (NestJS): org-scoped risks via `x-api-key`.
    Comp,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Framework {
    Nist,
    Asvs,
    Soc2,
    Iso27001,
}

#[derive(Args, Debug)]
pub struct ExportGrcArgs {
    /// Which GRC platform to push to.
    #[arg(long, value_enum, default_value = "gapps")]
    pub target: Target,

    /// Path to the engagement-seed.json produced by `codered report`.
    #[arg(long)]
    pub seed: PathBuf,

    /// GRC base URL, e.g. https://gapps.internal or https://comp.internal
    /// (no trailing /api/v1).
    #[arg(long)]
    pub base_url: Option<String>,

    /// API token. gapps: the `token` JWT. comp: the `comp_<key>` API key.
    /// Falls back to GRC_TOKEN.
    #[arg(long)]
    pub token: Option<String>,

    /// gapps project id (the framework assessment). Required for --target gapps;
    /// ignored for comp (org is derived from the key).
    #[arg(long)]
    pub project_id: Option<String>,

    /// Which framework control IDs to cite in each risk (repeatable; default all).
    #[arg(long, value_enum)]
    pub framework: Vec<Framework>,

    /// Directory holding the engagement's Ed25519 public key, to verify the
    /// seed signature. If omitted, verification is skipped (with a warning).
    #[arg(long)]
    pub keys_dir: Option<PathBuf>,

    /// Print the platform risk payloads instead of POSTing them. No token needed.
    #[arg(long)]
    pub dry_run: bool,
}

// ---------------------------------------------------------------------------
// Crosswalk
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Crosswalk {
    version: String,
    map: BTreeMap<String, ControlMapping>,
}

#[derive(Debug, Deserialize, Clone)]
struct ControlMapping {
    title: String,
    nist_800_53: Vec<String>,
    owasp_asvs: Vec<String>,
    soc2: Vec<String>,
    iso_27001: Vec<String>,
}

impl ControlMapping {
    fn controls_for(&self, frameworks: &[Framework]) -> Vec<(&'static str, &Vec<String>)> {
        frameworks
            .iter()
            .map(|f| match f {
                Framework::Nist => ("NIST 800-53", &self.nist_800_53),
                Framework::Asvs => ("OWASP ASVS", &self.owasp_asvs),
                Framework::Soc2 => ("SOC2", &self.soc2),
                Framework::Iso27001 => ("ISO 27001", &self.iso_27001),
            })
            .collect()
    }
}

fn load_crosswalk() -> Result<Crosswalk> {
    serde_json::from_str(CROSSWALK_JSON).context("parsing embedded GRC crosswalk")
}

// ---------------------------------------------------------------------------
// Neutral mapped-risk, then per-target serialization
// ---------------------------------------------------------------------------

/// Platform-neutral risk derived from a seed finding. Each [`Target`]
/// serializes this into its own payload.
#[derive(Debug)]
struct MappedRisk {
    title: String,
    description: String,
    /// gapps risk level ∈ {unknown,low,moderate,high,critical}.
    risk_level: &'static str,
    /// gapps priority ∈ {unknown,low,moderate,high}.
    priority: &'static str,
}

/// codered severity -> (risk_level, priority) using gapps' validated value sets.
fn severity_to_risk(severity: &str) -> (&'static str, &'static str) {
    match severity {
        "critical" => ("critical", "high"),
        "high" => ("high", "high"),
        "medium" => ("moderate", "moderate"),
        "low" => ("low", "low"),
        _ => ("unknown", "low"),
    }
}

/// Map one seed finding to a [`MappedRisk`], or `Err(reason)` if the CWE is
/// unmapped. The description is plain prose with inline separators — GRC UIs
/// render it as text (no markdown), and newlines may collapse to spaces.
fn finding_to_mapped(
    finding: &Value,
    crosswalk: &Crosswalk,
    frameworks: &[Framework],
) -> std::result::Result<MappedRisk, String> {
    let cwe = finding.get("cwe").and_then(|v| v.as_str()).unwrap_or("");
    let mapping = crosswalk
        .map
        .get(cwe)
        .ok_or_else(|| format!("unmapped CWE {cwe:?}"))?;

    let g = |k: &str| finding.get(k).and_then(|v| v.as_str()).unwrap_or("-");
    let id = g("id");
    let title = g("title");
    let desc = g("description");
    let file = g("file_path");
    let line = finding.get("line_start").and_then(|v| v.as_i64()).unwrap_or(0);
    let severity = finding.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown");
    let owasp = g("owasp");
    let verdict = g("advocate_verdict");
    let poc = g("poc_status");
    let envelope = g("evidence_envelope_id");

    let (risk_level, priority) = severity_to_risk(severity);

    let controls = mapping
        .controls_for(frameworks)
        .into_iter()
        .filter(|(_, ids)| !ids.is_empty())
        .map(|(label, ids)| format!("{label}: {}", ids.join(", ")))
        .collect::<Vec<_>>()
        .join(". ");

    // Title carries the finding id (gapps enforces unique (title, tenant_id);
    // distinct findings can share a scanner title).
    let risk_title = format!("[codered] {}: {title} ({id})", mapping.title);
    let description = format!(
        "Source: {id} - severity {severity}, {cwe}, OWASP {owasp}. \
         Location: {file}:{line}. \
         Advocate verdict: {verdict}. PoC status: {poc}. \
         Evidence envelope: {envelope}.\n\n\
         Mapped controls (deficiency, NOT an attestation) - {controls}.\n\n\
         Detail: {desc}\n\n\
         Imported from symbi-codered; a finding indicates a control gap - \
         absence of findings does not imply control satisfaction."
    );

    Ok(MappedRisk {
        title: risk_title,
        description,
        risk_level,
        priority,
    })
}

// ---------------------------------------------------------------------------
// Target adapters
// ---------------------------------------------------------------------------

impl Target {
    /// The HTTP auth header name this platform expects.
    fn auth_header(&self) -> &'static str {
        match self {
            Target::Gapps => "token",
            Target::Comp => "x-api-key",
        }
    }

    /// Whether a project/assessment id must be supplied (gapps) or the org is
    /// derived from the credential (comp).
    fn requires_project_id(&self) -> bool {
        matches!(self, Target::Gapps)
    }

    /// The risks endpoint for this platform.
    fn risks_url(&self, base: &str, project_id: Option<&str>) -> Result<String> {
        let base = base.trim_end_matches('/');
        Ok(match self {
            Target::Gapps => {
                let pid = project_id.context("--project-id required for --target gapps")?;
                format!("{base}/api/v1/projects/{pid}/risks")
            }
            Target::Comp => format!("{base}/api/v1/risks"),
        })
    }

    /// Serialize a [`MappedRisk`] into this platform's create-risk payload.
    fn payload(&self, r: &MappedRisk) -> Value {
        match self {
            // gapps RiskRegister: status ∈ {new,…}, risk/priority validated.
            Target::Gapps => json!({
                "title":       r.title,
                "description": r.description,
                "status":      "new",
                "risk":        r.risk_level,
                "priority":    r.priority,
            }),
            // Comp CreateRiskDto: title, description, category (enum), status
            // (enum, default open). codered findings are technology risks.
            Target::Comp => json!({
                "title":       r.title,
                "description": r.description,
                "category":    "technology",
                "status":      "open",
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

fn verify_seed(seed: &Value, keys_dir: &Path, engagement_id: Uuid) -> Result<()> {
    let sig_hex = seed
        .get("signature")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .context("seed has no signature to verify")?;
    let mut unsigned = seed.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.insert("signature".into(), Value::String(String::new()));
    }
    let canonical =
        serde_json::to_string(&unsigned).context("re-canonicalising seed for verification")?;
    let keypair = symbi_codered_core::signing::load_from(keys_dir, engagement_id)
        .context("loading engagement public key")?;
    keypair
        .verify_hex(canonical.as_bytes(), sig_hex)
        .context("seed signature verification failed")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: ExportGrcArgs) -> Result<()> {
    let frameworks = if args.framework.is_empty() {
        vec![
            Framework::Nist,
            Framework::Asvs,
            Framework::Soc2,
            Framework::Iso27001,
        ]
    } else {
        args.framework.clone()
    };

    let crosswalk = load_crosswalk()?;
    let raw = std::fs::read_to_string(&args.seed)
        .with_context(|| format!("reading seed {}", args.seed.display()))?;
    let seed: Value = serde_json::from_str(&raw).context("parsing engagement-seed.json")?;

    let engagement_id: Uuid = seed
        .get("engagement_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .context("seed missing a valid engagement_id")?;

    match &args.keys_dir {
        Some(dir) => {
            verify_seed(&seed, dir, engagement_id)?;
            println!("seed signature: VERIFIED");
        }
        None => eprintln!(
            "WARNING: --keys-dir not given; pushing UNVERIFIED seed. \
             Pass --keys-dir to check the Ed25519 signature."
        ),
    }

    let findings = seed
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut risks: Vec<Value> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for f in &findings {
        match finding_to_mapped(f, &crosswalk, &frameworks) {
            Ok(mapped) => risks.push(args.target.payload(&mapped)),
            Err(reason) => {
                let id = f.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                skipped.push(format!("{id}: {reason}"));
            }
        }
    }

    println!(
        "crosswalk v{} · target {:?} · {} finding(s) · {} mapped · {} skipped",
        crosswalk.version,
        args.target,
        findings.len(),
        risks.len(),
        skipped.len()
    );
    for s in &skipped {
        eprintln!("  skipped (logged, not dropped): {s}");
    }

    if args.dry_run {
        println!("--- DRY RUN: {:?} risk payloads ---", args.target);
        for r in &risks {
            println!("{}", serde_json::to_string_pretty(r)?);
        }
        return Ok(());
    }

    let base = args
        .base_url
        .as_deref()
        .context("--base-url required for live push (or use --dry-run)")?;
    let token_env = std::env::var("GRC_TOKEN").ok();
    let token = args
        .token
        .as_deref()
        .or(token_env.as_deref())
        .context("--token / GRC_TOKEN required for live push (or use --dry-run)")?;
    if args.target.requires_project_id() && args.project_id.is_none() {
        bail!("--project-id required for --target gapps");
    }
    let url = args.target.risks_url(base, args.project_id.as_deref())?;

    let client = reqwest::blocking::Client::new();
    let mut pushed = 0usize;
    let mut already = 0usize;
    for r in &risks {
        let resp = client
            .post(&url)
            .header(args.target.auth_header(), token)
            .json(r)
            .send()
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        if status.is_success() {
            pushed += 1;
        } else {
            let body = resp.text().unwrap_or_default();
            if body.contains("duplicate key") || body.contains("already exists") {
                already += 1;
                continue;
            }
            bail!("{:?} POST failed ({status}): {body}", args.target);
        }
    }
    println!(
        "pushed {pushed}/{} risk(s) to {url} ({already} already present)",
        risks.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(cwe: &str, sev: &str) -> Value {
        json!({
            "id": "F-pattern-scout-0001",
            "title": "SQL injection via field parameter",
            "description": "Untrusted field reaches EXTRACT clause",
            "file_path": "api_filter/expressions.go",
            "line_start": 22,
            "severity": sev,
            "cwe": cwe,
            "owasp": "A03:2021",
            "advocate_verdict": "confirmed",
            "poc_status": "reproduced",
            "evidence_envelope_id": "S-001-pattern_scout-deadbeef"
        })
    }

    fn all_fw() -> Vec<Framework> {
        vec![
            Framework::Nist,
            Framework::Asvs,
            Framework::Soc2,
            Framework::Iso27001,
        ]
    }

    #[test]
    fn crosswalk_loads_and_covers_core_cwes_with_iso() {
        let cw = load_crosswalk().unwrap();
        for cwe in ["CWE-89", "CWE-285", "CWE-639", "CWE-78", "CWE-79"] {
            let m = cw.map.get(cwe).unwrap_or_else(|| panic!("missing {cwe}"));
            assert!(!m.iso_27001.is_empty(), "{cwe} missing ISO 27001 mapping");
        }
    }

    #[test]
    fn mapped_description_cites_all_four_frameworks() {
        let cw = load_crosswalk().unwrap();
        let m = finding_to_mapped(&sample_finding("CWE-89", "high"), &cw, &all_fw()).unwrap();
        for needle in ["NIST 800-53", "SI-10", "OWASP ASVS", "V5.3.4", "SOC2", "CC6.1", "ISO 27001", "A.8.28"] {
            assert!(m.description.contains(needle), "description missing {needle}");
        }
    }

    #[test]
    fn gapps_payload_uses_validated_value_sets() {
        let cw = load_crosswalk().unwrap();
        let m = finding_to_mapped(&sample_finding("CWE-89", "high"), &cw, &all_fw()).unwrap();
        let p = Target::Gapps.payload(&m);
        assert_eq!(p.get("status").unwrap(), "new");
        assert_eq!(p.get("risk").unwrap(), "high");
        assert_eq!(p.get("priority").unwrap(), "high");
        assert!(p.get("category").is_none(), "gapps has no category field");
    }

    #[test]
    fn comp_payload_uses_createrisk_dto_shape() {
        let cw = load_crosswalk().unwrap();
        let m = finding_to_mapped(&sample_finding("CWE-285", "medium"), &cw, &all_fw()).unwrap();
        let p = Target::Comp.payload(&m);
        assert_eq!(p.get("category").unwrap(), "technology");
        assert_eq!(p.get("status").unwrap(), "open");
        assert!(p.get("risk").is_none(), "comp has no gapps-style risk field");
        assert!(p.get("title").unwrap().as_str().unwrap().starts_with("[codered] Improper Authorization:"));
    }

    #[test]
    fn endpoints_and_auth_headers_differ_per_target() {
        assert_eq!(Target::Gapps.auth_header(), "token");
        assert_eq!(Target::Comp.auth_header(), "x-api-key");
        assert_eq!(
            Target::Comp.risks_url("https://x/", None).unwrap(),
            "https://x/api/v1/risks"
        );
        assert_eq!(
            Target::Gapps.risks_url("https://x", Some("p1")).unwrap(),
            "https://x/api/v1/projects/p1/risks"
        );
        assert!(Target::Gapps.risks_url("https://x", None).is_err());
    }

    #[test]
    fn unmapped_cwe_is_reported_not_dropped() {
        let cw = load_crosswalk().unwrap();
        let err = finding_to_mapped(&sample_finding("CWE-99999", "high"), &cw, &all_fw()).unwrap_err();
        assert!(err.contains("unmapped CWE"));
    }
}
