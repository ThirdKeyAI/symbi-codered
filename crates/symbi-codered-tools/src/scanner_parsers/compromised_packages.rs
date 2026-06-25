//! `check_compromised_packages.py` (jaschadub/compromised-packages-check)
//! text output → RawFinding (one per matched package version).
//!
//! Script docstring contract: "exit 0 clean, 1 hit(s) found, 2 error".
//! Hit lines look like:
//!
//! ```text
//!   [npm] @tanstack/react-router@1.169.5  (package-lock.json)
//!   [pypi] requests@2.27.1  (requirements.txt)
//!   [crates.io] some-crate@0.1.0  (Cargo.lock)
//! ```
//!
//! The list is small and ecosystem-tagged; we mint a finding per hit with
//! severity "critical" (these packages are KNOWN-MALICIOUS, not just
//! known-vulnerable) and CWE-506 (Malicious Code Embedded in Product).

use regex::Regex;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum CompromisedPackagesParseError {
    #[error("regex compile: {0}")]
    Regex(#[from] regex::Error),
}

/// Parse the script's stdout. Lines that don't match the hit shape are
/// ignored (banner / "Scanning ..." progress lines / etc.).
pub fn parse(stdout: &str) -> Result<Vec<RawFinding>, CompromisedPackagesParseError> {
    // `  [eco] pkg@ver  (path)` — leading whitespace is two spaces in the
    // script but be lenient. Package names can contain `@` (npm scoped
    // packages start with `@`) so we match greedily up to the LAST `@`.
    let re = Regex::new(
        r"^\s*\[(?P<eco>[^\]]+)\]\s+(?P<pkg>.+)@(?P<ver>[^\s]+)\s+\((?P<path>[^)]+)\)\s*$",
    )?;
    let mut out = Vec::new();
    for line in stdout.lines() {
        let Some(caps) = re.captures(line) else { continue };
        let eco = caps.name("eco").map(|m| m.as_str()).unwrap_or("");
        let pkg = caps.name("pkg").map(|m| m.as_str()).unwrap_or("").trim();
        let ver = caps.name("ver").map(|m| m.as_str()).unwrap_or("").trim();
        let path = caps.name("path").map(|m| m.as_str()).unwrap_or("").to_string();
        out.push(RawFinding {
            tool: "compromised-packages-check".into(),
            rule_id: format!("compromised:{eco}/{pkg}@{ver}"),
            file_path: path,
            line_start: 0,
            line_end: 0,
            severity: "critical".into(),
            confidence: "high".into(),
            cwe: Some("CWE-506".into()),
            owasp: None,
            title: format!("Known-malicious package: {eco}/{pkg}@{ver}"),
            description: format!(
                "The {eco} package `{pkg}` at version `{ver}` matches an entry \
                 in jaschadub/compromised-packages-check, which catalogs \
                 packages flagged in recent supply-chain compromise events. \
                 Treat any artifact built from this dependency as suspect; \
                 audit access logs and rebuild from a pinned earlier version."
            ),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_scoped_package_hit() {
        let stdout = "Scanning /repo for compromised packages...\n\
                      \n  [npm] @tanstack/react-router@1.169.5  (package-lock.json)\n\
                      Done.\n";
        let out = parse(stdout).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "compromised-packages-check");
        assert_eq!(f.severity, "critical");
        assert_eq!(f.cwe.as_deref(), Some("CWE-506"));
        assert_eq!(f.file_path, "package-lock.json");
        assert!(f.title.contains("@tanstack/react-router"));
        assert!(f.title.contains("1.169.5"));
        assert!(f.rule_id.contains("npm"));
    }

    #[test]
    fn parses_pypi_and_crates_hits() {
        let stdout = "  [pypi] requests@2.27.1  (requirements.txt)\n\
                      [crates.io] some-crate@0.1.0  (Cargo.lock)\n";
        let out = parse(stdout).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].file_path, "requirements.txt");
        assert_eq!(out[1].file_path, "Cargo.lock");
    }

    #[test]
    fn ignores_non_hit_lines() {
        let stdout = "Scanning /repo...\n\
                      Found 0 hits.\n\
                      \n";
        assert!(parse(stdout).unwrap().is_empty());
    }

    #[test]
    fn handles_at_sign_in_package_name() {
        // npm scoped packages can have `@` in the name (e.g. @vue/cli).
        // The regex anchors on the LAST `@` so the version split is correct.
        let stdout = "  [npm] @vue/cli@4.5.0  (yarn.lock)\n";
        let out = parse(stdout).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("@vue/cli"));
        assert!(out[0].title.contains("4.5.0"));
    }
}
