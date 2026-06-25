//! Cedar policy loading + evaluation.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityUid, PolicyId, PolicySet, Request,
    RestrictedExpression,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cedar parse: {0}")]
    Parse(String),
    #[error("cedar eval: {0}")]
    Eval(String),
}

/// Diagnostics returned alongside a Decision. The matched policy IDs let
/// the caller surface a structured "why" to the agent that asked.
#[derive(Debug, Clone, Default)]
pub struct Diagnostics {
    pub permit_reasons: Vec<String>,
    pub forbid_reasons: Vec<String>,
    pub errors: Vec<String>,
}

impl Diagnostics {
    pub fn primary_reason(&self) -> Option<&str> {
        self.forbid_reasons
            .first()
            .map(String::as_str)
            .or_else(|| self.permit_reasons.first().map(String::as_str))
    }
}

pub struct PolicyEngine {
    policies: PolicySet,
    authorizer: Authorizer,
}

impl PolicyEngine {
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let mut combined = String::new();
        let mut paths: Vec<_> = std::fs::read_dir(dir.as_ref())?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("cedar"))
            .collect();
        paths.sort();
        for p in paths {
            let body = std::fs::read_to_string(&p)?;
            combined.push_str(&body);
            combined.push('\n');
        }
        let policies = combined
            .parse::<PolicySet>()
            .map_err(|e| PolicyError::Parse(format!("{e}")))?;
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    pub fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
    ) -> Result<(Decision, Diagnostics), PolicyError> {
        let p: EntityUid = principal
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let a: EntityUid = action
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let r: EntityUid = resource
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let req = Request::new(p, a, r, Context::empty(), None)
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let resp = self
            .authorizer
            .is_authorized(&req, &self.policies, &Entities::empty());
        let decision = resp.decision();
        let diag = self.collect_diagnostics(&resp, decision);
        Ok((decision, diag))
    }

    /// Evaluate with a resource entity carrying attributes. Lets policies
    /// reference `resource.<attr>` (e.g., `resource.citations`).
    pub fn evaluate_with_attrs(
        &self,
        principal: &str,
        action: &str,
        resource_uid: &str,
        resource_attrs: HashMap<String, RestrictedExpression>,
    ) -> Result<(Decision, Diagnostics), PolicyError> {
        let p: EntityUid = principal
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let a: EntityUid = action
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let r: EntityUid = resource_uid
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;

        let resource_entity = Entity::new(r.clone(), resource_attrs, HashSet::new())
            .map_err(|e| PolicyError::Eval(format!("entity build: {e}")))?;

        let entities = Entities::from_entities(std::iter::once(resource_entity), None)
            .map_err(|e| PolicyError::Eval(format!("entities build: {e}")))?;

        let req = Request::new(p, a, r, Context::empty(), None)
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let resp = self
            .authorizer
            .is_authorized(&req, &self.policies, &entities);
        let decision = resp.decision();
        let diag = self.collect_diagnostics(&resp, decision);
        Ok((decision, diag))
    }

    /// Evaluate `principal` doing `action` on `resource`, attaching
    /// `principal_attrs` to the principal entity and `resource_attrs` to the
    /// resource entity. Lets policies reference both `principal.<attr>` and
    /// `resource.<attr>` in the same decision. Returns `(Decision,
    /// Diagnostics)` like `evaluate_with_attrs`.
    pub fn evaluate_with_principal_and_resource_attrs(
        &self,
        principal_uid: &str,
        action_uid: &str,
        resource_uid: &str,
        principal_attrs: HashMap<String, RestrictedExpression>,
        resource_attrs: HashMap<String, RestrictedExpression>,
    ) -> Result<(Decision, Diagnostics), PolicyError> {
        let p: EntityUid = principal_uid
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let a: EntityUid = action_uid
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let r: EntityUid = resource_uid
            .parse()
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;

        let principal_entity = Entity::new(p.clone(), principal_attrs, HashSet::new())
            .map_err(|e| PolicyError::Eval(format!("principal entity build: {e}")))?;
        let resource_entity = Entity::new(r.clone(), resource_attrs, HashSet::new())
            .map_err(|e| PolicyError::Eval(format!("resource entity build: {e}")))?;

        let entities =
            Entities::from_entities([principal_entity, resource_entity], None)
                .map_err(|e| PolicyError::Eval(format!("entities build: {e}")))?;

        let req = Request::new(p, a, r, Context::empty(), None)
            .map_err(|e| PolicyError::Eval(format!("{e}")))?;
        let resp = self
            .authorizer
            .is_authorized(&req, &self.policies, &entities);
        let decision = resp.decision();
        let diag = self.collect_diagnostics(&resp, decision);
        Ok((decision, diag))
    }

    fn collect_diagnostics(
        &self,
        resp: &cedar_policy::Response,
        decision: Decision,
    ) -> Diagnostics {
        let mut d = Diagnostics::default();
        for pid in resp.diagnostics().reason() {
            let label = self.label_for(pid);
            match decision {
                Decision::Allow => d.permit_reasons.push(label),
                Decision::Deny => d.forbid_reasons.push(label),
            }
        }
        for err in resp.diagnostics().errors() {
            d.errors.push(format!("{err}"));
        }
        d
    }

    fn label_for(&self, pid: &PolicyId) -> String {
        if let Some(policy) = self.policies.policy(pid) {
            if let Some(ann) = policy.annotation("id") {
                return ann.to_string();
            }
        }
        pid.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_policy(dir: &TempDir, name: &str, body: &str) {
        std::fs::write(dir.path().join(name), body).unwrap();
    }

    #[test]
    fn permits_when_policy_matches_and_returns_reason() {
        let dir = TempDir::new().unwrap();
        write_policy(
            &dir,
            "p.cedar",
            r#"@id("test-permit-t") permit(principal == Agent::"a", action == Action::"execute_tool", resource == Resource::"t");"#,
        );
        let engine = PolicyEngine::from_dir(dir.path()).unwrap();
        let (d, diag) = engine
            .evaluate(
                r#"Agent::"a""#,
                r#"Action::"execute_tool""#,
                r#"Resource::"t""#,
            )
            .unwrap();
        assert_eq!(d, Decision::Allow);
        assert!(
            diag.permit_reasons.iter().any(|r| r == "test-permit-t"),
            "expected permit reason; got: {diag:?}"
        );
    }

    #[test]
    fn deny_by_default_yields_no_reasons_but_decision_deny() {
        let dir = TempDir::new().unwrap();
        write_policy(
            &dir,
            "p.cedar",
            r#"@id("permit-x") permit(principal == Agent::"a", action == Action::"execute_tool", resource == Resource::"x");"#,
        );
        let engine = PolicyEngine::from_dir(dir.path()).unwrap();
        let (d, diag) = engine
            .evaluate(
                r#"Agent::"a""#,
                r#"Action::"execute_tool""#,
                r#"Resource::"different""#,
            )
            .unwrap();
        assert_eq!(d, Decision::Deny);
        assert!(diag.errors.is_empty());
    }

    #[test]
    fn forbid_returns_rule_id_in_diagnostics() {
        let dir = TempDir::new().unwrap();
        write_policy(
            &dir,
            "p.cedar",
            r#"
            @id("test-permit-r") permit(principal == Agent::"a", action == Action::"x", resource == Resource::"r");
            @id("test-forbid-r") forbid(principal == Agent::"a", action == Action::"x", resource == Resource::"r");
        "#,
        );
        let engine = PolicyEngine::from_dir(dir.path()).unwrap();
        let (d, diag) = engine
            .evaluate(r#"Agent::"a""#, r#"Action::"x""#, r#"Resource::"r""#)
            .unwrap();
        assert_eq!(d, Decision::Deny);
        assert!(
            diag.forbid_reasons.iter().any(|r| r == "test-forbid-r"),
            "expected forbid reason; got: {diag:?}"
        );
        assert_eq!(diag.primary_reason(), Some("test-forbid-r"));
    }

    #[test]
    fn evaluate_with_attrs_permits_when_citation_set_nonempty() {
        use cedar_policy::RestrictedExpression;
        use std::collections::HashMap;

        let dir = TempDir::new().unwrap();
        // A blanket permit pairs with the citation-gating forbid so that a
        // satisfying `citations` attr actually yields Allow (Cedar is
        // default-deny, so the unless-bypass alone isn't enough).
        write_policy(
            &dir,
            "p.cedar",
            r#"
            @id("permit-store") permit(principal, action == Action::"store_finding", resource);
            @id("require-citation")
            forbid(principal, action == Action::"store_finding", resource)
            unless { resource has citations && resource.citations.contains("analyzer") };
        "#,
        );
        let engine = PolicyEngine::from_dir(dir.path()).unwrap();

        let mut attrs = HashMap::new();
        attrs.insert(
            "citations".to_string(),
            RestrictedExpression::new_set(vec![RestrictedExpression::new_string(
                "analyzer".to_string(),
            )]),
        );
        let (d, _diag) = engine
            .evaluate_with_attrs(
                r#"Agent::"x""#,
                r#"Action::"store_finding""#,
                r#"Finding::"f1""#,
                attrs,
            )
            .unwrap();
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn devils_advocate_forbids_store_finding_unconditionally() {
        // Loads the real repo policies (relative to crate root, matching the
        // convention used by tests/policy_load.rs).
        let engine = PolicyEngine::from_dir("../../policies").unwrap();
        let mut attrs = std::collections::HashMap::new();
        attrs.insert(
            "citations".to_string(),
            cedar_policy::RestrictedExpression::new_set(vec![
                cedar_policy::RestrictedExpression::new_string("analyzer".to_string()),
            ]),
        );
        let (d, diag) = engine
            .evaluate_with_attrs(
                r#"Agent::"devils_advocate""#,
                r#"Action::"store_finding""#,
                r#"Finding::"f1""#,
                attrs,
            )
            .unwrap();
        assert_eq!(d, cedar_policy::Decision::Deny);
        assert!(
            diag.forbid_reasons
                .iter()
                .any(|r| r == "devils-advocate-forbids-store"),
            "expected devils-advocate-forbids-store; got {diag:?}"
        );
    }

    // -----------------------------------------------------------------
    // Plan G: handoff.cedar — 5 rules + happy path. Each test constructs
    // a Finding-shaped resource entity, calls evaluate_with_attrs against
    // the real repo policies, and asserts the matching rule fires (or
    // the permit fires for the happy path).
    // -----------------------------------------------------------------

    /// Build a "valid" attrs map (passes all 4 forbid rules). Individual
    /// tests mutate one attr to trip one rule.
    fn handoff_valid_attrs() -> HashMap<String, RestrictedExpression> {
        let mut attrs = HashMap::new();
        attrs.insert(
            "advocate_verdict".into(),
            RestrictedExpression::new_string("confirmed".into()),
        );
        attrs.insert(
            "poc_status".into(),
            RestrictedExpression::new_string("reproduced".into()),
        );
        attrs.insert(
            "severity".into(),
            RestrictedExpression::new_string("high".into()),
        );
        attrs.insert(
            "citations".into(),
            RestrictedExpression::new_set(vec![RestrictedExpression::new_string(
                "analyzer".into(),
            )]),
        );
        attrs
    }

    fn eval_handoff(
        attrs: HashMap<String, RestrictedExpression>,
    ) -> (cedar_policy::Decision, Diagnostics) {
        let engine = PolicyEngine::from_dir("../../policies").unwrap();
        engine
            .evaluate_with_attrs(
                r#"Agent::"reporter""#,
                r#"Action::"emit_to_seed""#,
                r#"Finding::"f1""#,
                attrs,
            )
            .unwrap()
    }

    #[test]
    fn handoff_rule_requires_confirmed_or_uncertain_verdict() {
        let mut attrs = handoff_valid_attrs();
        attrs.insert(
            "advocate_verdict".into(),
            RestrictedExpression::new_string("rebutted".into()),
        );
        let (d, diag) = eval_handoff(attrs);
        assert_eq!(d, Decision::Deny);
        assert!(
            diag.forbid_reasons
                .iter()
                .any(|r| r == "handoff-requires-confirmed-or-uncertain"),
            "expected handoff-requires-confirmed-or-uncertain; got {diag:?}"
        );
    }

    #[test]
    fn handoff_rule_forbids_refuted_poc() {
        let mut attrs = handoff_valid_attrs();
        attrs.insert(
            "poc_status".into(),
            RestrictedExpression::new_string("refuted".into()),
        );
        let (d, diag) = eval_handoff(attrs);
        assert_eq!(d, Decision::Deny);
        assert!(
            diag.forbid_reasons
                .iter()
                .any(|r| r == "handoff-forbids-refuted-poc"),
            "expected handoff-forbids-refuted-poc; got {diag:?}"
        );
    }

    #[test]
    fn handoff_rule_requires_citation() {
        let mut attrs = handoff_valid_attrs();
        // The relaxed rule (commit 8a71bf6) admits a finding on ANY of:
        // analyzer citation, poc_status=="reproduced", or advocate_verdict==
        // "confirmed". To exercise the forbid we must strip all three: a
        // non-analyzer citation set AND a non-reproduced poc AND a
        // non-confirmed (but still handoff-eligible) verdict.
        attrs.insert(
            "citations".into(),
            RestrictedExpression::new_set(vec![RestrictedExpression::new_string(
                "code".into(),
            )]),
        );
        attrs.insert(
            "poc_status".into(),
            RestrictedExpression::new_string("poc_attempted".into()),
        );
        attrs.insert(
            "advocate_verdict".into(),
            RestrictedExpression::new_string("uncertain".into()),
        );
        let (d, diag) = eval_handoff(attrs);
        assert_eq!(d, Decision::Deny);
        assert!(
            diag.forbid_reasons
                .iter()
                .any(|r| r == "handoff-requires-citation"),
            "expected handoff-requires-citation; got {diag:?}"
        );
    }

    #[test]
    fn handoff_rule_minimum_severity_medium() {
        let mut attrs = handoff_valid_attrs();
        attrs.insert(
            "severity".into(),
            RestrictedExpression::new_string("low".into()),
        );
        let (d, diag) = eval_handoff(attrs);
        assert_eq!(d, Decision::Deny);
        assert!(
            diag.forbid_reasons
                .iter()
                .any(|r| r == "handoff-minimum-severity-medium"),
            "expected handoff-minimum-severity-medium; got {diag:?}"
        );
    }

    #[test]
    fn handoff_rule_minimum_severity_blocks_info() {
        let mut attrs = handoff_valid_attrs();
        attrs.insert(
            "severity".into(),
            RestrictedExpression::new_string("info".into()),
        );
        let (d, diag) = eval_handoff(attrs);
        assert_eq!(d, Decision::Deny);
        assert!(
            diag.forbid_reasons
                .iter()
                .any(|r| r == "handoff-minimum-severity-medium"),
            "expected handoff-minimum-severity-medium for info; got {diag:?}"
        );
    }

    #[test]
    fn handoff_permits_reporter_when_all_rules_satisfied() {
        let attrs = handoff_valid_attrs();
        let (d, diag) = eval_handoff(attrs);
        assert_eq!(d, Decision::Allow, "expected Allow; diag={diag:?}");
        assert!(
            diag.permit_reasons
                .iter()
                .any(|r| r == "handoff-permits-reporter"),
            "expected handoff-permits-reporter permit reason; got {diag:?}"
        );
    }

    #[test]
    fn evaluate_with_principal_and_resource_attrs_matches_on_shared_attr() {
        let dir = TempDir::new().unwrap();
        write_policy(
            &dir,
            "p.cedar",
            r#"
            @id("same-client")
            permit(principal, action == Action::"view", resource)
            when { principal has client && resource has client && principal.client == resource.client };
        "#,
        );
        let engine = PolicyEngine::from_dir(dir.path()).unwrap();

        let mut p_attrs = HashMap::new();
        p_attrs.insert(
            "client".to_string(),
            RestrictedExpression::new_string("acme".to_string()),
        );
        let mut r_attrs = HashMap::new();
        r_attrs.insert(
            "client".to_string(),
            RestrictedExpression::new_string("acme".to_string()),
        );
        let (d, _diag) = engine
            .evaluate_with_principal_and_resource_attrs(
                r#"User::"u1""#,
                r#"Action::"view""#,
                r#"Engagement::"e1""#,
                p_attrs,
                r_attrs,
            )
            .unwrap();
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn evaluate_with_principal_and_resource_attrs_denies_on_mismatch() {
        let dir = TempDir::new().unwrap();
        write_policy(
            &dir,
            "p.cedar",
            r#"
            @id("same-client")
            permit(principal, action == Action::"view", resource)
            when { principal has client && resource has client && principal.client == resource.client };
        "#,
        );
        let engine = PolicyEngine::from_dir(dir.path()).unwrap();

        let mut p_attrs = HashMap::new();
        p_attrs.insert(
            "client".to_string(),
            RestrictedExpression::new_string("acme".to_string()),
        );
        let mut r_attrs = HashMap::new();
        r_attrs.insert(
            "client".to_string(),
            RestrictedExpression::new_string("other".to_string()),
        );
        let (d, _diag) = engine
            .evaluate_with_principal_and_resource_attrs(
                r#"User::"u1""#,
                r#"Action::"view""#,
                r#"Engagement::"e1""#,
                p_attrs,
                r_attrs,
            )
            .unwrap();
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn evaluate_with_attrs_denies_when_citation_set_empty() {
        use cedar_policy::RestrictedExpression;
        use std::collections::HashMap;

        let dir = TempDir::new().unwrap();
        write_policy(
            &dir,
            "p.cedar",
            r#"
            @id("require-citation")
            forbid(principal, action == Action::"store_finding", resource)
            unless { resource has citations && resource.citations.contains("analyzer") };
        "#,
        );
        let engine = PolicyEngine::from_dir(dir.path()).unwrap();

        let mut attrs = HashMap::new();
        attrs.insert(
            "citations".to_string(),
            RestrictedExpression::new_set(Vec::<RestrictedExpression>::new()),
        );
        let (d, diag) = engine
            .evaluate_with_attrs(
                r#"Agent::"x""#,
                r#"Action::"store_finding""#,
                r#"Finding::"f1""#,
                attrs,
            )
            .unwrap();
        assert_eq!(d, Decision::Deny);
        assert!(diag.forbid_reasons.iter().any(|r| r == "require-citation"));
    }
}
