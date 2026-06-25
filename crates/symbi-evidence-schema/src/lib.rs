//! Shared evidence types for symbi-codered and symbi-redteam.
//!
//! Both projects depend on the SAME crate version so the handoff payload
//! (`engagement-seed.json`) is type-safe across the boundary.

pub mod engagement;
pub mod finding;
pub mod evidence;
pub mod knowledge;
pub mod citation;
pub mod hypothesis;
pub mod threat_model;
pub mod taint_chain;
pub mod attack_chain;

pub use engagement::Engagement;
pub use finding::{Finding, Phase, Severity, Confidence, Status, AdvocateVerdict, PocStatus};
pub use evidence::{Evidence, EvidenceEnvelope};
pub use knowledge::KnowledgeTriple;
pub use citation::Citation;
pub use hypothesis::{Hypothesis, HypothesisStatus};
pub use threat_model::ThreatModel;
pub use taint_chain::{TaintChain, TaintHop};
pub use attack_chain::{AttackChainNode, KillChainStage};

/// Schema version emitted into every handoff payload. Bump on breaking changes.
/// 1.0 = Plan A baseline. 1.1 = + Citation/Hypothesis/ThreatModel/TaintChain/AttackChainNode.
pub const SCHEMA_VERSION: &str = "1.1";
