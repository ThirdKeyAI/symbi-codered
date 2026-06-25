// handoff.cedar — gates which findings reach engagement-seed.json.
//
// Reporter may emit a finding to the seed IFF it has:
//   - at least one analyzer citation,
//   - advocate_verdict ∈ {confirmed, uncertain},
//   - poc_status ≠ refuted,   (inconclusive is NOT dropped — see below)
//   - severity ≥ medium (not low/info).
//
// Cedar is default-deny; the @id("handoff-permits-reporter") permit pairs with
// the four forbid-unless / forbid-when rules to make any single violation
// dominate.

@id("handoff-requires-confirmed-or-uncertain")
forbid(
    principal == Agent::"reporter",
    action == Action::"emit_to_seed",
    resource
) unless {
    resource has advocate_verdict &&
    (resource.advocate_verdict == "confirmed" || resource.advocate_verdict == "uncertain")
};

// Only a genuine disproof (`refuted` = the exploit ran and did not fire) drops
// a finding from the seed. `inconclusive` (the reproducer could not run) is
// deliberately NOT matched here — a non-test is not a disproof, so the finding
// stays in play for a human (subject to the citation + severity rules below).
@id("handoff-forbids-refuted-poc")
forbid(
    principal == Agent::"reporter",
    action == Action::"emit_to_seed",
    resource
) when {
    resource has poc_status && resource.poc_status == "refuted"
};

// A finding must be evidence-backed to reach the seed. A raw analyzer
// citation qualifies; so does a reproduced PoC or a confirmed advocate
// verdict — those are the chain-aware pattern_scout findings (e.g. the
// cross-file authz bypasses and the reproduced Go SQLi), which cite "code"
// from their own reasoning rather than a scanner. PoC reproduction is the
// strongest evidence we have, so excluding it here would drop our highest-
// value findings from the handoff.
@id("handoff-requires-citation")
forbid(
    principal == Agent::"reporter",
    action == Action::"emit_to_seed",
    resource
) unless {
    (resource has citations && resource.citations.contains("analyzer")) ||
    (resource has poc_status && resource.poc_status == "reproduced") ||
    (resource has advocate_verdict && resource.advocate_verdict == "confirmed")
};

@id("handoff-minimum-severity-medium")
forbid(
    principal == Agent::"reporter",
    action == Action::"emit_to_seed",
    resource
) when {
    resource has severity && (resource.severity == "low" || resource.severity == "info")
};

@id("handoff-permits-reporter")
permit(
    principal == Agent::"reporter",
    action == Action::"emit_to_seed",
    resource
);
