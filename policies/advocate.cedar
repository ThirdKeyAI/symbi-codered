// advocate.cedar — the witness rule for SUPPRESSION, symmetric with
// citation.cedar's witness rule for CREATION (store_finding).
//
// Creating a finding is structurally witness-gated (citation.cedar). Dropping
// one must be too: a `rebutted` advocate verdict SUPPRESSES a finding — the
// dangerous direction for an auditor and the one most exposed to confabulation
// or prompt-injection. So a rebuttal must cite its witness — the same
// attribute-bearing resource-entity pattern citation.cedar uses.
//
// The resource (a Finding) carries:
//   - verdict        : the advocate's verdict ("confirmed"|"rebutted"|"uncertain")
//   - witness_types  : set of the witness kinds the agent supplied
//
// Only `rebutted` is gated. `confirmed` and `uncertain` keep the finding in
// play and need no witness — the asymmetric cost (dropping a finding always
// costs more than keeping it). The unconditional permit lives in
// tool-authorization.cedar; this forbid pairs with it.

@id("advocate-rebuttal-requires-witness")
forbid(
    principal == Agent::"devils_advocate",
    action == Action::"advocate_finding",
    resource
) when {
    resource has verdict && resource.verdict == "rebutted"
} unless {
    resource has witness_types &&
    (resource.witness_types.contains("envelope") ||
     resource.witness_types.contains("sanitizer") ||
     resource.witness_types.contains("closed_set") ||
     resource.witness_types.contains("constant_caller") ||
     // wrong_library: the rule fired on a symbol it does not own (e.g. a
     // jQuery rule matching lit-html's auto-escaping `html` template). The
     // witness ref points at the import line proving the other library.
     resource.witness_types.contains("wrong_library"))
};
