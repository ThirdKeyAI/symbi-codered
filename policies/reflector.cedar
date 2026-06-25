// reflector.cedar — the bounded-reflector pattern.
//
// Plan G: reflector is read-only on findings/chains and may ONLY write
// knowledge_triples. Forbid everything for the reflector EXCEPT the small
// whitelist of read query tools, the self-execute permit, and the single
// write tool write_knowledge_triple. The companion permits live in
// tool-authorization.cedar.
@id("reflector-bounded")
forbid(
    principal == Agent::"reflector",
    action,
    resource
) unless {
    action == Action::"execute_tool"
    || action == Action::"write_knowledge_triple"
    || action == Action::"query_findings"
    || action == Action::"query_finding_detail"
    || action == Action::"query_taint_chains"
    || action == Action::"query_attack_chains"
    || action == Action::"store_knowledge"
    || action == Action::"recall_knowledge"
    || action == Action::"recall_journal"
};
