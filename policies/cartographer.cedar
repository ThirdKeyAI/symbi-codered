// cartographer.cedar — permissions for the pure-fact cartographer agent.
//
// The cartographer reads the target repo and writes ONLY to:
//   - repo_facts / symbol_index / routes tables
//   - LanceDB code_chunk + journal indices
//   - the audit journal (hash-chained)
//
// It must NOT call analyzers (that's static_hunter in Plan C) and must NOT
// produce findings (cartographer is pre-specifier; findings need a
// specifier_hash).

@id("cartographer-execute-repo-intel-tools")
permit(
    principal == Agent::"cartographer",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::RepoIntel"
};

@id("cartographer-execute-journal-tools")
permit(
    principal == Agent::"cartographer",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::Journal"
};

@id("cartographer-write-fact-tables")
permit(
    principal == Agent::"cartographer",
    action == Action::"write",
    resource
) when {
    resource.table == "repo_facts"
    || resource.table == "symbol_index"
    || resource.table == "routes"
};

@id("cartographer-no-findings-without-specifier")
forbid(
    principal == Agent::"cartographer",
    action == Action::"store_finding",
    resource
);
