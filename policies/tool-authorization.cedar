// tool-authorization.cedar — per-agent tool-execution permits.

@id("cartographer-permits-repo-intel")
permit(
    principal == Agent::"cartographer",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::RepoIntel"
    || resource.type == "Audit::Journal"
};

@id("specifier-permits-specifier-tools")
permit(
    principal == Agent::"specifier",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::Specifier"
};

@id("static-hunter-permits-analyzer-tools")
permit(
    principal == Agent::"static_hunter",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::StaticHunter"
};

@id("static-hunter-permits-store-finding")
permit(
    principal == Agent::"static_hunter",
    action == Action::"store_finding",
    resource
);

@id("pattern-scout-permits-reasoning-tools")
permit(
    principal == Agent::"pattern_scout",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::PatternScout"
};

@id("pattern-scout-permits-store-finding")
permit(
    principal == Agent::"pattern_scout",
    action == Action::"store_finding",
    resource
);

@id("hypothesis-repl-permits-self")
permit(
    principal == Agent::"hypothesis_repl",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::HypothesisRepl"
};

@id("chain-builder-permits-build")
permit(
    principal == Agent::"chain_builder",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::ChainBuilder"
};

// Plan E: devils_advocate is read-only; can ONLY annotate advocate_verdict.
@id("devils-advocate-permits-self")
permit(
    principal == Agent::"devils_advocate",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::DevilsAdvocate"
};

@id("devils-advocate-permits-advocate")
permit(
    principal == Agent::"devils_advocate",
    action == Action::"advocate_finding",
    resource
);

@id("devils-advocate-forbids-store")
forbid(
    principal == Agent::"devils_advocate",
    action == Action::"store_finding",
    resource
);

// Plan E: poc_forge ships reproducer scripts + marks poc_status.
@id("poc-forge-permits-self")
permit(
    principal == Agent::"poc_forge",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::PocForge"
};

@id("poc-forge-permits-mark-poc")
permit(
    principal == Agent::"poc_forge",
    action == Action::"mark_poc_status",
    resource
);

// Plan G: reflector is read-only on findings/chains; can ONLY write
// knowledge_triples (and is explicitly forbidden from store_finding).
@id("reflector-permits-self")
permit(
    principal == Agent::"reflector",
    action == Action::"execute_tool",
    resource
) when {
    resource.type == "Audit::Reflector"
};

@id("reflector-permits-write-knowledge")
permit(
    principal == Agent::"reflector",
    action == Action::"write_knowledge_triple",
    resource
);

@id("reflector-forbids-store-finding")
forbid(
    principal == Agent::"reflector",
    action == Action::"store_finding",
    resource
);
