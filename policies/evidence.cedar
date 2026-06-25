// evidence.cedar — finding admissibility rules.

@id("evidence-store-finding-requires-envelope")
forbid(
    principal,
    action == Action::"store_finding",
    resource
) when {
    resource has evidence_envelope_id && resource.evidence_envelope_id == ""
};

@id("evidence-store-finding-requires-specifier-hash")
forbid(
    principal,
    action == Action::"store_finding",
    resource
) unless {
    resource has specifier_hash
};
