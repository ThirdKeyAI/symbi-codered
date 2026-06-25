// citation.cedar — the witness/lawyer rule (now with attribute-bearing
// resource entities, see Plan D Task 8).

@id("citation-required-on-store-finding")
forbid(
    principal,
    action == Action::"store_finding",
    resource
) unless {
    resource has citations &&
    (resource.citations.contains("analyzer") ||
     resource.citations.contains("code") ||
     resource.citations.contains("hypothesis"))
};
