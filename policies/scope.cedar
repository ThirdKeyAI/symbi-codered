// scope.cedar — restricts writes to reports/, data/, evidence/, .symbiont/audit/.
// Skeleton: only the audit-controller may write to .symbiont/audit/* in Plan A.

@id("scope-write-audit-journal")
permit(
    principal == Agent::"audit-controller",
    action == Action::"write",
    resource
) when {
    resource.path like ".symbiont/audit/*"
};
