// portal.cedar — client-portal report (engagement) access decisions.
// Used by symbi-codered-portal's authz::can_view_engagement.

// Operators see everything.
@id("operator-all")
permit(principal, action == Action::"view_engagement", resource)
when { principal has role && principal.role == "operator" };

// A client user sees a run iff it belongs to their client AND (they have no
// per-repo grants => all client repos) OR the run's repo is in their grant set.
@id("client-scoped-view")
permit(principal, action == Action::"view_engagement", resource)
when {
  principal has client && resource has client && principal.client == resource.client &&
  (principal.repos == [] || principal.repos.contains(resource.repo))
};
