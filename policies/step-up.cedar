// step-up.cedar — actions that require an explicit step-up auth before they
// can run.

@id("step-up-required-for-network-egress")
forbid(
    principal,
    action == Action::"network",
    resource
) unless {
    resource has step_up_token && resource.step_up_token != ""
};

@id("step-up-required-for-secret-read")
forbid(
    principal,
    action == Action::"read_secret",
    resource
) unless {
    resource has step_up_token && resource.step_up_token != ""
};
