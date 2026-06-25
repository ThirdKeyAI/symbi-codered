// network.cedar — default deny outbound. Per-endpoint permits added in Plan C.
@id("network-default-deny")
forbid(
    principal,
    action == Action::"network",
    resource
);
