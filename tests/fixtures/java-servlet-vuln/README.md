# java-servlet-vuln

Deliberately vulnerable Java servlet fixture for the Plan F multilang (Java)
end-to-end coverage test.

`UserServlet.doGet` reads a user-controlled `id` from
`HttpServletRequest.getParameter` (the taint **source**) and concatenates it
into a raw SQL string passed to `Statement.executeQuery` (the CWE-89 **sink**),
with no parameterization.

Expected pipeline results (`carto` → `specifier` → `hunt`):

- ≥1 `dataflow_edge` row touching a `.java` file
- ≥1 `taint_chain` row linking a `getParameter` source to an `executeQuery` sink
- ≥1 finding with `tool_origin = semgrep` from the java scanner sidecar

This fixture is intentionally insecure. Do not copy into real code.
