# go-net-http-vuln

Deliberately vulnerable net/http + exec fixture used by Plan F
multilang coverage tests. The `/run` handler in `main.go` reads
`?cmd=` from the URL query and passes it directly to `exec.Command`
via `/bin/sh -c` — an intentional CWE-78 (OS command injection) sink
and must NOT be used outside this test fixture.
