# typescript-express-vuln

Deliberately vulnerable Express + TypeScript fixture used by Plan F
multilang coverage tests. The `/search` handler in `src/index.ts` reads
`req.query.q` (user-controlled) and interpolates it into an HTML
response via `res.send` without escaping — an intentional CWE-79
(reflected XSS) sink and must NOT be used outside this test fixture.
