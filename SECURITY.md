# Security Policy

## Supported Versions

symbi-codered is pre-1.0; the latest released `0.1.x` line receives security
updates. Older snapshots are unsupported — upgrade to the current release.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover one in
symbi-codered, please report it to us privately.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please:

1. **Email**: Send details to security@thirdkey.ai
2. **Subject**: Include "SECURITY" in the subject line
3. **Content**: Include a description of the vulnerability, steps to reproduce,
   potential impact, and any suggested fix.

### What to Expect

- **Acknowledgment**: within 48 hours of your report
- **Assessment**: an initial response within 5 business days
- **Updates**: we keep you informed of progress throughout
- **Resolution**: we aim to resolve critical issues within 30 days

### Disclosure Policy

- We follow responsible disclosure practices.
- We will work with you to understand and resolve the issue before any public
  disclosure, and coordinate timing with you.
- We will credit you for the discovery unless you prefer to remain anonymous.

## Security Model & Best Practices

symbi-codered audits untrusted source code. It runs language scanners and
LLM-backed analysis agents against a target repository, so treat every run as
processing untrusted input:

1. **Sandboxed scanners**: scanners run in the orchestrator's Docker tiers.
   Run audits inside the provided container, bind-mounting the target repo
   **read-only** (`/audit`), rather than against your host filesystem.
2. **Cedar authorization**: every tool invocation is authorized by the Cedar
   policies in `policies/*.cedar` before it runs. Keep these policies under
   review; do not loosen the tool-authorization or scope policies casually.
3. **Hash-chained audit journal**: `.symbiont/audit/audit.jsonl` records every
   tool call with its Cedar decision, chained via SHA-256. Use
   `audit::verify_chain` to detect tampering; preserve the journal as evidence.
4. **Secrets**: never commit `.env` or API keys. Provide model/provider keys via
   environment variables or a secret store at runtime, not in the repo.
5. **LLM-supplied output is untrusted**: findings, file paths, and tool
   arguments produced by analysis agents are validated and citation-gated
   before they are trusted. Do not bypass the citation/witness gates.
6. **Network**: the optional web viewer (enterprise) binds `127.0.0.1` by
   default; never expose it on `0.0.0.0` without a TLS-terminating reverse
   proxy and authentication.

## Third-Party Dependencies

- `cargo-deny` / `cargo audit` for license and vulnerability auditing
- Cargo lockfile pinning for reproducible builds
- Automated dependency vulnerability scanning in CI

## Contact

- Security: security@thirdkey.ai
- Website: https://thirdkey.ai

---

*This security policy is subject to change. Check this document regularly for updates.*
