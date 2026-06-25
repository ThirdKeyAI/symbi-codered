# AGENTS.md

This file enumerates the Symbiont agents loaded by the orchestrator.

## audit-controller

- **Description:** Engagement orchestrator. Owns engagement state, runs
  phase gates, delegates phase work via `ask()` to phase agents.
- **DSL:** `agents/audit-controller.symbi`
- **Sandbox:** Tier 1 (Docker)
- **Memory:** Ephemeral per engagement
- **Cedar policies:** `policies/phase-gates.cedar`, `policies/scope.cedar`
- **Status (Plan A):** Stub — creates engagement row, no phase delegation yet.

(Phase agents — `repo-intel`, `sast`, `deps`, `secrets`, `config`, `triage`,
`reflector`, `reporter` — added in Plans B–F.)
