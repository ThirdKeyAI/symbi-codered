# Governance & Trust

Everything that touches a finding or a tool call is policy-gated and audited. The guarantees are structural — enforced by [Cedar](https://www.cedarpolicy.com/) policies and a hash-chained journal, not by convention.

## Cedar policies

Policies live in [`policies/`](https://github.com/ThirdKeyAI/symbi-codered/tree/main/policies):

| Policy | Invariant |
|--------|-----------|
| `citation.cedar` | Every `store_finding` requires ≥1 citation (`Citation::{Analyzer,Code,Hypothesis}`). |
| `evidence.cedar` | Every `store_finding` requires a `specifier_hash` + non-empty `envelope_id`. |
| `tool-authorization.cedar` | Per-agent permits + the `devils-advocate-forbids-store` invariant. |
| `advocate.cedar` | A `rebutted` advocate verdict requires a structural witness (suppression is witness-bound, symmetric with finding creation). |
| `handoff.cedar` | Which findings are eligible for the redteam handoff (advocate-confirmed/uncertain, citation-bearing, severity ≥ medium, poc not refuted; `inconclusive` is **not** dropped — a non-test is not a disproof). |
| `step-up.cedar` | Actions requiring out-of-band approval. |
| `phase-gates.cedar` | Ordering constraints between stages. |
| `reflector.cedar` | The reflector's capability surface. |

## The witness/lawyer rule

A finding cannot be *created* without a citation, and — symmetrically — cannot be *suppressed* without one either. The `devils_advocate` runs an inverted prompt that tries to refute each finding, but Cedar forbids it from calling `store_finding` at all, and `advocate.cedar` forbids a `rebutted` verdict unless the rebuttal cites a structural witness (envelope / sanitizer / closed-set / constant-caller). The rebuttal's witness is written as an evidence envelope referenced from the signed journal.

The result: both *asserting* and *retracting* a finding are evidence-bound operations. There is no path where an LLM's bare assertion changes the reported set.

## Audit journal

The audit journal at `.symbiont/audit/audit.jsonl` records every tool invocation with its Cedar decision and chains entries via SHA-256. `audit::verify_chain` proves the journal hasn't been tampered with — if any entry is edited or removed, the chain breaks.

## Signing

A per-engagement Ed25519 keypair (`.symbiont/keys/<eng>.{priv,pub}`) anchors two artifacts:

- The **specifier** signs the threat model, so the scan target can't silently drift onto the wrong tree.
- The **reporter** signs the `engagement-seed.json` handoff, which is also Cedar-filtered so only handoff-eligible findings leave the engagement.

Downstream consumers (e.g. [symbi-redteam](https://github.com/ThirdKeyAI/symbi-redteam)) verify the signature before ingesting the seed.
