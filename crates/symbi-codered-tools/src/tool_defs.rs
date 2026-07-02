//! JSON-Schema tool definitions handed to the LLM via Symbiont's
//! [`LoopConfig::tool_definitions`]. Without these, the model has no
//! tools to call — it can only return text.
//!
//! One helper per agent; each returns the slice of tools that agent is
//! authorized to invoke (matches the agent's `.symbi` capabilities list).

use serde_json::json;
use symbi_runtime::reasoning::inference::ToolDefinition;

fn td(name: &str, description: &str, parameters: serde_json::Value) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        parameters,
    }
}

pub fn pattern_scout() -> Vec<ToolDefinition> {
    vec![
        td("query_threat_model",
           "Read the pinned threat model (sources, sinks, scope, languages) for this engagement.",
           json!({"type":"object","properties":{},"required":[]})),
        td("query_findings",
           "Paginated list of existing findings. Returns {findings, page, page_size, total, returned, has_more, compact}. Call with page=0 first; if has_more=true, increment page. Pass compact=true to drop description (halves per-row tokens) — use this for index/triage passes, then query_finding_detail(id) when you need full text.",
           json!({"type":"object","properties":{
               "tool_origin":{"type":"string","description":"Filter by producing tool (semgrep|bandit|pip_audit|ruff)"},
               "page":{"type":"integer","minimum":0,"default":0,"description":"0-indexed page number"},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30},
               "compact":{"type":"boolean","default":false,"description":"Drop description field; saves ~50% tokens per row"}
           }})),
        td("query_finding_detail",
           "Fetch ONE finding's full record (incl. description). Use after query_findings(compact=true) when you want to read a specific finding's narrative.",
           json!({"type":"object","properties":{
               "finding_id":{"type":"string"}
           },"required":["finding_id"]})),
        td("query_taint_chains",
           "PAGINATED list of taint chains. Returns {chains, page, page_size, total, returned, has_more}. UNGUARDED chains (unguarded=true) are surfaced first — they're missing-auth candidates. The list view gives source/sink file:line + hop_count + unguarded flag; use read_context_range on the sink to see code. Iterate page=N until has_more=false.",
           json!({"type":"object","properties":{
               "page":{"type":"integer","minimum":0,"default":0},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30}
           }})),
        td("read_context_range",
           "Read a line range from a file inside the target repo (read-only).",
           json!({"type":"object","properties":{
               "file_path":{"type":"string","description":"Path relative to target repo"},
               "line_start":{"type":"integer","minimum":1},
               "line_end":{"type":"integer","minimum":1}
           },"required":["file_path","line_start","line_end"]})),
        td("hypothesis_repl",
           "Spin up an isolated fresh-context sub-agent that REASONS about one hypothesis from its text alone (no code/file access yet) and returns {verdict, transcript_envelope_id}. verdict ∈ reproduced|refuted|uncertain. budget_iterations bounds the sub-agent's turns.",
           json!({"type":"object","properties":{
               "hypothesis_text":{"type":"string"},
               "budget_iterations":{"type":"integer","minimum":1,"maximum":20,"default":5}
           },"required":["hypothesis_text"]})),
        td("store_finding",
           "Write a finding. Every finding MUST carry at least one citation (analyzer|code|hypothesis). Cedar will deny otherwise.",
           json!({"type":"object","properties":{
               "severity":{"type":"string","enum":["critical","high","medium","low","info"]},
               "confidence":{"type":"string","enum":["high","medium","low"]},
               "cwe":{"type":"string"},
               "owasp":{"type":"string"},
               "file_path":{"type":"string"},
               "line_start":{"type":"integer"},
               "line_end":{"type":"integer"},
               "title":{"type":"string"},
               "description":{"type":"string"},
               "citations":{"type":"array","items":{"type":"object","properties":{
                   "type":{"type":"string","enum":["analyzer","code","hypothesis"]},
                   "rule_id":{"type":"string","description":"For type=analyzer: the source rule id"},
                   "file_path":{"type":"string","description":"For type=code: path"},
                   "line_start":{"type":"integer"},
                   "line_end":{"type":"integer"},
                   "hypothesis_id":{"type":"string","description":"For type=hypothesis"},
                   "intended_poc":{"type":"string"}
               },"required":["type"]},"minItems":1}
           },"required":["severity","file_path","line_start","line_end","title","description","citations"]})),
    ]
}

pub fn chain_builder() -> Vec<ToolDefinition> {
    vec![
        td("query_findings",
           "Paginated list of findings (compact by default — id+file:line+cwe+severity+title only, no description). Returns {findings, page, page_size, total, returned, has_more, compact}. Iterate page=0,1,2... while has_more=true.",
           json!({"type":"object","properties":{
               "tool_origin":{"type":"string"},
               "page":{"type":"integer","minimum":0,"default":0},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30},
               "compact":{"type":"boolean","default":true}
           }})),
        td("query_taint_chains",
           "PAGINATED list of taint chains. Returns {chains, page, page_size, total, returned, has_more}. UNGUARDED chains (unguarded=true) surface first. Per row: source/sink file:line + hop_count + unguarded flag. Iterate page=N until has_more=false.",
           json!({"type":"object","properties":{
               "page":{"type":"integer","minimum":0,"default":0},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30}
           }})),
        td("build_attack_chain",
           "Cluster findings into one kill-chain stage. stage ∈ {surface_mapping, tool_subversion, instruction_injection, reasoning_capture, gate_evasion, privileged_action, audit_evasion}.",
           json!({"type":"object","properties":{
               "stage":{"type":"string","enum":[
                   "surface_mapping","tool_subversion","instruction_injection",
                   "reasoning_capture","gate_evasion","privileged_action","audit_evasion"
               ]},
               "finding_ids":{"type":"array","items":{"type":"string"},"minItems":1},
               "rationale":{"type":"string","description":"Brief why-this-cluster explanation"}
           },"required":["stage","finding_ids"]})),
    ]
}

pub fn devils_advocate() -> Vec<ToolDefinition> {
    vec![
        td("query_findings",
           "Paginated list of findings to challenge (compact by default — id+file:line+cwe+severity+title, no description). Returns {findings, page, page_size, total, returned, has_more, compact}. ADVOCATE EACH PAGE before fetching the next: call query_findings(page=N), then advocate_finding(...) on every id returned, then query_findings(page=N+1).",
           json!({"type":"object","properties":{
               "tool_origin":{"type":"string"},
               "page":{"type":"integer","minimum":0,"default":0},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30},
               "compact":{"type":"boolean","default":true}
           }})),
        td("read_context_range",
           "Read a line range from a file inside the target repo (read-only). Use this to VERIFY a finding before confirming it: open the sink AND its callers/registration to check claims like 'X is request-controlled' or 'this argument is attacker-influenced'. Do not confirm an injection/taint finding on its description alone.",
           json!({"type":"object","properties":{
               "file_path":{"type":"string","description":"Path relative to target repo"},
               "line_start":{"type":"integer","minimum":1},
               "line_end":{"type":"integer","minimum":1}
           },"required":["file_path","line_start","line_end"]})),
        td("advocate_finding",
           "Set findings.advocate_verdict for one finding. verdict ∈ {confirmed, rebutted, uncertain}. SUPPRESSION IS WITNESS-GATED (Cedar): verdict=rebutted REQUIRES a non-empty `reason` AND a `witness` array naming at least one recognized kind — otherwise the rebuttal is denied by policy and the finding is NOT dropped. confirmed/uncertain need neither (asymmetric cost: dropping a finding costs more than keeping it).",
           json!({"type":"object","properties":{
               "finding_id":{"type":"string"},
               "verdict":{"type":"string","enum":["confirmed","rebutted","uncertain"]},
               "reason":{"type":"string","description":"Required & non-empty for verdict=rebutted (prose argument). Optional otherwise."},
               "witness":{"type":"array","description":"Required for verdict=rebutted. Each item cites the rebuttal's evidence.","items":{"type":"object","properties":{
                   "type":{"type":"string","enum":["envelope","sanitizer","closed_set","constant_caller","wrong_library"],"description":"envelope = a read_context_range envelope id you read; sanitizer = a named sanitizer that neutralizes the sink; closed_set = the value is a closed set of literals; constant_caller = every caller passes a constant; wrong_library = the rule fired on the wrong library (e.g. a jQuery .html() rule matching lit-html's auto-escaping `html` template) — ref the import line that proves it."},
                   "ref":{"type":"string","description":"The id/name/location backing the witness."}
               },"required":["type"]}}
           },"required":["finding_id","verdict"]})),
    ]
}

pub fn reflector() -> Vec<ToolDefinition> {
    vec![
        td("query_findings",
           "Paginated list of findings (compact by default — id+file:line+cwe+severity+title only). Returns {findings, page, page_size, total, returned, has_more, compact}. Iterate page=0,1,2... while has_more=true.",
           json!({"type":"object","properties":{
               "tool_origin":{"type":"string"},
               "page":{"type":"integer","minimum":0,"default":0},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30},
               "compact":{"type":"boolean","default":true}
           }})),
        td("query_finding_detail",
           "Fetch ONE finding's full record (incl. description). Use after query_findings(compact=true) when distilling a specific pattern.",
           json!({"type":"object","properties":{
               "finding_id":{"type":"string"}
           },"required":["finding_id"]})),
        td("query_taint_chains",
           "PAGINATED list of taint chains. Returns {chains, page, page_size, total, returned, has_more}. UNGUARDED chains (unguarded=true) are surfaced first — they're missing-auth candidates. The list view gives source/sink file:line + hop_count + unguarded flag; use read_context_range on the sink to see code. Iterate page=N until has_more=false.",
           json!({"type":"object","properties":{
               "page":{"type":"integer","minimum":0,"default":0},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30}
           }})),
        td("query_attack_chains",
           "Paginated list of chain_builder-emitted attack_chain nodes for this engagement. Returns {nodes, page, page_size, total, returned, has_more}. Iterate while has_more=true.",
           json!({"type":"object","properties":{
               "page":{"type":"integer","minimum":0,"default":0},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30}
           }})),
        td("write_knowledge_triple",
           "Insert one (subject, predicate, object) knowledge triple distilled from this engagement. Predicates are free-form but should be reusable patterns like is_taint_source_for, mitigates, commonly_misused_via, prefers_pattern, false_positive_class. Confidence in [0.0, 1.0].",
           json!({"type":"object","properties":{
               "subject":{"type":"string"},
               "predicate":{"type":"string"},
               "object":{"type":"string"},
               "confidence":{"type":"number","minimum":0.0,"maximum":1.0},
               "rationale":{"type":"string"}
           },"required":["subject","predicate","object"]})),
    ]
}

pub fn poc_forge() -> Vec<ToolDefinition> {
    vec![
        td("query_findings",
           "Paginated list of candidate findings eligible for reproduction (CWE-89/78/22/94/79, status=open, poc_status NULL). Returns {findings, page, page_size, total, returned, has_more}. Iterate while has_more=true.",
           json!({"type":"object","properties":{
               "page":{"type":"integer","minimum":0,"default":0},
               "page_size":{"type":"integer","minimum":1,"maximum":100,"default":30}
           }})),
        td("read_context_range",
           "Read a line range from a file inside the target repo.",
           json!({"type":"object","properties":{
               "file_path":{"type":"string"},
               "line_start":{"type":"integer"},
               "line_end":{"type":"integer"}
           },"required":["file_path","line_start","line_end"]})),
        td("run_reproducer",
           "Ship a reproducer script to the language-appropriate sandbox. Script MUST print REPRODUCED on success or REFUTED on failure. The `language` arg routes the script to the right sandbox (python|rust|typescript|javascript|go); if omitted, language is inferred from `finding_id`'s file extension (and falls back to python). Returns {verdict, ok, exit_code, timed_out, stdout, stderr, language}.",
           json!({"type":"object","properties":{
               "script":{"type":"string","description":"Source code in the target sandbox's language"},
               "timeout_seconds":{"type":"integer","minimum":1,"maximum":120,"default":30},
               "language":{"type":"string","enum":["python","rust","typescript","javascript","go"],"description":"Optional — inferred from finding_id's file extension if absent, then defaults to python"},
               "finding_id":{"type":"string","description":"Optional — used to infer language when `language` is absent"}
           },"required":["script"]})),
        td("mark_poc_status",
           "Set findings.poc_status for one finding. status ∈ {reproduced, refuted, reproduced_by_citation}. A refuted mark also downgrades findings.status to 'hypothesis'.",
           json!({"type":"object","properties":{
               "finding_id":{"type":"string"},
               "status":{"type":"string","enum":["reproduced","refuted","reproduced_by_citation"]}
           },"required":["finding_id","status"]})),
        td("emit_source_proof",
           "Tier-B PoC: prove a finding by citing the relevant source code locations rather than running an exploit. Each citation gets re-read by the executor — if the cited line range no longer contains the `expected_substring`, the proof is rejected. Use this for findings that cannot be reproduced in a sandbox (authz bypass, missing-auth chains, multi-service flows). On success, the finding's poc_status is set to 'reproduced_by_citation'.",
           json!({"type":"object","properties":{
               "finding_id":{"type":"string"},
               "claim":{"type":"string","description":"One-paragraph statement of what the citations together prove"},
               "citations":{"type":"array","items":{"type":"object","properties":{
                   "file_path":{"type":"string"},
                   "line_start":{"type":"integer","minimum":1},
                   "line_end":{"type":"integer","minimum":1},
                   "expected_substring":{"type":"string","description":"A substring that MUST be present in the cited range — the executor will fail the proof if missing"},
                   "role":{"type":"string","description":"Why this citation matters: e.g., 'sink', 'unguarded_handler', 'safe_sibling'"}
               },"required":["file_path","line_start","line_end","expected_substring"]},"minItems":1}
           },"required":["finding_id","claim","citations"]})),
    ]
}
