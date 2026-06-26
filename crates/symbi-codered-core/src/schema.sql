-- =============================================================================
-- symbi-codered SQLite schema
--
-- Applied via include_str! in symbi-codered-core::db::init_db. All statements
-- use CREATE IF NOT EXISTS so init is idempotent across multiple connections.
--
-- Shared rows with symbi-redteam: engagements, findings, tool_runs, knowledge,
-- evidence. Code-audit specific: repo_facts, symbol_index, routes, secrets,
-- sboms.
-- =============================================================================

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS engagements (
    id           TEXT PRIMARY KEY,
    client       TEXT NOT NULL,
    scope_hash   TEXT NOT NULL,
    start_date   TEXT NOT NULL,
    end_date     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'planning',
    roa_hash     TEXT,
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id                    TEXT PRIMARY KEY,
    engagement_id         TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    phase                 TEXT NOT NULL,
    severity              TEXT NOT NULL,
    confidence            TEXT NOT NULL,
    cwe                   TEXT,
    owasp                 TEXT,
    file_path             TEXT NOT NULL,
    line_start            INTEGER NOT NULL,
    line_end              INTEGER NOT NULL,
    title                 TEXT NOT NULL,
    description           TEXT NOT NULL,
    reachable             INTEGER,          -- nullable bool: 0/1/NULL
    exploitable           INTEGER,
    evidence_envelope_id  TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'open',
    rank_score            REAL,
    -- AI-perspective amendments: pinned threat-model reference, devil's-advocate
    -- verdict, producing-analyzer attribution, and PoC outcome status.
    specifier_hash        TEXT,
    advocate_verdict      TEXT,             -- confirmed | rebutted | uncertain
    tool_origin           TEXT,             -- which analyzer produced the finding
    poc_status            TEXT,             -- hypothesis | poc_attempted | reproduced | refuted
    created_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_status     ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);

CREATE TABLE IF NOT EXISTS tool_runs (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    tool            TEXT NOT NULL,
    args_json       TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    duration_ms     INTEGER NOT NULL,
    exit_code       INTEGER NOT NULL,
    envelope_id     TEXT,
    cedar_decision  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tool_runs_engagement ON tool_runs(engagement_id);

CREATE TABLE IF NOT EXISTS knowledge (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    subject         TEXT NOT NULL,
    predicate       TEXT NOT NULL,
    object          TEXT NOT NULL,
    confidence      REAL NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_knowledge_engagement ON knowledge(engagement_id);

CREATE TABLE IF NOT EXISTS evidence (
    envelope_id     TEXT PRIMARY KEY,
    sha256          TEXT NOT NULL,
    path            TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- Code-audit specific tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS repo_facts (
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,    -- language | framework | entrypoint | dependency | route | symbol
    json            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_repo_facts_engagement_kind ON repo_facts(engagement_id, kind);

CREATE TABLE IF NOT EXISTS symbol_index (
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    file_path       TEXT NOT NULL,
    line_start      INTEGER NOT NULL,
    line_end        INTEGER NOT NULL,
    kind            TEXT NOT NULL,   -- function | class | method | trait | type
    name            TEXT NOT NULL,
    language        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_symbol_index_engagement_name ON symbol_index(engagement_id, name);

CREATE TABLE IF NOT EXISTS routes (
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    handler_symbol  TEXT NOT NULL,
    middleware      TEXT,             -- JSON array
    auth_required   INTEGER,          -- nullable bool
    roles           TEXT               -- JSON array
);
CREATE INDEX IF NOT EXISTS idx_routes_engagement ON routes(engagement_id);

CREATE TABLE IF NOT EXISTS dataflow_edges (
    engagement_id  TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    from_symbol    TEXT NOT NULL,
    to_symbol      TEXT NOT NULL,
    edge_kind      TEXT NOT NULL,    -- "assign" | "call_arg" | "subscript" | "return"
    file_path      TEXT NOT NULL,
    line           INTEGER NOT NULL,
    PRIMARY KEY (engagement_id, from_symbol, to_symbol, line)
);
CREATE INDEX IF NOT EXISTS idx_dataflow_to       ON dataflow_edges(engagement_id, to_symbol);
CREATE INDEX IF NOT EXISTS idx_dataflow_from     ON dataflow_edges(engagement_id, from_symbol);

CREATE TABLE IF NOT EXISTS secrets (
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    file_path       TEXT NOT NULL,
    line            INTEGER NOT NULL,
    kind            TEXT NOT NULL,
    classification  TEXT NOT NULL,   -- real | fake | test_fixture | expired | public
    git_age_days    INTEGER,
    packaged        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_secrets_engagement ON secrets(engagement_id);

CREATE TABLE IF NOT EXISTS sboms (
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    format          TEXT NOT NULL,   -- spdx | cyclonedx
    path            TEXT NOT NULL,
    envelope_id     TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- AI-perspective amendment tables (see 2026-05-22-ai-perspective-amendments.md)
-- ---------------------------------------------------------------------------

-- Pinned threat model produced by the specifier agent.
-- Every finding's specifier_hash must reference a row here.
CREATE TABLE IF NOT EXISTS threat_models (
    specifier_hash   TEXT PRIMARY KEY,         -- sha256(canonical JSON)
    engagement_id    TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    json             TEXT NOT NULL,            -- structured threat model
    signed_at        TEXT NOT NULL,
    signature        TEXT NOT NULL             -- Ed25519 signature (AgentPin)
);
CREATE INDEX IF NOT EXISTS idx_threat_models_engagement ON threat_models(engagement_id);

-- Citations attached to pattern_scout findings. citation.cedar enforces non-empty.
CREATE TABLE IF NOT EXISTS finding_citations (
    finding_id       TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    citation_type    TEXT NOT NULL,            -- analyzer | code | hypothesis
    analyzer_finding TEXT,
    code_path        TEXT,
    code_line_start  INTEGER,
    code_line_end    INTEGER,
    hypothesis_id    TEXT,
    intended_poc     TEXT
);
CREATE INDEX IF NOT EXISTS idx_finding_citations_id ON finding_citations(finding_id);

-- Hypotheses flagged for poc_forge to attempt reproduction.
CREATE TABLE IF NOT EXISTS hypotheses (
    id               TEXT PRIMARY KEY,
    engagement_id    TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    description      TEXT NOT NULL,
    status           TEXT NOT NULL,            -- proposed | poc_attempted | reproduced | refuted
    created_by_agent TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_engagement ON hypotheses(engagement_id);

-- Mechanical taint chains from taint_tracer.
-- Reproducible: given a fixed dataflow graph, the same (source,sink) yields the same chain.
CREATE TABLE IF NOT EXISTS taint_chains (
    id                  TEXT PRIMARY KEY,
    engagement_id       TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    source_file         TEXT NOT NULL,
    source_line         INTEGER NOT NULL,
    sink_file           TEXT NOT NULL,
    sink_line           INTEGER NOT NULL,
    chain_json          TEXT NOT NULL,         -- [{file, line, propagation_reason}, ...]
    sanitizers_seen     TEXT,                  -- JSON array
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_taint_chains_engagement ON taint_chains(engagement_id);

-- Attack chains: kill-chain graph rows. Stages:
--   surface_mapping | tool_subversion | instruction_injection | reasoning_capture |
--   gate_evasion | privileged_action | audit_evasion
-- Each hop links to the next via next_chain_id and must carry evidence.
CREATE TABLE IF NOT EXISTS attack_chains (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    stage           TEXT NOT NULL,
    finding_id      TEXT REFERENCES findings(id),
    evidence_id     TEXT REFERENCES evidence(envelope_id),
    next_chain_id   TEXT REFERENCES attack_chains(id),
    rationale       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attack_chains_engagement ON attack_chains(engagement_id);

-- ---------------------------------------------------------------------------
-- Plan G: knowledge_triples — reflector-emitted reusable knowledge
-- ---------------------------------------------------------------------------
-- Cross-engagement (subject, predicate, object) facts distilled at the end of
-- each engagement by the reflector agent. Future engagements can
-- `recall_knowledge_by_subject` to pull prior learnings.
CREATE TABLE IF NOT EXISTS knowledge_triples (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    subject         TEXT NOT NULL,   -- e.g. "axum::extract::Query"
    predicate       TEXT NOT NULL,   -- e.g. "is_taint_source_for"
    object          TEXT NOT NULL,   -- e.g. "sqlx::query"
    confidence      REAL,            -- 0.0-1.0
    rationale       TEXT,
    source_phase    TEXT NOT NULL,   -- "static_hunter" | "pattern_scout" | "chain_builder" | "poc_forge" | "devils_advocate" | "reflector"
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_kt_engagement ON knowledge_triples(engagement_id);
CREATE INDEX IF NOT EXISTS idx_kt_subject ON knowledge_triples(subject);
CREATE INDEX IF NOT EXISTS idx_kt_predicate ON knowledge_triples(predicate);
