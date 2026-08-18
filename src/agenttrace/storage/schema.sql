-- AgentTrace SQLite schema
-- Full-fidelity, tamper-evident hash-chained event ledger
-- All sensitive columns & payloads are AES-256-GCM encrypted at rest

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    config_enc      BLOB NOT NULL,          -- AES-256-GCM encrypted JSON
    task_desc_enc   BLOB NOT NULL,          -- AES-256-GCM encrypted text
    status          TEXT NOT NULL DEFAULT 'starting',
    agents_json     TEXT NOT NULL DEFAULT '[]',
    started_at      TEXT NOT NULL,
    stopped_at      TEXT,
    event_count     INTEGER NOT NULL DEFAULT 0,
    last_event_hash TEXT NOT NULL DEFAULT '',
    metadata_enc    BLOB                    -- AES-256-GCM encrypted JSON
);

CREATE TABLE IF NOT EXISTS events (
    event_id            TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL REFERENCES sessions(session_id),
    event_type          TEXT NOT NULL,
    timestamp           TEXT NOT NULL,
    actor_id            TEXT NOT NULL,
    source_adapter      TEXT NOT NULL,
    confidence          TEXT NOT NULL DEFAULT 'high',
    canonical_json      TEXT NOT NULL DEFAULT '',  -- Legacy plaintext envelope (pre-v0.3); empty for new rows
    canonical_json_enc  BLOB,                      -- AES-256-GCM encrypted canonical envelope
    canonical_json_hash TEXT NOT NULL DEFAULT '',  -- SHA-256 of the canonical envelope (tamper evidence w/o plaintext)
    payload_enc         BLOB,                      -- AES-256-GCM encrypted payload
    event_hash          TEXT NOT NULL UNIQUE,
    prev_hash           TEXT NOT NULL DEFAULT '',
    seq                 INTEGER NOT NULL,          -- Strict monotonic 0-based sequence
    index_binding_hash  TEXT NOT NULL DEFAULT ''   -- SHA-256 binding over the indexed projection
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id);
CREATE INDEX IF NOT EXISTS idx_events_seq ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_hash ON events(event_hash);

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id         TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    node_type       TEXT NOT NULL,
    label_enc       BLOB NOT NULL,          -- AES-256-GCM encrypted label
    timestamp       TEXT NOT NULL,
    actor_id        TEXT NOT NULL DEFAULT '',
    source_adapter  TEXT NOT NULL DEFAULT '',
    confidence      TEXT NOT NULL DEFAULT 'high',
    content_hash    TEXT NOT NULL DEFAULT '',
    evidence_json   TEXT NOT NULL DEFAULT '[]',
    data_enc        BLOB                    -- AES-256-GCM encrypted JSON
);

CREATE INDEX IF NOT EXISTS idx_nodes_session ON graph_nodes(session_id);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id         TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    source_node_id  TEXT NOT NULL REFERENCES graph_nodes(node_id),
    target_node_id  TEXT NOT NULL REFERENCES graph_nodes(node_id),
    edge_type       TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    actor_id        TEXT NOT NULL DEFAULT '',
    source_adapter  TEXT NOT NULL DEFAULT '',
    confidence      TEXT NOT NULL DEFAULT 'high',
    evidence_json   TEXT NOT NULL DEFAULT '[]',
    data_enc        BLOB
);

CREATE INDEX IF NOT EXISTS idx_edges_session ON graph_edges(session_id);
CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON graph_edges(edge_type);

CREATE TABLE IF NOT EXISTS blobs (
    blob_hash       TEXT PRIMARY KEY,
    session_id      TEXT REFERENCES sessions(session_id),
    file_path       TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blobs_session ON blobs(session_id);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id     TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    finding_id      TEXT NOT NULL,
    approved        INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'granted',  -- requested | granted | denied
    reason_enc      BLOB NOT NULL,          -- AES-256-GCM encrypted text
    scope_enc       BLOB NOT NULL,          -- AES-256-GCM encrypted text
    expiry          TEXT,
    affected_enc    BLOB NOT NULL,          -- AES-256-GCM encrypted JSON
    created_at      TEXT NOT NULL,
    event_hash      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);
CREATE INDEX IF NOT EXISTS idx_approvals_finding ON approvals(finding_id);

CREATE TABLE IF NOT EXISTS task_contracts (
    contract_id     TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    goal_enc        BLOB NOT NULL,          -- AES-256-GCM encrypted text
    allowed_enc     BLOB NOT NULL,          -- AES-256-GCM encrypted JSON
    prohibited_enc  BLOB NOT NULL,          -- AES-256-GCM encrypted JSON
    tests_enc       BLOB NOT NULL,          -- AES-256-GCM encrypted JSON
    tools_enc       BLOB NOT NULL,          -- AES-256-GCM encrypted JSON
    risk_level      TEXT NOT NULL DEFAULT 'medium',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    notes_enc       BLOB                    -- AES-256-GCM encrypted text
);

CREATE INDEX IF NOT EXISTS idx_contracts_session ON task_contracts(session_id);

CREATE TABLE IF NOT EXISTS review_runs (
    loop_id     TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(session_id),
    passed      INTEGER NOT NULL DEFAULT 0,
    iterations  INTEGER NOT NULL DEFAULT 0,
    payload_enc BLOB NOT NULL,          -- AES-256-GCM encrypted JSON (redacted)
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_review_runs_session ON review_runs(session_id);

-- Per-session adapter resume state (file offsets, seen records) so a
-- restarted daemon resumes observation exactly where it left off instead of
-- replaying the source (duplicates) or skipping downtime activity.
CREATE TABLE IF NOT EXISTS adapter_cursors (
    session_id   TEXT PRIMARY KEY REFERENCES sessions(session_id),
    adapter_name TEXT NOT NULL,
    cursor_enc   BLOB NOT NULL,          -- AES-256-GCM encrypted JSON
    updated_at   TEXT NOT NULL
);

-- Per-workspace egress destination baseline: destinations that have already
-- been observed and approved for a workspace. New destinations not in this
-- baseline pause behind the network-egress gate instead of being re-flagged
-- on every daemon restart.
CREATE TABLE IF NOT EXISTS destination_baseline (
    workspace_path TEXT NOT NULL,
    destination    TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    PRIMARY KEY (workspace_path, destination)
);
