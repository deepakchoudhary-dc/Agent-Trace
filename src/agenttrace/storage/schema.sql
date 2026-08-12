-- AgentTrace SQLite schema
-- All payload data is application-level encrypted (AES-256-GCM)
-- Hash chain provides tamper detection

CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    config_json   TEXT NOT NULL,
    task_desc     TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'starting',
    agents_json   TEXT NOT NULL DEFAULT '[]',
    started_at    TEXT NOT NULL,
    stopped_at    TEXT,
    event_count   INTEGER NOT NULL DEFAULT 0,
    last_event_hash TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    event_type    TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    actor_id      TEXT NOT NULL,
    source_adapter TEXT NOT NULL,
    confidence    TEXT NOT NULL DEFAULT 'high',
    payload_enc   BLOB,           -- AES-256-GCM encrypted JSON
    event_hash    TEXT NOT NULL,
    prev_hash     TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    seq           INTEGER NOT NULL  -- Monotonic sequence within session
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id);
CREATE INDEX IF NOT EXISTS idx_events_seq ON events(session_id, seq);

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id       TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    node_type     TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT '',
    timestamp     TEXT NOT NULL,
    actor_id      TEXT NOT NULL DEFAULT '',
    source_adapter TEXT NOT NULL DEFAULT '',
    confidence    TEXT NOT NULL DEFAULT 'high',
    content_hash  TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    data_enc      BLOB            -- AES-256-GCM encrypted JSON
);

CREATE INDEX IF NOT EXISTS idx_nodes_session ON graph_nodes(session_id);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id       TEXT PRIMARY KEY,
    source_node_id TEXT NOT NULL REFERENCES graph_nodes(node_id),
    target_node_id TEXT NOT NULL REFERENCES graph_nodes(node_id),
    edge_type     TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    actor_id      TEXT NOT NULL DEFAULT '',
    source_adapter TEXT NOT NULL DEFAULT '',
    confidence    TEXT NOT NULL DEFAULT 'high',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    data_enc      BLOB
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON graph_edges(edge_type);

CREATE TABLE IF NOT EXISTS blobs (
    content_hash  TEXT PRIMARY KEY,
    file_path     TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id   TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    finding_id    TEXT NOT NULL,
    approved      INTEGER NOT NULL DEFAULT 0,
    reason        TEXT NOT NULL DEFAULT '',
    scope         TEXT NOT NULL DEFAULT '',
    expiry        TEXT,
    affected_json TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    event_hash    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);
CREATE INDEX IF NOT EXISTS idx_approvals_finding ON approvals(finding_id);

CREATE TABLE IF NOT EXISTS task_contracts (
    contract_id   TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    goal          TEXT NOT NULL,
    allowed_paths TEXT NOT NULL DEFAULT '[]',
    prohibited_paths TEXT NOT NULL DEFAULT '[]',
    expected_tests TEXT NOT NULL DEFAULT '[]',
    allowed_tools TEXT NOT NULL DEFAULT '[]',
    risk_level    TEXT NOT NULL DEFAULT 'medium',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    notes         TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_contracts_session ON task_contracts(session_id);
