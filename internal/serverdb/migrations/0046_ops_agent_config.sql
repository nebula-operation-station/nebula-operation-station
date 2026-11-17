-- 0046_ops_agent_config.sql
--
-- Ops agent settings (ADR 0016 D12, D5; AG-13; the pattern of 0041 for the
-- vulnerability agent). One row (id = 1) that the admin edits with a fresh
-- WebAuthn assertion; internal/opsconfig validates every value and writes
-- the row together with its audit entry. The row is seeded with the
-- defaults: the agent is OFF, the data class is `lab`, the language is `de`.
--
-- Deliberately no column for a credential: the LLM credential (if any) lives
-- on the agent host, never in this database. The schema test in
-- internal/opsconfig checks the column list.
--
-- The CHECKs repeat the store's bounds as a second layer; the store checks
-- scheme, host, userinfo, query and fragment of the URL, and that a `lab`
-- URL is a literal address in the lab networks.

CREATE TABLE ops_agent_config (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    enabled               INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    base_url              TEXT NOT NULL DEFAULT '' CHECK (length(CAST(base_url AS BLOB)) <= 512),
    model                 TEXT NOT NULL DEFAULT '' CHECK (length(CAST(model AS BLOB)) <= 128),
    allow_plain_http      INTEGER NOT NULL DEFAULT 0 CHECK (allow_plain_http IN (0, 1)),
    data_class            TEXT NOT NULL DEFAULT 'lab' CHECK (data_class IN ('lab', 'external')),
    operator_instructions TEXT NOT NULL DEFAULT '' CHECK (length(CAST(operator_instructions AS BLOB)) <= 4096),
    language              TEXT NOT NULL DEFAULT 'de' CHECK (language IN ('de', 'en')),
    updated_by            TEXT NOT NULL DEFAULT '' CHECK (length(CAST(updated_by AS BLOB)) <= 128),
    updated_at            INTEGER NOT NULL DEFAULT 0,
    version               INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0)
);

INSERT INTO ops_agent_config (id) VALUES (1);
