-- Vulnerability agent LLM settings (ADR 0011 amendment 1, "LLM settings";
-- autopilot va09).
--
-- One row (id = 1) that the admin edits on the settings page with a fresh
-- WebAuthn assertion; every change is audited by internal/vulnstore
-- (AgentConfigStore.Change) in the same write transaction. The agent reads
-- it through GET /api/v1/vuln/agent-config with its token. No row means
-- "never saved": the store returns its defaults. An empty llm_base_url or
-- llm_model means the agent's local configuration wins. The LLM API key is
-- never stored here; it stays on the agent host.
--
-- The CHECKs repeat the store's bounds as a second layer; the store
-- validates scheme, host, userinfo, query and fragment of the URL.

CREATE TABLE vuln_agent_config (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    llm_enabled           INTEGER NOT NULL CHECK (llm_enabled IN (0, 1)),
    llm_base_url          TEXT NOT NULL CHECK (length(CAST(llm_base_url AS BLOB)) <= 512),
    llm_model             TEXT NOT NULL CHECK (length(CAST(llm_model AS BLOB)) <= 128),
    operator_instructions TEXT NOT NULL CHECK (length(CAST(operator_instructions AS BLOB)) <= 4096),
    language              TEXT NOT NULL CHECK (language IN ('de', 'en')),
    updated_by            TEXT NOT NULL CHECK (length(CAST(updated_by AS BLOB)) BETWEEN 1 AND 128),
    updated_at            INTEGER NOT NULL,
    version               INTEGER NOT NULL CHECK (version >= 1)
);
