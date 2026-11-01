-- 0017_pve_jobs.sql (ADR 0006 P2-01 subset, ADR 0008 PV-01): durable
-- record of every PVE mutation step. A row is written in state
-- 'dispatching' (intent) and synced before the mutation is sent; the
-- returned UPID and task node are stored before the step is reported or
-- the next step is dispatched. A persisted row confers observation
-- authority only: reconciliation after a restart or a lost response reads
-- the task with the read token and never sends the mutation again.
--
-- States: dispatching (intent durable, fate of the request unknown),
-- running (UPID stored), reconciling (response lost or restart; task not
-- yet identified), succeeded, failed, unknown (terminal; the exact task
-- could not be identified or its record is gone).
--
-- task_type and task_user are the PVE task type and the action token ID
-- (user@realm!token) the step's task must carry: a UPID is stored for a
-- step only when both match, and one UPID never belongs to two steps.
CREATE TABLE pve_jobs (
    execution_id     TEXT NOT NULL CHECK (length(execution_id) BETWEEN 1 AND 64),
    step             INTEGER NOT NULL CHECK (step BETWEEN 1 AND 16),
    digest           TEXT NOT NULL CHECK (length(digest) = 64),
    action           TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
    remote_id        TEXT NOT NULL CHECK (length(remote_id) BETWEEN 1 AND 64),
    trust_generation INTEGER NOT NULL CHECK (trust_generation BETWEEN 1 AND 281474976710655),
    kind             TEXT NOT NULL CHECK (kind IN ('qemu', 'lxc', 'node')),
    node             TEXT NOT NULL CHECK (length(node) BETWEEN 1 AND 63),
    vmid             INTEGER NOT NULL CHECK (vmid BETWEEN 0 AND 9999999999),
    request_digest   TEXT NOT NULL CHECK (length(request_digest) = 64),
    task_type        TEXT NOT NULL CHECK (length(task_type) BETWEEN 1 AND 32),
    task_user        TEXT NOT NULL CHECK (length(task_user) BETWEEN 1 AND 128),
    state            TEXT NOT NULL CHECK (state IN ('dispatching', 'running', 'reconciling', 'succeeded', 'failed', 'unknown')),
    upid             TEXT CHECK (upid IS NULL OR length(upid) BETWEEN 1 AND 255),
    task_node        TEXT CHECK (task_node IS NULL OR length(task_node) BETWEEN 1 AND 63),
    exit_status      TEXT NOT NULL DEFAULT '' CHECK (length(exit_status) <= 128),
    created_at       INTEGER NOT NULL,
    dispatched_at    INTEGER,
    updated_at       INTEGER NOT NULL,
    finished_at      INTEGER,
    PRIMARY KEY (execution_id, step),
    CHECK ((upid IS NULL) = (task_node IS NULL))
);

CREATE UNIQUE INDEX pve_jobs_upid_uq ON pve_jobs (upid) WHERE upid IS NOT NULL;

CREATE INDEX pve_jobs_open_idx ON pve_jobs (state) WHERE state IN ('dispatching', 'running', 'reconciling');
