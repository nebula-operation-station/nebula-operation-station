-- 0015_discovery.sql: discovery jobs, their staged results and schedules
-- (M9-2, spec 12). Staged rows are what a scan saw; how they match the
-- inventory is computed when they are shown, and nothing reaches the
-- assets until a user imports it.
CREATE TABLE discovery_jobs (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    spec        TEXT    NOT NULL CHECK (length(spec) <= 16384),
    description TEXT    NOT NULL CHECK (length(description) <= 200),
    targets     TEXT    NOT NULL CHECK (length(targets) <= 1000),
    created_by  TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at  INTEGER NOT NULL,
    schedule_id TEXT    NOT NULL DEFAULT '' CHECK (length(schedule_id) <= 36),
    state       TEXT    NOT NULL CHECK (state IN ('queued', 'done', 'failed', 'cancelled')),
    finished_at INTEGER NOT NULL DEFAULT 0,
    error       TEXT    NOT NULL DEFAULT '' CHECK (length(error) <= 200),
    hosts       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX discovery_jobs_created ON discovery_jobs (created_at);

CREATE TABLE discovery_staging (
    job_id         TEXT    NOT NULL REFERENCES discovery_jobs (id) ON DELETE CASCADE,
    address        TEXT    NOT NULL CHECK (length(address) BETWEEN 2 AND 45),
    mac            TEXT    NOT NULL DEFAULT '' CHECK (mac = '' OR length(mac) = 17),
    vendor         TEXT    NOT NULL DEFAULT '' CHECK (length(vendor) <= 128),
    hostname       TEXT    NOT NULL DEFAULT '' CHECK (length(hostname) <= 253),
    os             TEXT    NOT NULL DEFAULT '' CHECK (length(os) <= 128),
    ports          TEXT    NOT NULL DEFAULT '[]',
    imported_at    INTEGER NOT NULL DEFAULT 0,
    imported_by    TEXT    NOT NULL DEFAULT '' CHECK (length(imported_by) <= 64),
    imported_asset TEXT    NOT NULL DEFAULT '' CHECK (length(imported_asset) <= 63),
    PRIMARY KEY (job_id, address)
);

CREATE TABLE discovery_schedules (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    spec        TEXT    NOT NULL CHECK (length(spec) <= 16384),
    description TEXT    NOT NULL CHECK (length(description) <= 200),
    targets     TEXT    NOT NULL CHECK (length(targets) <= 1000),
    interval_s  INTEGER NOT NULL CHECK (interval_s = 0 OR interval_s >= 3600),
    next_at     INTEGER NOT NULL,
    created_by  TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at  INTEGER NOT NULL,
    enabled     INTEGER NOT NULL CHECK (enabled IN (0, 1))
);
