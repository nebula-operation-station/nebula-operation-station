-- 0044_fim_baseline.sql
--
-- Per-host FIM baseline store (ADR 0015 D7 "Initial baseline" and
-- "Approval"; plan IG-06). The logic lives in internal/fimstore; these
-- tables hold its rows and enforce the sizes and links that must never be
-- violated. The baseline exists only on NOS: the full record list is kept
-- here, and its digest as tamper evidence in executor storage (IG-06c).
--
-- Two kinds of state per host:
--   fim_baselines / fim_baseline_entries: the approved baseline. At most
--     one row per host; version counts approvals (1 = first approval).
--   fim_baseline_proposals / fim_baseline_proposal_entries: the open
--     proposal. At most one row per host (host_id is the primary key). A
--     proposal is never a baseline; it becomes one only by an approval that
--     names its digest and the approved digest it was built on.
--
-- Entries are keyed by raw path bytes (BLOB), so an ORDER BY path reads them
-- in the same byte order as fimbaseline's digest. Both entry tables carry
-- the same columns; a record's hash sum is NULL when its kind is 'none'.

-- fim_store_state: one row (id = 1). lock_counter is bumped at the start of
-- every write transaction so that writers take the database write lock
-- before they read (the same pattern as integrity_store_state).
CREATE TABLE fim_store_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    lock_counter  INTEGER NOT NULL DEFAULT 0 CHECK (lock_counter >= 0)
);
INSERT INTO fim_store_state (id, lock_counter) VALUES (1, 0);

CREATE TABLE fim_baselines (
    host_id      INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    version      INTEGER NOT NULL CHECK (version >= 1),
    digest       BLOB NOT NULL CHECK (length(digest) = 32),
    profile_id   TEXT NOT NULL CHECK (length(CAST(profile_id AS BLOB)) BETWEEN 1 AND 64),
    entry_count  INTEGER NOT NULL CHECK (entry_count BETWEEN 0 AND 300000),
    approved_at  INTEGER NOT NULL
);

CREATE TABLE fim_baseline_entries (
    host_id     INTEGER NOT NULL REFERENCES fim_baselines(host_id) ON DELETE CASCADE,
    path        BLOB NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
    type        INTEGER NOT NULL CHECK (type BETWEEN 1 AND 4),
    size        INTEGER NOT NULL CHECK (size >= 0),
    mode        INTEGER NOT NULL CHECK (mode BETWEEN 0 AND 4095),
    uid         INTEGER NOT NULL CHECK (uid BETWEEN 0 AND 4294967295),
    gid         INTEGER NOT NULL CHECK (gid BETWEEN 0 AND 4294967295),
    inode       INTEGER NOT NULL,
    mtime       INTEGER NOT NULL,
    ctime       INTEGER NOT NULL,
    hash_kind   INTEGER NOT NULL CHECK (hash_kind BETWEEN 0 AND 2),
    hash_secret INTEGER NOT NULL CHECK (hash_secret IN (0, 1)),
    hash_sum    BLOB CHECK (hash_sum IS NULL OR length(hash_sum) = 32),
    link        BLOB CHECK (link IS NULL OR length(link) BETWEEN 1 AND 4096),
    PRIMARY KEY (host_id, path),
    CHECK ((hash_kind = 0) = (hash_sum IS NULL)),
    CHECK ((type = 3) = (link IS NOT NULL))
) WITHOUT ROWID;

CREATE TABLE fim_baseline_proposals (
    host_id       INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    base_version  INTEGER NOT NULL CHECK (base_version >= 0),
    base_digest   BLOB CHECK (base_digest IS NULL OR length(base_digest) = 32),
    digest        BLOB NOT NULL CHECK (length(digest) = 32),
    profile_id    TEXT NOT NULL CHECK (length(CAST(profile_id AS BLOB)) BETWEEN 1 AND 64),
    entry_count   INTEGER NOT NULL CHECK (entry_count BETWEEN 0 AND 300000),
    proposed_at   INTEGER NOT NULL,
    CHECK ((base_version = 0) = (base_digest IS NULL))
);

CREATE TABLE fim_baseline_proposal_entries (
    host_id     INTEGER NOT NULL REFERENCES fim_baseline_proposals(host_id) ON DELETE CASCADE,
    path        BLOB NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
    type        INTEGER NOT NULL CHECK (type BETWEEN 1 AND 4),
    size        INTEGER NOT NULL CHECK (size >= 0),
    mode        INTEGER NOT NULL CHECK (mode BETWEEN 0 AND 4095),
    uid         INTEGER NOT NULL CHECK (uid BETWEEN 0 AND 4294967295),
    gid         INTEGER NOT NULL CHECK (gid BETWEEN 0 AND 4294967295),
    inode       INTEGER NOT NULL,
    mtime       INTEGER NOT NULL,
    ctime       INTEGER NOT NULL,
    hash_kind   INTEGER NOT NULL CHECK (hash_kind BETWEEN 0 AND 2),
    hash_secret INTEGER NOT NULL CHECK (hash_secret IN (0, 1)),
    hash_sum    BLOB CHECK (hash_sum IS NULL OR length(hash_sum) = 32),
    link        BLOB CHECK (link IS NULL OR length(link) BETWEEN 1 AND 4096),
    PRIMARY KEY (host_id, path),
    CHECK ((hash_kind = 0) = (hash_sum IS NULL)),
    CHECK ((type = 3) = (link IS NOT NULL))
) WITHOUT ROWID;

-- The mount points of the run that produced the baseline or the proposal.
-- fimbaseline's digest covers them and Diff compares the /boot/efi file
-- system type (D5), so they are stored with the entries; without them the
-- digest cannot be recomputed from the stored rows. At most 256 per host
-- (fimbaseline.MaxMounts) is enforced in Go before any row is written.
CREATE TABLE fim_baseline_mounts (
    host_id     INTEGER NOT NULL REFERENCES fim_baselines(host_id) ON DELETE CASCADE,
    path        BLOB NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
    fstype      TEXT NOT NULL CHECK (length(CAST(fstype AS BLOB)) BETWEEN 1 AND 64),
    PRIMARY KEY (host_id, path)
) WITHOUT ROWID;

CREATE TABLE fim_baseline_proposal_mounts (
    host_id     INTEGER NOT NULL REFERENCES fim_baseline_proposals(host_id) ON DELETE CASCADE,
    path        BLOB NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
    fstype      TEXT NOT NULL CHECK (length(CAST(fstype AS BLOB)) BETWEEN 1 AND 64),
    PRIMARY KEY (host_id, path)
) WITHOUT ROWID;
