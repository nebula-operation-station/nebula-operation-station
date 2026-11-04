-- Software catalog, observations, unknown queue and icon references
-- (ADR 0009 draft, TM13; decisions D5, D6, D7).
--
-- software_catalog has one row per catalog key (internal/softwarecat
-- key format). Rows are created automatically when an observation
-- names a key without an entry: state 'known' with the seed map's
-- display name for reviewed identifiers, state 'observed' with an
-- empty display name otherwise. Observed, unmerged rows are the
-- "Unknown software" queue. An admin can rename (display name, which
-- also confirms the entry as 'known'), merge into another key
-- (merged_into, always one level deep: a target is never itself
-- merged), ignore, or set an icon. first_host is the managed host whose
-- observation created the row ('' for rows not created by a host); it
-- bounds how many queue entries one host can create.
--
-- software_observations records what was seen where: one row per
-- (host, target, source action, key) with the latest version and the
-- raw identifier (bounded, printable text) and first/last seen. The
-- target is the managed host itself, a guest or a container on it.
-- Observations are facts only: nothing here creates placements, assets
-- or hosts.
--
-- software_icons references sanitized icons in the content-addressed
-- icon store (internal/iconstore) by their SHA-256. source_url is kept
-- for audit only and is never rendered as a link or image source.
-- Icon bytes do not live in the database. A NULL icon_sha / prev_sha
-- means "no icon" (the generic symbol); software_icons rows are never
-- deleted, so history stays resolvable.
--
-- software_icon_history keeps every icon change of a catalog key or of
-- an asset (per-asset override) with the previous hash, so a change can
-- be rolled back; a rollback is itself a new history row.
-- asset_icon_overrides holds the current per-asset override.
--
-- software_catalog_audit records every admin change (rename, merge,
-- ignore, icon registration, icon set, rollback, override) in the same
-- transaction as the change.
--
-- software_catalog_lock has one row; every write transaction updates it
-- first, so the transaction holds the write lock before it reads caps.
--
-- Every host-supplied value (identifier, version, container or guest
-- reference) is validated against explicit limits in
-- internal/softwarecat before it reaches the database.

CREATE TABLE software_catalog (
    key         TEXT PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 64),
    display     TEXT NOT NULL DEFAULT '' CHECK (length(display) <= 128),
    state       TEXT NOT NULL CHECK (state IN ('known', 'observed', 'ignored')),
    merged_into TEXT NOT NULL DEFAULT '' CHECK (merged_into <> key),
    icon_sha    TEXT REFERENCES software_icons (sha),
    first_host  TEXT NOT NULL DEFAULT '' CHECK (length(first_host) <= 63),
    created_at  INTEGER NOT NULL,
    updated_by  TEXT NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    updated_at  INTEGER NOT NULL
);

CREATE INDEX software_catalog_queue ON software_catalog (state, merged_into);
CREATE INDEX software_catalog_first_host ON software_catalog (first_host) WHERE first_host <> '';
CREATE INDEX software_catalog_merged_into ON software_catalog (merged_into) WHERE merged_into <> '';

CREATE TABLE software_observations (
    id            INTEGER PRIMARY KEY,
    host_id       TEXT NOT NULL CHECK (length(host_id) BETWEEN 1 AND 63),
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('host', 'guest', 'container')),
    target_ref    TEXT NOT NULL DEFAULT '' CHECK (length(target_ref) <= 128),
    key           TEXT NOT NULL REFERENCES software_catalog (key),
    identifier    TEXT NOT NULL DEFAULT '' CHECK (length(identifier) <= 256),
    version       TEXT NOT NULL DEFAULT '' CHECK (length(version) <= 128),
    source_action TEXT NOT NULL CHECK (source_action IN ('core.facts', 'docker.list', 'gpu.status', 'service.list')),
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL CHECK (last_seen >= first_seen),
    CHECK ((target_kind = 'host' AND target_ref = '') OR (target_kind <> 'host' AND target_ref <> '')),
    UNIQUE (host_id, target_kind, target_ref, source_action, key)
);

CREATE INDEX software_observations_key ON software_observations (key);

CREATE TABLE software_icons (
    sha         TEXT PRIMARY KEY CHECK (length(sha) = 64),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('upload', 'url')),
    source_url  TEXT NOT NULL DEFAULT '' CHECK (length(source_url) <= 2048),
    added_by    TEXT NOT NULL CHECK (length(added_by) BETWEEN 1 AND 64),
    added_at    INTEGER NOT NULL,
    CHECK ((source_kind = 'upload' AND source_url = '') OR (source_kind = 'url' AND source_url <> ''))
);

CREATE TABLE software_icon_history (
    id           INTEGER PRIMARY KEY,
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('catalog', 'asset')),
    subject_id   TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 64),
    icon_sha     TEXT REFERENCES software_icons (sha),
    prev_sha     TEXT REFERENCES software_icons (sha),
    rollback_of  INTEGER NOT NULL DEFAULT 0,
    changed_by   TEXT NOT NULL CHECK (length(changed_by) BETWEEN 1 AND 64),
    changed_at   INTEGER NOT NULL
);

CREATE INDEX software_icon_history_subject ON software_icon_history (subject_kind, subject_id, id);

CREATE TABLE asset_icon_overrides (
    asset_id   TEXT PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 63),
    icon_sha   TEXT NOT NULL REFERENCES software_icons (sha),
    updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 64),
    updated_at INTEGER NOT NULL
);

CREATE TABLE software_catalog_audit (
    id     INTEGER PRIMARY KEY,
    at     INTEGER NOT NULL,
    actor  TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 64),
    action TEXT NOT NULL CHECK (action IN ('rename', 'merge', 'ignore', 'icon_register', 'icon_set', 'icon_rollback', 'asset_icon_set', 'asset_icon_clear')),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 64),
    detail TEXT NOT NULL DEFAULT '' CHECK (length(detail) <= 4096)
);

CREATE TABLE software_catalog_lock (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    n  INTEGER NOT NULL
);

INSERT INTO software_catalog_lock (id, n) VALUES (1, 0);
