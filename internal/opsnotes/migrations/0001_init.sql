-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Notes of the ops agent (ADR 0016 D7) and their steps (D9). This file
-- lives in its own database; it is not part of the server schema.

CREATE TABLE notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL CHECK (kind IN ('fix', 'summary', 'answer')),
    ref         TEXT    NOT NULL,
    digest      TEXT    NOT NULL,
    -- Canonical JSON of the validated body, compared on Put.
    body        TEXT    NOT NULL,
    -- Facts snapshot from the caller, never from the body.
    snapshot    TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    superseded  INTEGER NOT NULL DEFAULT 0 CHECK (superseded IN (0, 1)),
    dismissed   INTEGER NOT NULL DEFAULT 0 CHECK (dismissed IN (0, 1)),
    UNIQUE (kind, ref, digest)
);

CREATE INDEX notes_ref ON notes (ref);
CREATE INDEX notes_created_at ON notes (created_at);

CREATE TABLE steps (
    note_id   INTEGER NOT NULL REFERENCES notes (id) ON DELETE CASCADE,
    idx       INTEGER NOT NULL CHECK (idx >= 1),
    action_id TEXT    NOT NULL,
    family    TEXT    NOT NULL,
    host_id   TEXT    NOT NULL,
    why       TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (note_id, idx)
);

CREATE INDEX steps_family_host ON steps (family, host_id);
