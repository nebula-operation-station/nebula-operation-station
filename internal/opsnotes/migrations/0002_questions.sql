-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Admin questions of the Ops tab (ADR 0016 D11). Same database and
-- migration chain as the notes; the text leaves this file only as the
-- agent's work item and in the admin's own question list.

CREATE TABLE questions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name    TEXT    NOT NULL,
    text         TEXT    NOT NULL CHECK (length(CAST(text AS BLOB)) <= 2048),
    digest       TEXT    NOT NULL,
    state        TEXT    NOT NULL CHECK (state IN ('open', 'answered', 'expired')),
    created_at   INTEGER NOT NULL,
    answered_at  INTEGER NOT NULL DEFAULT 0,
    answer_note  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX questions_state ON questions (state, created_at);
CREATE INDEX questions_created_at ON questions (created_at);
