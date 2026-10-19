-- 0012_events.sql (M10-1): the executor's signed event chain. Rows are
-- appended only; nothing in the executor updates or deletes them, and the
-- triggers refuse it (a root attacker can still rewrite the file; the
-- chain shows that only while the event key was not taken too).
CREATE TABLE events (
    seq       INTEGER PRIMARY KEY CHECK (seq >= 1),
    body      BLOB    NOT NULL CHECK (length(body) <= 65536),
    prev_hash BLOB    NOT NULL CHECK (length(prev_hash) = 32),
    hash      BLOB    NOT NULL CHECK (length(hash) = 32),
    sig       BLOB    NOT NULL CHECK (length(sig) = 64)
);

CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;
