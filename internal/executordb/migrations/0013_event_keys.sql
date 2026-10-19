-- 0013_event_keys.sql (M10-2): the event keys that signed the chain, each
-- from its first sequence number on. A restore onto a new machine starts
-- a new key (the key is never in a backup); the old events still verify
-- with the key recorded here. Append-only like the events.
CREATE TABLE event_keys (
    first_seq  INTEGER PRIMARY KEY CHECK (first_seq >= 1),
    public_key BLOB    NOT NULL UNIQUE CHECK (length(public_key) = 32),
    added_at   INTEGER NOT NULL
);

CREATE TRIGGER event_keys_no_update BEFORE UPDATE ON event_keys
BEGIN
    SELECT RAISE(ABORT, 'event keys are append-only');
END;

CREATE TRIGGER event_keys_no_delete BEFORE DELETE ON event_keys
BEGIN
    SELECT RAISE(ABORT, 'event keys are append-only');
END;
