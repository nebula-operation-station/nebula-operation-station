-- 0006_host_updates.sql (M5): the latest package.list_updates result per
-- host, parsed by the server (untrusted host data, spec 09). packages is a
-- bounded JSON list for display.
CREATE TABLE host_updates (
    host_id         TEXT    PRIMARY KEY CHECK (length(host_id) BETWEEN 1 AND 200),
    observed_at     INTEGER NOT NULL,
    execution_id    TEXT    NOT NULL,
    total           INTEGER NOT NULL,
    security        INTEGER NOT NULL,
    kernel          INTEGER NOT NULL,
    reboot_required INTEGER NOT NULL CHECK (reboot_required IN (0, 1)),
    lists_updated   INTEGER NOT NULL DEFAULT 0,
    packages        TEXT    NOT NULL
) WITHOUT ROWID;
