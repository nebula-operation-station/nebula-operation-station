-- 0017_host_pins.sql
-- Per-host pinned quick actions (spec 12, job ui5): the catalog actions an
-- admin pins to a host so the host page and the inventory can run them in
-- one step. Only catalog actions may be pinned (validated in the UI layer);
-- pinning changes no risk and no approval. Deleting a host removes its
-- pins.
CREATE TABLE host_pinned_actions (
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    action_id  TEXT NOT NULL,
    position   INTEGER NOT NULL CHECK (position >= 0),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (host_id, action_id),
    UNIQUE (host_id, position)
);
