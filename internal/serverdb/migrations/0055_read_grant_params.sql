-- 0055_read_grant_params.sql
-- Plain-text parameters of the image read leases (ADR 0011, amendment
-- 2026-11-23). A read-grant-v2 document binds only the SHA-256 of an action's
-- parameters; the lease page needs the parameters themselves to show what the
-- hashes bind. This table keeps exactly the two parameters of the image lease:
-- container (docker.inspect) and image (image.packages), as JSON objects of
-- one or two members. Secrets are never stored here.
--
-- Additive only: no existing table or row changes. Rows older than the
-- longest read lease plus one day are removed by the executions service when
-- it writes new rows (readgrants_image.go).
CREATE TABLE read_grant_params (
    grant_id   TEXT    NOT NULL CHECK (length(grant_id) BETWEEN 1 AND 64),
    action_id  TEXT    NOT NULL CHECK (length(action_id) BETWEEN 1 AND 100),
    params     TEXT    NOT NULL CHECK (length(CAST(params AS BLOB)) BETWEEN 2 AND 1024),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (grant_id, action_id)
);
