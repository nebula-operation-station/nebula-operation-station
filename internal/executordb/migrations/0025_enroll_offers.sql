-- 0025_enroll_offers.sql (ADR 0013 D2, spec 03 v25-03-03/v25-03-04, EN-05
-- part 1): the executor's store of one-step enrollment offers.
--
-- Secrets: the offer ID is never stored, only its SHA-256 (id_hash). The
-- 256-bit salt is the only secret column; it is NULL in every final state
-- (CHECK below), and the store sets it to NULL in the same UPDATE that
-- makes the offer final. The rendered script is never stored: only its
-- SHA-256 (script_sha256). session_hash is a digest of the creating web
-- session, not the session token.
--
-- States (spec 03 v25-03-04): awaiting_approval -> open -> downloaded ->
-- pairing_proposed -> enrolled; every non-final state -> expired, revoked
-- or failed. Final states never change again. The store changes state
-- only by compare-and-set (UPDATE ... WHERE state = <expected>); the
-- triggers below refuse every other transition as a second line of
-- defence, also for code that bypasses the store.
--
-- NetBird fields (setup-key record, key ID, orphan peers) follow in a later
-- migration (EN-05 part 2).
CREATE TABLE enroll_offers (
    id_hash         BLOB    PRIMARY KEY CHECK (typeof(id_hash) = 'blob' AND length(id_hash) = 32),
    salt            BLOB    CHECK (salt IS NULL OR (typeof(salt) = 'blob' AND length(salt) = 32)),
    host_id         TEXT    NOT NULL CHECK (length(host_id) BETWEEN 1 AND 63),
    ssh_user        TEXT    NOT NULL CHECK (length(ssh_user) BETWEEN 1 AND 32),
    credential_ref  TEXT    NOT NULL CHECK (length(credential_ref) BETWEEN 1 AND 64),
    session_hash    BLOB    NOT NULL CHECK (typeof(session_hash) = 'blob' AND length(session_hash) = 32),
    netbird         INTEGER NOT NULL CHECK (netbird IN (0, 1)),
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL CHECK (expires_at > created_at),
    state           TEXT    NOT NULL CHECK (state IN ('awaiting_approval', 'open', 'downloaded',
                        'pairing_proposed', 'enrolled', 'expired', 'revoked', 'failed')),
    state_changed_at INTEGER NOT NULL,
    script_sha256   BLOB    CHECK (script_sha256 IS NULL
                        OR (typeof(script_sha256) = 'blob' AND length(script_sha256) = 32)),
    downloaded_at   INTEGER,
    client_addr     TEXT    CHECK (client_addr IS NULL OR length(client_addr) BETWEEN 1 AND 64),
    peer_addr       TEXT    CHECK (peer_addr IS NULL OR length(peer_addr) BETWEEN 1 AND 64),
    code_submitted_at INTEGER,
    probes          INTEGER NOT NULL DEFAULT 0 CHECK (probes BETWEEN 0 AND 5),
    rejected_codes  INTEGER NOT NULL DEFAULT 0 CHECK (rejected_codes BETWEEN 0 AND 3),
    -- A final offer holds no salt; a non-final one always does.
    CHECK ((state IN ('enrolled', 'expired', 'revoked', 'failed')) = (salt IS NULL)),
    -- Only a NetBird offer waits for approval, and it has no script hash
    -- until it is opened; every offer past that point has one.
    CHECK (state <> 'awaiting_approval' OR (netbird = 1 AND script_sha256 IS NULL)),
    CHECK (state IN ('awaiting_approval', 'expired', 'revoked', 'failed') OR script_sha256 IS NOT NULL),
    -- A download records its time and addresses together.
    CHECK ((downloaded_at IS NULL) = (client_addr IS NULL)
        AND (downloaded_at IS NULL) = (peer_addr IS NULL)),
    CHECK (state NOT IN ('downloaded', 'pairing_proposed', 'enrolled') OR downloaded_at IS NOT NULL),
    CHECK (state NOT IN ('pairing_proposed', 'enrolled') OR code_submitted_at IS NOT NULL)
) WITHOUT ROWID;

CREATE INDEX enroll_offers_state_idx ON enroll_offers (state, expires_at);

-- Everything fixed at creation stays fixed.
CREATE TRIGGER enroll_offers_immutable
BEFORE UPDATE OF id_hash, host_id, ssh_user, credential_ref, session_hash, netbird, created_at, expires_at
ON enroll_offers
WHEN NEW.id_hash IS NOT OLD.id_hash OR NEW.host_id IS NOT OLD.host_id
  OR NEW.ssh_user IS NOT OLD.ssh_user OR NEW.credential_ref IS NOT OLD.credential_ref
  OR NEW.session_hash IS NOT OLD.session_hash OR NEW.netbird IS NOT OLD.netbird
  OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: creation fields are immutable');
END;

-- A final offer is an audit record: none of its offer fields change again.
-- (Columns added later, such as the NetBird key ID that is wiped after a
-- successful revoke, are deliberately not listed.)
CREATE TRIGGER enroll_offers_final_frozen
BEFORE UPDATE OF state, salt, state_changed_at, script_sha256, downloaded_at, client_addr,
    peer_addr, code_submitted_at, probes, rejected_codes ON enroll_offers
WHEN OLD.state IN ('enrolled', 'expired', 'revoked', 'failed')
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: final offers are frozen');
END;

-- Only forward transitions (spec 03 v25-03-04).
CREATE TRIGGER enroll_offers_forward_only
BEFORE UPDATE OF state ON enroll_offers
WHEN NEW.state IS NOT OLD.state AND NOT (
       (OLD.state = 'awaiting_approval' AND NEW.state = 'open')
    OR (OLD.state = 'open' AND NEW.state = 'downloaded')
    OR (OLD.state = 'downloaded' AND NEW.state = 'pairing_proposed')
    OR (OLD.state = 'pairing_proposed' AND NEW.state = 'enrolled')
    OR (NEW.state IN ('expired', 'revoked', 'failed'))
)
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: transition not allowed');
END;

-- The salt is only ever removed, never set or replaced after creation.
CREATE TRIGGER enroll_offers_salt_wipe_only
BEFORE UPDATE OF salt ON enroll_offers
WHEN NEW.salt IS NOT NULL AND NEW.salt IS NOT OLD.salt
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: salt can only be wiped');
END;

-- The script hash is set once, never changed or removed.
CREATE TRIGGER enroll_offers_script_hash_once
BEFORE UPDATE OF script_sha256 ON enroll_offers
WHEN OLD.script_sha256 IS NOT NULL AND NEW.script_sha256 IS NOT OLD.script_sha256
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: script hash is fixed');
END;

-- Download and code-submission records are written once.
CREATE TRIGGER enroll_offers_claims_once
BEFORE UPDATE OF downloaded_at, client_addr, peer_addr, code_submitted_at ON enroll_offers
WHEN (OLD.downloaded_at IS NOT NULL AND (NEW.downloaded_at IS NOT OLD.downloaded_at
        OR NEW.client_addr IS NOT OLD.client_addr OR NEW.peer_addr IS NOT OLD.peer_addr))
  OR (OLD.code_submitted_at IS NOT NULL AND NEW.code_submitted_at IS NOT OLD.code_submitted_at)
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: claim already recorded');
END;

-- Counters only grow.
CREATE TRIGGER enroll_offers_counters_grow
BEFORE UPDATE OF probes, rejected_codes ON enroll_offers
WHEN NEW.probes < OLD.probes OR NEW.rejected_codes < OLD.rejected_codes
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: counters never decrease');
END;

-- Offers are audit records; an offer that is not final is never deleted.
CREATE TRIGGER enroll_offers_no_delete_live
BEFORE DELETE ON enroll_offers
WHEN OLD.state NOT IN ('enrolled', 'expired', 'revoked', 'failed')
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: only final offers may be deleted');
END;
