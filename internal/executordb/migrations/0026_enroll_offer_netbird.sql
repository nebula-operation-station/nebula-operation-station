-- 0026_enroll_offer_netbird.sql (ADR 0013 D6, spec 03 v25-03-04, spec 06
-- v25-06-02/v25-06-03, spec 09 v25-09-01; EN-05 part 2): the NetBird
-- setup-key record of an enrollment offer and the orphan-peer records.
--
-- Secrets: the setup key itself is never stored here. It exists at rest
-- only envelope-encrypted in vault_secrets, under the reference
-- setup_key_vault_ref, and that secret row is deleted in the same
-- statement that clears the reference (trigger below), which every final
-- state does (CHECK). The key ID, the key name and the managed group are
-- identifiers, not secrets.
--
-- Setup-key record (setup_key_record): none -> pending -> created, only
-- forward. pending is written before NetBird's create call, with the
-- reconcile record (key name, group, creation window); created holds the
-- key ID (and the vault reference while the offer is live). A record is
-- open until setup_key_closed_at is set: after a successful revoke
-- ('revoked') or once the key's latest possible expiry has passed
-- ('expired_unrevoked'). The key ID is cleared only in that closing
-- write. Revoke and expiry of the offer leave the record as it is.

-- SQLite allows a column CHECK to name other columns; the cross-column
-- invariants are attached to the column they are about.
ALTER TABLE enroll_offers ADD COLUMN setup_key_record TEXT NOT NULL DEFAULT 'none'
    CHECK (setup_key_record IN ('none', 'pending', 'created'));

-- The requested key name is always nos-offer-<first 8 hex of the offer ID
-- hash> (ADR 0013 D6).
ALTER TABLE enroll_offers ADD COLUMN setup_key_name TEXT
    CHECK (setup_key_name IS NULL OR setup_key_name = 'nos-offer-' || lower(hex(substr(id_hash, 1, 4))));

ALTER TABLE enroll_offers ADD COLUMN setup_key_group TEXT
    CHECK (setup_key_group IS NULL OR length(setup_key_group) BETWEEN 1 AND 64);

ALTER TABLE enroll_offers ADD COLUMN setup_key_window_start INTEGER;

ALTER TABLE enroll_offers ADD COLUMN setup_key_window_end INTEGER
    CHECK (setup_key_window_end IS NULL OR setup_key_window_end > setup_key_window_start);

-- Set when NetBird's create answer carried another key name (spec 09).
ALTER TABLE enroll_offers ADD COLUMN setup_key_name_mismatch INTEGER NOT NULL DEFAULT 0
    CHECK (setup_key_name_mismatch IN (0, 1));

-- NetBird's key ID: 1..64 characters 0-9a-z (NetBirdKeyIDMaxLen, spec 09).
ALTER TABLE enroll_offers ADD COLUMN setup_key_id TEXT
    CHECK (setup_key_id IS NULL OR (length(setup_key_id) BETWEEN 1 AND 64
        AND setup_key_id NOT GLOB '*[^0-9a-z]*'));

-- 0 for a key ID taken from a create answer that failed another check;
-- such an ID is revoked only after a get by ID or the reconcile confirmed
-- it (ADR 0013 D6 step 3).
ALTER TABLE enroll_offers ADD COLUMN setup_key_verified INTEGER NOT NULL DEFAULT 0
    CHECK (setup_key_verified IN (0, 1));

-- Only the offer's own vault entry can be referenced, so the delete
-- trigger below can never remove another secret.
ALTER TABLE enroll_offers ADD COLUMN setup_key_vault_ref TEXT REFERENCES vault_secrets (id)
    CHECK (setup_key_vault_ref IS NULL
        OR setup_key_vault_ref = 'netbird-setup-key-' || lower(hex(substr(id_hash, 1, 16))));

ALTER TABLE enroll_offers ADD COLUMN setup_key_closed_at INTEGER;

ALTER TABLE enroll_offers ADD COLUMN setup_key_close TEXT
    CHECK (setup_key_close IS NULL OR setup_key_close IN ('revoked', 'expired_unrevoked'));

ALTER TABLE enroll_offers ADD COLUMN setup_key_revoke_failures INTEGER NOT NULL DEFAULT 0
    CHECK (setup_key_revoke_failures >= 0);

-- The record invariants, as one CHECK on the last column.
ALTER TABLE enroll_offers ADD COLUMN setup_key_next_retry_at INTEGER CHECK (
    -- No record: nothing of it is set.
    (setup_key_record <> 'none' OR (setup_key_name IS NULL AND setup_key_group IS NULL
        AND setup_key_window_start IS NULL AND setup_key_window_end IS NULL
        AND setup_key_name_mismatch = 0 AND setup_key_id IS NULL AND setup_key_verified = 0
        AND setup_key_vault_ref IS NULL AND setup_key_closed_at IS NULL
        AND setup_key_revoke_failures = 0 AND setup_key_next_retry_at IS NULL))
    -- A record exists only for a NetBird offer and always has its
    -- reconcile record.
    AND (setup_key_record = 'none' OR (netbird = 1 AND setup_key_name IS NOT NULL
        AND setup_key_group IS NOT NULL AND setup_key_window_start IS NOT NULL
        AND setup_key_window_end IS NOT NULL))
    -- pending has no key ID and no secret.
    AND (setup_key_record <> 'pending' OR (setup_key_id IS NULL AND setup_key_verified = 0
        AND setup_key_vault_ref IS NULL))
    -- A secret belongs to a verified, open created record.
    AND (setup_key_vault_ref IS NULL OR (setup_key_record = 'created' AND setup_key_verified = 1
        AND setup_key_id IS NOT NULL AND setup_key_closed_at IS NULL))
    -- An open created record keeps its key ID; a closed record has none.
    AND (setup_key_record <> 'created' OR setup_key_closed_at IS NOT NULL OR setup_key_id IS NOT NULL)
    AND ((setup_key_closed_at IS NULL) = (setup_key_close IS NULL))
    AND (setup_key_closed_at IS NULL OR (setup_key_id IS NULL
        AND state IN ('enrolled', 'expired', 'revoked', 'failed')))
    AND (setup_key_close IS NOT 'revoked' OR setup_key_verified = 1)
    -- A NetBird offer waits for approval without a created key, is live
    -- past that point only with its secret, and every final offer has
    -- lost its secret.
    AND (state <> 'awaiting_approval' OR setup_key_record IN ('none', 'pending'))
    AND (netbird = 0 OR state NOT IN ('open', 'downloaded', 'pairing_proposed')
        OR setup_key_vault_ref IS NOT NULL)
    AND (netbird = 0 OR state <> 'enrolled' OR setup_key_record = 'created')
    AND (state NOT IN ('enrolled', 'expired', 'revoked', 'failed') OR setup_key_vault_ref IS NULL)
    AND (setup_key_next_retry_at IS NULL OR setup_key_revoke_failures > 0)
);

CREATE INDEX enroll_offers_setup_key_open_idx ON enroll_offers (setup_key_record, setup_key_closed_at);

-- The record only moves forward: none -> pending (while the offer waits
-- for approval) -> created.
CREATE TRIGGER enroll_offers_setup_key_forward_only
BEFORE UPDATE OF setup_key_record ON enroll_offers
WHEN NEW.setup_key_record IS NOT OLD.setup_key_record AND NOT (
       (OLD.setup_key_record = 'none' AND NEW.setup_key_record = 'pending'
        AND OLD.state = 'awaiting_approval' AND NEW.state = 'awaiting_approval')
    OR (OLD.setup_key_record = 'pending' AND NEW.setup_key_record = 'created')
)
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: setup-key record transition not allowed');
END;

-- The reconcile record is written once, with none -> pending.
CREATE TRIGGER enroll_offers_setup_key_reconcile_fixed
BEFORE UPDATE OF setup_key_name, setup_key_group, setup_key_window_start, setup_key_window_end
ON enroll_offers
WHEN (NEW.setup_key_name IS NOT OLD.setup_key_name OR NEW.setup_key_group IS NOT OLD.setup_key_group
      OR NEW.setup_key_window_start IS NOT OLD.setup_key_window_start
      OR NEW.setup_key_window_end IS NOT OLD.setup_key_window_end)
  AND NOT (OLD.setup_key_record = 'none' AND NEW.setup_key_record = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: setup-key reconcile record is fixed');
END;

-- The name-mismatch marker is only ever set, by the failure write of a
-- pending record (which also makes the offer final).
CREATE TRIGGER enroll_offers_setup_key_mismatch_once
BEFORE UPDATE OF setup_key_name_mismatch ON enroll_offers
WHEN NEW.setup_key_name_mismatch IS NOT OLD.setup_key_name_mismatch
  AND NOT (OLD.setup_key_name_mismatch = 0 AND OLD.setup_key_record = 'pending'
           AND NEW.state IN ('expired', 'revoked', 'failed'))
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: setup-key name-mismatch marker is set once');
END;

-- The key ID is set with pending -> created, replaced only when a get by
-- ID or the reconcile verifies an unverified record of a final offer, and
-- cleared only by the write that closes the record of a final offer.
CREATE TRIGGER enroll_offers_setup_key_id_guarded
BEFORE UPDATE OF setup_key_id, setup_key_verified ON enroll_offers
WHEN (NEW.setup_key_verified < OLD.setup_key_verified)
  OR (NEW.setup_key_id IS NOT OLD.setup_key_id AND NOT (
       (OLD.setup_key_id IS NULL AND NEW.setup_key_id IS NOT NULL
        AND OLD.setup_key_record = 'pending' AND NEW.setup_key_record = 'created')
    OR (OLD.setup_key_id IS NOT NULL AND NEW.setup_key_id IS NOT NULL
        AND OLD.setup_key_verified = 0 AND NEW.setup_key_verified = 1
        AND OLD.setup_key_closed_at IS NULL
        AND OLD.state IN ('enrolled', 'expired', 'revoked', 'failed'))
    OR (NEW.setup_key_id IS NULL AND OLD.setup_key_closed_at IS NULL AND NEW.setup_key_closed_at IS NOT NULL
        AND OLD.state IN ('enrolled', 'expired', 'revoked', 'failed'))
  ))
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: setup-key ID can only be cleared when its record closes');
END;

-- The vault reference is set only by the write that opens the offer with
-- its created key, and never replaced.
CREATE TRIGGER enroll_offers_setup_key_vault_ref_once
BEFORE UPDATE OF setup_key_vault_ref ON enroll_offers
WHEN NEW.setup_key_vault_ref IS NOT NULL AND NEW.setup_key_vault_ref IS NOT OLD.setup_key_vault_ref
  AND NOT (OLD.setup_key_vault_ref IS NULL AND OLD.setup_key_record = 'pending'
           AND NEW.setup_key_record = 'created' AND OLD.state = 'awaiting_approval' AND NEW.state = 'open')
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: setup-key vault reference is set once');
END;

-- Clearing the reference deletes the secret in the same statement.
-- secure_delete zeroes the old cells; the wiping call checkpoints the WAL
-- (purgeWipedSalt).
CREATE TRIGGER enroll_offers_setup_key_secret_wipe
AFTER UPDATE OF setup_key_vault_ref ON enroll_offers
WHEN OLD.setup_key_vault_ref IS NOT NULL AND NEW.setup_key_vault_ref IS NULL
BEGIN
    DELETE FROM vault_secrets WHERE id = OLD.setup_key_vault_ref;
END;

-- A closed record is an audit record; it never changes again.
CREATE TRIGGER enroll_offers_setup_key_closed_frozen
BEFORE UPDATE OF setup_key_record, setup_key_name, setup_key_group, setup_key_window_start,
    setup_key_window_end, setup_key_name_mismatch, setup_key_id, setup_key_verified,
    setup_key_vault_ref, setup_key_closed_at, setup_key_close, setup_key_revoke_failures,
    setup_key_next_retry_at ON enroll_offers
WHEN OLD.setup_key_closed_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: closed setup-key records are frozen');
END;

-- Revoke failures only count up.
CREATE TRIGGER enroll_offers_setup_key_failures_grow
BEFORE UPDATE OF setup_key_revoke_failures ON enroll_offers
WHEN NEW.setup_key_revoke_failures < OLD.setup_key_revoke_failures
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: revoke failures never decrease');
END;

-- An open setup-key record is the only trace of a key that may still be
-- live; its offer is never deleted.
CREATE TRIGGER enroll_offers_no_delete_open_setup_key
BEFORE DELETE ON enroll_offers
WHEN OLD.setup_key_record <> 'none' AND OLD.setup_key_closed_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'enroll offer: offer with an open setup-key record cannot be deleted');
END;

-- Orphan NetBird peers (ADR 0013 D6 "Peers from offers that did not
-- enrol"): a peer that joined with the setup key of an offer that ended
-- failed, expired or revoked. Peer ID, name and address come from the
-- NetBird API and are untrusted (spec 09); the store validates them, the
-- CHECKs repeat the limits. NOS never deletes a peer on its own; the
-- operator's decision is recorded once.
CREATE TABLE enroll_orphan_peers (
    peer_id       TEXT    PRIMARY KEY CHECK (length(peer_id) BETWEEN 1 AND 64
                      AND peer_id NOT GLOB '*[^0-9a-z]*'),
    offer_id_hash BLOB    NOT NULL REFERENCES enroll_offers (id_hash),
    peer_name     TEXT    NOT NULL CHECK (length(peer_name) BETWEEN 1 AND 255),
    netbird_ip    TEXT    NOT NULL CHECK (length(netbird_ip) BETWEEN 1 AND 64),
    attribution   TEXT    NOT NULL CHECK (attribution IN ('setup_key', 'time_window')),
    recorded_at   INTEGER NOT NULL,
    decision      TEXT    CHECK (decision IS NULL OR decision IN ('deleted', 'kept')),
    decided_at    INTEGER,
    CHECK ((decision IS NULL) = (decided_at IS NULL))
) WITHOUT ROWID;

CREATE INDEX enroll_orphan_peers_offer_idx ON enroll_orphan_peers (offer_id_hash);

CREATE TRIGGER enroll_orphan_peers_offer_ended
BEFORE INSERT ON enroll_orphan_peers
WHEN NOT EXISTS (SELECT 1 FROM enroll_offers WHERE id_hash = NEW.offer_id_hash AND netbird = 1
                 AND setup_key_record <> 'none' AND state IN ('expired', 'revoked', 'failed'))
BEGIN
    SELECT RAISE(ABORT, 'enroll orphan peer: offer is not a NetBird offer that ended without enrolling');
END;

CREATE TRIGGER enroll_orphan_peers_fixed
BEFORE UPDATE ON enroll_orphan_peers
WHEN NEW.peer_id IS NOT OLD.peer_id OR NEW.offer_id_hash IS NOT OLD.offer_id_hash
  OR NEW.peer_name IS NOT OLD.peer_name OR NEW.netbird_ip IS NOT OLD.netbird_ip
  OR NEW.attribution IS NOT OLD.attribution OR NEW.recorded_at IS NOT OLD.recorded_at
  OR (OLD.decision IS NOT NULL AND (NEW.decision IS NOT OLD.decision OR NEW.decided_at IS NOT OLD.decided_at))
BEGIN
    SELECT RAISE(ABORT, 'enroll orphan peer: record is fixed and decided once');
END;
