// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// SetupKeyStatus is the status of an offer's NetBird setup-key record
// (ADR 0013 D6 "Creation order"). It only moves forward: none → pending →
// created.
type SetupKeyStatus string

// Setup-key record statuses.
const (
	// SetupKeyNone: no setup key was requested. Every offer starts here.
	SetupKeyNone SetupKeyStatus = "none"
	// SetupKeyPending: the reconcile record is written and NetBird's
	// create call may have run, but no key ID is known. Revoke and expiry
	// of the offer leave it pending; only the reconcile or the expiry
	// close ends it.
	SetupKeyPending SetupKeyStatus = "pending"
	// SetupKeyCreated: NetBird's key ID is known.
	SetupKeyCreated SetupKeyStatus = "created"
)

// SetupKeyClose is how an open setup-key record was closed.
type SetupKeyClose string

// Ways a setup-key record closes. Only the closing write clears the key ID.
const (
	// SetupKeyClosedRevoked: NetBird confirmed the revoke.
	SetupKeyClosedRevoked SetupKeyClose = "revoked"
	// SetupKeyClosedExpiredUnrevoked: the key's latest possible expiry
	// passed without a successful revoke (audit
	// netbird_setup_key_expired_unrevoked).
	SetupKeyClosedExpiredUnrevoked SetupKeyClose = "expired_unrevoked"
)

// NetBird setup-key limits and timing (ADR 0013 D6, spec 06 v25-06-02,
// spec 09 v25-09-01). The key-ID and group limits are also CHECK
// constraints in 0026_enroll_offer_netbird.sql.
const (
	// NetBirdCreateTimeout bounds NetBird's create-setup-key call, counted
	// from the write that makes the record pending.
	NetBirdCreateTimeout = 30 * time.Second
	// NetBirdKeyClockSkew is the allowed clock difference between the
	// executor and NetBird's management server; it widens the creation
	// window on both sides.
	NetBirdKeyClockSkew = 5 * time.Minute
	// NetBirdSetupKeyMaxLifetime is the longest expiry a setup key gets
	// after its creation.
	NetBirdSetupKeyMaxLifetime = time.Hour
	// NetBirdKeyIDMaxLen is the longest key ID accepted from NetBird.
	NetBirdKeyIDMaxLen = 64
	// SetupKeyRevokeFirstRetry is the wait after the first failed revoke.
	SetupKeyRevokeFirstRetry = time.Minute
	// SetupKeyRevokeRetryInterval is the wait after every later failed
	// revoke.
	SetupKeyRevokeRetryInterval = 5 * time.Minute

	maxSetupKeyGroupLen  = 64
	maxOrphanPeerIDLen   = 64
	maxOrphanPeerNameLen = 255

	setupKeyNamePrefix     = "nos-offer-"
	setupKeyVaultRefPrefix = "netbird-setup-key-"
)

// Setup-key and orphan-peer store errors.
var (
	// ErrSetupKeyState: the setup-key record is not in the state the call
	// needs (or the offer has none); nothing was changed.
	ErrSetupKeyState = errors.New("executordb: setup-key record is not in the expected state")
	// ErrSetupKeyLive: the key may still be valid, so its record cannot be
	// closed by expiry yet; nothing was changed.
	ErrSetupKeyLive = errors.New("executordb: setup key may still be valid")
	// ErrOrphanPeerExists: the peer is already recorded.
	ErrOrphanPeerExists = errors.New("executordb: orphan peer already recorded")
	// ErrOrphanPeerNotFound: no orphan peer with this ID.
	ErrOrphanPeerNotFound = errors.New("executordb: orphan peer not found")
	// ErrOrphanPeerDecided: the operator's decision is already recorded.
	ErrOrphanPeerDecided = errors.New("executordb: orphan peer already decided")
)

// SetupKeyRecord is an offer's NetBird setup-key record. It holds
// identifiers only; the setup key itself is in the vault under VaultRef.
type SetupKeyRecord struct {
	Status SetupKeyStatus
	// The reconcile record, written with none → pending.
	Name         string // nos-offer-<first 8 hex of the offer ID hash>
	Group        string // the managed group the key was requested for
	WindowStart  time.Time
	WindowEnd    time.Time
	NameMismatch bool // NetBird's create answer carried another key name

	KeyID string // NetBird's key ID; "" while pending and after closing
	// Verified is false for a key ID from a create answer that failed
	// another check; it is revoked only after a get by ID or the
	// reconcile confirmed it.
	Verified bool
	VaultRef string // vault entry of the setup key; "" once the offer is final

	ClosedAt       time.Time // zero while the record is open
	Close          SetupKeyClose
	RevokeFailures int
	NextRetryAt    time.Time // zero until a revoke failed
}

// Open reports whether the record still stands for a key that may be
// live: it exists and was not closed.
func (r SetupKeyRecord) Open() bool {
	return r.Status != SetupKeyNone && r.ClosedAt.IsZero()
}

// Deadline is the latest time at which a key created for this record can
// still be valid: the end of its creation window plus the longest key
// lifetime. Before it, the record is closed only by a successful revoke.
func (r SetupKeyRecord) Deadline() time.Time {
	return r.WindowEnd.Add(NetBirdSetupKeyMaxLifetime)
}

// SetupKeyName is the NetBird key name for the offer: nos-offer- and the
// first 8 hex characters of its ID hash. It reveals nothing usable.
func SetupKeyName(idHash [offerHashLen]byte) string {
	return setupKeyNamePrefix + offerLogID(idHash)
}

// SetupKeyVaultRef is the vault secret ID under which the offer's setup
// key is stored; the schema accepts no other reference.
func SetupKeyVaultRef(idHash [offerHashLen]byte) string {
	return fmt.Sprintf("%s%x", setupKeyVaultRefPrefix, idHash[:16])
}

const setupKeyColumns = `setup_key_record, setup_key_name, setup_key_group, setup_key_window_start,
	setup_key_window_end, setup_key_name_mismatch, setup_key_id, setup_key_verified, setup_key_vault_ref,
	setup_key_closed_at, setup_key_close, setup_key_revoke_failures, setup_key_next_retry_at`

const finalStates = `('enrolled', 'expired', 'revoked', 'failed')`

// setupKeyScan receives the setupKeyColumns of one row.
type setupKeyScan struct {
	status                  string
	name, group, id, ref    sql.NullString
	start, end, closed, nxt sql.NullInt64
	close                   sql.NullString
	mismatch, verified      int64
	failures                int64
}

func (s *setupKeyScan) dest() []any {
	return []any{&s.status, &s.name, &s.group, &s.start, &s.end, &s.mismatch, &s.id, &s.verified,
		&s.ref, &s.closed, &s.close, &s.failures, &s.nxt}
}

func (s *setupKeyScan) record() (SetupKeyRecord, error) {
	r := SetupKeyRecord{
		Status: SetupKeyStatus(s.status), Name: s.name.String, Group: s.group.String,
		NameMismatch: s.mismatch == 1, KeyID: s.id.String, Verified: s.verified == 1, VaultRef: s.ref.String,
		Close: SetupKeyClose(s.close.String), RevokeFailures: int(s.failures),
	}
	switch r.Status {
	case SetupKeyNone, SetupKeyPending, SetupKeyCreated:
	default:
		return SetupKeyRecord{}, fmt.Errorf("unknown stored setup-key record %q", s.status)
	}
	for _, x := range []struct {
		v sql.NullInt64
		t *time.Time
	}{{s.start, &r.WindowStart}, {s.end, &r.WindowEnd}, {s.closed, &r.ClosedAt}, {s.nxt, &r.NextRetryAt}} {
		if x.v.Valid {
			*x.t = time.Unix(x.v.Int64, 0)
		}
	}
	return r, nil
}

// MarkSetupKeyPending moves the offer's setup-key record from none to
// pending and persists its reconcile record (key name, managed group and
// creation window), in one compare-and-set, before NetBird's create call
// (ADR 0013 D6 "Creation order" step 1). It succeeds only for a NetBird
// offer that is still awaiting_approval and not expired: otherwise no key
// may be created (ErrOfferState, ErrOfferExpired). A record that is
// already pending or created is never moved again (ErrSetupKeyState), so
// of concurrent calls exactly one wins and create is never called twice
// for one offer, also not after a restart.
//
// The creation window runs from now minus NetBirdKeyClockSkew to now plus
// NetBirdCreateTimeout plus NetBirdKeyClockSkew.
func (db *DB) MarkSetupKeyPending(idHash [offerHashLen]byte, group string) (SetupKeyRecord, error) {
	if err := checkText("managed group", group, maxSetupKeyGroupLen, false); err != nil {
		return SetupKeyRecord{}, err
	}
	now := db.now().Unix()
	skew := int64(NetBirdKeyClockSkew / time.Second)
	timeout := int64(NetBirdCreateTimeout / time.Second)
	n, err := db.setupKeyExec(idHash, "setup key pending", `UPDATE enroll_offers
		SET setup_key_record = 'pending', setup_key_name = ?, setup_key_group = ?,
			setup_key_window_start = ?, setup_key_window_end = ?
		WHERE id_hash = ? AND netbird = 1 AND state = 'awaiting_approval' AND setup_key_record = 'none'
		  AND expires_at > ?`,
		SetupKeyName(idHash), group, now-skew, now+timeout+skew, idHash[:], now)
	if err != nil {
		return SetupKeyRecord{}, err
	}
	if n == 0 {
		return SetupKeyRecord{}, db.setupKeyRefusal(idHash, "setup key pending", now, OfferAwaitingApproval, SetupKeyNone)
	}
	o, err := db.Offer(idHash)
	if err != nil {
		return SetupKeyRecord{}, fmt.Errorf("executordb: setup key pending: %w", err)
	}
	return o.SetupKey, nil
}

// OpenNetBirdOffer records a valid create answer and opens the offer, in
// one transaction (ADR 0013 D6 step 3): it stores the sealed setup key as
// vault secret SetupKeyVaultRef(idHash) (version 1), moves the record
// pending → created with the key ID and the vault reference, stores the
// SHA-256 of the full render and moves the offer awaiting_approval → open.
// The caller has validated the answer (spec 09) and seals the key with
// package vault; the plaintext key never reaches the store.
//
// If the offer became final or expired meanwhile (ErrOfferState,
// ErrOfferExpired), or the record is not pending (ErrSetupKeyState),
// nothing is stored, also not the secret; the caller then records the key
// ID with FailSetupKeyCreate before it revokes the key.
func (db *DB) OpenNetBirdOffer(idHash [offerHashLen]byte, keyID string, secret VaultSecret, scriptSHA256 [offerHashLen]byte) (err error) {
	if err := checkSetupKeyID(keyID); err != nil {
		return err
	}
	if scriptSHA256 == zeroHash {
		return fmt.Errorf("executordb: %w: offer script hash is required", ErrInvalid)
	}
	if secret.ID != SetupKeyVaultRef(idHash) || secret.Version != 1 {
		return fmt.Errorf("executordb: %w: setup-key secret must be version 1 of the offer's own vault entry", ErrInvalid)
	}
	now := db.now()
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("executordb: open NetBird offer %s: %w", offerLogID(idHash), err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	// Check first, so a refused open does not touch the vault at all.
	var ok int
	err = tx.QueryRow(`SELECT count(*) FROM enroll_offers
		WHERE id_hash = ? AND netbird = 1 AND state = 'awaiting_approval' AND setup_key_record = 'pending'
		  AND expires_at > ?`, idHash[:], now.Unix()).Scan(&ok)
	if err != nil {
		return fmt.Errorf("executordb: open NetBird offer %s: %w", offerLogID(idHash), err)
	}
	if ok == 1 {
		if err := putSecret(tx, secret, now); err != nil {
			return fmt.Errorf("executordb: open NetBird offer %s: %w", offerLogID(idHash), err)
		}
		res, err := tx.Exec(`UPDATE enroll_offers
			SET state = 'open', state_changed_at = ?, script_sha256 = ?, setup_key_record = 'created',
				setup_key_id = ?, setup_key_verified = 1, setup_key_vault_ref = ?
			WHERE id_hash = ? AND netbird = 1 AND state = 'awaiting_approval' AND setup_key_record = 'pending'
			  AND expires_at > ?`,
			now.Unix(), scriptSHA256[:], keyID, secret.ID, idHash[:], now.Unix())
		if err != nil {
			return fmt.Errorf("executordb: open NetBird offer %s: %w", offerLogID(idHash), err)
		}
		if k, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("executordb: open NetBird offer %s: %w", offerLogID(idHash), err)
		} else if k == 1 {
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("executordb: open NetBird offer %s: %w", offerLogID(idHash), err)
			}
			committed = true
			return nil
		}
	}
	if err := tx.Rollback(); err != nil {
		return fmt.Errorf("executordb: open NetBird offer %s: %w", offerLogID(idHash), err)
	}
	committed = true
	return db.setupKeyRefusal(idHash, "open NetBird offer", now.Unix(), OfferAwaitingApproval, SetupKeyPending)
}

// FailSetupKeyCreate is the write that precedes every revoke or reconcile
// after a create answer that cannot be used (ADR 0013 D6 step 3, spec 09):
// in one transaction it fails the offer if it is not final yet (wiping the
// salt) and updates the pending record. With a keyID (one that passed its
// check) the record moves pending → created with that key ID and no vault
// reference; verified tells whether the rest of the answer passed too
// (false: revoke only after ReconcileSetupKey). Without a keyID the record
// stays pending with its reconcile record. nameMismatch marks a record
// whose answer carried another key name.
//
// A record that is not pending, or already closed, gets ErrSetupKeyState.
func (db *DB) FailSetupKeyCreate(idHash [offerHashLen]byte, keyID string, verified, nameMismatch bool) (err error) {
	if keyID != "" {
		if err := checkSetupKeyID(keyID); err != nil {
			return err
		}
	} else if verified {
		return fmt.Errorf("executordb: %w: a verified setup-key record needs a key ID", ErrInvalid)
	}
	const what = "fail setup-key create"
	now := db.now().Unix()
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	var state, record string
	var closed sql.NullInt64
	err = tx.QueryRow(`SELECT state, setup_key_record, setup_key_closed_at FROM enroll_offers WHERE id_hash = ?`,
		idHash[:]).Scan(&state, &record, &closed)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), ErrOfferNotFound)
	}
	if err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	if record != string(SetupKeyPending) || closed.Valid {
		return fmt.Errorf("executordb: %s %s: record %s: %w", what, offerLogID(idHash), record, ErrSetupKeyState)
	}
	newRecord, id := SetupKeyPending, any(nil)
	if keyID != "" {
		newRecord, id = SetupKeyCreated, keyID
	}
	ending := !OfferState(state).Final()
	q := `UPDATE enroll_offers SET setup_key_record = ?, setup_key_id = ?, setup_key_verified = ?,
			setup_key_name_mismatch = ?`
	args := []any{string(newRecord), id, boolInt(verified), boolInt(nameMismatch)}
	if ending {
		q += `, state = 'failed', state_changed_at = ?, salt = NULL, setup_key_vault_ref = NULL`
		args = append(args, now)
	}
	q += ` WHERE id_hash = ? AND state = ? AND setup_key_record = 'pending' AND setup_key_closed_at IS NULL`
	args = append(args, idHash[:], state)
	res, err := tx.Exec(q, args...)
	if err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	if k, err := res.RowsAffected(); err != nil || k != 1 {
		return fmt.Errorf("executordb: %s %s: %d rows changed: %w", what, offerLogID(idHash), k, errors.Join(err, ErrSetupKeyState))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	if ending {
		return db.purgeWipedSalt(what)
	}
	return nil
}

// ReconcileSetupKey records the key ID that a get by ID confirmed or the
// reconcile matched for a final offer's open record (ADR 0013 D6 step 5):
// a pending or unverified created record becomes created and verified with
// keyID, and can then be revoked. A record that is already verified,
// closed or on a live offer gets ErrSetupKeyState.
func (db *DB) ReconcileSetupKey(idHash [offerHashLen]byte, keyID string) error {
	if err := checkSetupKeyID(keyID); err != nil {
		return err
	}
	return db.setupKeyCAS(idHash, "reconcile setup key", `UPDATE enroll_offers
		SET setup_key_record = 'created', setup_key_id = ?, setup_key_verified = 1
		WHERE id_hash = ? AND state IN `+finalStates+` AND setup_key_closed_at IS NULL
		  AND (setup_key_record = 'pending' OR (setup_key_record = 'created' AND setup_key_verified = 0))`,
		keyID, idHash[:])
}

// SetupKeyRevoked records NetBird's confirmation that keyID was revoked:
// the record closes as revoked and the key ID is cleared, in one
// compare-and-set (ADR 0013 D6 "Revocation at the final state" step 3).
// It needs a final offer (whose secret is already wiped) and an open,
// verified record holding exactly keyID; otherwise ErrSetupKeyState.
func (db *DB) SetupKeyRevoked(idHash [offerHashLen]byte, keyID string) error {
	if err := checkSetupKeyID(keyID); err != nil {
		return err
	}
	return db.setupKeyCAS(idHash, "setup key revoked", `UPDATE enroll_offers
		SET setup_key_id = NULL, setup_key_closed_at = ?, setup_key_close = 'revoked', setup_key_next_retry_at = NULL
		WHERE id_hash = ? AND state IN `+finalStates+` AND setup_key_record = 'created'
		  AND setup_key_verified = 1 AND setup_key_closed_at IS NULL AND setup_key_id = ?`,
		db.now().Unix(), idHash[:], keyID)
}

// CloseExpiredSetupKey closes a final offer's open record as
// expired_unrevoked and clears its key ID once the record's Deadline has
// passed: any key created for it is dead on NetBird's side. Before that it
// fails with ErrSetupKeyLive; without an open record on a final offer,
// with ErrSetupKeyState.
func (db *DB) CloseExpiredSetupKey(idHash [offerHashLen]byte) error {
	now := db.now().Unix()
	err := db.setupKeyCAS(idHash, "close expired setup key", `UPDATE enroll_offers
		SET setup_key_id = NULL, setup_key_closed_at = ?, setup_key_close = 'expired_unrevoked',
			setup_key_next_retry_at = NULL
		WHERE id_hash = ? AND state IN `+finalStates+` AND setup_key_record <> 'none'
		  AND setup_key_closed_at IS NULL AND setup_key_window_end + ? <= ?`,
		now, idHash[:], int64(NetBirdSetupKeyMaxLifetime/time.Second), now)
	if !errors.Is(err, ErrSetupKeyState) {
		return err
	}
	if o, rerr := db.Offer(idHash); rerr == nil && o.State.Final() && o.SetupKey.Open() {
		return fmt.Errorf("executordb: close expired setup key %s: %w", offerLogID(idHash), ErrSetupKeyLive)
	}
	return err
}

// RecordSetupKeyRevokeFailure counts a failed revoke (or reconcile pass)
// for a final offer's open record and returns when to retry: after
// SetupKeyRevokeFirstRetry the first time, SetupKeyRevokeRetryInterval
// afterwards. The count and the retry time survive a restart.
func (db *DB) RecordSetupKeyRevokeFailure(idHash [offerHashLen]byte) (time.Time, error) {
	const what = "record setup-key revoke failure"
	now := db.now().Unix()
	var next int64
	err := db.sql.QueryRow(`UPDATE enroll_offers
		SET setup_key_revoke_failures = setup_key_revoke_failures + 1,
			setup_key_next_retry_at = ? + CASE WHEN setup_key_revoke_failures = 0 THEN ? ELSE ? END
		WHERE id_hash = ? AND state IN `+finalStates+` AND setup_key_record <> 'none'
		  AND setup_key_closed_at IS NULL
		RETURNING setup_key_next_retry_at`,
		now, int64(SetupKeyRevokeFirstRetry/time.Second), int64(SetupKeyRevokeRetryInterval/time.Second),
		idHash[:]).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := db.Offer(idHash); err != nil {
			return time.Time{}, fmt.Errorf("executordb: %s: %w", what, err)
		}
		return time.Time{}, fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), ErrSetupKeyState)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	return time.Unix(next, 0), nil
}

// OpenSetupKeyRecords returns every offer whose setup-key record needs
// the executor's attention: open records of final offers (revoke retries
// and reconciles) and pending records of live offers (left by a crash
// during the create call; the caller fails those offers). They are what
// a restart resumes from. The number is bounded by the offer limits and
// by CloseExpiredSetupKey, which closes every record at its Deadline.
func (db *DB) OpenSetupKeyRecords() ([]Offer, error) {
	rows, err := db.sql.Query(`SELECT ` + offerColumns + ` FROM enroll_offers
		WHERE setup_key_record <> 'none' AND setup_key_closed_at IS NULL
		  AND (state IN ` + finalStates + ` OR setup_key_record = 'pending')
		ORDER BY created_at, id_hash`)
	if err != nil {
		return nil, fmt.Errorf("executordb: open setup-key records: %w", err)
	}
	defer rows.Close()
	var out []Offer
	for rows.Next() {
		o, err := scanOffer(rows, zeroHash)
		if err != nil {
			return nil, fmt.Errorf("executordb: open setup-key records: %w", err)
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: open setup-key records: %w", err)
	}
	return out, nil
}

// setupKeyExec runs one UPDATE and returns the number of changed rows.
func (db *DB) setupKeyExec(idHash [offerHashLen]byte, what, query string, args ...any) (int64, error) {
	res, err := db.sql.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	return n, nil
}

// setupKeyCAS runs one compare-and-set on a setup-key record. When it
// changed no row, the result is ErrOfferNotFound or ErrSetupKeyState.
func (db *DB) setupKeyCAS(idHash [offerHashLen]byte, what, query string, args ...any) error {
	n, err := db.setupKeyExec(idHash, what, query, args...)
	if err != nil || n == 1 {
		return err
	}
	o, err := db.Offer(idHash)
	if err != nil {
		return fmt.Errorf("executordb: %s: %w", what, err)
	}
	return fmt.Errorf("executordb: %s %s: offer %s, record %s: %w", what, offerLogID(idHash), o.State, o.SetupKey.Status, ErrSetupKeyState)
}

// setupKeyRefusal explains a compare-and-set that changed nothing and
// needed a NetBird offer in state with a record in status: ErrOfferNotFound,
// ErrOfferState (wrong offer or offer state), ErrSetupKeyState (wrong
// record) or ErrOfferExpired. It never leads to a change.
func (db *DB) setupKeyRefusal(idHash [offerHashLen]byte, what string, now int64, state OfferState, status SetupKeyStatus) error {
	o, err := db.Offer(idHash)
	if err != nil {
		return fmt.Errorf("executordb: %s: %w", what, err)
	}
	switch {
	case !o.NetBird || o.State != state:
		return fmt.Errorf("executordb: %s %s: %s: %w", what, offerLogID(idHash), o.State, ErrOfferState)
	case o.SetupKey.Status != status:
		return fmt.Errorf("executordb: %s %s: record %s: %w", what, offerLogID(idHash), o.SetupKey.Status, ErrSetupKeyState)
	case o.ExpiresAt.Unix() <= now:
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), ErrOfferExpired)
	}
	return fmt.Errorf("executordb: %s %s: %s: %w", what, offerLogID(idHash), o.State, ErrOfferState)
}

// checkSetupKeyID checks a NetBird key ID: 1 to NetBirdKeyIDMaxLen
// characters from 0-9a-z (spec 09).
func checkSetupKeyID(id string) error {
	if !lowerAlnum(id, NetBirdKeyIDMaxLen) {
		return fmt.Errorf("executordb: %w: setup-key ID must be 1..%d characters 0-9a-z", ErrInvalid, NetBirdKeyIDMaxLen)
	}
	return nil
}

func lowerAlnum(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// OrphanAttribution is how a peer was tied to an offer's setup key
// (ADR 0013 Q8).
type OrphanAttribution string

// Attribution methods.
const (
	// AttributionSetupKey: the NetBird API named the setup key the peer
	// joined with.
	AttributionSetupKey OrphanAttribution = "setup_key"
	// AttributionTimeWindow: the weaker time-window fallback; deleting
	// such a peer needs a NetBird peer delete permit.
	AttributionTimeWindow OrphanAttribution = "time_window"
)

// OrphanDecision is the operator's decision on an orphan peer.
type OrphanDecision string

// Orphan-peer decisions.
const (
	OrphanPeerDeleted OrphanDecision = "deleted" // the peer was deleted from NetBird
	OrphanPeerKept    OrphanDecision = "kept"    // the peer stays as an ordinary peer
)

// OrphanPeer is a NetBird peer that joined with the setup key of an offer
// that ended failed, expired or revoked. PeerID, PeerName and NetBirdIP
// come from the NetBird API and are validated as untrusted input.
type OrphanPeer struct {
	OfferIDHash [offerHashLen]byte
	PeerID      string // 1..64 characters 0-9a-z
	PeerName    string // printable UTF-8, at most 255 bytes; render as text only
	NetBirdIP   string // IP literal without zone, stored in canonical form
	Attribution OrphanAttribution
	RecordedAt  time.Time
	Decision    OrphanDecision // "" until decided
	DecidedAt   time.Time
}

// RecordOrphanPeer records p for an offer that is a NetBird offer with a
// setup-key record and ended failed, expired or revoked (otherwise
// ErrOfferState). A peer is recorded once (ErrOrphanPeerExists).
func (db *DB) RecordOrphanPeer(p OrphanPeer) (err error) {
	if !lowerAlnum(p.PeerID, maxOrphanPeerIDLen) {
		return fmt.Errorf("executordb: %w: peer ID must be 1..%d characters 0-9a-z", ErrInvalid, maxOrphanPeerIDLen)
	}
	if err := checkText("peer name", p.PeerName, maxOrphanPeerNameLen, false); err != nil {
		return err
	}
	ip, err := offerAddr("NetBird IP", p.NetBirdIP)
	if err != nil {
		return err
	}
	if p.Attribution != AttributionSetupKey && p.Attribution != AttributionTimeWindow {
		return fmt.Errorf("executordb: %w: unknown peer attribution", ErrInvalid)
	}
	const what = "record orphan peer"
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("executordb: %s: %w", what, err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	var netbird int
	var state, record string
	err = tx.QueryRow(`SELECT netbird, state, setup_key_record FROM enroll_offers WHERE id_hash = ?`,
		p.OfferIDHash[:]).Scan(&netbird, &state, &record)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("executordb: %s for offer %s: %w", what, offerLogID(p.OfferIDHash), ErrOfferNotFound)
	}
	if err != nil {
		return fmt.Errorf("executordb: %s for offer %s: %w", what, offerLogID(p.OfferIDHash), err)
	}
	switch OfferState(state) {
	case OfferFailed, OfferExpired, OfferRevoked:
		if netbird == 1 && record != string(SetupKeyNone) {
			break
		}
		fallthrough
	default:
		return fmt.Errorf("executordb: %s for offer %s: %s: %w", what, offerLogID(p.OfferIDHash), state, ErrOfferState)
	}
	res, err := tx.Exec(`INSERT INTO enroll_orphan_peers (peer_id, offer_id_hash, peer_name, netbird_ip,
			attribution, recorded_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(peer_id) DO NOTHING`,
		p.PeerID, p.OfferIDHash[:], p.PeerName, ip, string(p.Attribution), db.now().Unix())
	if err != nil {
		return fmt.Errorf("executordb: %s for offer %s: %w", what, offerLogID(p.OfferIDHash), err)
	}
	if k, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("executordb: %s for offer %s: %w", what, offerLogID(p.OfferIDHash), err)
	} else if k == 0 {
		return fmt.Errorf("executordb: %s %s: %w", what, p.PeerID, ErrOrphanPeerExists)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("executordb: %s for offer %s: %w", what, offerLogID(p.OfferIDHash), err)
	}
	return nil
}

// DecideOrphanPeer records the operator's decision on an orphan peer,
// once (ErrOrphanPeerDecided). The caller has already carried it out
// (delete call) or chosen to keep the peer.
func (db *DB) DecideOrphanPeer(peerID string, d OrphanDecision) error {
	if !lowerAlnum(peerID, maxOrphanPeerIDLen) {
		return fmt.Errorf("executordb: %w: peer ID must be 1..%d characters 0-9a-z", ErrInvalid, maxOrphanPeerIDLen)
	}
	if d != OrphanPeerDeleted && d != OrphanPeerKept {
		return fmt.Errorf("executordb: %w: unknown orphan-peer decision", ErrInvalid)
	}
	const what = "decide orphan peer"
	res, err := db.sql.Exec(`UPDATE enroll_orphan_peers SET decision = ?, decided_at = ?
		WHERE peer_id = ? AND decision IS NULL`, string(d), db.now().Unix(), peerID)
	if err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, peerID, err)
	}
	if k, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, peerID, err)
	} else if k == 1 {
		return nil
	}
	var n int
	if err := db.sql.QueryRow(`SELECT count(*) FROM enroll_orphan_peers WHERE peer_id = ?`, peerID).Scan(&n); err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, peerID, err)
	}
	if n == 0 {
		return fmt.Errorf("executordb: %s %s: %w", what, peerID, ErrOrphanPeerNotFound)
	}
	return fmt.Errorf("executordb: %s %s: %w", what, peerID, ErrOrphanPeerDecided)
}

// OrphanPeers returns the orphan peers still awaiting the operator's
// decision, oldest first.
func (db *DB) OrphanPeers() ([]OrphanPeer, error) {
	rows, err := db.sql.Query(`SELECT peer_id, offer_id_hash, peer_name, netbird_ip, attribution, recorded_at
		FROM enroll_orphan_peers WHERE decision IS NULL ORDER BY recorded_at, peer_id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: orphan peers: %w", err)
	}
	defer rows.Close()
	var out []OrphanPeer
	for rows.Next() {
		var p OrphanPeer
		var offer []byte
		var attr string
		var at int64
		if err := rows.Scan(&p.PeerID, &offer, &p.PeerName, &p.NetBirdIP, &attr, &at); err != nil {
			return nil, fmt.Errorf("executordb: orphan peers: %w", err)
		}
		if len(offer) != offerHashLen {
			return nil, fmt.Errorf("executordb: orphan peers: stored offer ID hash has %d bytes", len(offer))
		}
		if _, err := netip.ParseAddr(p.NetBirdIP); err != nil {
			return nil, fmt.Errorf("executordb: orphan peers: stored NetBird IP is not an address")
		}
		p.OfferIDHash = [offerHashLen]byte(offer)
		p.Attribution = OrphanAttribution(attr)
		p.RecordedAt = time.Unix(at, 0)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: orphan peers: %w", err)
	}
	return out, nil
}
