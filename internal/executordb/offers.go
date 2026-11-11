// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// OfferState is the state of a one-step enrollment offer (spec 03
// v25-03-04).
type OfferState string

// Offer states. The only forward paths are awaiting_approval → open →
// downloaded → pairing_proposed → enrolled, plus every non-final state →
// expired, revoked or failed.
const (
	OfferAwaitingApproval OfferState = "awaiting_approval"
	OfferOpen             OfferState = "open"
	OfferDownloaded       OfferState = "downloaded"
	OfferPairingProposed  OfferState = "pairing_proposed"
	OfferEnrolled         OfferState = "enrolled"
	OfferExpired          OfferState = "expired"
	OfferRevoked          OfferState = "revoked"
	OfferFailed           OfferState = "failed"
)

// Final reports whether s is a final state. A final offer is an audit
// record without salt and never changes state again.
func (s OfferState) Final() bool {
	switch s {
	case OfferEnrolled, OfferExpired, OfferRevoked, OfferFailed:
		return true
	}
	return false
}

func (s OfferState) known() bool {
	switch s {
	case OfferAwaitingApproval, OfferOpen, OfferDownloaded, OfferPairingProposed,
		OfferEnrolled, OfferExpired, OfferRevoked, OfferFailed:
		return true
	}
	return false
}

// Limits of the offer store (ADR 0013 D2, E9). The probe and rejected-code
// limits are also CHECK constraints in 0025_enroll_offers.sql.
const (
	// OfferLifetime is the total time from creation for download and code
	// submission (Q2).
	OfferLifetime = 15 * time.Minute
	// OfferMaxProbes is the number of probes per offer.
	OfferMaxProbes = 5
	// OfferMaxRejectedCodes is the number of malformed code submissions
	// per offer.
	OfferMaxRejectedCodes = 3
	// OfferProposedGrace is how long after its expiry an offer in
	// pairing_proposed may still be committed: an approval started before
	// expiry finishes within its permit's lifetime, which is at most
	// canonical.MaxPermitLifetime. The expiry sweep ends such offers only
	// after this grace.
	OfferProposedGrace = canonical.MaxPermitLifetime

	// OfferMaxLive is the number of non-final offers per executor.
	OfferMaxLive = 10
	// OfferMaxLiveNetBird is the number of non-final NetBird offers per
	// executor, on top of OfferMaxLive.
	OfferMaxLiveNetBird = 2
	// OfferMaxPerHour is the number of offers created in any hour
	// (created_at within the last OfferRateWindow).
	OfferMaxPerHour = 30
	// OfferRateWindow is the window of OfferMaxPerHour.
	OfferRateWindow = time.Hour

	proposedGraceSeconds = int64(OfferProposedGrace / time.Second)

	offerHashLen       = 32
	offerSaltLen       = 32 // 256-bit salt (spec 03 v25-03-03)
	maxOfferHostIDLen  = 63 // as host_keys.host_id
	maxOfferSSHUserLen = 32
	maxOfferCredRefLen = 64
	maxOfferAddrLen    = 64 // CHECK in 0025_enroll_offers.sql
)

// Offer store errors. Callers answer every one of them towards the
// download client with the same uniform refusal; the distinction is for
// the executor's own decisions and audit.
var (
	// ErrOfferNotFound: no offer with this ID hash.
	ErrOfferNotFound = errors.New("executordb: enrollment offer not found")
	// ErrOfferExists: an offer with this ID hash already exists.
	ErrOfferExists = errors.New("executordb: enrollment offer already exists")
	// ErrOfferState: the compare-and-set found the offer in another state
	// than expected (or the claim it needs was already taken); nothing was
	// changed.
	ErrOfferState = errors.New("executordb: enrollment offer is not in the expected state")
	// ErrOfferExpired: the offer's lifetime is over; nothing was changed.
	ErrOfferExpired = errors.New("executordb: enrollment offer expired")
	// ErrOfferLimit: a per-offer counter or a per-executor offer limit was
	// reached; nothing was changed.
	ErrOfferLimit = errors.New("executordb: enrollment offer limit reached")
	// ErrOfferWipeIncomplete: the offer's final state and the NULL salt are
	// committed, but the WAL checkpoint that removes the old salt from the
	// -wal file did not complete. The state change stands; the next wiping
	// call, the next Open or Close retries the checkpoint.
	ErrOfferWipeIncomplete = errors.New("executordb: enrollment offer salt wiped, but not yet removed from the WAL")
)

// NewOffer is what CreateOffer stores. The offer ID itself is never passed
// in, only its SHA-256.
type NewOffer struct {
	IDHash        [offerHashLen]byte // SHA-256 of the offer ID
	Salt          [offerSaltLen]byte // from crypto/rand; wiped at the final state
	HostID        string
	SSHUser       string
	CredentialRef string
	SessionHash   [offerHashLen]byte // digest binding the creating web session
	// NetBird offers start in awaiting_approval without a script hash;
	// all others start open with ScriptSHA256 set.
	NetBird      bool
	ScriptSHA256 [offerHashLen]byte // SHA-256 of the full render; zero for NetBird offers
}

// Offer is a stored enrollment offer. It never contains script bytes.
type Offer struct {
	IDHash          [offerHashLen]byte
	Salt            []byte // nil in every final state
	HostID          string
	SSHUser         string
	CredentialRef   string
	SessionHash     [offerHashLen]byte
	NetBird         bool
	CreatedAt       time.Time
	ExpiresAt       time.Time
	State           OfferState
	StateChangedAt  time.Time
	ScriptSHA256    []byte    // nil until set (NetBird offers before approval)
	DownloadedAt    time.Time // zero until downloaded
	ClientAddr      string    // client address of the download, "" until downloaded
	PeerAddr        string    // direct peer address of the download, "" until downloaded
	CodeSubmittedAt time.Time // zero until a well-formed code was submitted
	Probes          int
	RejectedCodes   int
}

var zeroHash [offerHashLen]byte

// CreateOffer stores a new offer, created now and expiring after
// OfferLifetime. A NetBird offer starts in awaiting_approval, every other
// offer in open. It enforces the per-executor limits of ADR 0013 D2
// (OfferMaxLive, OfferMaxLiveNetBird, OfferMaxPerHour) with ErrOfferLimit;
// the NetBird setup-key limit belongs to the setup-key store (EN-05 part
// 2).
func (db *DB) CreateOffer(n NewOffer) (Offer, error) {
	if n.IDHash == zeroHash {
		return Offer{}, fmt.Errorf("executordb: %w: offer ID hash is required", ErrInvalid)
	}
	if n.Salt == [offerSaltLen]byte{} {
		return Offer{}, fmt.Errorf("executordb: %w: offer salt is required", ErrInvalid)
	}
	if n.SessionHash == zeroHash {
		return Offer{}, fmt.Errorf("executordb: %w: offer session binding is required", ErrInvalid)
	}
	if err := checkText("host_id", n.HostID, maxOfferHostIDLen, false); err != nil {
		return Offer{}, err
	}
	if err := checkText("ssh_user", n.SSHUser, maxOfferSSHUserLen, false); err != nil {
		return Offer{}, err
	}
	if err := checkText("credential_ref", n.CredentialRef, maxOfferCredRefLen, false); err != nil {
		return Offer{}, err
	}
	state := OfferOpen
	var script any = n.ScriptSHA256[:]
	if n.NetBird {
		if n.ScriptSHA256 != zeroHash {
			return Offer{}, fmt.Errorf("executordb: %w: a NetBird offer gets its script hash only when it is opened", ErrInvalid)
		}
		state, script = OfferAwaitingApproval, nil
	} else if n.ScriptSHA256 == zeroHash {
		return Offer{}, fmt.Errorf("executordb: %w: offer script hash is required", ErrInvalid)
	}
	now := db.now().Unix()
	if err := db.insertOffer(n, now, state, script); err != nil {
		return Offer{}, fmt.Errorf("executordb: create offer %s: %w", offerLogID(n.IDHash), err)
	}
	return db.Offer(n.IDHash)
}

// offerLimits are the per-executor offer limits CreateOffer enforces.
type offerLimits struct {
	live, liveNetBird, perHour int
}

var defaultOfferLimits = offerLimits{live: OfferMaxLive, liveNetBird: OfferMaxLiveNetBird, perHour: OfferMaxPerHour}

// insertOffer checks the per-executor limits and inserts the offer in one
// transaction. Every offer that is not final counts as live, also one
// whose lifetime is over but which the sweep has not ended yet: the caller
// runs ExpireOffers first (it audits what that ends).
func (db *DB) insertOffer(n NewOffer, now int64, state OfferState, script any) (err error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	var live, liveNetBird, recent int
	if err := tx.QueryRow(`SELECT
			count(*) FILTER (WHERE state IN ('awaiting_approval', 'open', 'downloaded', 'pairing_proposed')),
			count(*) FILTER (WHERE netbird = 1 AND state IN ('awaiting_approval', 'open', 'downloaded', 'pairing_proposed')),
			count(*) FILTER (WHERE created_at > ?)
		FROM enroll_offers`, now-int64(OfferRateWindow/time.Second)).Scan(&live, &liveNetBird, &recent); err != nil {
		return err
	}
	l := db.offerLimits
	switch {
	case live >= l.live:
		return fmt.Errorf("%d non-final offers: %w", live, ErrOfferLimit)
	case n.NetBird && liveNetBird >= l.liveNetBird:
		return fmt.Errorf("%d non-final NetBird offers: %w", liveNetBird, ErrOfferLimit)
	case recent >= l.perHour:
		return fmt.Errorf("%d offers created in the last hour: %w", recent, ErrOfferLimit)
	}
	res, err := tx.Exec(`INSERT INTO enroll_offers (id_hash, salt, host_id, ssh_user, credential_ref,
			session_hash, netbird, created_at, expires_at, state, state_changed_at, script_sha256)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id_hash) DO NOTHING`,
		n.IDHash[:], n.Salt[:], n.HostID, n.SSHUser, n.CredentialRef, n.SessionHash[:], boolInt(n.NetBird),
		now, now+int64(OfferLifetime/time.Second), string(state), now, script)
	if err != nil {
		return err
	}
	if k, err := res.RowsAffected(); err != nil {
		return err
	} else if k == 0 {
		return ErrOfferExists
	}
	return tx.Commit()
}

const offerColumns = `id_hash, salt, host_id, ssh_user, credential_ref, session_hash, netbird, created_at,
	expires_at, state, state_changed_at, script_sha256, downloaded_at, client_addr, peer_addr,
	code_submitted_at, probes, rejected_codes`

// Offer returns the offer with this ID hash, or ErrOfferNotFound.
func (db *DB) Offer(idHash [offerHashLen]byte) (Offer, error) {
	var (
		o                         Offer
		id, salt, session, script []byte
		netbird                   int
		created, expires, changed int64
		state                     string
		downloaded, submitted     sql.NullInt64
		client, peer              sql.NullString
		probes, rejected          int64
	)
	err := db.sql.QueryRow(`SELECT `+offerColumns+` FROM enroll_offers WHERE id_hash = ?`, idHash[:]).Scan(
		&id, &salt, &o.HostID, &o.SSHUser, &o.CredentialRef, &session, &netbird, &created,
		&expires, &state, &changed, &script, &downloaded, &client, &peer,
		&submitted, &probes, &rejected)
	if errors.Is(err, sql.ErrNoRows) {
		return Offer{}, fmt.Errorf("executordb: offer %s: %w", offerLogID(idHash), ErrOfferNotFound)
	}
	if err != nil {
		return Offer{}, fmt.Errorf("executordb: offer %s: %w", offerLogID(idHash), err)
	}
	if len(id) != offerHashLen || len(session) != offerHashLen ||
		(salt != nil && len(salt) != offerSaltLen) || (script != nil && len(script) != offerHashLen) {
		return Offer{}, fmt.Errorf("executordb: offer %s: stored hash or salt has the wrong length", offerLogID(idHash))
	}
	o.State = OfferState(state)
	if !o.State.known() {
		return Offer{}, fmt.Errorf("executordb: offer %s: unknown stored state %q", offerLogID(idHash), state)
	}
	copy(o.IDHash[:], id)
	copy(o.SessionHash[:], session)
	o.Salt, o.ScriptSHA256 = salt, script
	o.NetBird = netbird == 1
	o.CreatedAt, o.ExpiresAt, o.StateChangedAt = time.Unix(created, 0), time.Unix(expires, 0), time.Unix(changed, 0)
	if downloaded.Valid {
		o.DownloadedAt = time.Unix(downloaded.Int64, 0)
	}
	if submitted.Valid {
		o.CodeSubmittedAt = time.Unix(submitted.Int64, 0)
	}
	o.ClientAddr, o.PeerAddr = client.String, peer.String
	o.Probes, o.RejectedCodes = int(probes), int(rejected)
	return o, nil
}

// OpenOffer moves a NetBird offer from awaiting_approval to open and
// records the SHA-256 of its full render, in one compare-and-set. It fails
// with ErrOfferExpired once the offer's lifetime is over.
func (db *DB) OpenOffer(idHash, scriptSHA256 [offerHashLen]byte) error {
	if scriptSHA256 == zeroHash {
		return fmt.Errorf("executordb: %w: offer script hash is required", ErrInvalid)
	}
	now := db.now().Unix()
	return db.offerCAS(idHash, "open offer", now, true, OfferAwaitingApproval, nil, `UPDATE enroll_offers
		SET state = 'open', state_changed_at = ?, script_sha256 = ?
		WHERE id_hash = ? AND state = 'awaiting_approval' AND expires_at > ?`,
		now, scriptSHA256[:], idHash[:], now)
}

// ClaimOfferDownload is the single-use download claim: it moves the offer
// from open to downloaded and records the time and the client and peer
// addresses, in one compare-and-set. Of concurrent claims exactly one
// succeeds; the others get ErrOfferState. Addresses must be IP literals
// without zone; they are stored in canonical form.
func (db *DB) ClaimOfferDownload(idHash [offerHashLen]byte, clientAddr, peerAddr string) error {
	client, err := offerAddr("client address", clientAddr)
	if err != nil {
		return err
	}
	peer, err := offerAddr("peer address", peerAddr)
	if err != nil {
		return err
	}
	now := db.now().Unix()
	return db.offerCAS(idHash, "claim offer download", now, true, OfferOpen, nil, `UPDATE enroll_offers
		SET state = 'downloaded', state_changed_at = ?, downloaded_at = ?, client_addr = ?, peer_addr = ?
		WHERE id_hash = ? AND state = 'open' AND expires_at > ?`,
		now, now, client, peer, idHash[:], now)
}

// ClaimOfferSubmission accepts the one well-formed code submission of a
// downloaded offer (ADR 0013 D3). Of concurrent claims exactly one
// succeeds; the others, and every later one, get ErrOfferState. An offer
// with OfferMaxRejectedCodes rejected submissions accepts none any more
// (ErrOfferLimit), even if the caller has not ended it yet.
func (db *DB) ClaimOfferSubmission(idHash [offerHashLen]byte) error {
	now := db.now().Unix()
	return db.offerCAS(idHash, "claim offer submission", now, true, OfferDownloaded,
		func(o Offer) bool { return o.CodeSubmittedAt.IsZero() && o.RejectedCodes >= OfferMaxRejectedCodes },
		`UPDATE enroll_offers
		SET code_submitted_at = ?
		WHERE id_hash = ? AND state = 'downloaded' AND code_submitted_at IS NULL
		  AND rejected_codes < ? AND expires_at > ?`,
		now, idHash[:], OfferMaxRejectedCodes, now)
}

// CountOfferProbe counts one probe for the submitted code of a downloaded
// offer and returns the new count. It fails with ErrOfferLimit once
// OfferMaxProbes probes were counted, without changing anything.
func (db *DB) CountOfferProbe(idHash [offerHashLen]byte) (int, error) {
	now := db.now().Unix()
	return db.offerCount(idHash, "count offer probe", now, `UPDATE enroll_offers
		SET probes = probes + 1
		WHERE id_hash = ? AND state = 'downloaded' AND code_submitted_at IS NOT NULL
		  AND probes < ? AND expires_at > ?
		RETURNING probes`,
		func(o Offer) bool { return !o.CodeSubmittedAt.IsZero() && o.Probes >= OfferMaxProbes },
		idHash[:], OfferMaxProbes, now)
}

// CountOfferRejectedCode counts one malformed code submission of a
// downloaded offer whose code is not yet submitted, and returns the new
// count. It fails with ErrOfferLimit once OfferMaxRejectedCodes were
// counted, without changing anything.
func (db *DB) CountOfferRejectedCode(idHash [offerHashLen]byte) (int, error) {
	now := db.now().Unix()
	return db.offerCount(idHash, "count rejected code", now, `UPDATE enroll_offers
		SET rejected_codes = rejected_codes + 1
		WHERE id_hash = ? AND state = 'downloaded' AND code_submitted_at IS NULL
		  AND rejected_codes < ? AND expires_at > ?
		RETURNING rejected_codes`,
		func(o Offer) bool { return o.CodeSubmittedAt.IsZero() && o.RejectedCodes >= OfferMaxRejectedCodes },
		idHash[:], OfferMaxRejectedCodes, now)
}

// ProposeOfferPairing moves a downloaded offer whose code was submitted
// and matched to pairing_proposed, in one compare-and-set, before expiry.
// The match comes from a probe, and every probe is counted before it runs
// (CountOfferProbe): an offer without a counted probe is refused
// (ErrOfferState), and so is one whose counters are outside their limits
// (ErrOfferLimit; the CHECK constraints make that unreachable through the
// store). A proposal at exactly OfferMaxProbes is the result of the last
// allowed probe and is accepted.
func (db *DB) ProposeOfferPairing(idHash [offerHashLen]byte) error {
	now := db.now().Unix()
	return db.offerCAS(idHash, "propose offer pairing", now, true, OfferDownloaded,
		func(o Offer) bool { return o.Probes > OfferMaxProbes || o.RejectedCodes > OfferMaxRejectedCodes },
		`UPDATE enroll_offers
		SET state = 'pairing_proposed', state_changed_at = ?
		WHERE id_hash = ? AND state = 'downloaded' AND code_submitted_at IS NOT NULL
		  AND probes BETWEEN 1 AND ? AND rejected_codes <= ? AND expires_at > ?`,
		now, idHash[:], OfferMaxProbes, OfferMaxRejectedCodes, now)
}

// CompleteOffer moves an offer from pairing_proposed to enrolled and wipes
// its salt, in one compare-and-set, and removes the old salt from the WAL
// before it returns (purgeWipedSalt). The approval started before the
// offer's expiry and its permit's lifetime governs the commit (ADR 0013
// D2); the store still refuses with ErrOfferExpired once the offer is
// OfferProposedGrace or more past its expiry, the bound at which the
// expiry sweep ends it, so a late commit does not depend on the sweep
// having run.
func (db *DB) CompleteOffer(idHash [offerHashLen]byte) error {
	now := db.now().Unix()
	cutoff := now - proposedGraceSeconds
	if err := db.offerCAS(idHash, "complete offer", cutoff, true, OfferPairingProposed, nil, `UPDATE enroll_offers
		SET state = 'enrolled', state_changed_at = ?, salt = NULL
		WHERE id_hash = ? AND state = 'pairing_proposed' AND expires_at > ?`,
		now, idHash[:], cutoff); err != nil {
		return err
	}
	return db.purgeWipedSalt("complete offer")
}

// EndOffer moves an offer from the non-final state from to the final state
// to (expired, revoked or failed) and wipes its salt, in one
// compare-and-set, and removes the old salt from the WAL before it returns
// (purgeWipedSalt). If the offer is no longer in from, nothing changes and
// ErrOfferState is returned; the caller re-reads the offer and decides
// again (a revoke racing a download, for example).
func (db *DB) EndOffer(idHash [offerHashLen]byte, from, to OfferState) error {
	if !from.known() || from.Final() {
		return fmt.Errorf("executordb: %w: offer can only end from a non-final state, not %q", ErrInvalid, from)
	}
	if to != OfferExpired && to != OfferRevoked && to != OfferFailed {
		return fmt.Errorf("executordb: %w: offer can only end as expired, revoked or failed, not %q", ErrInvalid, to)
	}
	now := db.now().Unix()
	if err := db.offerCAS(idHash, "end offer", now, false, from, nil, `UPDATE enroll_offers
		SET state = ?, state_changed_at = ?, salt = NULL
		WHERE id_hash = ? AND state = ?`,
		string(to), now, idHash[:], string(from)); err != nil {
		return err
	}
	return db.purgeWipedSalt("end offer")
}

// ExpireOffers is the expiry sweep: every offer in awaiting_approval, open
// or downloaded whose lifetime is over, and every offer in
// pairing_proposed more than OfferProposedGrace past its expiry, moves to
// expired and loses its salt, in one statement; the old salts are removed
// from the WAL before it returns (purgeWipedSalt). One call ends at most
// maxSweptOffers offers, those that expired first; the next call ends the
// rest.
//
// It returns the ID hashes of the offers it expired, for audit, and no
// offer ends without its ID being returned (review en05af2, finding 2):
// the IDs are read inside the transaction, before the commit, and a failed
// read rolls the sweep back. If the commit itself reports an error, the
// sweep cannot know whether it happened, so it returns the IDs with the
// error and purges anyway; if it did not happen, the next sweep returns
// the same IDs again. The IDs also come with ErrOfferWipeIncomplete.
func (db *DB) ExpireOffers() ([][offerHashLen]byte, error) {
	now := db.now().Unix()
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("executordb: expire offers: %w", err)
	}
	rows, err := tx.Query(`UPDATE enroll_offers
		SET state = 'expired', state_changed_at = ?, salt = NULL
		WHERE id_hash IN (SELECT id_hash FROM enroll_offers
			WHERE (state IN ('awaiting_approval', 'open', 'downloaded') AND expires_at <= ?)
			   OR (state = 'pairing_proposed' AND expires_at <= ?)
			ORDER BY expires_at, id_hash LIMIT ?)
		RETURNING id_hash`,
		now, now, now-proposedGraceSeconds, maxSweptOffers)
	if err != nil {
		return nil, rollbackSweep(tx, err)
	}
	out, err := scanExpiredOffers(rows)
	if err == nil && len(out) > maxSweptOffers {
		err = fmt.Errorf("sweep read %d IDs, more than %d", len(out), maxSweptOffers)
	}
	if err != nil {
		rows.Close()
		return nil, rollbackSweep(tx, err)
	}
	// rows is closed, so after the commit the single connection is free
	// for the checkpoint.
	if err := commitSweep(tx); err != nil {
		err = fmt.Errorf("executordb: expire offers: commit: %w", err)
		if perr := db.purgeWipedSalt("expire offers"); perr != nil {
			return out, errors.Join(err, perr)
		}
		return out, err
	}
	if len(out) > 0 {
		if err := db.purgeWipedSalt("expire offers"); err != nil {
			return out, err
		}
	}
	return out, nil
}

// maxSweptOffers bounds how many offers one expiry sweep ends, and so how
// many IDs it reads before it commits. It is far above OfferMaxLive +
// OfferMaxLiveNetBird, so with the real limits one sweep ends every due
// offer.
const maxSweptOffers = 64

// rollbackSweep rolls the expiry sweep back after err; nothing it changed
// is committed.
func rollbackSweep(tx *sql.Tx, err error) error {
	if rerr := tx.Rollback(); rerr != nil {
		err = errors.Join(err, fmt.Errorf("rollback: %w", rerr))
	}
	return fmt.Errorf("executordb: expire offers: %w", err)
}

// scanExpiredOffers reads the expiry sweep's RETURNING rows; tests replace
// it to fail after the rows were read.
var scanExpiredOffers = scanOfferIDs

// commitSweep commits the expiry sweep; tests replace it to report an
// error after (or instead of) the commit.
var commitSweep = (*sql.Tx).Commit

// scanOfferIDs reads rows of ID hashes and closes rows.
func scanOfferIDs(rows *sql.Rows) ([][offerHashLen]byte, error) {
	defer rows.Close()
	var out [][offerHashLen]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if len(id) != offerHashLen {
			return nil, fmt.Errorf("stored ID hash has %d bytes", len(id))
		}
		out = append(out, [offerHashLen]byte(id))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return out, nil
}

// purgeWipedSalt removes a salt that a just-committed wipe set to NULL
// from every on-disk file before the wiping call returns (review en05a,
// finding 1). secure_delete (executordb.go) zeroes the old cell content in
// the new page image, but the WAL frames written while the offer was live
// still hold the salt in the -wal file. A TRUNCATE checkpoint copies the
// current page images (without the salt) into the main file, syncs it and
// truncates the -wal file to zero bytes.
//
// A checkpoint can only be blocked by a reader on another connection that
// still needs the old frames. There is none: the pool has a single
// connection, so an in-process reader holds that connection and the
// wiping call waits for it before it commits or checkpoints, and the
// exclusive locking mode keeps every other process out of the file. If the
// checkpoint still reports busy, the call fails with
// ErrOfferWipeIncomplete. A crash between the commit and the checkpoint
// leaves the salt in the WAL until the next Open, which checkpoints the
// same way before it returns. Outside this guarantee is everything below
// the file interface: blocks freed by the truncate, and copies kept by the
// storage device or by a file-system snapshot or backup taken while the
// offer was live.
func (db *DB) purgeWipedSalt(what string) error {
	if err := checkpointTruncate(db.sql); err != nil {
		return fmt.Errorf("executordb: %s: %w: %w", what, ErrOfferWipeIncomplete, err)
	}
	return nil
}

// offerCAS runs one compare-and-set UPDATE. When it changed no row, it
// reads the offer to report why: ErrOfferNotFound, ErrOfferExpired (when
// checkExpiry and the offer is still in the expected state but its expiry
// is at or before cutoff), ErrOfferLimit (when atLimit holds for an offer
// in the expected state) or ErrOfferState. The read only explains a
// refusal; it never leads to a change.
func (db *DB) offerCAS(idHash [offerHashLen]byte, what string, cutoff int64, checkExpiry bool, expected OfferState, atLimit func(Offer) bool, query string, args ...any) error {
	res, err := db.sql.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	if n == 1 {
		return nil
	}
	o, err := db.Offer(idHash)
	if err != nil {
		return fmt.Errorf("executordb: %s: %w", what, err)
	}
	if checkExpiry && o.State == expected && o.ExpiresAt.Unix() <= cutoff {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), ErrOfferExpired)
	}
	if atLimit != nil && o.State == expected && atLimit(o) {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), ErrOfferLimit)
	}
	return fmt.Errorf("executordb: %s %s: %s: %w", what, offerLogID(idHash), o.State, ErrOfferState)
}

// offerCount runs one counter compare-and-set (an UPDATE ... RETURNING the
// new count) on a downloaded offer. When it changed no row, it reads the
// offer to report why: ErrOfferLimit when atLimit holds for a downloaded
// offer, otherwise as offerCAS.
func (db *DB) offerCount(idHash [offerHashLen]byte, what string, now int64, query string, atLimit func(Offer) bool, args ...any) (int, error) {
	var count int
	err := db.sql.QueryRow(query, args...).Scan(&count)
	if err == nil {
		return count, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), err)
	}
	o, err := db.Offer(idHash)
	if err != nil {
		return 0, fmt.Errorf("executordb: %s: %w", what, err)
	}
	switch {
	case o.State != OfferDownloaded:
		return 0, fmt.Errorf("executordb: %s %s: %s: %w", what, offerLogID(idHash), o.State, ErrOfferState)
	case o.ExpiresAt.Unix() <= now:
		return 0, fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), ErrOfferExpired)
	case atLimit(o):
		return 0, fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), ErrOfferLimit)
	}
	return 0, fmt.Errorf("executordb: %s %s: %s: %w", what, offerLogID(idHash), o.State, ErrOfferState)
}

// offerAddr validates an address from the download path and returns its
// canonical form (IPv4-mapped IPv6 unmapped).
func offerAddr(field, s string) (string, error) {
	if s == "" || len(s) > maxOfferAddrLen {
		return "", fmt.Errorf("executordb: %w: %s length %d outside 1..%d", ErrInvalid, field, len(s), maxOfferAddrLen)
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", fmt.Errorf("executordb: %w: %s is not an IP address without zone", ErrInvalid, field)
	}
	return a.Unmap().String(), nil
}

// offerLogID is the only form in which an offer appears in errors and
// logs: the first 8 hex characters of its ID hash (ADR 0013 D2).
func offerLogID(idHash [offerHashLen]byte) string {
	return fmt.Sprintf("%x", idHash[:4])
}
