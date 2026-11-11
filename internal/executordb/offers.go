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
	// ErrOfferLimit: a per-offer counter reached its limit; nothing was
	// changed.
	ErrOfferLimit = errors.New("executordb: enrollment offer limit reached")
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
// offer in open.
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
	res, err := db.sql.Exec(`INSERT INTO enroll_offers (id_hash, salt, host_id, ssh_user, credential_ref,
			session_hash, netbird, created_at, expires_at, state, state_changed_at, script_sha256)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id_hash) DO NOTHING`,
		n.IDHash[:], n.Salt[:], n.HostID, n.SSHUser, n.CredentialRef, n.SessionHash[:], boolInt(n.NetBird),
		now, now+int64(OfferLifetime/time.Second), string(state), now, script)
	if err != nil {
		return Offer{}, fmt.Errorf("executordb: create offer %s: %w", offerLogID(n.IDHash), err)
	}
	if k, err := res.RowsAffected(); err != nil {
		return Offer{}, fmt.Errorf("executordb: create offer %s: %w", offerLogID(n.IDHash), err)
	} else if k == 0 {
		return Offer{}, fmt.Errorf("executordb: create offer %s: %w", offerLogID(n.IDHash), ErrOfferExists)
	}
	return db.Offer(n.IDHash)
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
	return db.offerCAS(idHash, "open offer", now, true, OfferAwaitingApproval, `UPDATE enroll_offers
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
	return db.offerCAS(idHash, "claim offer download", now, true, OfferOpen, `UPDATE enroll_offers
		SET state = 'downloaded', state_changed_at = ?, downloaded_at = ?, client_addr = ?, peer_addr = ?
		WHERE id_hash = ? AND state = 'open' AND expires_at > ?`,
		now, now, client, peer, idHash[:], now)
}

// ClaimOfferSubmission accepts the one well-formed code submission of a
// downloaded offer (ADR 0013 D3). Of concurrent claims exactly one
// succeeds; the others, and every later one, get ErrOfferState.
func (db *DB) ClaimOfferSubmission(idHash [offerHashLen]byte) error {
	now := db.now().Unix()
	return db.offerCAS(idHash, "claim offer submission", now, true, OfferDownloaded, `UPDATE enroll_offers
		SET code_submitted_at = ?
		WHERE id_hash = ? AND state = 'downloaded' AND code_submitted_at IS NULL AND expires_at > ?`,
		now, idHash[:], now)
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
func (db *DB) ProposeOfferPairing(idHash [offerHashLen]byte) error {
	now := db.now().Unix()
	return db.offerCAS(idHash, "propose offer pairing", now, true, OfferDownloaded, `UPDATE enroll_offers
		SET state = 'pairing_proposed', state_changed_at = ?
		WHERE id_hash = ? AND state = 'downloaded' AND code_submitted_at IS NOT NULL AND expires_at > ?`,
		now, idHash[:], now)
}

// CompleteOffer moves an offer from pairing_proposed to enrolled and wipes
// its salt, in one compare-and-set. The offer's own expiry is not checked
// here: the approval started before it, and its permit's lifetime governs
// the commit (ADR 0013 D2).
func (db *DB) CompleteOffer(idHash [offerHashLen]byte) error {
	now := db.now().Unix()
	return db.offerCAS(idHash, "complete offer", now, false, OfferPairingProposed, `UPDATE enroll_offers
		SET state = 'enrolled', state_changed_at = ?, salt = NULL
		WHERE id_hash = ? AND state = 'pairing_proposed'`,
		now, idHash[:])
}

// EndOffer moves an offer from the non-final state from to the final state
// to (expired, revoked or failed) and wipes its salt, in one
// compare-and-set. If the offer is no longer in from, nothing changes and
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
	return db.offerCAS(idHash, "end offer", now, false, from, `UPDATE enroll_offers
		SET state = ?, state_changed_at = ?, salt = NULL
		WHERE id_hash = ? AND state = ?`,
		string(to), now, idHash[:], string(from))
}

// ExpireOffers is the expiry sweep: every offer in awaiting_approval, open
// or downloaded whose lifetime is over, and every offer in
// pairing_proposed more than OfferProposedGrace past its expiry, moves to
// expired and loses its salt, in one statement. It returns the ID hashes
// of the offers it expired, for audit.
func (db *DB) ExpireOffers() ([][offerHashLen]byte, error) {
	now := db.now().Unix()
	rows, err := db.sql.Query(`UPDATE enroll_offers
		SET state = 'expired', state_changed_at = ?, salt = NULL
		WHERE (state IN ('awaiting_approval', 'open', 'downloaded') AND expires_at <= ?)
		   OR (state = 'pairing_proposed' AND expires_at <= ?)
		RETURNING id_hash`,
		now, now, now-int64(OfferProposedGrace/time.Second))
	if err != nil {
		return nil, fmt.Errorf("executordb: expire offers: %w", err)
	}
	defer rows.Close()
	var out [][offerHashLen]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("executordb: expire offers: %w", err)
		}
		if len(id) != offerHashLen {
			return nil, fmt.Errorf("executordb: expire offers: stored ID hash has %d bytes", len(id))
		}
		out = append(out, [offerHashLen]byte(id))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: expire offers: %w", err)
	}
	return out, nil
}

// offerCAS runs one compare-and-set UPDATE. When it changed no row, it
// reads the offer to report why: ErrOfferNotFound, ErrOfferExpired (when
// checkExpiry and the offer is still in the expected state but past its
// expiry) or ErrOfferState. The read only explains a refusal; it never
// leads to a change.
func (db *DB) offerCAS(idHash [offerHashLen]byte, what string, now int64, checkExpiry bool, expected OfferState, query string, args ...any) error {
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
	if checkExpiry && o.State == expected && o.ExpiresAt.Unix() <= now {
		return fmt.Errorf("executordb: %s %s: %w", what, offerLogID(idHash), ErrOfferExpired)
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
