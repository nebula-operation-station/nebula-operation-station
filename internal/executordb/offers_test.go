// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// offerClock is an injected, adjustable clock.
type offerClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *offerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *offerClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func openOfferDB(t *testing.T, dir string, clk *offerClock) *DB {
	t.Helper()
	db, err := open(dir, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func offerDB(t *testing.T) (*DB, *offerClock) {
	t.Helper()
	clk := &offerClock{t: t0}
	return openOfferDB(t, privateDir(t), clk), clk
}

func rand32(t *testing.T) [32]byte {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func newOffer(t *testing.T, netbird bool) NewOffer {
	t.Helper()
	n := NewOffer{
		IDHash:        rand32(t),
		Salt:          rand32(t),
		HostID:        "web-01",
		SSHUser:       "nebula",
		CredentialRef: "cred-web-01",
		SessionHash:   rand32(t),
		NetBird:       netbird,
	}
	if !netbird {
		n.ScriptSHA256 = sha256.Sum256([]byte("script"))
	}
	return n
}

func mustCreateOffer(t *testing.T, db *DB, netbird bool) NewOffer {
	t.Helper()
	n := newOffer(t, netbird)
	if _, err := db.CreateOffer(n); err != nil {
		t.Fatalf("create offer: %v", err)
	}
	return n
}

func mustOffer(t *testing.T, db *DB, id [32]byte) Offer {
	t.Helper()
	o, err := db.Offer(id)
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	return o
}

// offerIn creates an offer and drives it through the store API into state.
func offerIn(t *testing.T, db *DB, state OfferState) NewOffer {
	t.Helper()
	netbird := state == OfferAwaitingApproval
	n := mustCreateOffer(t, db, netbird)
	step := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("drive offer to %s: %v", state, err)
		}
	}
	switch state {
	case OfferAwaitingApproval, OfferOpen:
	case OfferDownloaded:
		step(db.ClaimOfferDownload(n.IDHash, "192.0.2.10", "127.0.0.1"))
	case OfferPairingProposed, OfferEnrolled:
		step(db.ClaimOfferDownload(n.IDHash, "192.0.2.10", "127.0.0.1"))
		step(db.ClaimOfferSubmission(n.IDHash))
		step(db.ProposeOfferPairing(n.IDHash))
		if state == OfferEnrolled {
			step(db.CompleteOffer(n.IDHash))
		}
	case OfferExpired, OfferRevoked, OfferFailed:
		step(db.EndOffer(n.IDHash, OfferOpen, state))
	default:
		t.Fatalf("unknown state %s", state)
	}
	if got := mustOffer(t, db, n.IDHash).State; got != state {
		t.Fatalf("offer in %s, want %s", got, state)
	}
	return n
}

var allOfferStates = []OfferState{
	OfferAwaitingApproval, OfferOpen, OfferDownloaded, OfferPairingProposed,
	OfferEnrolled, OfferExpired, OfferRevoked, OfferFailed,
}

func TestOfferMigrationShippedInOrder(t *testing.T) {
	ms := mustMigrations(t)
	idx := -1
	for i, m := range ms {
		if m.name == "0025_enroll_offers.sql" {
			idx = i
		}
	}
	if idx < 1 || ms[idx].version != 25 || ms[idx-1].version != 24 {
		t.Fatalf("offer migration not shipped as 0025 after 0024 (index %d)", idx)
	}
}

func TestCreateOfferStartsOpenOrAwaitingApproval(t *testing.T) {
	db, _ := offerDB(t)
	n := newOffer(t, false)
	o, err := db.CreateOffer(n)
	if err != nil {
		t.Fatal(err)
	}
	if o.State != OfferOpen || o.NetBird {
		t.Fatalf("plain offer: state %s netbird %v", o.State, o.NetBird)
	}
	if o.IDHash != n.IDHash || !bytes.Equal(o.Salt, n.Salt[:]) || o.SessionHash != n.SessionHash ||
		o.HostID != n.HostID || o.SSHUser != n.SSHUser || o.CredentialRef != n.CredentialRef ||
		!bytes.Equal(o.ScriptSHA256, n.ScriptSHA256[:]) {
		t.Fatalf("stored offer differs: %+v", o)
	}
	if !o.CreatedAt.Equal(t0) || !o.ExpiresAt.Equal(t0.Add(OfferLifetime)) || !o.StateChangedAt.Equal(t0) {
		t.Fatalf("times: created %v expires %v changed %v", o.CreatedAt, o.ExpiresAt, o.StateChangedAt)
	}
	if !o.DownloadedAt.IsZero() || o.ClientAddr != "" || o.PeerAddr != "" || !o.CodeSubmittedAt.IsZero() ||
		o.Probes != 0 || o.RejectedCodes != 0 {
		t.Fatalf("fresh offer has claims or counters: %+v", o)
	}

	nb, err := db.CreateOffer(newOffer(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if nb.State != OfferAwaitingApproval || !nb.NetBird || nb.ScriptSHA256 != nil {
		t.Fatalf("NetBird offer: state %s netbird %v hash %x", nb.State, nb.NetBird, nb.ScriptSHA256)
	}
}

func TestOfferUnknownIDNotFound(t *testing.T) {
	db, _ := offerDB(t)
	id := rand32(t)
	if _, err := db.Offer(id); !errors.Is(err, ErrOfferNotFound) {
		t.Fatalf("Offer: %v, want ErrOfferNotFound", err)
	}
	if err := db.ClaimOfferDownload(id, "192.0.2.1", "127.0.0.1"); !errors.Is(err, ErrOfferNotFound) {
		t.Fatalf("ClaimOfferDownload: %v, want ErrOfferNotFound", err)
	}
	if err := db.EndOffer(id, OfferOpen, OfferRevoked); !errors.Is(err, ErrOfferNotFound) {
		t.Fatalf("EndOffer: %v, want ErrOfferNotFound", err)
	}
}

func TestCreateOfferDuplicateIDRefused(t *testing.T) {
	db, _ := offerDB(t)
	n := mustCreateOffer(t, db, false)
	dup := newOffer(t, false)
	dup.IDHash = n.IDHash
	if _, err := db.CreateOffer(dup); !errors.Is(err, ErrOfferExists) {
		t.Fatalf("duplicate: %v, want ErrOfferExists", err)
	}
	if o := mustOffer(t, db, n.IDHash); !bytes.Equal(o.Salt, n.Salt[:]) {
		t.Fatal("duplicate create replaced the salt")
	}
}

func TestCreateOfferRejectsInvalidInput(t *testing.T) {
	db, _ := offerDB(t)
	cases := []struct {
		name string
		mod  func(*NewOffer)
	}{
		{"zero ID hash", func(n *NewOffer) { n.IDHash = [32]byte{} }},
		{"zero salt", func(n *NewOffer) { n.Salt = [32]byte{} }},
		{"zero session", func(n *NewOffer) { n.SessionHash = [32]byte{} }},
		{"empty host", func(n *NewOffer) { n.HostID = "" }},
		{"long host", func(n *NewOffer) { n.HostID = strings.Repeat("h", maxOfferHostIDLen+1) }},
		{"control in host", func(n *NewOffer) { n.HostID = "web\n01" }},
		{"empty user", func(n *NewOffer) { n.SSHUser = "" }},
		{"long user", func(n *NewOffer) { n.SSHUser = strings.Repeat("u", maxOfferSSHUserLen+1) }},
		{"bidi in user", func(n *NewOffer) { n.SSHUser = "root‮" }},
		{"invalid UTF-8 credential", func(n *NewOffer) { n.CredentialRef = "\xff" }},
		{"empty credential", func(n *NewOffer) { n.CredentialRef = "" }},
		{"long credential", func(n *NewOffer) { n.CredentialRef = strings.Repeat("c", maxOfferCredRefLen+1) }},
		{"plain offer without script hash", func(n *NewOffer) { n.ScriptSHA256 = [32]byte{} }},
		{"NetBird offer with script hash", func(n *NewOffer) { n.NetBird = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newOffer(t, false)
			tc.mod(&n)
			if _, err := db.CreateOffer(n); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
			if _, err := db.Offer(n.IDHash); !errors.Is(err, ErrOfferNotFound) {
				t.Fatalf("invalid offer was stored: %v", err)
			}
		})
	}
}

// offerOp is one state-changing store operation, tried in every state.
type offerOp struct {
	name string
	from OfferState // the only state in which it may succeed
	to   OfferState
	run  func(db *DB, id [32]byte) error
}

func offerOps() []offerOp {
	script := sha256.Sum256([]byte("netbird script"))
	ops := []offerOp{
		{"open", OfferAwaitingApproval, OfferOpen, func(db *DB, id [32]byte) error { return db.OpenOffer(id, script) }},
		{"download", OfferOpen, OfferDownloaded, func(db *DB, id [32]byte) error {
			return db.ClaimOfferDownload(id, "192.0.2.10", "127.0.0.1")
		}},
		{"propose", OfferDownloaded, OfferPairingProposed, func(db *DB, id [32]byte) error {
			if err := db.ClaimOfferSubmission(id); err != nil {
				return err
			}
			return db.ProposeOfferPairing(id)
		}},
		{"complete", OfferPairingProposed, OfferEnrolled, func(db *DB, id [32]byte) error { return db.CompleteOffer(id) }},
	}
	for _, to := range []OfferState{OfferExpired, OfferRevoked, OfferFailed} {
		for _, from := range allOfferStates {
			if from.Final() {
				continue
			}
			ops = append(ops, offerOp{"end " + string(from) + " as " + string(to), from, to,
				func(db *DB, id [32]byte) error { return db.EndOffer(id, from, to) }})
		}
	}
	return ops
}

// TestOfferTransitionsOnlyForward tries every operation in every state:
// it succeeds only in its one source state, and everywhere else it fails
// with ErrOfferState and changes nothing.
func TestOfferTransitionsOnlyForward(t *testing.T) {
	db, _ := offerDB(t)
	for _, op := range offerOps() {
		for _, state := range allOfferStates {
			t.Run(op.name+" in "+string(state), func(t *testing.T) {
				n := offerIn(t, db, state)
				before := mustOffer(t, db, n.IDHash)
				err := op.run(db, n.IDHash)
				after := mustOffer(t, db, n.IDHash)
				if state == op.from {
					if err != nil {
						t.Fatalf("allowed transition %s -> %s failed: %v", state, op.to, err)
					}
					if after.State != op.to {
						t.Fatalf("state %s, want %s", after.State, op.to)
					}
					return
				}
				if !errors.Is(err, ErrOfferState) {
					t.Fatalf("forbidden %s in %s: %v, want ErrOfferState", op.name, state, err)
				}
				if after.State != before.State || !bytes.Equal(after.Salt, before.Salt) ||
					!after.CodeSubmittedAt.Equal(before.CodeSubmittedAt) || !after.DownloadedAt.Equal(before.DownloadedAt) ||
					!bytes.Equal(after.ScriptSHA256, before.ScriptSHA256) {
					t.Fatalf("refused transition changed the offer: %+v -> %+v", before, after)
				}
			})
		}
	}
}

func TestEndOfferRejectsInvalidStates(t *testing.T) {
	db, _ := offerDB(t)
	n := offerIn(t, db, OfferOpen)
	for _, tc := range []struct{ from, to OfferState }{
		{OfferOpen, OfferEnrolled},
		{OfferOpen, OfferOpen},
		{OfferOpen, OfferDownloaded},
		{OfferOpen, "bogus"},
		{OfferExpired, OfferRevoked},
		{"bogus", OfferRevoked},
	} {
		if err := db.EndOffer(n.IDHash, tc.from, tc.to); !errors.Is(err, ErrInvalid) {
			t.Fatalf("EndOffer(%s, %s): %v, want ErrInvalid", tc.from, tc.to, err)
		}
	}
	if o := mustOffer(t, db, n.IDHash); o.State != OfferOpen {
		t.Fatalf("state %s after refused ends", o.State)
	}
}

// TestOfferSchemaRefusesBackwardTransitions bypasses the store: the
// triggers alone refuse every transition that is not forward.
func TestOfferSchemaRefusesBackwardTransitions(t *testing.T) {
	db, _ := offerDB(t)
	allowed := map[[2]OfferState]bool{
		{OfferAwaitingApproval, OfferOpen}:      true,
		{OfferOpen, OfferDownloaded}:            true,
		{OfferDownloaded, OfferPairingProposed}: true,
		{OfferPairingProposed, OfferEnrolled}:   true,
	}
	for _, from := range allOfferStates {
		for _, to := range allOfferStates {
			if from == to {
				continue
			}
			ok := allowed[[2]OfferState{from, to}] || (!from.Final() && to.Final() && to != OfferEnrolled)
			if ok {
				continue
			}
			n := offerIn(t, db, from)
			_, err := db.sql.Exec(`UPDATE enroll_offers SET state = ? WHERE id_hash = ?`, string(to), n.IDHash[:])
			if err == nil {
				t.Fatalf("schema allowed %s -> %s", from, to)
			}
			if got := mustOffer(t, db, n.IDHash).State; got != from {
				t.Fatalf("state changed to %s", got)
			}
		}
	}
}

func TestOfferSchemaKeepsSaltWipedAndFieldsFixed(t *testing.T) {
	db, _ := offerDB(t)
	live := offerIn(t, db, OfferOpen)
	final := offerIn(t, db, OfferRevoked)
	other := rand32(t)
	for _, tc := range []struct {
		name string
		q    string
		args []any
	}{
		{"final state without wiping salt", `UPDATE enroll_offers SET state = 'failed' WHERE id_hash = ?`, []any{live.IDHash[:]}},
		{"salt wiped while live", `UPDATE enroll_offers SET salt = NULL WHERE id_hash = ?`, []any{live.IDHash[:]}},
		{"salt replaced", `UPDATE enroll_offers SET salt = ? WHERE id_hash = ?`, []any{other[:], live.IDHash[:]}},
		{"salt restored on final offer", `UPDATE enroll_offers SET salt = ? WHERE id_hash = ?`, []any{other[:], final.IDHash[:]}},
		{"final offer changed", `UPDATE enroll_offers SET probes = 1 WHERE id_hash = ?`, []any{final.IDHash[:]}},
		{"host changed", `UPDATE enroll_offers SET host_id = 'other' WHERE id_hash = ?`, []any{live.IDHash[:]}},
		{"expiry extended", `UPDATE enroll_offers SET expires_at = expires_at + 3600 WHERE id_hash = ?`, []any{live.IDHash[:]}},
		{"script hash changed", `UPDATE enroll_offers SET script_sha256 = ? WHERE id_hash = ?`, []any{other[:], live.IDHash[:]}},
		{"script bytes in hash column", `UPDATE enroll_offers SET script_sha256 = ? WHERE id_hash = ?`, []any{[]byte(strings.Repeat("#!/bin/sh\n", 10)), live.IDHash[:]}},
		{"live offer deleted", `DELETE FROM enroll_offers WHERE id_hash = ?`, []any{live.IDHash[:]}},
	} {
		if _, err := db.sql.Exec(tc.q, tc.args...); err == nil {
			t.Errorf("%s: schema allowed it", tc.name)
		}
	}
	if o := mustOffer(t, db, live.IDHash); !bytes.Equal(o.Salt, live.Salt[:]) || o.State != OfferOpen {
		t.Fatal("live offer changed")
	}
}

// TestOfferFinalStatesWipeSalt checks every way into a final state.
func TestOfferFinalStatesWipeSalt(t *testing.T) {
	db, clk := offerDB(t)
	var ids [][32]byte
	for _, state := range allOfferStates {
		if state.Final() {
			ids = append(ids, offerIn(t, db, state).IDHash)
		}
	}
	for _, from := range []OfferState{OfferAwaitingApproval, OfferDownloaded, OfferPairingProposed} {
		n := offerIn(t, db, from)
		if err := db.EndOffer(n.IDHash, from, OfferFailed); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, n.IDHash)
	}
	swept := offerIn(t, db, OfferOpen)
	clk.Add(OfferLifetime)
	if _, err := db.ExpireOffers(); err != nil {
		t.Fatal(err)
	}
	ids = append(ids, swept.IDHash)
	for _, id := range ids {
		o := mustOffer(t, db, id)
		if !o.State.Final() || o.Salt != nil {
			t.Fatalf("offer %x in %s has salt %v", id[:4], o.State, o.Salt != nil)
		}
	}
}

// TestOfferWipedSaltNotOnDisk scans the database file, WAL and journal
// after the final state for the salt bytes.
func TestOfferWipedSaltNotOnDisk(t *testing.T) {
	dir := privateDir(t)
	clk := &offerClock{t: t0}
	db, err := open(dir, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	var salts [][32]byte
	for _, end := range []func(*DB, [32]byte) error{
		func(db *DB, id [32]byte) error { return db.EndOffer(id, OfferOpen, OfferRevoked) },
		func(db *DB, id [32]byte) error {
			if err := db.ClaimOfferDownload(id, "192.0.2.10", "127.0.0.1"); err != nil {
				return err
			}
			if err := db.ClaimOfferSubmission(id); err != nil {
				return err
			}
			if err := db.ProposeOfferPairing(id); err != nil {
				return err
			}
			return db.CompleteOffer(id)
		},
	} {
		// Live offers before and after on the same page, so the wiped
		// cell's old bytes are not simply overwritten by the new one.
		mustCreateOffer(t, db, false)
		n := mustCreateOffer(t, db, false)
		mustCreateOffer(t, db, false)
		salts = append(salts, n.Salt)
		if err := end(db, n.IDHash); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{FileName, FileName + "-wal", FileName + "-journal"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range salts {
			if bytes.Contains(b, s[:]) {
				t.Fatalf("wiped salt still in %s", name)
			}
		}
	}
}

func TestOfferParallelDownloadClaimsOneWins(t *testing.T) {
	db, _ := offerDB(t)
	n := offerIn(t, db, OfferOpen)
	const workers = 16
	errs := make([]error, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = db.ClaimOfferDownload(n.IDHash, "192.0.2.10", "127.0.0.1")
		}()
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrOfferState):
			t.Fatalf("losing claim: %v, want ErrOfferState", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d download claims won, want 1", wins)
	}
}

func TestOfferParallelSubmissionClaimsOneWins(t *testing.T) {
	db, _ := offerDB(t)
	n := offerIn(t, db, OfferDownloaded)
	const workers = 16
	errs := make([]error, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = db.ClaimOfferSubmission(n.IDHash)
		}()
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrOfferState):
			t.Fatalf("losing claim: %v, want ErrOfferState", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d submission claims won, want 1", wins)
	}
}

// TestOfferRevokeRacingDownload: of a revoke and a download started
// together exactly one takes effect.
func TestOfferRevokeRacingDownload(t *testing.T) {
	db, _ := offerDB(t)
	for range 20 {
		n := offerIn(t, db, OfferOpen)
		var dlErr, revErr error
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			dlErr = db.ClaimOfferDownload(n.IDHash, "192.0.2.10", "127.0.0.1")
		}()
		go func() {
			defer wg.Done()
			<-start
			revErr = db.EndOffer(n.IDHash, OfferOpen, OfferRevoked)
		}()
		close(start)
		wg.Wait()
		if (dlErr == nil) == (revErr == nil) {
			t.Fatalf("download %v, revoke %v: want exactly one to win", dlErr, revErr)
		}
		o := mustOffer(t, db, n.IDHash)
		if dlErr == nil && o.State != OfferDownloaded || revErr == nil && (o.State != OfferRevoked || o.Salt != nil) {
			t.Fatalf("state %s after race (download %v, revoke %v)", o.State, dlErr, revErr)
		}
	}
}

func TestOfferParallelProbeCountsStopAtLimit(t *testing.T) {
	db, _ := offerDB(t)
	n := offerIn(t, db, OfferDownloaded)
	if err := db.ClaimOfferSubmission(n.IDHash); err != nil {
		t.Fatal(err)
	}
	const workers = 12
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = db.CountOfferProbe(n.IDHash)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrOfferLimit):
			t.Fatalf("probe: %v, want ErrOfferLimit", err)
		}
	}
	if ok != OfferMaxProbes || mustOffer(t, db, n.IDHash).Probes != OfferMaxProbes {
		t.Fatalf("%d probes counted, want %d", ok, OfferMaxProbes)
	}
}

func TestOfferCounters(t *testing.T) {
	db, _ := offerDB(t)
	n := offerIn(t, db, OfferDownloaded)
	// Probes need a submitted code.
	if _, err := db.CountOfferProbe(n.IDHash); !errors.Is(err, ErrOfferState) {
		t.Fatalf("probe before submission: %v, want ErrOfferState", err)
	}
	for i := 1; i <= OfferMaxRejectedCodes; i++ {
		got, err := db.CountOfferRejectedCode(n.IDHash)
		if err != nil || got != i {
			t.Fatalf("rejected code %d: got %d, %v", i, got, err)
		}
	}
	if _, err := db.CountOfferRejectedCode(n.IDHash); !errors.Is(err, ErrOfferLimit) {
		t.Fatalf("rejected code over limit: %v, want ErrOfferLimit", err)
	}
	if err := db.ClaimOfferSubmission(n.IDHash); err != nil {
		t.Fatal(err)
	}
	// After the submission no malformed code is counted any more.
	if _, err := db.CountOfferRejectedCode(n.IDHash); !errors.Is(err, ErrOfferState) {
		t.Fatalf("rejected code after submission: %v, want ErrOfferState", err)
	}
	for i := 1; i <= OfferMaxProbes; i++ {
		got, err := db.CountOfferProbe(n.IDHash)
		if err != nil || got != i {
			t.Fatalf("probe %d: got %d, %v", i, got, err)
		}
	}
	if _, err := db.CountOfferProbe(n.IDHash); !errors.Is(err, ErrOfferLimit) {
		t.Fatalf("probe over limit: %v, want ErrOfferLimit", err)
	}
	o := mustOffer(t, db, n.IDHash)
	if o.Probes != OfferMaxProbes || o.RejectedCodes != OfferMaxRejectedCodes || o.State != OfferDownloaded {
		t.Fatalf("counters %d/%d state %s", o.Probes, o.RejectedCodes, o.State)
	}
	// Counters are refused outside downloaded.
	open := offerIn(t, db, OfferOpen)
	if _, err := db.CountOfferRejectedCode(open.IDHash); !errors.Is(err, ErrOfferState) {
		t.Fatalf("rejected code on open offer: %v, want ErrOfferState", err)
	}
}

func TestOfferDownloadRecordsAddresses(t *testing.T) {
	db, clk := offerDB(t)
	n := offerIn(t, db, OfferOpen)
	clk.Add(time.Minute)
	if err := db.ClaimOfferDownload(n.IDHash, "::ffff:192.0.2.7", "2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	o := mustOffer(t, db, n.IDHash)
	if o.ClientAddr != "192.0.2.7" || o.PeerAddr != "2001:db8::1" || !o.DownloadedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("download record: %q %q %v", o.ClientAddr, o.PeerAddr, o.DownloadedAt)
	}
}

func TestOfferDownloadRejectsBadAddresses(t *testing.T) {
	db, _ := offerDB(t)
	n := offerIn(t, db, OfferOpen)
	for _, tc := range [][2]string{
		{"", "127.0.0.1"},
		{"192.0.2.1", ""},
		{"192.0.2.1:443", "127.0.0.1"},
		{"example.org", "127.0.0.1"},
		{"192.0.2.1", "fe80::1%eth0"},
		{strings.Repeat("1", maxOfferAddrLen+1), "127.0.0.1"},
		{"192.0.2.1\n", "127.0.0.1"},
	} {
		if err := db.ClaimOfferDownload(n.IDHash, tc[0], tc[1]); !errors.Is(err, ErrInvalid) {
			t.Fatalf("addresses %q: %v, want ErrInvalid", tc, err)
		}
	}
	if o := mustOffer(t, db, n.IDHash); o.State != OfferOpen {
		t.Fatalf("state %s after refused claims", o.State)
	}
}

func TestOfferClaimsRefusedAfterExpiry(t *testing.T) {
	db, clk := offerDB(t)
	awaiting := offerIn(t, db, OfferAwaitingApproval)
	open := offerIn(t, db, OfferOpen)
	downloaded := offerIn(t, db, OfferDownloaded)
	submitted := offerIn(t, db, OfferDownloaded)
	if err := db.ClaimOfferSubmission(submitted.IDHash); err != nil {
		t.Fatal(err)
	}
	proposed := offerIn(t, db, OfferPairingProposed)
	clk.Add(OfferLifetime)

	for name, err := range map[string]error{
		"open":       db.OpenOffer(awaiting.IDHash, sha256.Sum256([]byte("s"))),
		"download":   db.ClaimOfferDownload(open.IDHash, "192.0.2.10", "127.0.0.1"),
		"submission": db.ClaimOfferSubmission(downloaded.IDHash),
		"propose":    db.ProposeOfferPairing(submitted.IDHash),
	} {
		if !errors.Is(err, ErrOfferExpired) {
			t.Errorf("%s after expiry: %v, want ErrOfferExpired", name, err)
		}
	}
	if _, err := db.CountOfferRejectedCode(downloaded.IDHash); !errors.Is(err, ErrOfferExpired) {
		t.Errorf("rejected code after expiry: %v, want ErrOfferExpired", err)
	}
	if _, err := db.CountOfferProbe(submitted.IDHash); !errors.Is(err, ErrOfferExpired) {
		t.Errorf("probe after expiry: %v, want ErrOfferExpired", err)
	}
	// An approval that started before expiry may still be committed.
	if err := db.CompleteOffer(proposed.IDHash); err != nil {
		t.Fatalf("complete after expiry: %v", err)
	}
	// A minute before expiry everything still worked: checked by the other
	// tests, which run at t0.
}

func TestExpireOffersSweep(t *testing.T) {
	db, clk := offerDB(t)
	early := map[OfferState]NewOffer{}
	for _, s := range []OfferState{OfferAwaitingApproval, OfferOpen, OfferDownloaded, OfferPairingProposed} {
		early[s] = offerIn(t, db, s)
	}
	done := offerIn(t, db, OfferEnrolled)
	clk.Add(time.Minute)
	late := offerIn(t, db, OfferOpen)

	clk.Add(OfferLifetime - time.Minute - time.Second)
	if got, err := db.ExpireOffers(); err != nil || len(got) != 0 {
		t.Fatalf("sweep before expiry: %d expired, %v", len(got), err)
	}
	clk.Add(time.Second)
	got, err := db.ExpireOffers()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("sweep expired %d offers, want 3", len(got))
	}
	expired := map[[32]byte]bool{}
	for _, id := range got {
		expired[id] = true
	}
	for _, s := range []OfferState{OfferAwaitingApproval, OfferOpen, OfferDownloaded} {
		o := mustOffer(t, db, early[s].IDHash)
		if !expired[o.IDHash] || o.State != OfferExpired || o.Salt != nil || !o.StateChangedAt.Equal(clk.Now()) {
			t.Fatalf("%s offer after sweep: state %s salt %v", s, o.State, o.Salt != nil)
		}
	}
	if o := mustOffer(t, db, early[OfferPairingProposed].IDHash); o.State != OfferPairingProposed || o.Salt == nil {
		t.Fatalf("proposed offer swept within its grace: %s", o.State)
	}
	if o := mustOffer(t, db, late.IDHash); o.State != OfferOpen {
		t.Fatalf("unexpired offer swept: %s", o.State)
	}
	if o := mustOffer(t, db, done.IDHash); o.State != OfferEnrolled {
		t.Fatalf("final offer swept: %s", o.State)
	}
	if got, err := db.ExpireOffers(); err != nil || len(got) != 0 {
		t.Fatalf("second sweep: %d expired, %v", len(got), err)
	}

	clk.Add(OfferProposedGrace)
	got, err = db.ExpireOffers()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("sweep after grace expired %d offers, want 2 (proposed and late)", len(got))
	}
	if o := mustOffer(t, db, early[OfferPairingProposed].IDHash); o.State != OfferExpired || o.Salt != nil {
		t.Fatalf("proposed offer after grace: %s", o.State)
	}
	if err := db.CompleteOffer(early[OfferPairingProposed].IDHash); !errors.Is(err, ErrOfferState) {
		t.Fatalf("complete after sweep: %v, want ErrOfferState", err)
	}
}

func TestOfferStateSurvivesRestart(t *testing.T) {
	dir := privateDir(t)
	clk := &offerClock{t: t0}
	db, err := open(dir, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	n := mustCreateOffer(t, db, false)
	if err := db.ClaimOfferDownload(n.IDHash, "192.0.2.10", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := db.ClaimOfferSubmission(n.IDHash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CountOfferProbe(n.IDHash); err != nil {
		t.Fatal(err)
	}
	revoked := mustCreateOffer(t, db, false)
	if err := db.EndOffer(revoked.IDHash, OfferOpen, OfferRevoked); err != nil {
		t.Fatal(err)
	}
	before := mustOffer(t, db, n.IDHash)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db2 := openOfferDB(t, dir, clk)
	after := mustOffer(t, db2, n.IDHash)
	if after.State != OfferDownloaded || !bytes.Equal(after.Salt, n.Salt[:]) || after.ClientAddr != before.ClientAddr ||
		!after.CodeSubmittedAt.Equal(before.CodeSubmittedAt) || after.Probes != 1 {
		t.Fatalf("offer after restart: %+v", after)
	}
	// The single-use claims stay spent across the restart.
	if err := db2.ClaimOfferDownload(n.IDHash, "192.0.2.10", "127.0.0.1"); !errors.Is(err, ErrOfferState) {
		t.Fatalf("second download after restart: %v, want ErrOfferState", err)
	}
	if err := db2.ClaimOfferSubmission(n.IDHash); !errors.Is(err, ErrOfferState) {
		t.Fatalf("second submission after restart: %v, want ErrOfferState", err)
	}
	if o := mustOffer(t, db2, revoked.IDHash); o.State != OfferRevoked || o.Salt != nil {
		t.Fatalf("revoked offer after restart: %s salt %v", o.State, o.Salt != nil)
	}
}

// TestOfferErrorsCarryNoSecret: errors name an offer only by the 8-hex
// prefix of its ID hash, never the salt or the full hash.
func TestOfferErrorsCarryNoSecret(t *testing.T) {
	db, _ := offerDB(t)
	n := offerIn(t, db, OfferRevoked)
	err := db.ClaimOfferDownload(n.IDHash, "192.0.2.10", "127.0.0.1")
	if err == nil {
		t.Fatal("download of revoked offer succeeded")
	}
	msg := err.Error()
	full := hex.EncodeToString(n.IDHash[:])
	if strings.Contains(msg, full) || strings.Contains(msg, hex.EncodeToString(n.Salt[:])) || !strings.Contains(msg, full[:8]) {
		t.Fatalf("error %q", msg)
	}
}
