// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Schedule grants (docs/implementation/schedule-grants.md, decision 5 of
// the M6 plan): a standing permission, approved with a user-verified
// assertion (or the CLI in hardened mode), to run fixed actions that the
// executor rates LOW on fixed hosts, at most once per interval, until it
// expires or is revoked. Unlike permits, approved grants are persisted
// (ScheduleStore) and survive a restart; pending ones do not.

// StoredGrant is an approved schedule grant.
type StoredGrant struct {
	ID         string
	Digest     string
	Doc        []byte // canonical document
	ApprovedBy string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time // zero while active
}

// ScheduleStore persists approved grants and the last run of each action
// on each host (internal/executordb implements it).
type ScheduleStore interface {
	SaveScheduleGrant(g StoredGrant) error
	ScheduleGrant(id string) (StoredGrant, bool, error)
	ScheduleGrants() ([]StoredGrant, error)
	// RevokeScheduleGrant marks a grant revoked; false if it is unknown or
	// was revoked before.
	RevokeScheduleGrant(id string, at time.Time) (bool, error)
	// ClaimScheduleRun records a run of actionID on hostID under the grant
	// at now if the last one is at least minInterval ago, atomically.
	ClaimScheduleRun(grantID, actionID, hostID string, now time.Time, minInterval time.Duration) (bool, error)
}

// Schedule failure codes.
const (
	CodeScheduleUnavailable Code = "schedule_grants_unavailable"
	CodeGrantInvalid        Code = "schedule_grant_invalid"
	CodeGrantInactive       Code = "schedule_grant_inactive"
	CodeGrantNotCovered     Code = "schedule_grant_does_not_cover"
	CodeTooSoon             Code = "schedule_interval_not_elapsed"
)

// MaxPendingGrants bounds proposed, unapproved grants.
const MaxPendingGrants = 16

type pendingGrant struct {
	doc       schedgrant.Doc
	canon     []byte
	digest    string
	challenge []byte
	expiry    time.Time
}

// PendingGrant describes a proposed grant.
type PendingGrant struct {
	Digest      string
	Canonical   []byte
	Requirement Requirement
	Challenge   []byte
	Expiry      time.Time
	Doc         schedgrant.Doc
}

func scheduleChallengeFor(digest string, expiry time.Time) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("permit: nonce: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("nebula-schedule-grant-v1\x00"))
	h.Write([]byte(digest))
	h.Write(nonce[:])
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiry.Unix()))
	h.Write(exp[:])
	return h.Sum(nil), nil
}

// lowEverywhere checks that the executor rates an action LOW on every
// target. Shared by schedule grants and read grants.
func (a *Authority) lowEverywhere(actionID, version, artifactSHA256 string, targets []canonical.Target) error {
	r := canonical.Request{ActionID: actionID, ModuleVersion: version, ArtifactSHA256: artifactSHA256}
	for _, t := range targets {
		floor, why, err := a.floor(r, []canonical.Target{t}, nil)
		if err != nil || floor.Rank() == 0 {
			return a.storageFailure("", fmt.Errorf("risk policy: %v (floor %q)", err, floor))
		}
		if floor != canonical.RiskLow {
			a.emit(Event{Kind: "rejected", Host: t.HostID, Code: CodeGrantInvalid, Detail: actionID + ": " + string(floor) + " (" + why + ")"})
			return fail(CodeGrantInvalid, "%s@%s is %s on %s, not LOW: only actions the executor trusts as LOW (read-only) can be granted",
				actionID, version, floor, t.HostID)
		}
	}
	return nil
}

// ProposeScheduleGrant checks a grant document and holds it for approval.
// It needs the privileged session.
func (a *Authority) ProposeScheduleGrant(raw []byte) (PendingGrant, error) {
	if a.schedules == nil {
		return PendingGrant{}, fail(CodeScheduleUnavailable, "")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcGrantsLocked(now)
	if !a.sessionActiveLocked(now) {
		return PendingGrant{}, fail(CodeSessionRequired, "a schedule grant needs an active privileged session")
	}
	doc, canon, digest, err := schedgrant.Parse(raw, now)
	if err != nil {
		return PendingGrant{}, fail(CodeGrantInvalid, "%v", err)
	}
	for _, act := range doc.Actions {
		if err := a.lowEverywhere(act.ActionID, act.ModuleVersion, act.ArtifactSHA256, doc.Targets); err != nil {
			return PendingGrant{}, err
		}
	}
	if _, ok, err := a.schedules.ScheduleGrant(doc.ID); err != nil {
		return PendingGrant{}, a.storageFailure(digest, err)
	} else if ok {
		return PendingGrant{}, fail(CodeGrantInvalid, "grant %s exists", doc.ID)
	}
	if len(a.grants) >= MaxPendingGrants {
		return PendingGrant{}, fail(CodeLimit, "too many pending schedule grants")
	}
	req := RequireAssertionVerified
	if a.mode == ModeHardened {
		req = RequireCLI
	}
	pg := &pendingGrant{doc: doc, canon: canon, digest: digest, expiry: now.Add(ApprovalWindow)}
	if req != RequireCLI {
		if pg.challenge, err = scheduleChallengeFor(digest, pg.expiry); err != nil {
			return PendingGrant{}, err
		}
	}
	a.grants[digest] = pg
	a.emit(Event{Kind: "schedule_grant_proposed", Digest: digest, Detail: fmt.Sprintf("%s: %d actions, %d hosts, every %ds, until %s",
		doc.ID, len(doc.Actions), len(doc.Targets), doc.MinIntervalS, time.Unix(doc.ExpiryUnix, 0).UTC().Format(time.RFC3339))})
	return PendingGrant{Digest: digest, Canonical: slices.Clone(canon), Requirement: req, Challenge: slices.Clone(pg.challenge),
		Expiry: pg.expiry, Doc: doc}, nil
}

// PendingScheduleGrants returns the grants waiting for approval.
func (a *Authority) PendingScheduleGrants() []PendingGrant {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcGrantsLocked(a.now())
	var out []PendingGrant
	for _, g := range a.grants {
		out = append(out, PendingGrant{Digest: g.digest, Canonical: slices.Clone(g.canon), Expiry: g.expiry, Doc: g.doc})
	}
	slices.SortFunc(out, func(x, y PendingGrant) int { return x.Expiry.Compare(y.Expiry) })
	return out
}

// CommitScheduleGrant approves a pending grant with a user-verified
// assertion over its challenge, inside the privileged session. The
// challenge is consumed whether or not the assertion verifies.
func (a *Authority) CommitScheduleGrant(digest string, assertionJSON []byte) (StoredGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcGrantsLocked(now)
	pg, ok := a.grants[digest]
	if !ok {
		return StoredGrant{}, fail(CodeNotFound, "no pending schedule grant with this digest")
	}
	if a.mode == ModeHardened {
		return StoredGrant{}, fail(CodeCLIRequired, "hardened mode: use nebula schedule approve")
	}
	if !a.sessionActiveLocked(now) {
		return StoredGrant{}, fail(CodeSessionRequired, "approval needs an active privileged session")
	}
	delete(a.grants, digest)
	credID, err := a.verifier.Verify(assertionJSON, pg.challenge, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return StoredGrant{}, a.storageFailure(digest, err)
	}
	if err != nil {
		a.emit(Event{Kind: "rejected", Digest: digest, Code: CodeAssertionRejected, Detail: "schedule grant: " + err.Error()})
		return StoredGrant{}, fail(CodeAssertionRejected, "%v", err)
	}
	return a.storeGrantLocked(pg, now, "webauthn:"+hex.EncodeToString(credID))
}

// ApproveScheduleGrantCLI approves a pending grant from the CLI; the
// caller has established that the peer is an admin on the executor host.
func (a *Authority) ApproveScheduleGrantCLI(digest, who string) (StoredGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcGrantsLocked(now)
	pg, ok := a.grants[digest]
	if !ok {
		return StoredGrant{}, fail(CodeNotFound, "no pending schedule grant with this digest")
	}
	delete(a.grants, digest)
	return a.storeGrantLocked(pg, now, "cli:"+who)
}

func (a *Authority) storeGrantLocked(pg *pendingGrant, now time.Time, by string) (StoredGrant, error) {
	// Trust may have been withdrawn while the grant waited.
	for _, act := range pg.doc.Actions {
		if err := a.lowEverywhere(act.ActionID, act.ModuleVersion, act.ArtifactSHA256, pg.doc.Targets); err != nil {
			return StoredGrant{}, err
		}
	}
	g := StoredGrant{ID: pg.doc.ID, Digest: pg.digest, Doc: pg.canon, ApprovedBy: by, CreatedAt: now, ExpiresAt: time.Unix(pg.doc.ExpiryUnix, 0)}
	if err := a.schedules.SaveScheduleGrant(g); err != nil {
		return StoredGrant{}, a.storageFailure(pg.digest, err)
	}
	a.emit(Event{Kind: "schedule_grant_approved", Digest: pg.digest, Detail: g.ID + " by " + by})
	return g, nil
}

// RevokeScheduleGrant revokes a grant. It needs no approval.
func (a *Authority) RevokeScheduleGrant(id, who string) error {
	if a.schedules == nil {
		return fail(CodeScheduleUnavailable, "")
	}
	ok, err := a.schedules.RevokeScheduleGrant(id, a.now())
	if err != nil {
		return a.storageFailure("", err)
	}
	if !ok {
		return fail(CodeNotFound, "no active schedule grant %s", id)
	}
	a.emit(Event{Kind: "schedule_grant_revoked", Detail: id + " by " + who})
	return nil
}

// ScheduleGrants returns the stored grants.
func (a *Authority) ScheduleGrants() ([]StoredGrant, error) {
	if a.schedules == nil {
		return nil, fail(CodeScheduleUnavailable, "")
	}
	gs, err := a.schedules.ScheduleGrants()
	if err != nil {
		return nil, a.storageFailure("", err)
	}
	return gs, nil
}

// AuthorizeScheduled checks one scheduled host run against a grant and
// records it (the interval starts now, whatever the run does). The grant's
// ID names a fresh execution for the run.
func (a *Authority) AuthorizeScheduled(grantID, executionID string, run Run) (Grant, error) {
	if a.schedules == nil {
		return Grant{}, fail(CodeScheduleUnavailable, "")
	}
	if len(run.Artifact) == 0 || len(run.Artifact) > MaxArtifactSize {
		return Grant{}, fail(CodeArtifactMismatch, "artifact size %d outside 1..%d", len(run.Artifact), MaxArtifactSize)
	}
	artSum := sha256.Sum256(run.Artifact)
	a.observe(artSum, run.Artifact)
	params, paramHash, perr := canonical.CanonicalParameters(run.ParametersJSON)
	if _, uses := secretFloor(params); perr == nil && uses {
		// Scheduled runs are LOW; a run with secrets never is.
		return Grant{}, fail(CodeGrantNotCovered, "scheduled runs cannot use vault secrets")
	}
	now := a.now()
	deny := func(code Code, detail string) error {
		a.emit(Event{Kind: "denied", Digest: "grant:" + grantID, Host: run.HostID, Code: code, Detail: detail})
		return &Error{Code: code, Detail: detail}
	}
	g, ok, err := a.schedules.ScheduleGrant(grantID)
	if err != nil {
		return Grant{}, a.storageFailure("grant:"+grantID, err)
	}
	if !ok {
		return Grant{}, deny(CodeNotFound, "no schedule grant "+grantID)
	}
	if !g.RevokedAt.IsZero() || !now.Before(g.ExpiresAt) {
		return Grant{}, deny(CodeGrantInactive, "the grant was revoked or has expired")
	}
	// The stored bytes are the approved canonical document; parse them
	// again rather than trusting anything else.
	doc, _, digest, err := schedgrant.Parse(g.Doc, g.CreatedAt)
	if err != nil || digest != g.Digest {
		return Grant{}, a.storageFailure("grant:"+grantID, fmt.Errorf("stored grant does not verify: %v", err))
	}
	act, ok := doc.Action(run.ActionID, run.ModuleVersion)
	if !ok {
		return Grant{}, deny(CodeGrantNotCovered, "action "+run.ActionID+"@"+run.ModuleVersion+" is not in the grant")
	}
	t, ok := doc.Target(run.HostID)
	if !ok || t.HostKeyFingerprint != run.HostKeyFingerprint {
		return Grant{}, deny(CodeGrantNotCovered, "host or host key is not in the grant")
	}
	if hex.EncodeToString(artSum[:]) != act.ArtifactSHA256 {
		return Grant{}, deny(CodeArtifactMismatch, "artifact bytes do not hash to the granted value")
	}
	if perr != nil || paramHash != act.ParametersHash {
		return Grant{}, deny(CodeParametersMismatch, "parameters do not hash to the granted value")
	}
	if err := a.lowEverywhere(act.ActionID, act.ModuleVersion, act.ArtifactSHA256, []canonical.Target{t}); err != nil {
		return Grant{}, err
	}
	claimed, err := a.schedules.ClaimScheduleRun(grantID, run.ActionID, run.HostID, now, time.Duration(doc.MinIntervalS)*time.Second)
	if err != nil {
		return Grant{}, a.storageFailure("grant:"+grantID, err)
	}
	if !claimed {
		return Grant{}, deny(CodeTooSoon, fmt.Sprintf("at most one run every %ds", doc.MinIntervalS))
	}
	a.emit(Event{Kind: "authorized", Digest: "grant:" + grantID, Host: run.HostID, Detail: run.ActionID + " as " + executionID})
	return Grant{ExecutionID: executionID, Parameters: params}, nil
}

// gcGrantsLocked drops pending grants whose approval window closed.
func (a *Authority) gcGrantsLocked(now time.Time) {
	for d, g := range a.grants {
		if !now.Before(g.expiry) {
			delete(a.grants, d)
		}
	}
}
