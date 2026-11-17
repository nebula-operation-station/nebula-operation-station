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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
type StoredGrant = StoredReadGrant

// ScheduleStore persists approved grants and the last run of each action
// on each host (internal/executordb implements it).
type ScheduleStore interface {
	ReadGrantStore
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

// Limits of a grant refusal's text (lowEverywhereAll): it names at most
// maxListedRefusals (action, host) pairs and is at most
// maxRefusalDetailBytes long; each action or host field is cut to
// maxRefusalField bytes.
const (
	maxListedRefusals     = 50
	maxRefusalDetailBytes = 16 << 10
	maxRefusalField       = 128
)

// refusalReason classifies why a pair is not LOW, for the hint in the text.
type refusalReason int

const (
	refusalOther         refusalReason = iota
	refusalNotGrantable                // batch-only container mutation
	refusalNotTrusted                  // artifact not trusted for this action/version
	refusalDeclaredRisk                // trusted, but above LOW
	refusalNoCriticality               // host has no matching criticality record
	refusalCriticalHost                // host is CRITICAL
	refusalScanner                     // raised by the safety scanner
)

// grantRefusal is one (action, host) pair the executor does not rate LOW.
// HostID is empty for an action that cannot be granted on any host.
type grantRefusal struct {
	actionID, version, hostID string
	floor                     canonical.Risk
	reason                    refusalReason
}

// classifyRefusal maps the risk policy's reason (internal/riskpolicy and
// Authority.floor) to a refusalReason. It only chooses the hint in the
// refusal text; the decision is the floor alone.
func classifyRefusal(why string) refusalReason {
	switch {
	case strings.HasPrefix(why, "safety scanner"):
		return refusalScanner
	case strings.Contains(why, "is not trusted on the executor"):
		return refusalNotTrusted
	case strings.HasPrefix(why, "host ") && strings.Contains(why, "has no matching criticality record"):
		return refusalNoCriticality
	case strings.HasPrefix(why, "host ") && strings.Contains(why, " is CRITICAL"):
		return refusalCriticalHost
	case strings.Contains(why, " is trusted as "):
		return refusalDeclaredRisk
	}
	return refusalOther
}

// refusalField makes an untrusted field safe for a one-line text: invalid
// UTF-8 and non-printable runes become '?', and it is cut to
// maxRefusalField bytes on a rune boundary.
func refusalField(s string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "?") {
		if !unicode.IsPrint(r) {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > maxRefusalField {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// text is one refusal with the hint how to resolve it.
func (r grantRefusal) text() string {
	act := refusalField(r.actionID) + "@" + refusalField(r.version)
	if r.hostID == "" {
		return act + " cannot be granted on any host (it runs only as an approved batch member)"
	}
	host := refusalField(r.hostID)
	s := fmt.Sprintf("%s is %s on %s", act, r.floor, host)
	switch r.reason {
	case refusalNotTrusted:
		s += " (artifact not trusted for this version: `nebula artifact trust-builtins` for built-ins, else `nebula artifact trust --action " +
			refusalField(r.actionID) + " --version " + refusalField(r.version) + " --risk LOW FILE`)"
	case refusalDeclaredRisk:
		s += " (trusted as " + string(r.floor) + ": only LOW actions can be granted, leave the action out)"
	case refusalNoCriticality:
		s += " (no criticality record for this host and key: `nebula host criticality " + host + " LEVEL`, or exclude the host)"
	case refusalCriticalHost:
		s += " (the host is CRITICAL: exclude the host from the scope)"
	case refusalScanner:
		s += " (raised by the safety scanner: review the artifact)"
	}
	return s
}

// refusalError is the CodeGrantInvalid failure naming refs; nil when refs is
// empty. unchecked notes that the check stopped early (the risk policy
// failed after the first refusal), so later pairs were not looked at.
func (a *Authority) refusalError(refs []grantRefusal, unchecked bool) error {
	if len(refs) == 0 {
		return nil
	}
	noun := "pairs are"
	if len(refs) == 1 {
		noun = "pair is"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d action/host %s not LOW; only actions the executor trusts as LOW (read-only) can be granted:", len(refs), noun)
	// Room for the longest possible tail.
	const tailRoom = 128
	listed := 0
	for _, r := range refs {
		if listed == maxListedRefusals {
			break
		}
		t := r.text()
		if b.Len()+2+len(t)+tailRoom > maxRefusalDetailBytes {
			break
		}
		if listed > 0 {
			b.WriteString(";")
		}
		b.WriteString(" ")
		b.WriteString(t)
		listed++
	}
	if rest := len(refs) - listed; rest > 0 {
		fmt.Fprintf(&b, "; … and %d more", rest)
	}
	if unchecked {
		b.WriteString("; the remaining pairs were not checked (risk policy unavailable)")
	}
	return &Error{Code: CodeGrantInvalid, Detail: b.String()}
}

// lowEverywhere checks that the executor rates an action LOW on every
// target. Shared by schedule grants and read grants.
func (a *Authority) lowEverywhere(actionID, version, artifactSHA256 string, targets []canonical.Target) error {
	return a.lowEverywhereAll([]schedgrant.Action{{ActionID: actionID, ModuleVersion: version, ArtifactSHA256: artifactSHA256}}, targets)
}

// lowEverywhereAll checks that the executor rates every action LOW on every
// target. It is exactly as strict as checking pair by pair and stopping at
// the first refusal: it refuses (CodeGrantInvalid) if any pair is not LOW,
// and fails closed (CodeStorage) when the risk policy fails before any
// refusal. It only goes on after a refusal so that the refusal names every
// pair, in action order and then target order, within the limits above.
func (a *Authority) lowEverywhereAll(actions []schedgrant.Action, targets []canonical.Target) error {
	var refs []grantRefusal
	for _, act := range actions {
		// No schedule or read grant over container mutations (no unattended
		// mutation), whatever risk a module declares.
		if canonical.IsBatchOnlyContainerAction(act.ActionID) {
			refs = append(refs, grantRefusal{actionID: act.ActionID, version: act.ModuleVersion, reason: refusalNotGrantable})
			continue
		}
		r := canonical.Request{ActionID: act.ActionID, ModuleVersion: act.ModuleVersion, ArtifactSHA256: act.ArtifactSHA256}
		for _, t := range targets {
			floor, why, err := a.floor(r, []canonical.Target{t}, nil)
			if err != nil || floor.Rank() == 0 {
				if len(refs) > 0 {
					// Checking pair by pair would have refused already.
					return a.refusalError(refs, true)
				}
				return a.storageFailure("", fmt.Errorf("risk policy: %v (floor %q)", err, floor))
			}
			if floor != canonical.RiskLow {
				if len(refs) < maxListedRefusals {
					a.emit(Event{Kind: "rejected", Host: t.HostID, Code: CodeGrantInvalid, Detail: act.ActionID + ": " + string(floor) + " (" + why + ")"})
				}
				refs = append(refs, grantRefusal{actionID: act.ActionID, version: act.ModuleVersion, hostID: t.HostID,
					floor: floor, reason: classifyRefusal(why)})
			}
		}
	}
	if n := len(refs) - maxListedRefusals; n > 0 {
		a.emit(Event{Kind: "rejected", Code: CodeGrantInvalid, Detail: fmt.Sprintf("%d more action/host pairs not LOW", n)})
	}
	return a.refusalError(refs, false)
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
	if err := a.lowEverywhereAll(doc.Actions, doc.Targets); err != nil {
		return PendingGrant{}, err
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
	if err := a.lowEverywhereAll(pg.doc.Actions, pg.doc.Targets); err != nil {
		return StoredGrant{}, err
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
	a.mu.Lock()
	defer a.mu.Unlock()
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
	grant, err := a.AuthorizeReadRun(grantID, executionID, TriggerScheduled, run)
	// Preserve the compatibility API's failure codes while using one grant
	// registry, scope check and durable reservation path.
	var denied *Error
	if errors.As(err, &denied) {
		code := denied.Code
		switch code {
		case CodeLeaseUnavailable:
			code = CodeScheduleUnavailable
		case CodeLeaseInactive:
			code = CodeGrantInactive
		case CodeLeaseNotCovered:
			code = CodeGrantNotCovered
		case CodeLeaseBudget:
			code = CodeTooSoon
		}
		if code != denied.Code {
			return Grant{}, fail(code, "schedule interval or budget: %s", denied.Detail)
		}
	}
	return grant, err
}

// gcGrantsLocked drops pending grants whose approval window closed.
func (a *Authority) gcGrantsLocked(now time.Time) {
	for d, g := range a.grants {
		if !now.Before(g.expiry) {
			delete(a.grants, d)
		}
	}
}
