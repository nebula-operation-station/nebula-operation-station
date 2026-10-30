// SPDX-License-Identifier: AGPL-3.0-or-later

// Read grants (ADR 0007, "One standing read-grant mechanism"): the single
// standing grant for read-only runs. One approval binds an explicit action
// allowlist, an explicit frozen target list, an absolute expiry and a
// per-target run budget. internal/executordb persists approved grants and
// their spent budgets; the executor enforces both before every run.
package permit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// ReadGrantFormat is the "grant" member of the read-grant document.
const ReadGrantFormat = "read-grant-v1"

// Triggers a read grant may declare. The trigger only selects which runs
// the grant covers; it never changes the authorized request.
const (
	TriggerScheduled = "scheduled"
	TriggerOnDemand  = "on_demand"
	TriggerBoth      = "both"
)

// Limits of the read-grant document (ADR 0007).
const (
	// MaxReadGrantActions bounds the explicit action allowlist.
	MaxReadGrantActions = 32
	// MaxReadGrantTargets bounds the frozen SSH target list.
	MaxReadGrantTargets = canonical.MaxTargets
	// ReadGrantMinLifetime rejects grants that expire almost immediately.
	ReadGrantMinLifetime = time.Hour
	// ReadGrantMaxLifetime bounds the absolute expiry (created + lifetime).
	ReadGrantMaxLifetime = 30 * 24 * time.Hour
	// DefaultReadGrantLifetime is the default expiry (created + 7 days).
	DefaultReadGrantLifetime = 7 * 24 * time.Hour
	// DefaultRunBudget is the default per-target rolling-hour run budget.
	DefaultRunBudget = 24
	// MaxRunBudget bounds the per-target rolling-hour run budget.
	MaxRunBudget = 240
	// GlobalRunBudget is the executor-wide per-target rolling-hour ceiling
	// shared by every read grant and legacy schedule grant. Overlapping
	// grants cannot multiply it.
	GlobalRunBudget = MaxRunBudget
	// RollingHour is the budget window.
	RollingHour = time.Hour
	// MaxReadGrantDocSize bounds the raw document.
	MaxReadGrantDocSize = 256 << 10
	// readGrantMaxDepth bounds the JSON depth.
	readGrantMaxDepth = 32
)

var readGrantIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var readGrantIssuerRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ReadOnlyAllowlist is the approved read-only action contract (ADR 0007):
// the only actions a read grant may cover. Effective LOW alone is not
// sufficient; e.g. package.refresh, docker.logs and secret-bearing actions
// are excluded even when the executor rates them LOW.
var ReadOnlyAllowlist = []string{
	"core.facts",
	"package.list_updates",
	"docker.list",
	"docker.inspect",
	"docker.check_updates",
	"service.list",
	"service.status",
}

// InReadOnlyAllowlist reports whether actionID is part of the approved
// read-only action contract.
func InReadOnlyAllowlist(actionID string) bool {
	for _, id := range ReadOnlyAllowlist {
		if id == actionID {
			return true
		}
	}
	return false
}

// ReadGrantAction is one entry of a read grant's action allowlist: this
// action at this version, with exactly this artifact and exactly these
// parameters.
type ReadGrantAction struct {
	ActionID       string `json:"action_id"`
	ModuleVersion  string `json:"module_version"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ParametersHash string `json:"parameters_hash"`
}

// ReadGrantDoc is the versioned read-grant document. The member names are
// part of the canonical form and must never change without bumping
// ReadGrantFormat.
type ReadGrantDoc struct {
	Grant        string             `json:"grant"`
	ID           string             `json:"id"`
	Issuer       string             `json:"issuer"`
	CreatedUnix  int64              `json:"created_unix"`
	ExpiryUnix   int64              `json:"expiry_unix"`
	Trigger      string             `json:"trigger"`
	Actions      []ReadGrantAction  `json:"actions"`
	Targets      []canonical.Target `json:"targets"`
	MinIntervalS int64              `json:"min_interval_s"`
	RunBudget    int64              `json:"run_budget"`
}

// Action returns the entry for actionID@version.
func (d ReadGrantDoc) Action(actionID, version string) (ReadGrantAction, bool) {
	for _, a := range d.Actions {
		if a.ActionID == actionID && a.ModuleVersion == version {
			return a, true
		}
	}
	return ReadGrantAction{}, false
}

// Target returns the frozen target for hostID.
func (d ReadGrantDoc) Target(hostID string) (canonical.Target, bool) {
	for _, t := range d.Targets {
		if t.HostID == hostID {
			return t, true
		}
	}
	return canonical.Target{}, false
}

// ParseReadGrant validates raw against now and returns the document, its
// RFC 8785 canonical bytes and their lowercase hex SHA-256. The document
// must be exactly the form it decodes to (no unknown, missing or
// differently cased members), so the executor enforces what was approved.
func ParseReadGrant(raw []byte, now time.Time) (ReadGrantDoc, []byte, string, error) {
	fail := func(format string, args ...any) (ReadGrantDoc, []byte, string, error) {
		return ReadGrantDoc{}, nil, "", fmt.Errorf("read grant: %s", fmt.Sprintf(format, args...))
	}
	if len(raw) == 0 || len(raw) > MaxReadGrantDocSize {
		return fail("the document must be 1 to %d bytes", MaxReadGrantDocSize)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return fail("%v", err)
	}
	var d ReadGrantDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return fail("%v", err)
	}
	again, err := json.Marshal(d)
	if err != nil {
		return fail("%v", err)
	}
	canon, err := jcs.Transform(again)
	if err != nil {
		return fail("%v", err)
	}
	rawCanon, err := jcs.Transform(raw)
	if err != nil || !bytes.Equal(rawCanon, canon) {
		return fail("the grant is not in its exact form (every member, lowercase names, nothing else)")
	}
	sum := sha256.Sum256(canon)
	digest := hex.EncodeToString(sum[:])
	switch {
	case d.Grant != ReadGrantFormat:
		return fail("grant must be %q", ReadGrantFormat)
	case !readGrantIDRe.MatchString(d.ID):
		return fail("id must be a lowercase UUIDv4")
	case !readGrantIssuerRe.MatchString(d.Issuer):
		return fail("issuer must be 1 to 64 characters of [a-z0-9._-], starting with a letter or digit")
	case d.CreatedUnix <= 0:
		return fail("created_unix must be a positive unix timestamp")
	case d.ExpiryUnix <= d.CreatedUnix:
		return fail("expiry_unix must be after created_unix")
	}
	created := time.Unix(d.CreatedUnix, 0)
	expiry := time.Unix(d.ExpiryUnix, 0)
	switch {
	case created.After(now):
		return fail("created_unix must not be in the future")
	case !expiry.After(now):
		return fail("the grant is already expired")
	case expiry.Sub(created) < ReadGrantMinLifetime || expiry.Sub(created) > ReadGrantMaxLifetime:
		return fail("the expiry must be 1 hour to 30 days after creation")
	}
	switch d.Trigger {
	case TriggerScheduled, TriggerOnDemand, TriggerBoth:
	default:
		return fail("trigger must be %q, %q or %q", TriggerScheduled, TriggerOnDemand, TriggerBoth)
	}
	if len(d.Actions) == 0 || len(d.Actions) > MaxReadGrantActions {
		return fail("a grant has 1 to %d actions", MaxReadGrantActions)
	}
	if len(d.Targets) == 0 || len(d.Targets) > MaxReadGrantTargets {
		return fail("a grant has 1 to %d targets", MaxReadGrantTargets)
	}
	switch {
	case d.MinIntervalS < int64(schedgrant.MinInterval/time.Second) || d.MinIntervalS > int64(schedgrant.MaxInterval/time.Second): // no overflowing multiply
		return fail("min_interval_s must be %d to %d", int64(schedgrant.MinInterval/time.Second), int64(schedgrant.MaxInterval/time.Second))
	case d.RunBudget < 1 || d.RunBudget > MaxRunBudget:
		return fail("run_budget must be 1 to %d", MaxRunBudget)
	}
	seen := map[string]bool{}
	for _, a := range d.Actions {
		switch {
		case !canonical.ValidActionID(a.ActionID) || !canonical.ValidModuleVersion(a.ModuleVersion):
			return fail("action %q@%q is malformed", a.ActionID, a.ModuleVersion)
		case !canonical.ValidSHA256Hex(a.ArtifactSHA256) || !canonical.ValidSHA256Hex(a.ParametersHash):
			return fail("action %s: hashes must be 64 lowercase hex characters", a.ActionID)
		case !InReadOnlyAllowlist(a.ActionID):
			return fail("action %s is not in the approved read-only contract", a.ActionID)
		case seen["a:"+a.ActionID+"@"+a.ModuleVersion]:
			return fail("action %s@%s listed twice", a.ActionID, a.ModuleVersion)
		}
		seen["a:"+a.ActionID+"@"+a.ModuleVersion] = true
	}
	for _, t := range d.Targets {
		switch {
		case !canonical.ValidHostID(t.HostID) || !canonical.ValidHostKeyFingerprint(t.HostKeyFingerprint):
			return fail("target %q is malformed", t.HostID)
		case seen["t:"+t.HostID]:
			return fail("host %s listed twice", t.HostID)
		}
		seen["t:"+t.HostID] = true
	}
	return d, canon, digest, nil
}

// rejectDuplicateKeys rejects any object with a duplicated member name at
// any depth, so one document cannot carry two meanings for one key.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("the top level must be an object")
	}
	if err := readGrantWalkObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("trailing data after the document")
	}
	return nil
}

// readGrantWalkObject walks an object whose opening brace has been read.
func readGrantWalkObject(dec *json.Decoder, depth int) error {
	if depth > readGrantMaxDepth {
		return errors.New("the document is nested too deep")
	}
	seen := map[string]bool{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		switch v := tok.(type) {
		case json.Delim:
			if v != '}' {
				return errors.New("malformed object")
			}
			return nil
		case string:
			if seen[v] {
				return fmt.Errorf("member %q appears twice", v)
			}
			seen[v] = true
		default:
			return errors.New("malformed object")
		}
		valTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if err := readGrantWalkValue(dec, depth, valTok); err != nil {
			return err
		}
	}
}

// readGrantWalkArray walks an array whose opening bracket has been read.
func readGrantWalkArray(dec *json.Decoder, depth int) error {
	if depth > readGrantMaxDepth {
		return errors.New("the document is nested too deep")
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if v, ok := tok.(json.Delim); ok && v == ']' {
			return nil
		}
		if err := readGrantWalkValue(dec, depth, tok); err != nil {
			return err
		}
	}
}

// readGrantWalkValue consumes the rest of a value whose first token has
// already been read: nested containers are walked, scalars are done.
func readGrantWalkValue(dec *json.Decoder, depth int, first any) error {
	switch v := first.(type) {
	case json.Delim:
		switch v {
		case '{':
			return readGrantWalkObject(dec, depth+1)
		case '[':
			return readGrantWalkArray(dec, depth+1)
		default:
			return errors.New("malformed value")
		}
	default:
		return nil
	}
}

// Read-grant failure codes.
const (
	CodeLeaseUnavailable Code = "read_grants_unavailable"
	CodeLeaseInvalid     Code = "read_grant_invalid"
	CodeLeaseInactive    Code = "read_grant_inactive"
	CodeLeaseNotCovered  Code = "read_grant_does_not_cover"
	CodeLeaseBudget      Code = "read_grant_budget_exhausted"
)

// ErrReadGrantInactive means a grant was absent, revoked or expired when the
// store attempted to reserve a run, atomically with the budget accounting.
var ErrReadGrantInactive = errors.New("permit: read grant is inactive")

// StoredReadGrant is an approved read grant.
type StoredReadGrant struct {
	ID         string
	Digest     string
	Doc        []byte // canonical document
	ApprovedBy string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time // zero while active
}

// ReadGrantStore persists approved read grants and the run budget each
// target has spent in its rolling hour (internal/executordb implements it).
type ReadGrantStore interface {
	SaveReadGrant(g StoredReadGrant) error
	ReadGrant(id string) (StoredReadGrant, bool, error)
	ReadGrants() ([]StoredReadGrant, error)
	// RevokeReadGrant marks a grant revoked; false if it is unknown or was
	// revoked before.
	RevokeReadGrant(id string, at time.Time) (bool, error)
	// ReserveReadRun atomically reserves one run of grantID (actionID on
	// hostID) at now. It returns ErrReadGrantInactive unless the grant exists,
	// is unrevoked and has not expired at the high-water time, checked in the
	// reservation transaction. It succeeds only while (a) the target's reservations
	// in the last hour are below the per-target ceiling budget, and (b) the
	// last reservation of actionID on hostID is at least minInterval ago
	// (the 15-minute per-action floor). Both counters are shared across
	// grants, so overlapping grants cannot multiply the per-target ceiling,
	// and they are durable across restart. minInterval is the grant's own
	// approved minimum interval (at least 15 minutes).
	ReserveReadRun(grantID, actionID, hostID string, now time.Time, budget int, minInterval time.Duration) (bool, error)
}

type pendingReadGrant struct {
	doc       ReadGrantDoc
	canon     []byte
	digest    string
	challenge []byte
	expiry    time.Time
}

// PendingReadGrant describes a proposed read grant.
type PendingReadGrant struct {
	Digest      string
	Canonical   []byte
	Requirement Requirement
	Challenge   []byte
	Expiry      time.Time
	Doc         ReadGrantDoc
}

// readGrantChallengeFor builds the read-grant approval challenge: a domain
// separator of its own, the grant digest, a fresh nonce and the challenge
// expiry.
func readGrantChallengeFor(digest string, expiry time.Time) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("permit: nonce: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("nebula-read-grant-v1\x00"))
	h.Write([]byte(digest))
	h.Write(nonce[:])
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiry.Unix()))
	h.Write(exp[:])
	return h.Sum(nil), nil
}

// ProposeReadGrant checks a read-grant document and holds it for approval.
// Unlike schedule grants it needs no privileged session (ADR 0007): the
// user-verified assertion over the grant digest is the approval.
func (a *Authority) ProposeReadGrant(raw []byte) (PendingReadGrant, error) {
	if a.leases == nil {
		return PendingReadGrant{}, fail(CodeLeaseUnavailable, "")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcReadGrantsLocked(now)
	doc, canon, digest, err := ParseReadGrant(raw, now)
	if err != nil {
		return PendingReadGrant{}, fail(CodeLeaseInvalid, "%v", err)
	}
	for _, act := range doc.Actions {
		if err := a.lowEverywhere(act.ActionID, act.ModuleVersion, act.ArtifactSHA256, doc.Targets); err != nil {
			return PendingReadGrant{}, err
		}
	}
	if _, ok, err := a.leases.ReadGrant(doc.ID); err != nil {
		return PendingReadGrant{}, a.storageFailure(digest, err)
	} else if ok {
		return PendingReadGrant{}, fail(CodeLeaseInvalid, "grant %s exists", doc.ID)
	}
	if len(a.readGrants) >= MaxPendingGrants {
		return PendingReadGrant{}, fail(CodeLimit, "too many pending read grants")
	}
	req := RequireAssertionVerified
	if a.mode == ModeHardened {
		req = RequireCLI
	}
	pg := &pendingReadGrant{doc: doc, canon: canon, digest: digest, expiry: now.Add(ApprovalWindow)}
	if req != RequireCLI {
		if pg.challenge, err = readGrantChallengeFor(digest, pg.expiry); err != nil {
			return PendingReadGrant{}, err
		}
	}
	a.readGrants[digest] = pg
	a.emit(Event{Kind: "read_grant_proposed", Digest: digest, Detail: fmt.Sprintf("%s: %d actions, %d hosts, %d runs/hour/host, until %s",
		doc.ID, len(doc.Actions), len(doc.Targets), doc.RunBudget, time.Unix(doc.ExpiryUnix, 0).UTC().Format(time.RFC3339))})
	return PendingReadGrant{Digest: digest, Canonical: slices.Clone(canon), Requirement: req, Challenge: slices.Clone(pg.challenge),
		Expiry: pg.expiry, Doc: doc}, nil
}

// PendingReadGrants returns the read grants waiting for approval.
func (a *Authority) PendingReadGrants() []PendingReadGrant {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcReadGrantsLocked(a.now())
	var out []PendingReadGrant
	for _, g := range a.readGrants {
		out = append(out, PendingReadGrant{Digest: g.digest, Canonical: slices.Clone(g.canon), Expiry: g.expiry, Doc: g.doc})
	}
	slices.SortFunc(out, func(x, y PendingReadGrant) int { return x.Expiry.Compare(y.Expiry) })
	return out
}

// CommitReadGrant approves a pending read grant with a user-verified
// assertion over its challenge. No privileged session is needed (ADR 0007);
// the assertion is the approval. The challenge is consumed whether or not
// the assertion verifies.
func (a *Authority) CommitReadGrant(digest string, assertionJSON []byte) (StoredReadGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcReadGrantsLocked(now)
	pg, ok := a.readGrants[digest]
	if !ok {
		return StoredReadGrant{}, fail(CodeNotFound, "no pending read grant with this digest")
	}
	if a.mode == ModeHardened {
		return StoredReadGrant{}, fail(CodeCLIRequired, "hardened mode: use nebula read-grant approve")
	}
	delete(a.readGrants, digest)
	credID, err := a.verifier.Verify(assertionJSON, pg.challenge, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return StoredReadGrant{}, a.storageFailure(digest, err)
	}
	if err != nil {
		a.emit(Event{Kind: "rejected", Digest: digest, Code: CodeAssertionRejected, Detail: "read grant: " + err.Error()})
		return StoredReadGrant{}, fail(CodeAssertionRejected, "%v", err)
	}
	return a.storeReadGrantLocked(pg, now, "webauthn:"+hex.EncodeToString(credID))
}

// ApproveReadGrantCLI approves a pending read grant from the CLI; the
// caller has established that the peer is an admin on the executor host.
func (a *Authority) ApproveReadGrantCLI(digest, who string) (StoredReadGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcReadGrantsLocked(now)
	pg, ok := a.readGrants[digest]
	if !ok {
		return StoredReadGrant{}, fail(CodeNotFound, "no pending read grant with this digest")
	}
	delete(a.readGrants, digest)
	return a.storeReadGrantLocked(pg, now, "cli:"+who)
}

func (a *Authority) storeReadGrantLocked(pg *pendingReadGrant, now time.Time, by string) (StoredReadGrant, error) {
	// Trust may have been withdrawn while the grant waited.
	for _, act := range pg.doc.Actions {
		if err := a.lowEverywhere(act.ActionID, act.ModuleVersion, act.ArtifactSHA256, pg.doc.Targets); err != nil {
			return StoredReadGrant{}, err
		}
	}
	g := StoredReadGrant{ID: pg.doc.ID, Digest: pg.digest, Doc: pg.canon, ApprovedBy: by, CreatedAt: now, ExpiresAt: time.Unix(pg.doc.ExpiryUnix, 0)}
	if err := a.leases.SaveReadGrant(g); err != nil {
		return StoredReadGrant{}, a.storageFailure(pg.digest, err)
	}
	a.emit(Event{Kind: "read_grant_approved", Digest: pg.digest, Detail: g.ID + " by " + by})
	return g, nil
}

// RevokeReadGrant revokes a read grant. It needs no approval.
func (a *Authority) RevokeReadGrant(id, who string) error {
	if a.leases == nil {
		return fail(CodeLeaseUnavailable, "")
	}
	ok, err := a.leases.RevokeReadGrant(id, a.now())
	if err != nil {
		return a.storageFailure("", err)
	}
	if !ok {
		return fail(CodeNotFound, "no active read grant %s", id)
	}
	a.emit(Event{Kind: "read_grant_revoked", Detail: id + " by " + who})
	return nil
}

// ReadGrants returns the stored read grants.
func (a *Authority) ReadGrants() ([]StoredReadGrant, error) {
	if a.leases == nil {
		return nil, fail(CodeLeaseUnavailable, "")
	}
	gs, err := a.leases.ReadGrants()
	if err != nil {
		return nil, a.storageFailure("", err)
	}
	return gs, nil
}

// gcReadGrantsLocked drops pending read grants whose approval window closed.
func (a *Authority) gcReadGrantsLocked(now time.Time) {
	for d, g := range a.readGrants {
		if !now.Before(g.expiry) {
			delete(a.readGrants, d)
		}
	}
}

// AuthorizeReadRun checks one read run against a read grant and reserves
// one unit of the target's rolling-hour budget. The trigger selects which
// runs the grant covers: its trigger must cover the run's. The grant's ID
// names a fresh execution for the run. The reservation is made durably
// before dispatch; a storage failure denies.
func (a *Authority) AuthorizeReadRun(grantID, executionID, trigger string, run Run) (Grant, error) {
	if a.leases == nil {
		return Grant{}, fail(CodeLeaseUnavailable, "")
	}
	switch trigger {
	case TriggerScheduled, TriggerOnDemand:
	default:
		return Grant{}, fail(CodeLeaseInvalid, "trigger must be %q or %q", TriggerScheduled, TriggerOnDemand)
	}
	if len(run.Artifact) == 0 || len(run.Artifact) > MaxArtifactSize {
		return Grant{}, fail(CodeArtifactMismatch, "artifact size %d outside 1..%d", len(run.Artifact), MaxArtifactSize)
	}
	artSum := sha256.Sum256(run.Artifact)
	a.observe(artSum, run.Artifact)
	params, paramHash, perr := canonical.CanonicalParameters(run.ParametersJSON)
	if _, uses := secretFloor(params); perr == nil && uses {
		// Read runs are LOW; a run with secrets never is.
		return Grant{}, fail(CodeLeaseNotCovered, "read runs cannot use vault secrets")
	}
	now := a.now()
	deny := func(code Code, detail string) error {
		a.emit(Event{Kind: "denied", Digest: "readgrant:" + grantID, Host: run.HostID, Code: code, Detail: detail})
		return &Error{Code: code, Detail: detail}
	}
	g, ok, err := a.leases.ReadGrant(grantID)
	if err != nil {
		return Grant{}, a.storageFailure("readgrant:"+grantID, err)
	}
	if !ok {
		return Grant{}, deny(CodeNotFound, "no read grant "+grantID)
	}
	if !g.RevokedAt.IsZero() || !now.Before(g.ExpiresAt) {
		return Grant{}, deny(CodeLeaseInactive, "the read grant was revoked or has expired")
	}
	// The stored bytes are the approved canonical document; parse them
	// again rather than trusting anything else.
	doc, digest, err := readGrantScope(g)
	if err != nil || digest != g.Digest {
		return Grant{}, a.storageFailure("readgrant:"+grantID, fmt.Errorf("stored read grant does not verify: %v", err))
	}
	switch doc.Trigger {
	case TriggerBoth:
	case trigger:
	default:
		return Grant{}, deny(CodeLeaseNotCovered, "the read grant does not cover "+trigger+" runs")
	}
	act, ok := doc.Action(run.ActionID, run.ModuleVersion)
	if !ok {
		return Grant{}, deny(CodeLeaseNotCovered, "action "+run.ActionID+"@"+run.ModuleVersion+" is not in the read grant")
	}
	t, ok := doc.Target(run.HostID)
	if !ok || t.HostKeyFingerprint != run.HostKeyFingerprint {
		return Grant{}, deny(CodeLeaseNotCovered, "host or host key is not in the read grant")
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
	reserved, err := a.leases.ReserveReadRun(grantID, run.ActionID, run.HostID, a.now(), int(doc.RunBudget), time.Duration(doc.MinIntervalS)*time.Second)
	if errors.Is(err, ErrReadGrantInactive) {
		return Grant{}, deny(CodeLeaseInactive, "the read grant was revoked or has expired")
	}
	if err != nil {
		return Grant{}, a.storageFailure("readgrant:"+grantID, err)
	}
	if !reserved {
		return Grant{}, deny(CodeLeaseBudget, fmt.Sprintf("per-target run budget of %d per hour is exhausted", doc.RunBudget))
	}
	a.emit(Event{Kind: "authorized", Digest: "readgrant:" + grantID, Host: run.HostID, Detail: run.ActionID + " as " + executionID})
	return Grant{ExecutionID: executionID, Parameters: params}, nil
}

// readGrantScope verifies the original signed document before adapting legacy
// schedule scope for the common authorization path. The adaptation is never
// persisted or treated as a new approval, and never grants on-demand access.
func readGrantScope(g StoredReadGrant) (ReadGrantDoc, string, error) {
	var header struct {
		Grant string `json:"grant"`
	}
	if err := json.Unmarshal(g.Doc, &header); err != nil {
		return ReadGrantDoc{}, "", err
	}
	if header.Grant != schedgrant.Format {
		doc, _, digest, err := ParseReadGrant(g.Doc, g.CreatedAt)
		return doc, digest, err
	}
	legacy, _, digest, err := schedgrant.Parse(g.Doc, g.CreatedAt)
	if err != nil {
		return ReadGrantDoc{}, "", err
	}
	doc := ReadGrantDoc{ID: legacy.ID, Trigger: TriggerScheduled, ExpiryUnix: legacy.ExpiryUnix,
		Targets: legacy.Targets, MinIntervalS: legacy.MinIntervalS, RunBudget: GlobalRunBudget}
	for _, action := range legacy.Actions {
		doc.Actions = append(doc.Actions, ReadGrantAction{ActionID: action.ActionID, ModuleVersion: action.ModuleVersion,
			ArtifactSHA256: action.ArtifactSHA256, ParametersHash: action.ParametersHash})
	}
	return doc, digest, nil
}
