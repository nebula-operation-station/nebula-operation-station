// SPDX-License-Identifier: AGPL-3.0-or-later

// Read grants (ADR 0007, "One standing read-grant mechanism"): the single
// standing grant for read-only runs. One approval binds an explicit action
// allowlist, an explicit frozen target list, an absolute expiry and a
// per-target run budget. internal/executordb persists approved grants and
// their spent budgets; the executor enforces both before every run.
package permit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
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
