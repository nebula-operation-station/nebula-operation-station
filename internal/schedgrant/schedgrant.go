// SPDX-License-Identifier: AGPL-3.0-or-later

// Package schedgrant is the document of a schedule grant: the standing,
// executor-held permission to run fixed read-only actions on fixed hosts
// on a schedule (docs/implementation/schedule-grants.md). The approval
// binds the SHA-256 of its RFC 8785 form; internal/permit enforces it.
package schedgrant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// Format is the document's "grant" member.
const Format = "read-schedule-v1"

// Limits.
const (
	MaxActions      = 10
	MaxTargets      = 100
	MinInterval     = 15 * time.Minute
	MaxInterval     = 7 * 24 * time.Hour
	MaxLifetime     = 90 * 24 * time.Hour
	MinLifetime     = time.Hour
	DefaultLifetime = 30 * 24 * time.Hour
)

// Action is one action a grant covers, with exactly these parameters.
type Action struct {
	ActionID       string `json:"action_id"`
	ModuleVersion  string `json:"module_version"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ParametersHash string `json:"parameters_hash"`
}

// Doc is a schedule grant document.
type Doc struct {
	Grant        string             `json:"grant"`
	ID           string             `json:"id"`
	Actions      []Action           `json:"actions"`
	Targets      []canonical.Target `json:"targets"`
	MinIntervalS int64              `json:"min_interval_s"`
	ExpiryUnix   int64              `json:"expiry_unix"`
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("schedgrant: invalid grant")

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Parse reads a grant document, checks it against now and returns it with
// its canonical bytes and their lowercase hex SHA-256. The document must
// be exactly the form it decodes to (no unknown, missing or differently
// cased members), so the executor enforces what was approved.
func Parse(raw []byte, now time.Time) (Doc, []byte, string, error) {
	canon, hash, err := canonical.CanonicalParameters(raw)
	if err != nil {
		return Doc{}, nil, "", invalid("%v", err)
	}
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Doc{}, nil, "", invalid("%v", err)
	}
	again, err := json.Marshal(d)
	if err != nil {
		return Doc{}, nil, "", invalid("%v", err)
	}
	if _, h, err := canonical.CanonicalParameters(again); err != nil || h != hash {
		return Doc{}, nil, "", invalid("the grant is not in its exact form (every member, lowercase names, nothing else)")
	}
	switch {
	case d.Grant != Format:
		return Doc{}, nil, "", invalid("grant must be %q", Format)
	case !uuidRe.MatchString(d.ID):
		return Doc{}, nil, "", invalid("id must be a lowercase UUIDv4")
	case len(d.Actions) == 0 || len(d.Actions) > MaxActions:
		return Doc{}, nil, "", invalid("a grant has 1 to %d actions", MaxActions)
	case len(d.Targets) == 0 || len(d.Targets) > MaxTargets:
		return Doc{}, nil, "", invalid("a grant has 1 to %d targets", MaxTargets)
	case d.MinIntervalS < int64(MinInterval/time.Second) || d.MinIntervalS > int64(MaxInterval/time.Second): // no overflowing multiply
		return Doc{}, nil, "", invalid("min_interval_s must be %d to %d", int64(MinInterval/time.Second), int64(MaxInterval/time.Second))
	}
	exp := time.Unix(d.ExpiryUnix, 0)
	if exp.Before(now.Add(MinLifetime)) || exp.After(now.Add(MaxLifetime)) {
		return Doc{}, nil, "", invalid("the expiry must be 1 hour to 90 days ahead")
	}
	seen := map[string]bool{}
	for _, a := range d.Actions {
		switch {
		case !canonical.ValidActionID(a.ActionID) || !canonical.ValidModuleVersion(a.ModuleVersion):
			return Doc{}, nil, "", invalid("action %q@%q is malformed", a.ActionID, a.ModuleVersion)
		case !canonical.ValidSHA256Hex(a.ArtifactSHA256) || !canonical.ValidSHA256Hex(a.ParametersHash):
			return Doc{}, nil, "", invalid("action %s: hashes must be 64 lowercase hex characters", a.ActionID)
		case seen["a:"+a.ActionID+"@"+a.ModuleVersion]:
			return Doc{}, nil, "", invalid("action %s@%s listed twice", a.ActionID, a.ModuleVersion)
		}
		seen["a:"+a.ActionID+"@"+a.ModuleVersion] = true
	}
	for _, t := range d.Targets {
		switch {
		case !canonical.ValidHostID(t.HostID) || !canonical.ValidHostKeyFingerprint(t.HostKeyFingerprint):
			return Doc{}, nil, "", invalid("target %q is malformed", t.HostID)
		case seen["t:"+t.HostID]:
			return Doc{}, nil, "", invalid("host %s listed twice", t.HostID)
		}
		seen["t:"+t.HostID] = true
	}
	return d, canon, hash, nil
}

// Action returns the entry for actionID@version.
func (d Doc) Action(actionID, version string) (Action, bool) {
	for _, a := range d.Actions {
		if a.ActionID == actionID && a.ModuleVersion == version {
			return a, true
		}
	}
	return Action{}, false
}

// Target returns the target for hostID.
func (d Doc) Target(hostID string) (canonical.Target, bool) {
	for _, t := range d.Targets {
		if t.HostID == hostID {
			return t, true
		}
	}
	return canonical.Target{}, false
}
