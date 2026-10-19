// SPDX-License-Identifier: AGPL-3.0-or-later

// Package modulelock reads a module's lock document (M7-5, spec 10): the
// canonical JSON an author signs with `ssh-keygen -Y sign -n
// nebula-module`. It names the module and version and, for every action,
// the script file's SHA-256, declared risk, run mode, typed parameters and
// secret slots. The executor verifies the signature over these exact
// bytes, checks every script against its hash and builds the action's
// artifact (internal/prelude) itself; module.yaml is only the author's
// input to `nebula module pack`.
package modulelock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
)

// Format is the lock's "format" member; Namespace the SSH signature
// namespace for module locks.
const (
	Format    = "nebula-module-v1"
	Namespace = "nebula-module"
)

// Limits.
const (
	MaxActions     = 50
	MaxScript      = 256 << 10
	MaxTitle       = 100
	MaxDescription = 2000
	minTimeout     = 10 * time.Second
	maxAttached    = 10 * time.Minute
	maxDurable     = 6 * time.Hour
)

// Reserved module names: built-in action families, runbooks and the
// executor's own actions.
var reserved = map[string]bool{"core": true, "package": true, "system": true, "service": true, "docker": true,
	"runbook": true, "nebula": true, "os": true, "test": true}

// Declarations a module may make (spec 10); they drive warnings, not a
// sandbox.
var declarations = map[string]bool{"requires_root": true, "writes_config": true, "network_access": true}

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{1,30}$`)
	actionRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)
	scriptRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}(/[a-z0-9][a-z0-9_.-]{0,63}){0,3}$`)
	hex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Action is one action of the module.
type Action struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Script      string          `json:"script"`
	SHA256      string          `json:"sha256"`
	Risk        string          `json:"risk"`
	Durable     bool            `json:"durable"`
	TimeoutS    int             `json:"timeout_s"`
	Params      []prelude.Param `json:"params"`
	Secrets     []string        `json:"secrets"`
	Declares    []string        `json:"declares"`
}

// Lock is a module's lock document.
type Lock struct {
	Format      string            `json:"format"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Actions     map[string]Action `json:"actions"`
}

// ErrInvalid is a lock that is not valid.
var ErrInvalid = errors.New("modulelock: invalid lock")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Parse reads a lock and returns it with the SHA-256 of its canonical
// form. The bytes must be exactly the form they decode to.
func Parse(raw []byte) (Lock, string, error) {
	canon, hash, err := canonical.CanonicalParameters(raw)
	if err != nil {
		return Lock{}, "", invalid("%v", err)
	}
	// The signed bytes are the lock: only its canonical encoding (RFC 8785,
	// as `nebula module pack` writes it) is accepted, so the recorded hash
	// is the hash of exactly the bytes that were signed.
	if !bytes.Equal(raw, canon) {
		return Lock{}, "", invalid("the lock is not in its canonical form; write it with nebula module pack")
	}
	var l Lock
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return Lock{}, "", invalid("%v", err)
	}
	again, err := json.Marshal(l)
	if err != nil {
		return Lock{}, "", invalid("%v", err)
	}
	if _, h, err := canonical.CanonicalParameters(again); err != nil || h != hash {
		return Lock{}, "", invalid("the lock is not in its exact form (every member, lowercase names, nothing else)")
	}
	if err := l.check(); err != nil {
		return Lock{}, "", err
	}
	return l, hash, nil
}

func (l Lock) check() error {
	switch {
	case l.Format != Format:
		return invalid("format must be %q", Format)
	case !nameRe.MatchString(l.Name) || reserved[l.Name]:
		return invalid("the module name must be 2 to 31 lowercase letters, digits or _, start with a letter, and not be reserved")
	case !canonical.ValidModuleVersion(l.Version):
		return invalid("the version must be X.Y.Z")
	case l.Title == "" || len(l.Title) > MaxTitle || !prelude.Clean(l.Title, false):
		return invalid("the title must be 1 to %d characters of plain text", MaxTitle)
	case len(l.Description) > MaxDescription || !prelude.Clean(l.Description, true):
		return invalid("the description must be at most %d characters of plain text", MaxDescription)
	case len(l.Actions) == 0 || len(l.Actions) > MaxActions:
		return invalid("a module has 1 to %d actions", MaxActions)
	}
	for name, a := range l.Actions {
		if err := a.check(name); err != nil {
			return err
		}
		if !canonical.ValidActionID(l.Name + "." + name) {
			return invalid("action %s: the action ID %s.%s is not valid", name, l.Name, name)
		}
	}
	return nil
}

func (a Action) check(name string) error {
	switch {
	case !actionRe.MatchString(name):
		return invalid("action names are 1 to 41 lowercase letters, digits or _, starting with a letter")
	case a.Title == "" || len(a.Title) > MaxTitle || !prelude.Clean(a.Title, false):
		return invalid("action %s: the title must be 1 to %d characters of plain text", name, MaxTitle)
	case len(a.Description) > MaxDescription || !prelude.Clean(a.Description, true):
		return invalid("action %s: the description is too long or not plain text", name)
	case !scriptRe.MatchString(a.Script):
		return invalid("action %s: the script must be a relative path of lowercase names", name)
	case !hex64.MatchString(a.SHA256):
		return invalid("action %s: sha256 must be 64 lowercase hex digits", name)
	case a.Risk != "LOW" && a.Risk != "MEDIUM" && a.Risk != "HIGH" && a.Risk != "CRITICAL":
		return invalid("action %s: the risk must be LOW, MEDIUM, HIGH or CRITICAL", name)
	case a.Params == nil || a.Secrets == nil || a.Declares == nil:
		return invalid("action %s: params, secrets and declares must be present (empty lists allowed)", name)
	}
	maxT := maxAttached
	if a.Durable {
		maxT = maxDurable
	}
	if t := time.Duration(a.TimeoutS) * time.Second; t < minTimeout || t > maxT {
		return invalid("action %s: the timeout must be %d to %d seconds", name, int(minTimeout/time.Second), int(maxT/time.Second))
	}
	if reason, ok := prelude.Check(a.Params, a.Secrets); !ok {
		return invalid("action %s: %s", name, reason)
	}
	seen := map[string]bool{}
	for _, d := range a.Declares {
		if !declarations[d] || seen[d] {
			return invalid("action %s: declares lists distinct values of requires_root, writes_config, network_access", name)
		}
		seen[d] = true
	}
	return nil
}

// Names returns the action names, sorted.
func (l Lock) Names() []string {
	out := make([]string, 0, len(l.Actions))
	for n := range l.Actions {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ActionID is the action ID of one of the module's actions.
func (l Lock) ActionID(name string) string { return l.Name + "." + name }

// Artifact checks an action's script against the lock and returns the
// bytes that run on the host and their SHA-256.
func (l Lock) Artifact(name string, script []byte) ([]byte, string, error) {
	a, ok := l.Actions[name]
	if !ok {
		return nil, "", invalid("no action %s", name)
	}
	if len(script) == 0 || len(script) > MaxScript || !prelude.Clean(string(script), true) {
		return nil, "", invalid("action %s: the script must be 1 byte to 256 KiB of UTF-8 text with Unix line ends and no control or invisible formatting characters", name)
	}
	sum := sha256.Sum256(script)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return nil, "", invalid("action %s: %s does not hash to the lock's sha256", name, a.Script)
	}
	art := prelude.Build("Nebula module "+l.Name+" "+l.Version+" action "+name+" (module-v1).", a.Params, a.Secrets, string(script))
	as := sha256.Sum256(art)
	return art, hex.EncodeToString(as[:]), nil
}

// TrustRisk is the risk the executor trusts a verified action at: the
// declared risk, at least MEDIUM for an action that declares it needs root
// or writes configuration (spec 10: declarations drive risk).
func (a Action) TrustRisk() string {
	rank := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	r := a.Risk
	for _, d := range a.Declares {
		if (d == "requires_root" || d == "writes_config") && rank[r] < rank["MEDIUM"] {
			r = "MEDIUM"
		}
	}
	return r
}
