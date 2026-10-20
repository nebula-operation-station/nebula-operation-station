// SPDX-License-Identifier: AGPL-3.0-or-later

// Package runbooks stores runbooks (spec 10): local single-action modules
// with an immutable version per save. A version becomes an action
// `runbook.<slug>` at version `N.0.0` whose artifact is a generated prelude
// followed by the author's script (see Artifact). The executor treats the
// artifact like any other script: untrusted until trusted on the executor
// host, so at least HIGH, and raised further by the Safety Scanner.
package runbooks

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ActionPrefix starts the action ID of every runbook.
const ActionPrefix = "runbook."

// Limits.
const (
	MaxBody        = 256 << 10
	MaxParams      = 10
	MaxSecrets     = 8
	MaxChoices     = 20
	MaxTitle       = 100
	MaxDescription = 2000
	MaxLabel       = 100
	MinTimeout     = 10 * time.Second
)

// Parameter types (decision 2 of the M7 plan): no free-form strings.
const (
	TypeName   = "name"
	TypeInt    = "int"
	TypePath   = "path"
	TypeChoice = "choice"
)

// ere is each type's pattern, written so that Go's regexp and POSIX ERE
// (grep -E, used by the prelude on the host) read it the same way.
//
// A path may contain ".." segments: it is an absolute path handed to the
// author's own script, which can name any path anyway, so the pattern only
// keeps quotes, spaces and shell metacharacters out (review m72, note 2).
var ere = map[string]string{
	TypeName: `[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}`,
	TypeInt:  `[0-9]{1,9}`,
	TypePath: `/[A-Za-z0-9._/-]{0,200}`,
}

var (
	slugRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,39}$`)
	paramNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	choiceRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	userRe      = regexp.MustCompile(`^[\x21-\x7e]{1,64}$`)
)

// Param is one typed parameter.
type Param struct {
	Name    string   `json:"name"`
	Label   string   `json:"label"`
	Type    string   `json:"type"`
	Choices []string `json:"choices,omitempty"`
}

// pattern is the parameter's ERE without anchors.
func (p Param) pattern() string {
	if p.Type == TypeChoice {
		return "(" + strings.Join(p.Choices, "|") + ")"
	}
	return ere[p.Type]
}

// Draft is what an author saves.
type Draft struct {
	Slug        string  `json:"slug"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Risk        string  `json:"risk"`
	Durable     bool    `json:"durable"`
	TimeoutS    int     `json:"timeout_s"`
	Params      []Param `json:"params"`
	// Secrets are secret slot names; the script reads each value from the
	// file $NEBULA_SECRET_<SLOT>.
	Secrets []string `json:"secrets"`
	Body    string   `json:"body"`
}

// Version is one stored, immutable version.
type Version struct {
	Draft
	Version        int
	Artifact       []byte
	ArtifactSHA256 string
	CreatedBy      string
	CreatedAt      time.Time
}

// ActionID is the version's action ID.
func (v Version) ActionID() string { return ActionPrefix + v.Slug }

// ModuleVersion is the version's module version.
func (v Version) ModuleVersion() string { return strconv.Itoa(v.Version) + ".0.0" }

// Errors.
var (
	ErrNotFound = errors.New("runbook not found")
)

// InvalidError says what is wrong with a draft; its text is safe to show.
type InvalidError struct{ Reason string }

func (e *InvalidError) Error() string { return "runbook not valid: " + e.Reason }

func invalid(format string, a ...any) error { return &InvalidError{Reason: fmt.Sprintf(format, a...)} }

// clean reports whether s is printable text without control, format
// (bidi) or line/paragraph separator characters; newline and tab are
// allowed only where multiline is true.
func clean(s string, multiline bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case multiline && (r == '\n' || r == '\t'):
		case r == '\r':
			return false
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == ' ', r == ' ', r == utf8.RuneError:
			return false
		}
	}
	return true
}

// Validate checks a draft.
func Validate(d Draft) error {
	switch {
	case !slugRe.MatchString(d.Slug) || d.Slug == "new":
		return invalid("the name must be 1 to 40 lowercase letters, digits or _, start with a letter or digit, and not be \"new\"")
	case d.Title == "" || len(d.Title) > MaxTitle || !clean(d.Title, false):
		return invalid("the title must be 1 to %d characters of plain text", MaxTitle)
	case len(d.Description) > MaxDescription || !clean(d.Description, true):
		return invalid("the description must be at most %d characters of plain text", MaxDescription)
	case d.Risk != "LOW" && d.Risk != "MEDIUM" && d.Risk != "HIGH" && d.Risk != "CRITICAL":
		return invalid("the risk must be LOW, MEDIUM, HIGH or CRITICAL")
	case len(d.Params) > MaxParams:
		return invalid("at most %d parameters", MaxParams)
	case d.Body == "" || len(d.Body) > MaxBody:
		return invalid("the script must be 1 byte to %d KiB", MaxBody>>10)
	case !clean(d.Body, true):
		// No control or invisible format characters (bidi overrides,
		// zero-width): what a reviewer reads must be what runs.
		return invalid("the script must be UTF-8 text with Unix line ends and without control or invisible formatting characters")
	}
	// The script runs inside a shell function of the generated artifact. A
	// body that is not valid shell on its own (an unpaired "}" for example)
	// could close that function early and run its rest at the top level,
	// where stdout is the result document. Refuse it at save time.
	if err := ShellCheck([]byte(d.Body)); err != nil {
		return invalid("the script is not valid shell syntax (sh -n): %v", err)
	}
	if err := ShellCheck(Artifact(Version{Draft: d, Version: 1})); err != nil {
		return invalid("the script does not fit into the runbook prelude (sh -n): %v", err)
	}
	maxT := hostrun.MaxTimeout
	if d.Durable {
		maxT = hostrun.MaxDurableTimeout
	}
	if t := time.Duration(d.TimeoutS) * time.Second; d.TimeoutS < int(MinTimeout/time.Second) || t > maxT {
		return invalid("the timeout must be %d to %d seconds", int(MinTimeout/time.Second), int(maxT/time.Second))
	}
	seen := map[string]bool{}
	if len(d.Secrets) > MaxSecrets {
		return invalid("at most %d secret slots", MaxSecrets)
	}
	for _, slot := range d.Secrets {
		if !paramNameRe.MatchString(slot) || strings.HasPrefix(slot, "nebula") || seen[slot] {
			return invalid("secret slots are distinct names of 1 to 32 lowercase letters, digits or _, starting with a letter (not nebula…)")
		}
		seen[slot] = true
	}
	for _, p := range d.Params {
		switch {
		case !paramNameRe.MatchString(p.Name) || strings.HasPrefix(p.Name, "nebula"):
			return invalid("parameter names are 1 to 32 lowercase letters, digits or _, starting with a letter (not nebula…)")
		case seen[p.Name]:
			return invalid("parameter %s appears twice or is also a secret slot", p.Name)
		case p.Label == "" || len(p.Label) > MaxLabel || !clean(p.Label, false):
			return invalid("parameter %s needs a label of 1 to %d characters of plain text", p.Name, MaxLabel)
		}
		seen[p.Name] = true
		switch p.Type {
		case TypeName, TypeInt, TypePath:
			if len(p.Choices) > 0 {
				return invalid("parameter %s: only a choice has choices", p.Name)
			}
		case TypeChoice:
			if len(p.Choices) == 0 || len(p.Choices) > MaxChoices {
				return invalid("parameter %s: a choice has 1 to %d values", p.Name, MaxChoices)
			}
			vals := map[string]bool{}
			for _, c := range p.Choices {
				if !choiceRe.MatchString(c) || vals[c] {
					return invalid("parameter %s: choices are distinct lowercase words (letters, digits, _ and -)", p.Name)
				}
				vals[c] = true
			}
		default:
			return invalid("parameter %s: the type must be name, int, path or choice", p.Name)
		}
	}
	return nil
}

// Action turns a version into the action the operation engine runs.
func (v Version) Action() actions.Action {
	a := actions.Action{
		ID: v.ActionID(), Version: v.ModuleVersion(), Title: v.Title, Description: v.Description,
		Risk: riskProto(v.Risk), Durable: v.Durable, Timeout: time.Duration(v.TimeoutS) * time.Second,
		Script: v.Artifact, Retry: actions.RetryNever, Secrets: append([]string(nil), v.Secrets...),
	}
	if v.Durable {
		a.Retry = actions.RetryReconcileFirst
	}
	for _, p := range v.Params {
		a.Params = append(a.Params, actions.Param{Name: p.Name, Label: p.Label, Pattern: regexp.MustCompile("^" + p.pattern() + "$")})
	}
	return a
}

func riskProto(r string) pb.RiskClass {
	switch r {
	case "LOW":
		return pb.RiskClass_RISK_CLASS_LOW
	case "MEDIUM":
		return pb.RiskClass_RISK_CLASS_MEDIUM
	case "CRITICAL":
		return pb.RiskClass_RISK_CLASS_CRITICAL
	}
	return pb.RiskClass_RISK_CLASS_HIGH
}

// Store keeps runbooks in the server database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New returns a store over the server database.
func New(db *sql.DB) *Store { return &Store{db: db, now: time.Now} }

// Save validates a draft and stores it as the runbook's next version.
func (s *Store) Save(ctx context.Context, user string, d Draft) (Version, error) {
	if !userRe.MatchString(user) {
		return Version{}, errors.New("runbooks: invalid user")
	}
	if err := Validate(d); err != nil {
		return Version{}, err
	}
	if d.Params == nil {
		d.Params = []Param{}
	}
	if d.Secrets == nil {
		d.Secrets = []string{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO runbooks (slug, created_by, created_at) VALUES (?, ?, ?) ON CONFLICT (slug) DO NOTHING`,
		d.Slug, user, now.Unix()); err != nil {
		return Version{}, err
	}
	var last sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT max(version) FROM runbook_versions WHERE slug = ?`, d.Slug).Scan(&last); err != nil {
		return Version{}, err
	}
	v := Version{Draft: d, Version: int(last.Int64) + 1, CreatedBy: user, CreatedAt: now}
	v.Artifact = Artifact(v)
	sum := sha256.Sum256(v.Artifact)
	v.ArtifactSHA256 = hex.EncodeToString(sum[:])
	params, err := json.Marshal(d.Params)
	if err != nil {
		return Version{}, err
	}
	secrets, err := json.Marshal(d.Secrets)
	if err != nil {
		return Version{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO runbook_versions (slug, version, title, description, risk, durable, timeout_s, params, secrets,
		body, artifact, artifact_sha256, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Slug, v.Version, d.Title, d.Description, d.Risk, d.Durable, d.TimeoutS, string(params), string(secrets), []byte(d.Body),
		v.Artifact, v.ArtifactSHA256, user, now.Unix()); err != nil {
		return Version{}, err
	}
	return v, tx.Commit()
}

const versionCols = `slug, version, title, description, risk, durable, timeout_s, params, secrets, body, artifact, artifact_sha256, created_by, created_at`

func scanVersion(row interface{ Scan(...any) error }) (Version, error) {
	var v Version
	var params, secrets string
	var body []byte
	var created int64
	if err := row.Scan(&v.Slug, &v.Version, &v.Title, &v.Description, &v.Risk, &v.Durable, &v.TimeoutS, &params, &secrets, &body,
		&v.Artifact, &v.ArtifactSHA256, &v.CreatedBy, &created); err != nil {
		return Version{}, err
	}
	if err := json.Unmarshal([]byte(secrets), &v.Secrets); err != nil {
		return Version{}, fmt.Errorf("runbooks: stored secret slots: %w", err)
	}
	v.Body = string(body)
	v.CreatedAt = time.Unix(created, 0)
	if err := json.Unmarshal([]byte(params), &v.Params); err != nil {
		return Version{}, fmt.Errorf("runbooks: stored parameters: %w", err)
	}
	// What runs is the stored artifact; it must still be what this
	// version generates (a changed database is caught here, and the
	// executor hashes the bytes again in any case).
	sum := sha256.Sum256(v.Artifact)
	if hex.EncodeToString(sum[:]) != v.ArtifactSHA256 || Validate(v.Draft) != nil || string(Artifact(v)) != string(v.Artifact) {
		return Version{}, fmt.Errorf("runbooks: stored version %s %d does not verify", v.Slug, v.Version)
	}
	return v, nil
}

// Get returns one version of a runbook; version 0 is the latest.
func (s *Store) Get(ctx context.Context, slug string, version int) (Version, error) {
	q := `SELECT ` + versionCols + ` FROM runbook_versions WHERE slug = ? AND version = ?`
	args := []any{slug, version}
	if version == 0 {
		q = `SELECT ` + versionCols + ` FROM runbook_versions WHERE slug = ? ORDER BY version DESC LIMIT 1`
		args = args[:1]
	}
	v, err := scanVersion(s.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	return v, err
}

// Latest returns the latest version of every runbook, by slug.
func (s *Store) Latest(ctx context.Context) ([]Version, error) {
	return s.list(ctx, `SELECT `+versionCols+` FROM runbook_versions v WHERE version = (SELECT max(version) FROM runbook_versions w WHERE w.slug = v.slug) ORDER BY slug`)
}

// Versions returns every version of a runbook, newest first.
func (s *Store) Versions(ctx context.Context, slug string) ([]Version, error) {
	return s.list(ctx, `SELECT `+versionCols+` FROM runbook_versions WHERE slug = ? ORDER BY version DESC`, slug)
}

func (s *Store) list(ctx context.Context, q string, args ...any) ([]Version, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ParseActionVersion splits a runbook action ID and module version into
// slug and version number; ok is false for anything else.
func ParseActionVersion(actionID, moduleVersion string) (slug string, version int, ok bool) {
	slug, found := strings.CutPrefix(actionID, ActionPrefix)
	if !found || !slugRe.MatchString(slug) {
		return "", 0, false
	}
	if moduleVersion == "" {
		return slug, 0, true
	}
	n, found := strings.CutSuffix(moduleVersion, ".0.0")
	v, err := strconv.Atoi(n)
	if !found || err != nil || v < 1 || strconv.Itoa(v) != n {
		return "", 0, false
	}
	return slug, v, true
}
