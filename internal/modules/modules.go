// SPDX-License-Identifier: AGPL-3.0-or-later

// Package modules imports and stores modules on the server (M7-5, spec
// 10). An import is a .tar.gz with the signed lock (module.lock.json), its
// SSH signature (module.lock.json.sig, optional) and the scripts the lock
// names. The executor decides trust: the server hands it lock, signature
// and scripts (RegisterModule) and records its verdict. A version never
// changes; only its verdict can be renewed.
package modules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Archive members.
const (
	LockFile      = "module.lock.json"
	SignatureFile = "module.lock.json.sig"
)

// Limits of an import.
const (
	MaxArchive  = 1 << 20
	MaxEntries  = 64
	MaxUnpacked = 4 << 20
	maxDetail   = 400
)

// States.
const (
	StateVerified   = "verified"
	StateUnverified = "unverified"
)

// Registrar is the executor's RegisterModule.
type Registrar interface {
	RegisterModule(ctx context.Context, in *pb.RegisterModuleRequest, opts ...grpc.CallOption) (*pb.RegisterModuleResponse, error)
}

// Version is one imported module version.
type Version struct {
	Lock       modulelock.Lock
	LockJSON   []byte
	LockSHA256 string
	Signature  []byte
	Scripts    map[string][]byte
	State      string
	Signer     string
	Detail     string
	ImportedBy string
	ImportedAt time.Time
}

// ImportError says what is wrong with an archive; its text is safe to show.
type ImportError struct{ Reason string }

func (e *ImportError) Error() string { return "module not imported: " + e.Reason }

func refuse(format string, a ...any) error { return &ImportError{Reason: fmt.Sprintf(format, a...)} }

// ErrNotFound is an unknown module or version.
var ErrNotFound = errors.New("module not found")

var userRe = regexp.MustCompile(`^[\x21-\x7e]{1,64}$`)

// Store keeps modules in the server database.
type Store struct {
	db   *sql.DB
	exec Registrar
	now  func() time.Time
}

// New returns a store; exec verifies modules (nil: every module stays
// unverified).
func New(db *sql.DB, exec Registrar) *Store { return &Store{db: db, exec: exec, now: time.Now} }

// unpack reads the archive into its files.
func unpack(archive []byte) (map[string][]byte, error) {
	if len(archive) == 0 || len(archive) > MaxArchive {
		return nil, refuse("the archive must be 1 byte to %d KiB", MaxArchive>>10)
	}
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, refuse("not a .tar.gz archive")
	}
	tr := tar.NewReader(io.LimitReader(zr, MaxUnpacked+1))
	files := map[string][]byte{}
	total, entries := 0, 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, refuse("the archive is damaged or too large")
		}
		entries++
		if entries > MaxEntries {
			return nil, refuse("at most %d entries", MaxEntries)
		}
		name := strings.TrimPrefix(h.Name, "./")
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, refuse("%q is not a regular file (no links or devices)", name)
		}
		if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.HasPrefix(name, "../") || name == ".." {
			return nil, refuse("%q is not a plain relative path", name)
		}
		if _, dup := files[name]; dup {
			return nil, refuse("%q appears twice", name)
		}
		if h.Size < 0 || h.Size > modulelock.MaxScript {
			return nil, refuse("%q is larger than %d KiB", name, modulelock.MaxScript>>10)
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(b)) != h.Size {
			return nil, refuse("the archive is damaged")
		}
		total += len(b)
		if total > MaxUnpacked {
			return nil, refuse("the archive unpacks to more than %d MiB", MaxUnpacked>>20)
		}
		files[name] = b
	}
	return files, nil
}

// Import reads an archive, asks the executor to verify it and stores the
// version with the executor's verdict.
func (s *Store) Import(ctx context.Context, user string, archive []byte) (Version, error) {
	if !userRe.MatchString(user) {
		return Version{}, errors.New("modules: invalid user")
	}
	files, err := unpack(archive)
	if err != nil {
		return Version{}, err
	}
	lockJSON, ok := files[LockFile]
	if !ok {
		return Version{}, refuse("the archive has no %s (run nebula module pack)", LockFile)
	}
	lock, lockSum, err := modulelock.Parse(lockJSON)
	if err != nil {
		return Version{}, refuse("%v", err)
	}
	v := Version{Lock: lock, LockJSON: lockJSON, LockSHA256: lockSum, Signature: files[SignatureFile], Scripts: map[string][]byte{},
		ImportedBy: user, ImportedAt: s.now()}
	// The archive holds the lock, its signature, the lock's scripts and
	// optionally the author's module.yaml (not stored), nothing else.
	wanted := map[string]bool{LockFile: true, SignatureFile: true, "module.yaml": true}
	for _, name := range lock.Names() {
		wanted[lock.Actions[name].Script] = true
	}
	for f := range files {
		if !wanted[f] {
			return Version{}, refuse("the archive holds %q, which the lock does not name", f)
		}
	}
	for _, name := range lock.Names() {
		p := lock.Actions[name].Script
		b, ok := files[p]
		if !ok {
			return Version{}, refuse("the archive lacks %s (action %s)", p, name)
		}
		if _, _, err := lock.Artifact(name, b); err != nil {
			return Version{}, refuse("%v", err)
		}
		v.Scripts[p] = b
	}
	if err := s.verify(ctx, &v); err != nil {
		return Version{}, err
	}
	scripts, err := json.Marshal(v.Scripts)
	if err != nil {
		return Version{}, err
	}
	sig := v.Signature
	if sig == nil {
		sig = []byte{}
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO module_versions (name, version, lock, lock_sha256, signature, scripts, state, signer, detail,
		imported_by, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		lock.Name, lock.Version, lockJSON, lockSum, sig, scripts, v.State, v.Signer, v.Detail, user, v.ImportedAt.Unix()); err != nil {
		var existing string
		if s.db.QueryRowContext(ctx, `SELECT lock_sha256 FROM module_versions WHERE name = ? AND version = ?`, lock.Name, lock.Version).Scan(&existing) == nil {
			return Version{}, refuse("%s %s is imported already; publish a new version for changes", lock.Name, lock.Version)
		}
		return Version{}, err
	}
	return v, nil
}

// verify asks the executor and sets State, Signer and Detail. Only a
// malformed module is an error.
func (s *Store) verify(ctx context.Context, v *Version) error {
	v.State, v.Signer = StateUnverified, ""
	switch {
	case len(v.Signature) == 0:
		v.Detail = "not signed: its actions run at least HIGH"
		return nil
	case s.exec == nil:
		v.Detail = "the executor is not connected; verify again later"
		return nil
	}
	r, err := s.exec.RegisterModule(ctx, &pb.RegisterModuleRequest{LockJson: v.LockJSON, Signature: v.Signature, Scripts: v.Scripts})
	if err != nil {
		st, _ := status.FromError(err)
		switch st.Code() {
		case codes.InvalidArgument:
			return refuse("the executor refused it: %s", clip(st.Message()))
		case codes.PermissionDenied, codes.FailedPrecondition:
			v.Detail = "the executor does not trust it: " + clip(st.Message())
		default:
			v.Detail = "the executor could not be asked; verify again later"
		}
		return nil
	}
	// The executor built the artifacts itself; they must be the ones this
	// server runs.
	want := map[string]string{}
	for _, a := range v.Actions() {
		want[a.ID] = a.SHA256()
	}
	for _, a := range r.GetActions() {
		if want[a.GetActionId()] != a.GetArtifactSha256() || a.GetModuleVersion() != v.Lock.Version {
			v.Detail = "the executor's artifacts differ from this server's; not used"
			return nil
		}
	}
	if len(r.GetActions()) != len(want) || r.GetLockSha256() != v.LockSHA256 {
		v.Detail = "the executor's answer does not match the module; not used"
		return nil
	}
	v.State, v.Signer, v.Detail = StateVerified, clip(r.GetSignerName()+" ("+r.GetSignerFingerprint()+")"), ""
	return nil
}

func clip(s string) string {
	if !prelude.Clean(s, false) {
		return "(unprintable text)"
	}
	if len(s) > maxDetail-60 {
		s = s[:maxDetail-60]
	}
	return s
}

// Verify asks the executor again (after a signer was added or confirmed).
func (s *Store) Verify(ctx context.Context, name, version string) (Version, error) {
	v, err := s.Get(ctx, name, version)
	if err != nil {
		return Version{}, err
	}
	if err := s.verify(ctx, &v); err != nil {
		return Version{}, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE module_versions SET state = ?, signer = ?, detail = ? WHERE name = ? AND version = ?`,
		v.State, v.Signer, v.Detail, v.Lock.Name, v.Lock.Version); err != nil {
		return Version{}, err
	}
	return v, nil
}

const cols = `lock, signature, scripts, state, signer, detail, imported_by, imported_at`

func scan(row interface{ Scan(...any) error }) (Version, error) {
	var v Version
	var scripts []byte
	var at int64
	if err := row.Scan(&v.LockJSON, &v.Signature, &scripts, &v.State, &v.Signer, &v.Detail, &v.ImportedBy, &at); err != nil {
		return Version{}, err
	}
	v.ImportedAt = time.Unix(at, 0)
	l, sum, err := modulelock.Parse(v.LockJSON)
	if err != nil {
		return Version{}, fmt.Errorf("modules: stored lock: %w", err)
	}
	v.Lock, v.LockSHA256 = l, sum
	if err := json.Unmarshal(scripts, &v.Scripts); err != nil {
		return Version{}, fmt.Errorf("modules: stored scripts: %w", err)
	}
	for _, name := range l.Names() {
		if _, _, err := l.Artifact(name, v.Scripts[l.Actions[name].Script]); err != nil {
			return Version{}, fmt.Errorf("modules: stored version %s %s does not verify: %w", l.Name, l.Version, err)
		}
	}
	if len(v.Signature) == 0 {
		v.Signature = nil
	}
	return v, nil
}

// Get returns a version; "" is the latest.
func (s *Store) Get(ctx context.Context, name, version string) (Version, error) {
	if version == "" {
		all, err := s.Versions(ctx, name)
		if err != nil {
			return Version{}, err
		}
		if len(all) == 0 {
			return Version{}, ErrNotFound
		}
		return all[0], nil
	}
	v, err := scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM module_versions WHERE name = ? AND version = ?`, name, version))
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	return v, err
}

// Versions returns a module's versions, newest first.
func (s *Store) Versions(ctx context.Context, name string) ([]Version, error) {
	return s.list(ctx, `SELECT `+cols+` FROM module_versions WHERE name = ?`, name)
}

// Latest returns the latest version of every module, by name.
func (s *Store) Latest(ctx context.Context) ([]Version, error) {
	all, err := s.list(ctx, `SELECT `+cols+` FROM module_versions`)
	if err != nil {
		return nil, err
	}
	var out []Version
	seen := map[string]bool{}
	for _, v := range all {
		if !seen[v.Lock.Name] {
			seen[v.Lock.Name] = true
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Lock.Name < out[j].Lock.Name })
	return out, nil
}

func (s *Store) list(ctx context.Context, q string, args ...any) ([]Version, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Lock.Name != out[j].Lock.Name {
			return out[i].Lock.Name < out[j].Lock.Name
		}
		return newer(out[i].Lock.Version, out[j].Lock.Version)
	})
	return out, nil
}

// newer compares X.Y.Z versions.
func newer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// Actions are the version's actions as the operation engine runs them.
func (v Version) Actions() []actions.Action {
	var out []actions.Action
	for _, name := range v.Lock.Names() {
		la := v.Lock.Actions[name]
		art, _, err := v.Lock.Artifact(name, v.Scripts[la.Script])
		if err != nil {
			continue
		}
		a := actions.Action{ID: v.Lock.ActionID(name), Version: v.Lock.Version, Title: la.Title, Description: la.Description,
			Risk: riskProto(la.Risk), Durable: la.Durable, Timeout: time.Duration(la.TimeoutS) * time.Second, Script: art,
			Retry: actions.RetryNever, Secrets: append([]string(nil), la.Secrets...)}
		if la.Durable {
			a.Retry = actions.RetryReconcileFirst
		}
		for _, p := range la.Params {
			a.Params = append(a.Params, actions.Param{Name: p.Name, Label: p.Label, Pattern: regexp.MustCompile("^" + p.Pattern() + "$")})
		}
		out = append(out, a)
	}
	return out
}

// Action finds one action of the version.
func (v Version) Action(id string) (actions.Action, bool) {
	for _, a := range v.Actions() {
		if a.ID == id {
			return a, true
		}
	}
	return actions.Action{}, false
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

// ScriptSHA256 is the hex SHA-256 of b (for display).
func ScriptSHA256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
