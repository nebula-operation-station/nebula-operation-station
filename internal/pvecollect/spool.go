// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The pvecollect spool (ADR 0006, P1-10) is the on-disk handoff between the
// collector process and the server-side importer. The collector is the only
// writer; the server revalidates every file before importing it. Spool
// ownership and validation follow docs/spec/09-untrusted-host-data.md:
// atomic writes (temp file + rename, mode 0640), a hard size limit, no
// symlinks followed, strict decoding, and replay rejection on the reading
// side.

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Spool size and layout limits.
const (
	// maxSpoolFileBytes is the hard limit for one spool file; it matches
	// the executor's per-response limit so a collector page never exceeds
	// what the server can revalidate.
	maxSpoolFileBytes = pvecontract.MaxResponseBytes
	// resultsDirName is the subdirectory of the spool root that holds
	// observation files.
	resultsDirName = "results"
	// spoolDirMode is the permission of the spool root and results
	// directory: the owning user (the collector) reads and writes, the
	// group (the server) may list and traverse so it can read the 0640
	// files.
	spoolDirMode = 0o710
	// spoolFileMode is the permission of spool files: the owner reads and
	// writes, the group (the server) reads.
	spoolFileMode = 0o640
	// generationDigits is the fixed width of the collection generation in
	// a spool file name, so lexicographic order matches generation order.
	generationDigits = 20
)

// Sentinel errors for spool operations.
var (
	// ErrSymlink is returned when a symlink is found where a regular file
	// is required.
	ErrSymlink = errors.New("pvecollect: symlink refused")
	// ErrOversize is returned when a spool file exceeds maxSpoolFileBytes.
	ErrOversize = errors.New("pvecollect: spool file exceeds the size limit")
	// ErrReplayed is returned when an observation does not advance the
	// collection watermark of its remote.
	ErrReplayed = errors.New("pvecollect: replayed observation")
	// ErrBadName is returned for malformed spool file names.
	ErrBadName = errors.New("pvecollect: malformed spool file name")
)

// spoolNameRe matches spool file names: <remote_id>.gen-<20-digit
// generation>.json. The remote id must already satisfy
// pvecontract.ValidRemoteID.
var spoolNameRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,63})\.gen-([0-9]{20})\.json$`)

// Spool is the on-disk observation spool. It is safe for concurrent use.
type Spool struct {
	root    string
	results string

	mu   sync.Mutex
	seen map[string]watermark
}

// watermark is the last ingested (generation, observedAt) pair for a
// remote, used by the reading side to reject replays.
type watermark struct {
	generation uint64
	observedAt int64 // unix seconds; nanoseconds are not meaningful here
}

// NewSpool creates or opens the spool rooted at root. The root must be an
// absolute path and must not be a symlink; the results directory is created
// with mode 0710 (the server group lists and traverses it to read the 0640
// files).
func NewSpool(root string) (*Spool, error) {
	if filepath.IsAbs(root) != true {
		return nil, fmt.Errorf("pvecollect: spool root %q must be an absolute path", root)
	}
	if err := checkDirNoSymlink(root); err != nil {
		return nil, fmt.Errorf("pvecollect: spool root: %w", err)
	}
	rootExisted := true
	if _, err := os.Lstat(root); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pvecollect: spool root: %w", err)
		}
		rootExisted = false
	}
	results := filepath.Join(root, resultsDirName)
	if err := os.MkdirAll(results, spoolDirMode); err != nil {
		return nil, fmt.Errorf("pvecollect: create results dir: %w", err)
	}
	// MkdirAll applies the mode through the process umask; chmod makes the
	// group access deterministic.
	if !rootExisted {
		if err := os.Chmod(root, spoolDirMode); err != nil {
			return nil, fmt.Errorf("pvecollect: chmod spool root: %w", err)
		}
	}
	if err := os.Chmod(results, spoolDirMode); err != nil {
		return nil, fmt.Errorf("pvecollect: chmod results dir: %w", err)
	}
	if err := checkDirNoSymlink(results); err != nil {
		return nil, fmt.Errorf("pvecollect: results dir: %w", err)
	}
	return &Spool{root: root, results: results, seen: make(map[string]watermark)}, nil
}

// ResultsDir returns the directory that holds observation files.
func (s *Spool) ResultsDir() string { return s.results }

// checkDirNoSymlink verifies that path exists, is a directory, and is not a
// symlink (neither the path itself nor any parent component may be a
// symlink that escapes the intended location).
func checkDirNoSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // MkdirAll will create it
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return ErrSymlink
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

// spoolFileName derives the flat spool file name for an observation.
func spoolFileName(remoteID string, generation uint64) (string, error) {
	if !pvecontract.ValidRemoteID(remoteID) {
		return "", fmt.Errorf("pvecollect: malformed remote id %q", remoteID)
	}
	if generation == 0 {
		return "", errors.New("pvecollect: collection generation must be positive")
	}
	return fmt.Sprintf("%s.gen-%0*d.json", remoteID, generationDigits, generation), nil
}

// parseSpoolName splits a spool file name into (remoteID, generation).
func parseSpoolName(name string) (string, uint64, error) {
	m := spoolNameRe.FindStringSubmatch(name)
	if m == nil {
		return "", 0, fmt.Errorf("%w: %q", ErrBadName, name)
	}
	var gen uint64
	for _, c := range m[2] {
		gen = gen*10 + uint64(c-'0')
	}
	return m[1], gen, nil
}

// WriteFile validates obs, marshals it to strict JSON, and writes it to the
// results directory atomically (temp file + fsync + rename, mode 0640).
// Rewriting a file with identical content is accepted (idempotent retry);
// a different payload under the same name is refused. It returns the final
// file path.
func (s *Spool) WriteFile(_ context.Context, obs pvecontract.Observation) (string, error) {
	name, err := spoolFileName(obs.RemoteID, obs.CollectionGeneration)
	if err != nil {
		return "", err
	}
	raw, err := pvecontract.MarshalObservation(obs)
	if err != nil {
		return "", fmt.Errorf("pvecollect: marshal observation: %w", err)
	}
	if len(raw) > maxSpoolFileBytes {
		return "", fmt.Errorf("%w: %d bytes", ErrOversize, len(raw))
	}
	final := filepath.Join(s.results, name)

	// Never follow or silently replace a pre-planted symlink.
	if fi, err := os.Lstat(final); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: %s", ErrSymlink, name)
		}
		if existing, err := os.ReadFile(final); err == nil {
			if string(existing) != string(raw) {
				return "", fmt.Errorf("pvecollect: %s already exists with different content", name)
			}
			return final, nil // idempotent retry
		}
	}

	tmp, err := os.CreateTemp(s.results, name+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("pvecollect: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return "", fmt.Errorf("pvecollect: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("pvecollect: sync temp file: %w", err)
	}
	if err := tmp.Chmod(spoolFileMode); err != nil {
		tmp.Close()
		return "", fmt.Errorf("pvecollect: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("pvecollect: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return "", fmt.Errorf("pvecollect: rename temp file: %w", err)
	}
	tmpName = ""
	return final, nil
}

// ReadFile reads and revalidates one spool file by name: the name must be a
// well-formed flat name, the entry must be a regular file (no symlinks),
// the size must be within the limit, the document must decode strictly, and
// the document's remote id and generation must match the file name.
func (s *Spool) ReadFile(_ context.Context, name string) (pvecontract.Observation, error) {
	remoteID, gen, err := parseSpoolName(name)
	if err != nil {
		return pvecontract.Observation{}, err
	}
	path := filepath.Join(s.results, name)
	fi, err := os.Lstat(path)
	if err != nil {
		return pvecontract.Observation{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return pvecontract.Observation{}, fmt.Errorf("%w: %s", ErrSymlink, name)
	}
	if !fi.Mode().IsRegular() {
		return pvecontract.Observation{}, fmt.Errorf("pvecollect: %s is not a regular file", name)
	}
	if fi.Size() > maxSpoolFileBytes {
		return pvecontract.Observation{}, fmt.Errorf("%w: %s is %d bytes", ErrOversize, name, fi.Size())
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return pvecontract.Observation{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSpoolFileBytes+1))
	if err != nil {
		return pvecontract.Observation{}, err
	}
	if len(raw) > maxSpoolFileBytes {
		return pvecontract.Observation{}, fmt.Errorf("%w: %s", ErrOversize, name)
	}
	obs, err := pvecontract.DecodeObservation(raw)
	if err != nil {
		return pvecontract.Observation{}, fmt.Errorf("pvecollect: decode %s: %w", name, err)
	}
	if obs.RemoteID != remoteID || obs.CollectionGeneration != gen {
		return pvecontract.Observation{}, fmt.Errorf("pvecollect: %s does not match its document (remote %q gen %d)", name, obs.RemoteID, obs.CollectionGeneration)
	}
	return obs, nil
}

// List returns the names of all regular, non-symlink spool files, sorted.
// It refuses the whole listing if any entry in the results directory is a
// symlink.
func (s *Spool) List(_ context.Context) ([]string, error) {
	entries, err := os.ReadDir(s.results)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s", ErrSymlink, e.Name())
		}
		if !e.Type().IsRegular() {
			continue
		}
		if _, _, err := parseSpoolName(e.Name()); err != nil {
			continue // temp files and foreign names are ignored
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// CheckReplay reports whether obs is a replay for its remote, using the
// in-memory watermark set by MarkIngested. An observation is accepted when
// it has a newer generation, or the same generation with an observedAt not
// earlier than the watermark. It does not mutate state.
func (s *Spool) CheckReplay(obs pvecontract.Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.seen[obs.RemoteID]
	if !ok {
		return nil
	}
	if obs.CollectionGeneration < w.generation {
		return fmt.Errorf("%w: %s gen %d < %d", ErrReplayed, obs.RemoteID, obs.CollectionGeneration, w.generation)
	}
	if obs.CollectionGeneration == w.generation && obs.ObservedAt.Unix() < w.observedAt {
		return fmt.Errorf("%w: %s gen %d observed earlier than the watermark", ErrReplayed, obs.RemoteID, obs.CollectionGeneration)
	}
	return nil
}

// MarkIngested advances the in-memory watermark for obs's remote. The
// importer calls it after a successful IngestObservation.
func (s *Spool) MarkIngested(obs pvecontract.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := watermark{generation: obs.CollectionGeneration, observedAt: obs.ObservedAt.Unix()}
	if cur, ok := s.seen[obs.RemoteID]; !ok || w.generation > cur.generation || (w.generation == cur.generation && w.observedAt > cur.observedAt) {
		s.seen[obs.RemoteID] = w
	}
}

// Remove deletes a spool file by name. It refuses symlinks and names that
// do not parse.
func (s *Spool) Remove(_ context.Context, name string) error {
	if _, _, err := parseSpoolName(name); err != nil {
		return err
	}
	path := filepath.Join(s.results, name)
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, name)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("pvecollect: %s is not a regular file", name)
	}
	return os.Remove(path)
}
