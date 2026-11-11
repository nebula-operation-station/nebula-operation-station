// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Store layout and limits.
const (
	// objectsDir holds snapshot files named by their SHA-256.
	objectsDir = "objects"
	// manifestsDir holds one manifest per feed, "<feed>.json".
	manifestsDir = "manifests"
	// tmpPrefix marks files that are not committed yet. They are never
	// read and are removed when the store is opened.
	tmpPrefix = ".tmp-"
	// MaxManifestBytes caps a manifest file.
	MaxManifestBytes = 64 << 10
	// MaxFutureSkew: a content date later than the clock plus this skew is
	// invalid (D4).
	MaxFutureSkew = 10 * time.Minute
)

// Snapshot store errors.
var (
	// ErrNoSnapshot: the feed has no accepted snapshot yet.
	ErrNoSnapshot = errors.New("vulnfeed: no accepted snapshot")
	// ErrRollback: the content date or sequence is below the newest ever
	// accepted for the feed; the previous snapshot stays in use.
	ErrRollback = errors.New("vulnfeed: snapshot older than the newest accepted")
	// ErrNoContentDate: a dated or proxy-dated feed has no content date.
	ErrNoContentDate = errors.New("vulnfeed: no content date")
	// ErrInvalidContentDate: an undated feed was given a content date.
	ErrInvalidContentDate = errors.New("vulnfeed: invalid content date")
	// ErrFutureContentDate: the content date lies beyond the allowed skew.
	ErrFutureContentDate = errors.New("vulnfeed: content date in the future")
	// ErrCorruptManifest: a manifest is unreadable or invalid. The feed's
	// high-water mark is unknown, so no new snapshot is accepted.
	ErrCorruptManifest = errors.New("vulnfeed: corrupt manifest")
	// ErrCorruptSnapshot: a snapshot file does not match its manifest.
	ErrCorruptSnapshot = errors.New("vulnfeed: corrupt snapshot")
	// ErrStageClosed: the staged file was already committed or aborted.
	ErrStageClosed = errors.New("vulnfeed: staged file closed")
)

// sha256HexRe is a lower-case SHA-256 hex digest.
var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HighWater is a feed's newest values ever accepted (D4 monotonicity).
type HighWater struct {
	ContentDate time.Time `json:"content_date,omitzero"`
	Sequence    uint64    `json:"sequence,omitempty"`
}

// Manifest describes a feed's current accepted snapshot.
type Manifest struct {
	Feed      string                    `json:"feed"`
	SourceID  string                    `json:"source_id"`
	SHA256    string                    `json:"sha256"`
	Size      int64                     `json:"size"`
	Integrity vulnfinding.IntegrityMode `json:"integrity"`
	DateKind  DateKind                  `json:"date_kind"`
	// FetchedAt is the agent's clock at commit; audit only, never a
	// content date.
	FetchedAt time.Time `json:"fetched_at"`
	// ContentDate comes from the data or a proxy companion; zero when
	// undated.
	ContentDate time.Time  `json:"content_date,omitzero"`
	Sequence    uint64     `json:"sequence,omitempty"`
	Validators  Validators `json:"validators,omitzero"`
	HighWater   HighWater  `json:"high_water,omitzero"`
}

// SnapshotID is the content-addressed snapshot ID ("sha256:<hex>", 71
// bytes, within the D5 snapshot ID pattern).
func (m Manifest) SnapshotID() string { return "sha256:" + m.SHA256 }

// Accept carries what the data says about a staged snapshot.
type Accept struct {
	// ContentDate from the data (dated) or the proxy companions (proxy);
	// zero for undated feeds.
	ContentDate time.Time
	// Sequence of a signed offline bundle; zero otherwise.
	Sequence uint64
	// Validators of the response, kept for the next conditional fetch.
	Validators Validators
}

// Store is a content-addressed snapshot store under one data directory.
type Store struct {
	dir string
	now func() time.Time
	mu  sync.Mutex // serialises commits
}

// OpenStore opens (creating if needed) the store under dir and removes
// temporary files left by an interrupted write. now defaults to time.Now.
func OpenStore(dir string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	for _, sub := range []string{objectsDir, manifestsDir} {
		p := filepath.Join(dir, sub)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, fmt.Errorf("open snapshot store: %w", err)
		}
		ents, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("open snapshot store: %w", err)
		}
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), tmpPrefix) {
				if err := os.Remove(filepath.Join(p, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return nil, fmt.Errorf("open snapshot store: remove leftover: %w", err)
				}
			}
		}
	}
	return &Store{dir: dir, now: now}, nil
}

// Staged is a snapshot being written. It hashes while writing and refuses
// to grow beyond the feed's cap. Commit or Abort it exactly once.
type Staged struct {
	f      *os.File
	max    int64
	size   int64
	h256   hash.Hash
	h512   hash.Hash // only for sha512 checksum feeds
	closed bool
}

// Stage starts a new snapshot for feed.
func (s *Store) Stage(feed Feed) (*Staged, error) {
	if err := feed.validate(); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Join(s.dir, objectsDir), tmpPrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("stage %s: %w", feed.Name, err)
	}
	st := &Staged{f: f, max: feed.MaxBytes, h256: sha256.New()}
	if feed.Checksum == ChecksumSHA512 {
		st.h512 = sha512.New()
	}
	return st, nil
}

// Write appends p, failing with ErrTooLarge past the cap.
func (st *Staged) Write(p []byte) (int, error) {
	if st.closed {
		return 0, ErrStageClosed
	}
	if int64(len(p)) > st.max-st.size {
		return 0, fmt.Errorf("staged snapshot over %d bytes: %w", st.max, ErrTooLarge)
	}
	n, err := st.f.Write(p)
	st.size += int64(n)
	st.h256.Write(p[:n])
	if st.h512 != nil {
		st.h512.Write(p[:n])
	}
	if err != nil {
		return n, fmt.Errorf("write staged snapshot: %w", err)
	}
	return n, nil
}

// digest returns the hex digest for alg ("" or sha256: SHA-256).
func (st *Staged) digest(alg ChecksumAlg) (string, bool) {
	switch alg {
	case "", ChecksumSHA256:
		return hex.EncodeToString(st.h256.Sum(nil)), true
	case ChecksumSHA512:
		if st.h512 == nil {
			return "", false
		}
		return hex.EncodeToString(st.h512.Sum(nil)), true
	}
	return "", false
}

// Reader returns a reader over the staged bytes from the start, for
// extracting the content date before Commit.
func (st *Staged) Reader() (io.Reader, error) {
	if st.closed {
		return nil, ErrStageClosed
	}
	if _, err := st.f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind staged snapshot: %w", err)
	}
	return io.LimitReader(st.f, st.size), nil
}

// Abort discards the staged file. It is safe to call more than once.
func (st *Staged) Abort() {
	if st.closed {
		return
	}
	st.closed = true
	_ = st.f.Close()
	_ = os.Remove(st.f.Name())
}

// Commit accepts the staged snapshot for feed if the D4 date rules allow
// it, and otherwise aborts it and keeps the previous snapshot. Content
// date and sequence must not fall below the newest values ever accepted;
// a dated feed needs a content date from the data (never the fetch time);
// an undated feed must have none; a date beyond MaxFutureSkew is invalid.
// The object is fsynced and renamed into place before the manifest is
// replaced atomically, so a crash leaves either the old or the new state.
func (s *Store) Commit(feed Feed, st *Staged, a Accept) (Manifest, error) {
	if st == nil || st.closed {
		return Manifest{}, ErrStageClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.checkAccept(feed, a)
	if err != nil {
		st.Abort()
		return Manifest{}, err
	}
	m.SHA256, _ = st.digest(ChecksumSHA256)
	m.Size = st.size
	if err := st.f.Sync(); err != nil {
		st.Abort()
		return Manifest{}, fmt.Errorf("commit %s: sync: %w", feed.Name, err)
	}
	if err := st.f.Close(); err != nil {
		st.Abort()
		return Manifest{}, fmt.Errorf("commit %s: close: %w", feed.Name, err)
	}
	st.closed = true
	objDir := filepath.Join(s.dir, objectsDir)
	if err := os.Rename(st.f.Name(), filepath.Join(objDir, m.SHA256)); err != nil {
		_ = os.Remove(st.f.Name())
		return Manifest{}, fmt.Errorf("commit %s: rename: %w", feed.Name, err)
	}
	if err := syncDir(objDir); err != nil {
		return Manifest{}, fmt.Errorf("commit %s: %w", feed.Name, err)
	}
	if err := s.writeManifest(m); err != nil {
		return Manifest{}, fmt.Errorf("commit %s: %w", feed.Name, err)
	}
	return m, nil
}

// checkAccept applies the date and sequence rules and returns the new
// manifest without its content fields.
func (s *Store) checkAccept(feed Feed, a Accept) (Manifest, error) {
	if err := feed.validate(); err != nil {
		return Manifest{}, err
	}
	prev, err := s.Load(feed.Name)
	switch {
	case errors.Is(err, ErrNoSnapshot):
		prev = Manifest{}
	case err != nil:
		return Manifest{}, fmt.Errorf("commit %s: %w", feed.Name, err)
	}
	now := s.now().UTC()
	switch feed.DateKind {
	case DateKindDated, DateKindProxy:
		if a.ContentDate.IsZero() {
			return Manifest{}, fmt.Errorf("commit %s: %w", feed.Name, ErrNoContentDate)
		}
		if a.ContentDate.After(now.Add(MaxFutureSkew)) {
			return Manifest{}, fmt.Errorf("commit %s: %w", feed.Name, ErrFutureContentDate)
		}
		if a.ContentDate.Before(prev.HighWater.ContentDate) {
			return Manifest{}, fmt.Errorf("commit %s: content date %s before %s: %w", feed.Name,
				a.ContentDate.UTC().Format(time.RFC3339), prev.HighWater.ContentDate.UTC().Format(time.RFC3339), ErrRollback)
		}
	case DateKindUndated:
		if !a.ContentDate.IsZero() {
			return Manifest{}, fmt.Errorf("commit %s: undated feed with a date: %w", feed.Name, ErrInvalidContentDate)
		}
	}
	if (a.Sequence != 0 || prev.HighWater.Sequence != 0) && a.Sequence <= prev.HighWater.Sequence {
		return Manifest{}, fmt.Errorf("commit %s: sequence %d not above %d: %w", feed.Name, a.Sequence, prev.HighWater.Sequence, ErrRollback)
	}
	m := Manifest{
		Feed: feed.Name, SourceID: feed.SourceID, Integrity: feed.Integrity, DateKind: feed.DateKind,
		FetchedAt: now, ContentDate: a.ContentDate.UTC(), Sequence: a.Sequence,
		Validators: sanitizeValidators(a.Validators.ETag, a.Validators.LastModified),
		HighWater:  prev.HighWater,
	}
	if m.ContentDate.After(m.HighWater.ContentDate) {
		m.HighWater.ContentDate = m.ContentDate
	}
	if m.Sequence > m.HighWater.Sequence {
		m.HighWater.Sequence = m.Sequence
	}
	return m, nil
}

// writeManifest replaces the feed's manifest atomically.
func (s *Store) writeManifest(m Manifest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	dir := filepath.Join(s.dir, manifestsDir)
	f, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, m.Feed+".json")); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write manifest: rename: %w", err)
	}
	return syncDir(dir)
}

// Load returns the feed's current manifest, ErrNoSnapshot if there is
// none, or ErrCorruptManifest.
func (s *Store) Load(feedName string) (Manifest, error) {
	if !feedNameRe.MatchString(feedName) {
		return Manifest{}, fmt.Errorf("load manifest: %w", ErrInvalidFeed)
	}
	f, err := os.Open(filepath.Join(s.dir, manifestsDir, feedName+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, ErrNoSnapshot
	}
	if err != nil {
		return Manifest{}, fmt.Errorf("load manifest %s: %w", feedName, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("load manifest %s: %w", feedName, err)
	}
	if len(b) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("load manifest %s: oversize: %w", feedName, ErrCorruptManifest)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || dec.More() {
		return Manifest{}, fmt.Errorf("load manifest %s: decode: %w", feedName, ErrCorruptManifest)
	}
	if m.Feed != feedName || !sourceIDRe.MatchString(m.SourceID) || !sha256HexRe.MatchString(m.SHA256) || m.Size < 0 {
		return Manifest{}, fmt.Errorf("load manifest %s: fields: %w", feedName, ErrCorruptManifest)
	}
	switch m.Integrity {
	case vulnfinding.IntegrityNone, vulnfinding.IntegrityChecksum, vulnfinding.IntegritySigned:
	default:
		return Manifest{}, fmt.Errorf("load manifest %s: integrity: %w", feedName, ErrCorruptManifest)
	}
	switch m.DateKind {
	case DateKindDated, DateKindProxy, DateKindUndated:
	default:
		return Manifest{}, fmt.Errorf("load manifest %s: date kind: %w", feedName, ErrCorruptManifest)
	}
	return m, nil
}

// Verify re-hashes the snapshot file of m.
func (s *Store) Verify(m Manifest) error {
	if !sha256HexRe.MatchString(m.SHA256) {
		return fmt.Errorf("verify snapshot: %w", ErrCorruptSnapshot)
	}
	f, err := os.Open(filepath.Join(s.dir, objectsDir, m.SHA256))
	if err != nil {
		return fmt.Errorf("verify snapshot %s: %w", m.Feed, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, m.Size+1))
	if err != nil {
		return fmt.Errorf("verify snapshot %s: %w", m.Feed, err)
	}
	if n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return fmt.Errorf("verify snapshot %s: %w", m.Feed, ErrCorruptSnapshot)
	}
	return nil
}

// ProxyDate returns the proxy content date of a proxy-dated feed: the
// newest content date among its companions' accepted snapshots (D4, Q5).
// Without any dated companion snapshot it fails with ErrNoContentDate;
// the fetch time is never used instead.
func (s *Store) ProxyDate(feed Feed) (time.Time, error) {
	if feed.DateKind != DateKindProxy {
		return time.Time{}, fmt.Errorf("proxy date of %s: not proxy-dated: %w", feed.Name, ErrInvalidFeed)
	}
	var newest time.Time
	for _, c := range feed.ProxyCompanions {
		m, err := s.Load(c)
		if errors.Is(err, ErrNoSnapshot) {
			continue
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("proxy date of %s: %w", feed.Name, err)
		}
		if m.DateKind == DateKindDated && m.ContentDate.After(newest) {
			newest = m.ContentDate
		}
	}
	if newest.IsZero() {
		return time.Time{}, fmt.Errorf("proxy date of %s: %w", feed.Name, ErrNoContentDate)
	}
	return newest, nil
}

// syncDir fsyncs a directory so a rename in it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	serr := d.Sync()
	cerr := d.Close()
	if err := errors.Join(serr, cerr); err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	return nil
}
