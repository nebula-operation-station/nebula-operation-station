// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// Monitor limits and defaults.
const (
	// DefaultInterval is the period of the I1 self-check after the start
	// check (ADR 0015 D4 "When", Q2: every 60 minutes).
	DefaultInterval = 60 * time.Minute
	// MaxStatusDeviations bounds the deviating files a SelfCheck lists
	// and a run logs one by one; the counts stay exact.
	MaxStatusDeviations = 64
)

// RootCompromiseNote is shown next to every I1 result (ADR 0015 D4).
const RootCompromiseNote = "NOS checks cannot detect a root compromise of the NOS machine; see ADR 0015"

// Sentinel errors of LoadReference.
var (
	// ErrNotCheckable is an installation without any installed-files
	// list to check against. It is never reported as ok.
	ErrNotCheckable = errors.New("integrity: no installed-files list, check not possible")
	// ErrDevelopmentBuild is a running version that is not a release
	// version. It wraps ErrNotCheckable.
	ErrDevelopmentBuild = fmt.Errorf("%w: development build", ErrNotCheckable)
	// ErrNoInstalledFiles is a release version whose installed-files.json
	// or reference directory is missing (corruption, partial upgrade).
	// The check could not run completely (ADR 0015 D4), so it does not
	// wrap ErrNotCheckable.
	ErrNoInstalledFiles = errors.New("integrity: installed-files list of the release is missing")
)

// State is the overall outcome of the latest self-check.
type State string

// States.
const (
	// StatePending: no check has finished yet.
	StatePending State = "pending"
	// StateOK: a complete check found every listed file as signed.
	StateOK State = "ok"
	// StateDeviations: at least one file differs, is missing or is an
	// unlisted NOS binary.
	StateDeviations State = "deviations"
	// StateIncomplete: the check could not run or not run completely
	// (rejected reference, I/O error, limit). Never clean (ADR 0015 D4).
	StateIncomplete State = "incomplete"
	// StateNotCheckable: a development build, which has no list to
	// check against. A release without its list is StateIncomplete.
	StateNotCheckable State = "not-checkable"
)

// Fixed causes in SelfCheck.Cause; a run stopped by a limit uses its
// Incomplete value instead.
const (
	// CauseNoList: the release's installed-files.json or the reference
	// directory is missing (StateIncomplete).
	CauseNoList = "no-installed-files-list"
	// CauseDevelopmentBuild: the running version is not a release.
	CauseDevelopmentBuild = "development-build"
	// CauseReferenceRejected: the list, manifest or signature is
	// missing, unreadable or did not verify.
	CauseReferenceRejected = "reference-rejected"
	// CauseCheckFailed: the check could not start (unknown flavour,
	// root not openable, invalid options).
	CauseCheckFailed = "check-failed"
	// CauseUnreadable: listed files could not be read.
	CauseUnreadable = "unreadable-files"
)

// Deviation is one file whose status is not ok. It never holds file
// content.
type Deviation struct {
	// Path is the listed path, or an escaped unlisted /usr/bin name.
	Path string `json:"path"`
	// Class is the ADR 0015 D4 class.
	Class Class `json:"class"`
	// Status is the file's outcome.
	Status Status `json:"status"`
	// Reason details different and unreadable files.
	Reason Reason `json:"reason,omitempty"`
}

// SelfCheck is the result of the latest self-check, safe to log and
// show: it holds paths, counts and fixed words, never file content.
type SelfCheck struct {
	// State is the overall outcome.
	State State `json:"state"`
	// Cause is a fixed word for not-ok states.
	Cause string `json:"cause,omitempty"`
	// Checked is when the latest check finished.
	Checked time.Time `json:"checked,omitzero"`
	// Runs counts finished checks since the process started.
	Runs uint64 `json:"runs"`
	// ReleaseVersion is the admitted release version.
	ReleaseVersion string `json:"release_version,omitempty"`
	// ListDigest is the SHA-256 of the admitted installed-files.json.
	ListDigest string `json:"list_digest,omitempty"`
	// Flavour is the install flavour checked.
	Flavour string `json:"flavour,omitempty"`
	// Files counts the results (listed files plus unlisted binaries).
	Files int `json:"files"`
	// OK counts matching files.
	OK int `json:"ok"`
	// Different counts files that differ.
	Different int `json:"different"`
	// Missing counts missing files.
	Missing int `json:"missing"`
	// Unreadable counts files that could not be checked.
	Unreadable int `json:"unreadable"`
	// Extra counts unlisted /usr/bin/nebula* entries.
	Extra int `json:"extra"`
	// NotChecked counts files not reached before a limit.
	NotChecked int `json:"not_checked"`
	// BytesHashed counts the bytes read.
	BytesHashed int64 `json:"bytes_hashed"`
	// Deviations lists at most MaxStatusDeviations non-ok files.
	Deviations []Deviation `json:"deviations,omitempty"`
	// DeviationsTruncated says Deviations is not complete.
	DeviationsTruncated bool `json:"deviations_truncated,omitempty"`
	// Note is RootCompromiseNote.
	Note string `json:"note"`
}

// Monitor runs the I1 self-check at start and every Interval and keeps
// the latest SelfCheck. It only logs and reports: reactions (findings,
// notifications, unlock refusal, refusing web assets) are not its job
// (ADR 0015 Q4, IG-04).
type Monitor struct {
	// Load returns the admitted reference; it is called on every run so
	// the reference is re-verified each time. An error wrapping
	// ErrDevelopmentBuild makes the run not-checkable, any other error
	// incomplete.
	Load func(ctx context.Context) (Reference, error)
	// Options configures Check. Options.Now defaults to Now.
	Options Options
	// Interval is the period after the start check; 0 means
	// DefaultInterval.
	Interval time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// After waits for a duration; nil means time.After.
	After func(time.Duration) <-chan time.Time
	// Log receives one record per run; nil means slog.Default().
	Log *slog.Logger

	mu     sync.Mutex
	latest SelfCheck
	runs   uint64
}

// Status returns the latest result, StatePending before the first run.
func (m *Monitor) Status() SelfCheck {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runs == 0 {
		return SelfCheck{State: StatePending, Note: RootCompromiseNote}
	}
	st := m.latest
	st.Deviations = append([]Deviation(nil), st.Deviations...)
	return st
}

// Run checks once now and then every Interval until ctx ends. Runs never
// overlap: the next wait starts after a run finished.
func (m *Monitor) Run(ctx context.Context) {
	after := m.After
	if after == nil {
		after = time.After
	}
	every := m.Interval
	if every <= 0 {
		every = DefaultInterval
	}
	for {
		if ctx.Err() != nil {
			return
		}
		m.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-after(every):
		}
	}
}

// RunOnce runs one check, logs it, stores and returns its SelfCheck.
//
// A run that ctx ended (server shutdown) is not a failed check: unless it
// already found deviations, its result is dropped, logged at INFO and the
// previous result is returned unchanged.
func (m *Monitor) RunOnce(ctx context.Context) SelfCheck {
	now := m.Now
	if now == nil {
		now = time.Now
	}
	log := m.Log
	if log == nil {
		log = slog.Default()
	}
	start := now()
	st, err := m.check(ctx, now)
	if ctx.Err() != nil && st.State != StateDeviations {
		log.LogAttrs(context.WithoutCancel(ctx), slog.LevelInfo, "integrity self-check stopped by shutdown",
			slog.String("kind", "integrity_self_check"),
			slog.Duration("took", now().Sub(start)),
		)
		return m.Status()
	}
	st.Checked = now()
	st.Note = RootCompromiseNote

	m.mu.Lock()
	m.runs++
	st.Runs = m.runs
	m.latest = st
	m.mu.Unlock()

	logSelfCheck(ctx, log, st, st.Checked.Sub(start), err)
	return st
}

func (m *Monitor) check(ctx context.Context, now func() time.Time) (SelfCheck, error) {
	if m.Load == nil {
		return SelfCheck{State: StateIncomplete, Cause: CauseReferenceRejected}, ErrNoReference
	}
	ref, err := m.Load(ctx)
	switch {
	case errors.Is(err, ErrDevelopmentBuild):
		return SelfCheck{State: StateNotCheckable, Cause: CauseDevelopmentBuild}, err
	case errors.Is(err, ErrNoInstalledFiles):
		return SelfCheck{State: StateIncomplete, Cause: CauseNoList}, err
	case err != nil:
		return SelfCheck{State: StateIncomplete, Cause: CauseReferenceRejected}, err
	}
	opts := m.Options
	if opts.Now == nil {
		opts.Now = now
	}
	rep, err := Check(ctx, ref, opts)
	if err != nil {
		return SelfCheck{State: StateIncomplete, Cause: CauseCheckFailed, ReleaseVersion: ref.ReleaseVersion(),
			ListDigest: ref.ListDigest()}, err
	}
	return summarize(rep), nil
}

// summarize turns a report into a SelfCheck. Deviations outrank an
// incomplete run; anything not clean is never ok.
func summarize(rep Report) SelfCheck {
	st := SelfCheck{ReleaseVersion: rep.ReleaseVersion, ListDigest: rep.ListDigest, Flavour: rep.Flavour,
		Files: len(rep.Files), BytesHashed: rep.BytesHashed}
	for _, f := range rep.Files {
		switch f.Status {
		case StatusOK:
			st.OK++
			continue
		case StatusNotChecked:
			st.NotChecked++
			continue
		case StatusDifferent:
			st.Different++
		case StatusMissing:
			st.Missing++
		case StatusExtra:
			st.Extra++
		default:
			// StatusUnreadable and anything unknown: not ok.
			st.Unreadable++
		}
		if len(st.Deviations) == MaxStatusDeviations {
			st.DeviationsTruncated = true
			continue
		}
		st.Deviations = append(st.Deviations, Deviation(f))
	}
	switch {
	case st.Different+st.Missing+st.Extra > 0:
		st.State = StateDeviations
		if !rep.Complete {
			st.Cause = string(rep.Incomplete)
		}
	case !rep.Complete:
		st.State, st.Cause = StateIncomplete, string(rep.Incomplete)
	case st.Unreadable > 0 || !rep.Clean():
		st.State, st.Cause = StateIncomplete, CauseUnreadable
	default:
		st.State = StateOK
	}
	return st
}

// logSelfCheck writes one structured record per run and one per listed
// deviation. No file content is ever logged.
func logSelfCheck(ctx context.Context, log *slog.Logger, st SelfCheck, took time.Duration, err error) {
	level := slog.LevelInfo
	switch st.State {
	case StateNotCheckable:
		level = slog.LevelWarn
	case StateDeviations, StateIncomplete:
		level = slog.LevelError
	}
	attrs := []slog.Attr{
		slog.String("kind", "integrity_self_check"),
		slog.String("state", string(st.State)),
		slog.String("cause", st.Cause),
		slog.String("release_version", st.ReleaseVersion),
		slog.String("flavour", st.Flavour),
		slog.String("list_digest", st.ListDigest),
		slog.Int("files", st.Files),
		slog.Int("ok", st.OK),
		slog.Int("different", st.Different),
		slog.Int("missing", st.Missing),
		slog.Int("unreadable", st.Unreadable),
		slog.Int("extra", st.Extra),
		slog.Int("not_checked", st.NotChecked),
		slog.Int64("bytes_hashed", st.BytesHashed),
		slog.Duration("took", took),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	log.LogAttrs(ctx, level, "integrity self-check", attrs...)
	for _, d := range st.Deviations {
		log.LogAttrs(ctx, slog.LevelError, "integrity self-check deviation",
			slog.String("kind", "integrity_self_check"),
			slog.String("path", d.Path),
			slog.String("class", string(d.Class)),
			slog.String("status", string(d.Status)),
			slog.String("reason", string(d.Reason)),
		)
	}
}

// LoadReference reads release-manifest.json, its signature and
// installed-files.json from dir (no symlink leaves dir, sizes bounded by
// the release limits) and admits them with Admit against state.
//
// A version that is not a release version returns ErrDevelopmentBuild; a
// missing installed-files.json (or directory) of a release returns
// ErrNoInstalledFiles. A present list with a missing or invalid manifest
// or signature is a rejected reference. Neither is ever "not checkable".
func LoadReference(state release.RootState, version, dir string) (Reference, error) {
	if !release.ValidReleaseVersion(version) {
		return Reference{}, ErrDevelopmentBuild
	}
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return Reference{}, fmt.Errorf("%w: %s does not exist", ErrNoInstalledFiles, dir)
	}
	if err != nil {
		return Reference{}, fmt.Errorf("open reference directory %s: %w", dir, err)
	}
	defer root.Close()
	list, err := readBounded(root, release.InstalledFilesArtifact, release.MaxInstalledFilesDocument)
	if errors.Is(err, fs.ErrNotExist) {
		return Reference{}, fmt.Errorf("%w: no %s in %s", ErrNoInstalledFiles, release.InstalledFilesArtifact, dir)
	}
	if err != nil {
		return Reference{}, err
	}
	manifest, err := readBounded(root, release.ManifestFile, release.MaxManifest)
	if err != nil {
		return Reference{}, err
	}
	sig, err := readBounded(root, release.SignatureFile, release.MaxSignature)
	if err != nil {
		return Reference{}, err
	}
	return Admit(state, version, manifest, sig, list)
}

// readBounded reads a regular file of at most limit bytes from root.
func readBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	// O_NONBLOCK: a FIFO in place of the file must not block the open.
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("read %s: not a regular file", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("read %s: larger than %d bytes", name, limit)
	}
	return b, nil
}
