// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// This file is the executor's periodic I1 check (ADR 0015 D4 "Who",
// "When", Q2): at start and every 60 minutes the executor checks every
// covered NOS file against the installed-files reference it admitted into
// its own storage (integrity_reference.go), never against /usr/share. Each
// run is bounded (integrity.Check: at most 4,096 files and 1 GiB hashed,
// O_NOFOLLOW, regular files only), recorded durably in the executor's data
// directory and audited with counts only. A run that could not check
// everything is "incomplete", never clean.
//
// A deviation in a class that integrity.Class.Locks opens the "open
// locking deviation" state. It survives restarts and is only set and
// audited here; refusing unlock and dispatch while it is open, and the
// executor-local ack that clears it, are IG-04a.

// IntegrityCheckStateFile is the state file name in the executor's data
// directory.
const IntegrityCheckStateFile = "integrity-check.json"

// Limits of the stored check state.
const (
	// maxIntegrityRuns bounds the runs kept (one day at the default
	// interval); older runs remain in the signed audit log.
	maxIntegrityRuns = 24
	// maxIntegrityRunDeviations bounds the deviations stored per run; the
	// rest is counted in IntegrityRun.DeviationsOmitted.
	maxIntegrityRunDeviations = integrity.MaxStatusDeviations
	// maxIntegrityPath bounds a stored (escaped) path.
	maxIntegrityPath = 1024
	// maxIntegrityCheckState bounds the state file; the limits above keep
	// a valid state well below it.
	maxIntegrityCheckState = 8 << 20
)

// Sentinel errors.
var (
	// ErrIntegrityCheckRunning: a check is already running; runs never
	// overlap.
	ErrIntegrityCheckRunning = errors.New("executor: integrity check already running")
	// ErrIntegrityCheckNotConfigured: SetIntegrityCheck was not called.
	ErrIntegrityCheckNotConfigured = errors.New("executor: integrity check not configured")
	// ErrIntegrityCheckConfig is an invalid IntegrityCheckConfig.
	ErrIntegrityCheckConfig = errors.New("executor: invalid integrity check configuration")
)

// IntegrityRunState is the overall outcome of one run.
type IntegrityRunState string

// Run states.
const (
	// IntegrityRunClean: complete, every file matches.
	IntegrityRunClean IntegrityRunState = "clean"
	// IntegrityRunDeviations: at least one file differs, is missing or is
	// an unlisted binary; Complete says whether everything was checked.
	IntegrityRunDeviations IntegrityRunState = "deviations"
	// IntegrityRunIncomplete: no deviation found, but the run could not
	// check everything; Incomplete says why. Never clean.
	IntegrityRunIncomplete IntegrityRunState = "incomplete"
)

// Reasons for an incomplete run besides the integrity.Incomplete values
// ("file-limit", "byte-limit", "time-budget", "canceled", "extra-scan").
const (
	// IncompleteNoReference: no admitted installed-files reference.
	IncompleteNoReference = "no-reference"
	// IncompleteDevelopmentBuild: a development build has no release
	// version and therefore no reference.
	IncompleteDevelopmentBuild = "development-build"
	// IncompleteReferenceRejected: the stored reference did not
	// re-verify (other root state, other running version).
	IncompleteReferenceRejected = "reference-rejected"
	// IncompleteCheckFailed: the check could not start (flavour, root).
	IncompleteCheckFailed = "check-failed"
	// IncompleteUnreadable: at least one file could not be read.
	IncompleteUnreadable = "unreadable-files"
)

// IntegrityLockCause says why the locking state is open.
type IntegrityLockCause string

// Lock causes.
const (
	// IntegrityLockDeviation: a run found a locking deviation.
	IntegrityLockDeviation IntegrityLockCause = "deviation"
	// IntegrityLockStateUnreadable: the stored state could not be read
	// at start; an earlier open lock cannot be ruled out (fail closed).
	IntegrityLockStateUnreadable IntegrityLockCause = "state-unreadable"
)

// IntegrityDeviation is one file whose status is not ok. It never holds
// file content.
type IntegrityDeviation struct {
	// Path is the listed path or the unlisted /usr/bin name, escaped to
	// printable ASCII and bounded.
	Path string `json:"path"`
	// Class is the ADR 0015 D4 class (integrity.Classify).
	Class integrity.Class `json:"class"`
	// Status is the file's outcome.
	Status integrity.Status `json:"status"`
	// Reason details different and unreadable files.
	Reason integrity.Reason `json:"reason,omitempty"`
	// Locks says this deviation opens the locking state.
	Locks bool `json:"locks"`
}

// IntegrityRun is the stored result of one run.
type IntegrityRun struct {
	// Started and Finished come from the injected clock.
	Started time.Time `json:"started"`
	// Finished is when the run ended.
	Finished time.Time `json:"finished"`
	// State is the overall outcome.
	State IntegrityRunState `json:"state"`
	// Complete says every listed file and /usr/bin were checked.
	Complete bool `json:"complete"`
	// Incomplete is the fixed reason of an incomplete run.
	Incomplete string `json:"incomplete,omitempty"`
	// ReleaseVersion, ManifestSHA256 and ListSHA256 identify the admitted
	// reference; empty when none could be loaded.
	ReleaseVersion string `json:"release_version,omitempty"`
	// ManifestSHA256 is the digest of the admitted manifest.
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	// ListSHA256 is the digest of the admitted installed-files.json.
	ListSHA256 string `json:"list_sha256,omitempty"`
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
	// Extra counts unlisted /usr/bin/nebula* entries.
	Extra int `json:"extra"`
	// Unreadable counts files that could not be checked.
	Unreadable int `json:"unreadable"`
	// NotChecked counts files not reached before a limit.
	NotChecked int `json:"not_checked"`
	// BytesHashed counts the bytes read.
	BytesHashed int64 `json:"bytes_hashed"`
	// Locking counts deviations that open the locking state.
	Locking int `json:"locking"`
	// Deviations lists at most maxIntegrityRunDeviations deviations.
	Deviations []IntegrityDeviation `json:"deviations,omitempty"`
	// DeviationsOmitted counts the deviations not listed.
	DeviationsOmitted int `json:"deviations_omitted,omitempty"`
}

// IntegrityLock is the open locking-deviation state. Only IG-04a's
// executor-local ack closes it; a later clean run does not.
type IntegrityLock struct {
	// Open says a locking deviation is open.
	Open bool `json:"open"`
	// Cause says why.
	Cause IntegrityLockCause `json:"cause,omitempty"`
	// Since is when the lock opened (the run's start).
	Since time.Time `json:"since,omitzero"`
	// Deviations counts the locking deviations of the opening run.
	Deviations int `json:"deviations,omitempty"`
}

// IntegrityCheckState is the stored check state.
type IntegrityCheckState struct {
	// Configured says SetIntegrityCheck wired the check.
	Configured bool `json:"-"`
	// Running says a run is in progress.
	Running bool `json:"-"`
	// Total counts every recorded run.
	Total uint64 `json:"total"`
	// Runs are the latest runs, oldest first, at most maxIntegrityRuns.
	Runs []IntegrityRun `json:"runs"`
	// Lock is the open locking-deviation state.
	Lock IntegrityLock `json:"lock"`
}

// IntegrityCheckConfig configures the periodic check.
type IntegrityCheckConfig struct {
	// StatePath is the absolute state file, normally
	// <data dir>/IntegrityCheckStateFile. Required.
	StatePath string
	// Root is the directory the installed paths are resolved under; ""
	// means "/".
	Root string
	// Flavour detects the install flavour on every run. Required.
	Flavour func(ctx context.Context) (string, error)
	// Interval is the period after the start run; 0 means
	// integrity.DefaultInterval (60 minutes, Q2).
	Interval time.Duration
	// Budget bounds one run; 0 means integrity.DefaultBudget. It may not
	// exceed Interval or integrity.MaxBudget.
	Budget time.Duration
	// MaxFiles and MaxBytes bound one run; 0 means integrity.MaxFiles
	// (4,096) and integrity.MaxBytes (1 GiB), which they may not exceed.
	MaxFiles int
	// MaxBytes bounds the bytes hashed per run.
	MaxBytes int64
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// After waits between runs; nil means time.After.
	After func(time.Duration) <-chan time.Time
	// Owners resolves listed owners; nil means the host user database.
	Owners func(owner string) (uid, gid uint32, err error)
}

func (c IntegrityCheckConfig) withDefaults() (IntegrityCheckConfig, error) {
	switch {
	case c.StatePath == "" || !filepath.IsAbs(c.StatePath):
		return c, fmt.Errorf("%w: state path must be absolute", ErrIntegrityCheckConfig)
	case c.Flavour == nil:
		return c, fmt.Errorf("%w: flavour detection required", ErrIntegrityCheckConfig)
	case c.Interval < 0 || c.Budget < 0 || c.MaxFiles < 0 || c.MaxBytes < 0:
		return c, fmt.Errorf("%w: negative value", ErrIntegrityCheckConfig)
	case c.MaxFiles > integrity.MaxFiles:
		return c, fmt.Errorf("%w: max files above %d", ErrIntegrityCheckConfig, integrity.MaxFiles)
	case c.MaxBytes > integrity.MaxBytes:
		return c, fmt.Errorf("%w: max bytes above %d", ErrIntegrityCheckConfig, int64(integrity.MaxBytes))
	}
	if c.Interval == 0 {
		c.Interval = integrity.DefaultInterval
	}
	if c.Budget == 0 {
		c.Budget = integrity.DefaultBudget
	}
	if c.MaxFiles == 0 {
		c.MaxFiles = integrity.MaxFiles
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = integrity.MaxBytes
	}
	// A run ends before the next one is due, so the periodic runs never
	// overlap (integrity.MaxBudget).
	if c.Budget > c.Interval || c.Budget > integrity.MaxBudget {
		return c, fmt.Errorf("%w: budget must not exceed the interval or %s", ErrIntegrityCheckConfig, integrity.MaxBudget)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.After == nil {
		c.After = time.After
	}
	return c, nil
}

// integrityCheckState is the Service's periodic check.
type integrityCheckState struct {
	// running is set while a run is in progress; it also serializes the
	// state file writes.
	running atomic.Bool

	mu    sync.Mutex
	cfg   *IntegrityCheckConfig
	state IntegrityCheckState

	// check is integrity.Check; tests replace it.
	check func(context.Context, integrity.Reference, integrity.Options) (integrity.Report, error)
}

// SetIntegrityCheck wires the periodic check and loads the stored state.
// A state file that cannot be read or validated opens the lock
// (IntegrityLockStateUnreadable, audited): an earlier open lock cannot be
// ruled out. Call it before RunIntegrityChecks.
func (s *Service) SetIntegrityCheck(cfg IntegrityCheckConfig) error {
	c, err := cfg.withDefaults()
	if err != nil {
		return err
	}
	if !s.integrityCheck.running.CompareAndSwap(false, true) {
		return ErrIntegrityCheckRunning
	}
	defer s.integrityCheck.running.Store(false)
	st, ok, err := loadIntegrityCheckState(c.StatePath)
	if err != nil {
		st = IntegrityCheckState{Lock: IntegrityLock{Open: true, Cause: IntegrityLockStateUnreadable, Since: c.Now()}}
		s.auditLog(slog.LevelError, "integrity_check_state_unreadable", slog.String("detail", err.Error()))
	} else if !ok {
		st = IntegrityCheckState{}
	}
	s.integrityCheck.mu.Lock()
	s.integrityCheck.cfg = &c
	s.integrityCheck.state = st
	s.integrityCheck.mu.Unlock()
	return nil
}

// IntegrityCheckStatus returns a copy of the stored state. It never waits
// for a running check.
func (s *Service) IntegrityCheckStatus() IntegrityCheckState {
	s.integrityCheck.mu.Lock()
	defer s.integrityCheck.mu.Unlock()
	st := copyIntegrityState(s.integrityCheck.state)
	st.Configured = s.integrityCheck.cfg != nil
	st.Running = s.integrityCheck.running.Load()
	return st
}

// IntegrityLockOpen reports whether a locking deviation is open. It never
// waits for a running check.
func (s *Service) IntegrityLockOpen() bool {
	s.integrityCheck.mu.Lock()
	defer s.integrityCheck.mu.Unlock()
	return s.integrityCheck.state.Lock.Open
}

// RunIntegrityChecks runs a check now (executor start, which is also the
// first start after an upgrade) and then every Interval until ctx ends.
// The next wait starts after a run finished; it runs in its own goroutine
// and holds no lock that dispatch takes.
func (s *Service) RunIntegrityChecks(ctx context.Context) {
	s.integrityCheck.mu.Lock()
	cfg := s.integrityCheck.cfg
	s.integrityCheck.mu.Unlock()
	if cfg == nil {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		// Errors are audited by the run itself; an overlapping caller
		// (ErrIntegrityCheckRunning) has its own run in progress.
		_, _ = s.RunIntegrityCheckOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-cfg.After(cfg.Interval):
		}
	}
}

// RunIntegrityCheckOnce runs one check, records and audits it and returns
// the run. A second call while one runs returns ErrIntegrityCheckRunning
// and changes nothing. A non-nil error with a run means the run was
// recorded in memory but could not be stored.
func (s *Service) RunIntegrityCheckOnce(ctx context.Context) (IntegrityRun, error) {
	s.integrityCheck.mu.Lock()
	cfg, check := s.integrityCheck.cfg, s.integrityCheck.check
	s.integrityCheck.mu.Unlock()
	if cfg == nil {
		return IntegrityRun{}, ErrIntegrityCheckNotConfigured
	}
	if !s.integrityCheck.running.CompareAndSwap(false, true) {
		return IntegrityRun{}, ErrIntegrityCheckRunning
	}
	defer s.integrityCheck.running.Store(false)
	if check == nil {
		check = integrity.Check
	}

	run := s.integrityRun(ctx, *cfg, check)

	s.integrityCheck.mu.Lock()
	st := &s.integrityCheck.state
	st.Total++
	st.Runs = append(st.Runs, run)
	if n := len(st.Runs) - maxIntegrityRuns; n > 0 {
		st.Runs = append([]IntegrityRun(nil), st.Runs[n:]...)
	}
	opened := false
	if run.Locking > 0 && !st.Lock.Open {
		st.Lock = IntegrityLock{Open: true, Cause: IntegrityLockDeviation, Since: run.Started, Deviations: run.Locking}
		opened = true
	}
	lock := st.Lock
	snapshot := copyIntegrityState(*st)
	s.integrityCheck.mu.Unlock()

	s.auditIntegrityRun(run, lock)
	if opened {
		s.auditLog(slog.LevelError, "integrity_lock_opened",
			slog.Time("since", lock.Since), slog.Int("locking", lock.Deviations),
			slog.String("manifest_sha256", run.ManifestSHA256))
	}
	if err := storeIntegrityCheckState(cfg.StatePath, snapshot); err != nil {
		s.auditLog(slog.LevelError, "integrity_check_state_failed", slog.String("detail", err.Error()))
		return run, err
	}
	return run, nil
}

// integrityRun loads the admitted reference and checks the files. Every
// failure is an incomplete run, never clean.
func (s *Service) integrityRun(ctx context.Context, cfg IntegrityCheckConfig,
	check func(context.Context, integrity.Reference, integrity.Options) (integrity.Report, error)) IntegrityRun {
	run := IntegrityRun{Started: cfg.Now(), State: IntegrityRunIncomplete}
	finish := func(reason string) IntegrityRun {
		run.Incomplete = reason
		run.Finished = cfg.Now()
		return run
	}
	if !release.ValidReleaseVersion(s.runningReleaseVersion()) {
		return finish(IncompleteDevelopmentBuild)
	}
	ref, err := s.AdmittedIntegrityReference(ctx)
	switch {
	case errors.Is(err, integrity.ErrNoReference), errors.Is(err, executordb.ErrNoIntegrityReference):
		return finish(IncompleteNoReference)
	case err != nil:
		return finish(IncompleteReferenceRejected)
	}
	run.ReleaseVersion, run.ManifestSHA256, run.ListSHA256 = ref.ReleaseVersion(), ref.ManifestDigest(), ref.ListDigest()
	flavour, err := cfg.Flavour(ctx)
	if err != nil {
		return finish(IncompleteCheckFailed)
	}
	run.Flavour = flavour
	rep, err := check(ctx, ref, integrity.Options{
		Root: cfg.Root, Flavour: flavour, MaxFiles: cfg.MaxFiles, MaxBytes: cfg.MaxBytes,
		Budget: cfg.Budget, Now: cfg.Now, Owners: cfg.Owners,
	})
	if err != nil {
		return finish(IncompleteCheckFailed)
	}
	summarizeIntegrityReport(&run, rep)
	run.Finished = cfg.Now()
	return run
}

// summarizeIntegrityReport fills the counts, deviations and state of run.
// Deviations outrank an incomplete run; anything not clean is never clean.
func summarizeIntegrityReport(run *IntegrityRun, rep integrity.Report) {
	run.Files, run.BytesHashed = len(rep.Files), rep.BytesHashed
	for _, f := range rep.Files {
		locks := false
		switch f.Status {
		case integrity.StatusOK:
			run.OK++
			continue
		case integrity.StatusNotChecked:
			run.NotChecked++
			continue
		case integrity.StatusDifferent:
			run.Different++
			locks = true
		case integrity.StatusMissing:
			run.Missing++
			locks = true
		case integrity.StatusExtra:
			run.Extra++
			locks = true
		default:
			// StatusUnreadable and anything unknown: the check could not
			// run completely (ADR 0015 D4), no lock.
			run.Unreadable++
		}
		class := f.Class
		if class == "" {
			class = integrity.Classify(f.Path)
		}
		locks = locks && class.Locks()
		if locks {
			run.Locking++
		}
		if len(run.Deviations) == maxIntegrityRunDeviations {
			run.DeviationsOmitted++
			continue
		}
		run.Deviations = append(run.Deviations, IntegrityDeviation{
			Path: escapeIntegrityPath(f.Path), Class: class, Status: f.Status, Reason: f.Reason, Locks: locks,
		})
	}
	run.Complete = rep.Complete && rep.Incomplete == "" && run.Unreadable == 0 && run.NotChecked == 0
	switch {
	case !rep.Complete || rep.Incomplete != "":
		run.Incomplete = string(rep.Incomplete)
		if run.Incomplete == "" {
			run.Incomplete = IncompleteCheckFailed
		}
	case run.Unreadable > 0:
		run.Incomplete = IncompleteUnreadable
	case run.NotChecked > 0:
		run.Incomplete = IncompleteCheckFailed
	}
	switch {
	case run.Different+run.Missing+run.Extra > 0:
		run.State = IntegrityRunDeviations
	case !run.Complete || !rep.Clean():
		run.State = IntegrityRunIncomplete
		if run.Incomplete == "" {
			run.Incomplete = IncompleteCheckFailed
		}
	default:
		run.State = IntegrityRunClean
	}
}

// auditIntegrityRun writes the per-run audit record: counts and digests,
// never file content or paths.
func (s *Service) auditIntegrityRun(run IntegrityRun, lock IntegrityLock) {
	level := slog.LevelInfo
	switch {
	case run.Locking > 0:
		level = slog.LevelError
	case run.State != IntegrityRunClean:
		level = slog.LevelWarn
	}
	s.auditLog(level, "integrity_check",
		slog.String("state", string(run.State)),
		slog.Bool("complete", run.Complete),
		slog.String("incomplete", run.Incomplete),
		slog.String("release_version", run.ReleaseVersion),
		slog.String("manifest_sha256", run.ManifestSHA256),
		slog.String("list_sha256", run.ListSHA256),
		slog.String("flavour", run.Flavour),
		slog.Int("files", run.Files),
		slog.Int("ok", run.OK),
		slog.Int("different", run.Different),
		slog.Int("missing", run.Missing),
		slog.Int("extra", run.Extra),
		slog.Int("unreadable", run.Unreadable),
		slog.Int("not_checked", run.NotChecked),
		slog.Int64("bytes_hashed", run.BytesHashed),
		slog.Int("locking", run.Locking),
		slog.Duration("took", run.Finished.Sub(run.Started)),
		slog.Bool("lock_open", lock.Open),
		slog.String("note", integrity.RootCompromiseNote),
	)
}

func (s *Service) auditLog(level slog.Level, kind string, attrs ...slog.Attr) {
	if s.log == nil {
		return
	}
	s.log.LogAttrs(context.Background(), level, "audit", append([]slog.Attr{slog.String("kind", kind)}, attrs...)...)
}

// escapeIntegrityPath returns p as printable ASCII, bounded to
// maxIntegrityPath bytes. Paths from the signed list and names Check
// already escaped stay unchanged.
func escapeIntegrityPath(p string) string {
	if !printableASCII(p) {
		q := strconv.QuoteToASCII(p)
		p = q[1 : len(q)-1]
	}
	if len(p) > maxIntegrityPath {
		p = p[:maxIntegrityPath-3] + "..."
	}
	return p
}

func printableASCII(p string) bool {
	if !utf8.ValidString(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

func copyIntegrityState(st IntegrityCheckState) IntegrityCheckState {
	runs := make([]IntegrityRun, len(st.Runs))
	for i, r := range st.Runs {
		r.Deviations = append([]IntegrityDeviation(nil), r.Deviations...)
		runs[i] = r
	}
	st.Runs = runs
	return st
}

// loadIntegrityCheckState reads and validates the state file; ok is false
// when none exists.
func loadIntegrityCheckState(path string) (IntegrityCheckState, bool, error) {
	// O_NOFOLLOW and O_NONBLOCK: a symlink or FIFO in its place is an
	// unreadable state, never followed or waited on.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return IntegrityCheckState{}, false, nil
	}
	if err != nil {
		return IntegrityCheckState{}, false, fmt.Errorf("open integrity check state: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxIntegrityCheckState+1))
	if err != nil {
		return IntegrityCheckState{}, false, fmt.Errorf("read integrity check state: %w", err)
	}
	if len(raw) > maxIntegrityCheckState {
		return IntegrityCheckState{}, false, fmt.Errorf("integrity check state exceeds %d bytes", maxIntegrityCheckState)
	}
	var st IntegrityCheckState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return IntegrityCheckState{}, false, fmt.Errorf("decode integrity check state: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return IntegrityCheckState{}, false, errors.New("decode integrity check state: trailing data")
	}
	if err := validateIntegrityState(st); err != nil {
		return IntegrityCheckState{}, false, fmt.Errorf("decode integrity check state: %w", err)
	}
	return st, true, nil
}

func validateIntegrityState(st IntegrityCheckState) error {
	if len(st.Runs) > maxIntegrityRuns || st.Total < uint64(len(st.Runs)) {
		return errors.New("run count out of range")
	}
	switch {
	case st.Lock.Open && st.Lock.Cause != IntegrityLockDeviation && st.Lock.Cause != IntegrityLockStateUnreadable:
		return errors.New("unknown lock cause")
	case !st.Lock.Open && st.Lock.Cause != "":
		return errors.New("closed lock with a cause")
	case st.Lock.Deviations < 0:
		return errors.New("negative lock count")
	}
	for _, r := range st.Runs {
		switch r.State {
		case IntegrityRunClean, IntegrityRunDeviations, IntegrityRunIncomplete:
		default:
			return errors.New("unknown run state")
		}
		if r.State == IntegrityRunClean && (!r.Complete || r.Incomplete != "") {
			return errors.New("incomplete run stored as clean")
		}
		if len(r.Deviations) > maxIntegrityRunDeviations {
			return errors.New("too many deviations")
		}
		for _, d := range r.Deviations {
			if len(d.Path) > maxIntegrityPath || !printableASCII(d.Path) {
				return errors.New("invalid deviation path")
			}
		}
	}
	return nil
}

// storeIntegrityCheckState writes the state atomically with mode 0600.
func storeIntegrityCheckState(path string, st IntegrityCheckState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode integrity check state: %w", err)
	}
	if len(raw) > maxIntegrityCheckState {
		return fmt.Errorf("integrity check state exceeds %d bytes", maxIntegrityCheckState)
	}
	if err := writeFileAtomic(path, raw); err != nil {
		return fmt.Errorf("write integrity check state: %w", err)
	}
	return nil
}

// Install flavour markers (the same rules as nebula-server's self-check).
const flavourDebPackageList = "var/lib/dpkg/info/nebula-operation-station.list"

var flavourContainerMarkers = []string{".dockerenv", "run/.containerenv"}

// DetectInstallFlavour names the install flavour of the installation under
// root: container, deb or tarball, on this architecture. A marker that
// cannot be inspected is an error, never a guessed flavour.
func DetectInstallFlavour(root string) (string, error) {
	exists := func(rel string) (bool, error) {
		_, err := os.Lstat(filepath.Join(root, rel))
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, fs.ErrNotExist):
			return false, nil
		default:
			return false, fmt.Errorf("inspect flavour marker %s: %w", rel, err)
		}
	}
	for _, m := range flavourContainerMarkers {
		found, err := exists(m)
		if err != nil {
			return "", err
		}
		if found {
			return "container:" + runtime.GOARCH, nil
		}
	}
	found, err := exists(flavourDebPackageList)
	switch {
	case err != nil:
		return "", err
	case found:
		return "deb:" + runtime.GOARCH, nil
	}
	return "tarball:" + runtime.GOARCH, nil
}
