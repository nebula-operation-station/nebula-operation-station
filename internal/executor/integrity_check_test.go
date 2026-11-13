// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// checkTreeFile is one installed file of the check fixture.
type checkTreeFile struct {
	path string
	data string
	mode os.FileMode
}

// checkTree is a binary, a unit and a web asset: one file of each
// reaction class.
var checkTree = []checkTreeFile{
	{"/lib/systemd/system/nebula-server.service", "[Unit]\nDescription=NOS server\n", 0o644},
	{"/usr/bin/nebula-server", "server binary", 0o755},
	{"/usr/share/nebula/web/app.css", "body{}", 0o644},
}

// checkEnv is an admitted reference for checkTree, the files installed
// under a temporary root, and a service started on them.
type checkEnv struct {
	*refEnv
	root  string
	state string
	clock *stepClock
	svc   *Service
	h     *recordingHandler
}

// stepClock is an injected clock that advances only when told.
type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func signedTree(t *testing.T, k *bundleSK, version string, tree []checkTreeFile) (man, sig, list []byte) {
	t.Helper()
	var files []release.InstalledFile
	for _, f := range tree {
		files = append(files, release.InstalledFile{Path: f.path, Type: release.FileRegular,
			Size: int64(len(f.data)), SHA256: bundleSum([]byte(f.data)), Mode: uint32(f.mode), Owner: release.GeneratedOwner})
	}
	l := release.InstalledFiles{ReleaseVersion: version, Flavours: []release.Flavour{{Name: "deb:amd64", Files: files}}}
	list, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	bundle, mod := []byte("builtins"), []byte("module tar")
	man = bundleCanon(t, map[string]any{"format": release.ManifestFormat, "release_version": version,
		"artifacts": []any{
			map[string]any{"name": release.BundleArtifact, "size": len(bundle), "sha256": bundleSum(bundle)},
			map[string]any{"name": release.InstalledFilesArtifact, "size": len(list), "sha256": bundleSum(list)},
		},
		"modules": []any{map[string]any{"name": "docker", "version": "1.2.0", "size": len(mod), "sha256": bundleSum(mod)}}})
	return man, k.sign(man), list
}

func installTree(t *testing.T, root string, tree []checkTreeFile) {
	t.Helper()
	for _, f := range tree {
		p := filepath.Join(root, f.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.data), f.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, f.mode); err != nil {
			t.Fatal(err)
		}
	}
}

// ownersAsTestUser maps every listed owner to the test process's IDs.
func ownersAsTestUser(string) (uint32, uint32, error) {
	return uint32(os.Getuid()), uint32(os.Getgid()), nil
}

func newCheckEnv(t *testing.T) *checkEnv {
	t.Helper()
	e := &checkEnv{refEnv: newRefEnv(t), root: t.TempDir(),
		clock: &stepClock{now: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)}}
	e.state = filepath.Join(e.dbDir, IntegrityCheckStateFile)
	man, sig, list := signedTree(t, e.k, "1.4.0", checkTree)
	e.write(t, man, sig, list)
	installTree(t, e.root, checkTree)
	e.svc, e.h = startService(t, e.refEnv, "1.4.0")
	if !e.svc.IntegrityReferenceStatus().Available {
		t.Fatalf("reference not admitted: %+v", e.svc.IntegrityReferenceStatus())
	}
	e.configure(t, e.svc, IntegrityCheckConfig{})
	return e
}

// configure wires the periodic check on s with the fixture defaults;
// fields set in cfg win.
func (e *checkEnv) configure(t *testing.T, s *Service, cfg IntegrityCheckConfig) {
	t.Helper()
	if cfg.StatePath == "" {
		cfg.StatePath = e.state
	}
	if cfg.Root == "" {
		cfg.Root = e.root
	}
	if cfg.Flavour == nil {
		cfg.Flavour = func(context.Context) (string, error) { return "deb:amd64", nil }
	}
	if cfg.Now == nil {
		cfg.Now = e.clock.Now
	}
	if cfg.Owners == nil {
		cfg.Owners = ownersAsTestUser
	}
	if err := s.SetIntegrityCheck(cfg); err != nil {
		t.Fatalf("SetIntegrityCheck: %v", err)
	}
}

func (e *checkEnv) run(t *testing.T) IntegrityRun {
	t.Helper()
	r, err := e.svc.RunIntegrityCheckOnce(context.Background())
	if err != nil {
		t.Fatalf("RunIntegrityCheckOnce: %v", err)
	}
	return r
}

func (e *checkEnv) path(p string) string { return filepath.Join(e.root, p) }

func deviationFor(r IntegrityRun, path string) (IntegrityDeviation, bool) {
	for _, d := range r.Deviations {
		if d.Path == path {
			return d, true
		}
	}
	return IntegrityDeviation{}, false
}

func TestIntegrityCheckCleanRun(t *testing.T) {
	e := newCheckEnv(t)
	r := e.run(t)
	if r.State != IntegrityRunClean || !r.Complete || r.Incomplete != "" {
		t.Fatalf("run = %+v", r)
	}
	if r.Files != 3 || r.OK != 3 || len(r.Deviations) != 0 || r.Locking != 0 {
		t.Fatalf("counts = %+v", r)
	}
	if r.ReleaseVersion != "1.4.0" || r.ManifestSHA256 == "" || r.ListSHA256 == "" || r.Flavour != "deb:amd64" {
		t.Fatalf("reference = %+v", r)
	}
	if !r.Started.Equal(e.clock.Now()) || r.BytesHashed == 0 {
		t.Fatalf("run = %+v", r)
	}
	st := e.svc.IntegrityCheckStatus()
	if st.Lock.Open || st.Total != 1 || len(st.Runs) != 1 {
		t.Fatalf("state = %+v", st)
	}
	if !containsKind(e.h.kinds(), "integrity_check") {
		t.Fatalf("no audit record: %v", e.h.kinds())
	}
}

func TestIntegrityCheckDeviations(t *testing.T) {
	cases := []struct {
		name    string
		tamper  func(t *testing.T, e *checkEnv)
		path    string
		class   integrity.Class
		status  integrity.Status
		reason  integrity.Reason
		locking bool
	}{
		{"changed binary", func(t *testing.T, e *checkEnv) {
			writeMode(t, e.path("/usr/bin/nebula-server"), "server binarY", 0o755)
		}, "/usr/bin/nebula-server", integrity.ClassBinary, integrity.StatusDifferent, integrity.ReasonSHA256, true},
		{"missing unit", func(t *testing.T, e *checkEnv) {
			if err := os.Remove(e.path("/lib/systemd/system/nebula-server.service")); err != nil {
				t.Fatal(err)
			}
		}, "/lib/systemd/system/nebula-server.service", integrity.ClassUnit, integrity.StatusMissing, "", true},
		{"extra binary", func(t *testing.T, e *checkEnv) {
			writeMode(t, e.path("/usr/bin/nebula-evil"), "implant", 0o755)
		}, "/usr/bin/nebula-evil", integrity.ClassBinary, integrity.StatusExtra, "", true},
		{"changed web asset", func(t *testing.T, e *checkEnv) {
			writeMode(t, e.path("/usr/share/nebula/web/app.css"), "body{x}", 0o644)
		}, "/usr/share/nebula/web/app.css", integrity.ClassWebAsset, integrity.StatusDifferent, integrity.ReasonSize, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newCheckEnv(t)
			tc.tamper(t, e)
			r := e.run(t)
			if r.State != IntegrityRunDeviations || !r.Complete {
				t.Fatalf("run = %+v", r)
			}
			d, ok := deviationFor(r, tc.path)
			if !ok {
				t.Fatalf("no deviation for %s: %+v", tc.path, r.Deviations)
			}
			if d.Class != tc.class || d.Status != tc.status || d.Reason != tc.reason || d.Locks != tc.locking {
				t.Fatalf("deviation = %+v", d)
			}
			st := e.svc.IntegrityCheckStatus()
			if st.Lock.Open != tc.locking {
				t.Fatalf("lock = %+v, want open=%v", st.Lock, tc.locking)
			}
			kinds := e.h.kinds()
			if tc.locking {
				if r.Locking != 1 || st.Lock.Cause != IntegrityLockDeviation || !st.Lock.Since.Equal(r.Started) {
					t.Fatalf("run = %+v lock = %+v", r, st.Lock)
				}
				if !containsKind(kinds, "integrity_lock_opened") {
					t.Fatalf("lock not audited: %v", kinds)
				}
			} else if r.Locking != 0 || containsKind(kinds, "integrity_lock_opened") {
				t.Fatalf("web asset locked: run = %+v, records %v", r, kinds)
			}
		})
	}
}

func writeMode(t *testing.T, p, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrityLockStaysOpenAfterCleanRun(t *testing.T) {
	e := newCheckEnv(t)
	p := e.path("/usr/bin/nebula-server")
	writeMode(t, p, "server binarY", 0o755)
	first := e.run(t)
	writeMode(t, p, "server binary", 0o755)
	e.clock.Add(time.Hour)
	if r := e.run(t); r.State != IntegrityRunClean {
		t.Fatalf("second run = %+v", r)
	}
	// Only the executor-local ack (IG-04) clears the lock.
	st := e.svc.IntegrityCheckStatus()
	if !st.Lock.Open || !st.Lock.Since.Equal(first.Started) {
		t.Fatalf("lock = %+v", st.Lock)
	}
}

func TestIntegrityCheckLimitReachedIsIncomplete(t *testing.T) {
	cases := []struct {
		name string
		cfg  IntegrityCheckConfig
		want integrity.Incomplete
	}{
		{"file limit", IntegrityCheckConfig{MaxFiles: 2}, integrity.IncompleteFiles},
		{"byte limit", IntegrityCheckConfig{MaxBytes: 10}, integrity.IncompleteBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newCheckEnv(t)
			e.configure(t, e.svc, tc.cfg)
			r := e.run(t)
			if r.State != IntegrityRunIncomplete || r.Complete || r.Incomplete != string(tc.want) {
				t.Fatalf("run = %+v", r)
			}
			if r.NotChecked == 0 {
				t.Fatalf("run = %+v", r)
			}
			if e.svc.IntegrityCheckStatus().Lock.Open {
				t.Fatal("an incomplete run opened the lock")
			}
		})
	}
}

func TestIntegrityCheckIncompleteWithoutReference(t *testing.T) {
	e := newCheckEnv(t)
	// A service whose built-in trust was never wired has no admitted
	// reference.
	s := &Service{db: e.db, log: e.svc.log, runningVersion: "1.4.0"}
	e.configure(t, s, IntegrityCheckConfig{StatePath: filepath.Join(t.TempDir(), IntegrityCheckStateFile)})
	r, err := s.RunIntegrityCheckOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.State != IntegrityRunIncomplete || r.Complete || r.Incomplete != IncompleteNoReference || r.Files != 0 {
		t.Fatalf("run = %+v", r)
	}
}

func TestIntegrityCheckIncompleteCauses(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, e *checkEnv) IntegrityCheckConfig
		want  string
	}{
		{"flavour detection fails", func(*testing.T, *checkEnv) IntegrityCheckConfig {
			return IntegrityCheckConfig{Flavour: func(context.Context) (string, error) { return "", errors.New("boom") }}
		}, IncompleteCheckFailed},
		{"unknown flavour", func(*testing.T, *checkEnv) IntegrityCheckConfig {
			return IntegrityCheckConfig{Flavour: func(context.Context) (string, error) { return "tarball:amd64", nil }}
		}, IncompleteCheckFailed},
		{"root missing", func(t *testing.T, _ *checkEnv) IntegrityCheckConfig {
			return IntegrityCheckConfig{Root: filepath.Join(t.TempDir(), "gone")}
		}, IncompleteCheckFailed},
		{"unreadable file", func(t *testing.T, e *checkEnv) IntegrityCheckConfig {
			if os.Geteuid() == 0 {
				// root ignores permissions; the test body injects the
				// unreadable result instead.
				return IntegrityCheckConfig{}
			}
			if err := os.Chmod(e.path("/usr/share/nebula/web"), 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(e.path("/usr/share/nebula/web"), 0o755) })
			return IntegrityCheckConfig{}
		}, IncompleteUnreadable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newCheckEnv(t)
			e.configure(t, e.svc, tc.setup(t, e))
			if tc.want == IncompleteUnreadable && os.Geteuid() == 0 {
				e.svc.integrityCheck.check = func(context.Context, integrity.Reference, integrity.Options) (integrity.Report, error) {
					return integrity.Report{Complete: true, Files: []integrity.FileResult{{Path: "/usr/share/nebula/web/app.css",
						Class: integrity.ClassWebAsset, Status: integrity.StatusUnreadable, Reason: integrity.ReasonOpen}}}, nil
				}
			}
			r := e.run(t)
			if r.State != IntegrityRunIncomplete || r.Complete || r.Incomplete != tc.want {
				t.Fatalf("run = %+v", r)
			}
			if e.svc.IntegrityCheckStatus().Lock.Open {
				t.Fatal("an incomplete run opened the lock")
			}
		})
	}
}

func TestIntegrityCheckNeverOverlaps(t *testing.T) {
	e := newCheckEnv(t)
	entered, release := make(chan struct{}), make(chan struct{})
	e.svc.integrityCheck.check = func(ctx context.Context, ref integrity.Reference, o integrity.Options) (integrity.Report, error) {
		close(entered)
		<-release
		return integrity.Check(ctx, ref, o)
	}
	done := make(chan IntegrityRun)
	go func() {
		r, err := e.svc.RunIntegrityCheckOnce(context.Background())
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	<-entered
	if _, err := e.svc.RunIntegrityCheckOnce(context.Background()); !errors.Is(err, ErrIntegrityCheckRunning) {
		t.Fatalf("second run: err = %v, want ErrIntegrityCheckRunning", err)
	}
	// A running check does not block status reads, the lock query or
	// dispatch bookkeeping.
	quick := make(chan struct{})
	go func() {
		_ = e.svc.IntegrityCheckStatus()
		_ = e.svc.IntegrityLockOpen()
		e.svc.setDispatching("run-1", true)
		e.svc.setDispatching("run-1", false)
		close(quick)
	}()
	select {
	case <-quick:
	case <-time.After(5 * time.Second):
		t.Fatal("status, lock query or dispatch blocked by a running check")
	}
	close(release)
	if r := <-done; r.State != IntegrityRunClean {
		t.Fatalf("run = %+v", r)
	}
	if st := e.svc.IntegrityCheckStatus(); st.Total != 1 {
		t.Fatalf("total = %d", st.Total)
	}
}

func TestIntegrityCheckLoopRunsAtStartAndEveryInterval(t *testing.T) {
	e := newCheckEnv(t)
	ticks := make(chan time.Time)
	var waits []time.Duration
	var mu sync.Mutex
	e.configure(t, e.svc, IntegrityCheckConfig{After: func(d time.Duration) <-chan time.Time {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return ticks
	}})
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { e.svc.RunIntegrityChecks(ctx); close(stopped) }()
	ticks <- e.clock.Now() // the start run has finished when the loop waits
	ticks <- e.clock.Now()
	cancel()
	<-stopped
	st := e.svc.IntegrityCheckStatus()
	if st.Total < 2 {
		t.Fatalf("runs = %d, want the start run plus one per tick", st.Total)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, d := range waits {
		if d != integrity.DefaultInterval {
			t.Fatalf("waited %s, want %s", d, integrity.DefaultInterval)
		}
	}
}

func TestIntegrityCheckStateSurvivesRestart(t *testing.T) {
	e := newCheckEnv(t)
	writeMode(t, e.path("/usr/bin/nebula-server"), "server binarY", 0o755)
	first := e.run(t)
	// The executor restarts; the binary is repaired meanwhile.
	writeMode(t, e.path("/usr/bin/nebula-server"), "server binary", 0o755)
	s2, _ := startService(t, e.refEnv, "1.4.0")
	e.configure(t, s2, IntegrityCheckConfig{})
	st := s2.IntegrityCheckStatus()
	if !st.Lock.Open || !st.Lock.Since.Equal(first.Started) || st.Total != 1 || len(st.Runs) != 1 {
		t.Fatalf("state after restart = %+v", st)
	}
	got := st.Runs[0]
	if got.State != IntegrityRunDeviations || got.ManifestSHA256 != first.ManifestSHA256 || len(got.Deviations) != 1 ||
		got.Deviations[0].Path != "/usr/bin/nebula-server" || got.Deviations[0].Reason != integrity.ReasonSHA256 {
		t.Fatalf("stored run = %+v", got)
	}
	if !s2.IntegrityLockOpen() {
		t.Fatal("lock query after restart says closed")
	}
}

func TestIntegrityCheckStateUnreadableFailsClosed(t *testing.T) {
	cases := map[string]string{
		"garbage":        "{not json",
		"unknown field":  `{"total":0,"runs":[],"lock":{"open":false},"x":1}`,
		"trailing data":  `{"total":0,"runs":[],"lock":{"open":false}} {}`,
		"bad lock cause": `{"total":1,"runs":[],"lock":{"open":true,"cause":"whatever"}}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			e := newCheckEnv(t)
			if err := os.WriteFile(e.state, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			s2, h := startService(t, e.refEnv, "1.4.0")
			e.configure(t, s2, IntegrityCheckConfig{})
			st := s2.IntegrityCheckStatus()
			if !st.Lock.Open || st.Lock.Cause != IntegrityLockStateUnreadable {
				t.Fatalf("lock = %+v", st.Lock)
			}
			if !containsKind(h.kinds(), "integrity_check_state_unreadable") {
				t.Fatalf("records = %v", h.kinds())
			}
			// The next clean run keeps the lock (only the ack clears it)
			// and rewrites a valid state.
			e.svc = s2
			if r := e.run(t); r.State != IntegrityRunClean {
				t.Fatalf("run = %+v", r)
			}
			s3, _ := startService(t, e.refEnv, "1.4.0")
			e.configure(t, s3, IntegrityCheckConfig{})
			if st := s3.IntegrityCheckStatus(); !st.Lock.Open || st.Lock.Cause != IntegrityLockStateUnreadable || st.Total != 1 {
				t.Fatalf("state after rewrite = %+v", st)
			}
		})
	}
}

func TestIntegrityCheckStateTooLargeFailsClosed(t *testing.T) {
	e := newCheckEnv(t)
	if err := os.WriteFile(e.state, []byte(strings.Repeat(" ", maxIntegrityCheckState+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, _ := startService(t, e.refEnv, "1.4.0")
	e.configure(t, s2, IntegrityCheckConfig{})
	if st := s2.IntegrityCheckStatus(); !st.Lock.Open || st.Lock.Cause != IntegrityLockStateUnreadable {
		t.Fatalf("lock = %+v", st.Lock)
	}
}

func TestIntegrityCheckBoundsStoredRuns(t *testing.T) {
	e := newCheckEnv(t)
	for i := 0; i < maxIntegrityRuns+3; i++ {
		e.clock.Add(time.Hour)
		e.run(t)
	}
	st := e.svc.IntegrityCheckStatus()
	if len(st.Runs) != maxIntegrityRuns || st.Total != maxIntegrityRuns+3 {
		t.Fatalf("runs = %d total = %d", len(st.Runs), st.Total)
	}
	if !st.Runs[len(st.Runs)-1].Started.Equal(e.clock.Now()) {
		t.Fatal("newest run is not last")
	}
}

func TestIntegrityCheckBoundsDeviations(t *testing.T) {
	e := newCheckEnv(t)
	var files []integrity.FileResult
	for i := 0; i < maxIntegrityRunDeviations+5; i++ {
		files = append(files, integrity.FileResult{Path: "/usr/share/nebula/web/a" + strings.Repeat("x", i),
			Class: integrity.ClassWebAsset, Status: integrity.StatusMissing})
	}
	// A path with control and non-UTF-8 bytes is stored escaped.
	files = append(files, integrity.FileResult{Path: "/usr/bin/nebula\x1b[31m\xff", Class: integrity.ClassBinary,
		Status: integrity.StatusExtra})
	e.svc.integrityCheck.check = func(context.Context, integrity.Reference, integrity.Options) (integrity.Report, error) {
		return integrity.Report{Complete: true, Files: files}, nil
	}
	r := e.run(t)
	if len(r.Deviations) != maxIntegrityRunDeviations || r.DeviationsOmitted != 6 {
		t.Fatalf("deviations = %d omitted = %d", len(r.Deviations), r.DeviationsOmitted)
	}
	// The locking extra binary is counted even though it was omitted.
	if r.Locking != 1 || r.Missing != maxIntegrityRunDeviations+5 || r.Extra != 1 {
		t.Fatalf("run = %+v", r)
	}
	if !e.svc.IntegrityCheckStatus().Lock.Open {
		t.Fatal("omitted locking deviation did not open the lock")
	}
	if got := escapeIntegrityPath("/usr/bin/nebula\x1b[31m\xff"); got != `/usr/bin/nebula\x1b[31m\xff` {
		t.Fatalf("escaped = %q", got)
	}
	if got := escapeIntegrityPath(strings.Repeat("a", 2*maxIntegrityPath)); len(got) > maxIntegrityPath {
		t.Fatalf("escaped path has %d bytes", len(got))
	}
}

func TestSetIntegrityCheckRejectsBadConfig(t *testing.T) {
	e := newCheckEnv(t)
	flavour := func(context.Context) (string, error) { return "deb:amd64", nil }
	cases := map[string]IntegrityCheckConfig{
		"relative state":    {StatePath: "state.json", Flavour: flavour},
		"no flavour":        {StatePath: e.state},
		"too many files":    {StatePath: e.state, Flavour: flavour, MaxFiles: integrity.MaxFiles + 1},
		"too many bytes":    {StatePath: e.state, Flavour: flavour, MaxBytes: integrity.MaxBytes + 1},
		"budget > interval": {StatePath: e.state, Flavour: flavour, Interval: time.Minute, Budget: 2 * time.Minute},
		"budget too long":   {StatePath: e.state, Flavour: flavour, Interval: 3 * time.Hour, Budget: integrity.MaxBudget + time.Minute},
		"negative interval": {StatePath: e.state, Flavour: flavour, Interval: -time.Minute},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			s := &Service{db: e.db, log: e.svc.log}
			if err := s.SetIntegrityCheck(cfg); !errors.Is(err, ErrIntegrityCheckConfig) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A short interval without a budget gets a budget that fits it.
	c, err := IntegrityCheckConfig{StatePath: e.state, Flavour: flavour, Interval: time.Minute}.withDefaults()
	if err != nil || c.Budget != time.Minute || c.MaxFiles != integrity.MaxFiles || c.MaxBytes != integrity.MaxBytes {
		t.Fatalf("defaults = %+v, %v", c, err)
	}
	if c, err := (IntegrityCheckConfig{StatePath: e.state, Flavour: flavour}).withDefaults(); err != nil ||
		c.Interval != integrity.DefaultInterval || c.Budget != integrity.DefaultBudget {
		t.Fatalf("defaults = %+v, %v", c, err)
	}
}

func TestIntegrityCheckNotConfigured(t *testing.T) {
	s := &Service{}
	if _, err := s.RunIntegrityCheckOnce(context.Background()); !errors.Is(err, ErrIntegrityCheckNotConfigured) {
		t.Fatalf("err = %v", err)
	}
	if st := s.IntegrityCheckStatus(); st.Configured || st.Lock.Open {
		t.Fatalf("status = %+v", st)
	}
}

func TestDetectInstallFlavour(t *testing.T) {
	root := t.TempDir()
	if f, err := DetectInstallFlavour(root); err != nil || !strings.HasPrefix(f, "tarball:") {
		t.Fatalf("flavour = %q, %v", f, err)
	}
	writeAt := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeAt("var/lib/dpkg/info/nebula-operation-station.list")
	if f, err := DetectInstallFlavour(root); err != nil || !strings.HasPrefix(f, "deb:") {
		t.Fatalf("flavour = %q, %v", f, err)
	}
	writeAt(".dockerenv")
	if f, err := DetectInstallFlavour(root); err != nil || !strings.HasPrefix(f, "container:") {
		t.Fatalf("flavour = %q, %v", f, err)
	}
}
