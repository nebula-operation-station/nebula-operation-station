// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// writeReferenceDir writes the fixture's manifest, signature and list
// into a new directory, as install.sh/the upgrade lays them out.
func (f *fixture) writeReferenceDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, b := range map[string][]byte{
		release.ManifestFile:           f.manifest,
		release.SignatureFile:          f.sig,
		release.InstalledFilesArtifact: f.list,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// newTestMonitor returns a monitor over f that loads the reference from
// dir and logs into buf. The fake After records requested durations and
// hands back channels the test fires.
func newTestMonitor(t *testing.T, f *fixture, dir string, buf *bytes.Buffer) (*Monitor, *fakeAfter) {
	t.Helper()
	state := f.k.state(t)
	fa := &fakeAfter{req: make(chan time.Duration, 4)}
	clock := &fakeClock{now: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), step: time.Second}
	m := &Monitor{
		Load:    func(context.Context) (Reference, error) { return LoadReference(state, testVersion, dir) },
		Options: f.opts(),
		Now:     clock.Now,
		After:   fa.After,
		Log:     slog.New(slog.NewJSONHandler(buf, nil)),
	}
	return m, fa
}

type fakeAfter struct {
	req chan time.Duration
	ch  chan time.Time
}

func (a *fakeAfter) After(d time.Duration) <-chan time.Time {
	a.ch = make(chan time.Time, 1)
	a.req <- d
	return a.ch
}

func TestSelfCheckWithMatchingListIsOK(t *testing.T) {
	f := newFixture(t, defaultTree())
	var buf bytes.Buffer
	m, _ := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	st := m.RunOnce(context.Background())
	if st.State != StateOK || st.Cause != "" {
		t.Fatalf("state %q cause %q, want ok", st.State, st.Cause)
	}
	if st.ReleaseVersion != testVersion || st.Flavour != testFlavour || st.ListDigest == "" {
		t.Fatalf("reference identity missing: %+v", st)
	}
	if st.Files != len(defaultTree()) || st.OK != st.Files || len(st.Deviations) != 0 || st.Runs != 1 {
		t.Fatalf("counts: %+v", st)
	}
	if st.Checked.IsZero() {
		t.Fatal("checked time not set")
	}
	if st.Note != RootCompromiseNote {
		t.Fatalf("note %q", st.Note)
	}
	if got := m.Status(); got.State != StateOK || got.Runs != 1 {
		t.Fatalf("Status() = %+v", got)
	}
	if !strings.Contains(buf.String(), `"state":"ok"`) {
		t.Fatalf("log lacks state: %s", buf.String())
	}
}

func TestSelfCheckTamperedFileIsDeviation(t *testing.T) {
	f := newFixture(t, defaultTree())
	const secret = "TAMPERED-CONTENT-must-not-be-logged"
	// Same size as "server binary" would be a sha256 mismatch; a longer
	// content is a size mismatch. Both must be deviations.
	writeFile(t, f.path("/usr/bin/nebula-server"), secret, 0o755)
	if err := os.Remove(f.path("/usr/share/nebula/web/app.css")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	m, _ := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	st := m.RunOnce(context.Background())
	if st.State != StateDeviations {
		t.Fatalf("state %q, want deviations", st.State)
	}
	if st.Different != 1 || st.Missing != 1 || len(st.Deviations) != 2 {
		t.Fatalf("counts: %+v", st)
	}
	want := map[string]Deviation{
		"/usr/bin/nebula-server":        {Path: "/usr/bin/nebula-server", Class: ClassBinary, Status: StatusDifferent, Reason: ReasonSize},
		"/usr/share/nebula/web/app.css": {Path: "/usr/share/nebula/web/app.css", Class: ClassWebAsset, Status: StatusMissing},
	}
	for _, d := range st.Deviations {
		if want[d.Path] != d {
			t.Fatalf("deviation %+v, want %+v", d, want[d.Path])
		}
	}
	logged := buf.String()
	if strings.Contains(logged, secret) {
		t.Fatal("file content in the log")
	}
	if !strings.Contains(logged, `"state":"deviations"`) || !strings.Contains(logged, "/usr/bin/nebula-server") || !strings.Contains(logged, `"level":"ERROR"`) {
		t.Fatalf("log lacks the deviation: %s", logged)
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatal("file content in the status")
	}
}

// TestSelfCheckReleaseWithoutListIsIncomplete: for a release version a
// missing installed-files.json or reference directory (corruption,
// partial upgrade) is ADR 0015 D4 "check could not run completely":
// incomplete at ERROR, never a milder state.
func TestSelfCheckReleaseWithoutListIsIncomplete(t *testing.T) {
	f := newFixture(t, defaultTree())
	dir := f.writeReferenceDir(t)
	if err := os.Remove(filepath.Join(dir, release.InstalledFilesArtifact)); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	for _, tc := range []struct {
		name, dir string
	}{
		{"list missing", dir},
		{"empty directory", empty},
		{"directory missing", filepath.Join(empty, "nope")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			m, _ := newTestMonitor(t, f, tc.dir, &buf)
			st := m.RunOnce(context.Background())
			if st.State != StateIncomplete || st.Cause != CauseNoList {
				t.Fatalf("state %q cause %q, want incomplete/%s", st.State, st.Cause, CauseNoList)
			}
			if st.Files != 0 {
				t.Fatalf("reported as checked: %+v", st)
			}
			logged := buf.String()
			if !strings.Contains(logged, `"state":"incomplete"`) || !strings.Contains(logged, `"level":"ERROR"`) {
				t.Fatalf("log: %s", logged)
			}
			_, err := LoadReference(f.k.state(t), testVersion, tc.dir)
			if !errors.Is(err, ErrNoInstalledFiles) || errors.Is(err, ErrNotCheckable) {
				t.Fatalf("LoadReference error %v, want ErrNoInstalledFiles and not ErrNotCheckable", err)
			}
		})
	}
}

// TestSelfCheckDevelopmentBuildIsNotCheckable: only a version that is not
// a release has no list to check against.
func TestSelfCheckDevelopmentBuildIsNotCheckable(t *testing.T) {
	f := newFixture(t, defaultTree())
	dir := f.writeReferenceDir(t)
	var buf bytes.Buffer
	m, _ := newTestMonitor(t, f, dir, &buf)
	state := f.k.state(t)
	m.Load = func(context.Context) (Reference, error) { return LoadReference(state, "dev", dir) }
	st := m.RunOnce(context.Background())
	if st.State != StateNotCheckable || st.Cause != CauseDevelopmentBuild || st.Files != 0 {
		t.Fatalf("%+v, want not-checkable/%s", st, CauseDevelopmentBuild)
	}
	if !strings.Contains(buf.String(), `"state":"not-checkable"`) {
		t.Fatalf("log: %s", buf.String())
	}
}

// TestSelfCheckUnreadableFilesAreIncompleteNeverOK: a complete run with
// files that could not be checked is never clean (ADR 0015 D4).
func TestSelfCheckUnreadableFilesAreIncompleteNeverOK(t *testing.T) {
	f := newFixture(t, defaultTree())
	var buf bytes.Buffer
	m, _ := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	// Every file matches in type, size and mode, but the listed owner
	// cannot be resolved: the run completes and no file is checked ok.
	m.Options.Owners = func(string) (uint32, uint32, error) { return 0, 0, errors.New("no such user") }
	st := m.RunOnce(context.Background())
	if st.State != StateIncomplete || st.Cause != CauseUnreadable {
		t.Fatalf("state %q cause %q, want incomplete/%s", st.State, st.Cause, CauseUnreadable)
	}
	if st.Unreadable == 0 || st.OK+st.Unreadable != st.Files || st.NotChecked != 0 {
		t.Fatalf("counts: %+v", st)
	}
	for _, d := range st.Deviations {
		if d.Status != StatusUnreadable || d.Reason != ReasonOwnerUnknown {
			t.Fatalf("deviation %+v", d)
		}
	}
	if !strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Fatalf("log: %s", buf.String())
	}
}

// TestSelfCheckShutdownIsNotRecordedIncomplete: a run ended by the
// server's shutdown is not a "check incomplete" result; the previous
// result stays and nothing is logged at ERROR.
func TestSelfCheckShutdownIsNotRecordedIncomplete(t *testing.T) {
	f := newFixture(t, defaultTree())
	for _, tc := range []struct {
		name  string
		cause func(m *Monitor, cancel context.CancelFunc)
	}{
		{"canceled before the run", func(_ *Monitor, cancel context.CancelFunc) { cancel() }},
		{"canceled while loading", func(m *Monitor, cancel context.CancelFunc) {
			m.Load = func(ctx context.Context) (Reference, error) {
				cancel()
				return Reference{}, fmt.Errorf("load reference: %w", ctx.Err())
			}
		}},
		{"canceled while checking", func(m *Monitor, cancel context.CancelFunc) {
			resolve := m.Options.Owners
			m.Options.Owners = func(owner string) (uint32, uint32, error) {
				cancel()
				return resolve(owner)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			m, _ := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
			if st := m.RunOnce(context.Background()); st.State != StateOK {
				t.Fatalf("first run: %+v", st)
			}
			buf.Reset()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.cause(m, cancel)
			st := m.RunOnce(ctx)
			if st.State != StateOK || st.Runs != 1 {
				t.Fatalf("returned %+v, want the previous ok result", st)
			}
			if got := m.Status(); got.State != StateOK || got.Runs != 1 {
				t.Fatalf("stored %+v, want the previous ok result", got)
			}
			logged := buf.String()
			if strings.Contains(logged, `"level":"ERROR"`) || strings.Contains(logged, `"state":"incomplete"`) {
				t.Fatalf("shutdown logged as a failed check: %s", logged)
			}
			if !strings.Contains(logged, `"kind":"integrity_self_check"`) {
				t.Fatalf("shutdown not logged: %s", logged)
			}
		})
	}
}

// TestSelfCheckDeviationsSurviveShutdown: deviations found before the
// shutdown are real and still reported.
func TestSelfCheckDeviationsSurviveShutdown(t *testing.T) {
	f := newFixture(t, defaultTree())
	// The first listed file differs in size (found before any owner
	// lookup); the shutdown arrives while the second file is checked.
	writeFile(t, f.path("/lib/systemd/system/nebula-server.service"), "[Unit]\nreplaced\n", 0o644)
	var buf bytes.Buffer
	m, _ := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolve := m.Options.Owners
	m.Options.Owners = func(owner string) (uint32, uint32, error) {
		cancel()
		return resolve(owner)
	}
	st := m.RunOnce(ctx)
	if st.State != StateDeviations || st.Different != 1 || st.NotChecked == 0 || st.Runs != 1 {
		t.Fatalf("%+v, want the deviation reported", st)
	}
	if got := m.Status(); got.State != StateDeviations {
		t.Fatalf("stored %+v", got)
	}
}

func TestSelfCheckRejectedReferenceIsIncomplete(t *testing.T) {
	f := newFixture(t, defaultTree())
	other := newTestSK(t) // a root the state does not trust
	tamperedList := append(bytes.Clone(f.list[:len(f.list)-1]), ' ', '}')
	for _, tc := range []struct {
		name  string
		edit  func(dir string)
		state release.RootState
	}{
		{"list edited", func(dir string) { mustWrite(t, filepath.Join(dir, release.InstalledFilesArtifact), tamperedList) }, f.k.state(t)},
		{"signature missing", func(dir string) { mustRemove(t, filepath.Join(dir, release.SignatureFile)) }, f.k.state(t)},
		{"manifest missing", func(dir string) { mustRemove(t, filepath.Join(dir, release.ManifestFile)) }, f.k.state(t)},
		{"unknown root", func(string) {}, other.state(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := f.writeReferenceDir(t)
			tc.edit(dir)
			var buf bytes.Buffer
			m, _ := newTestMonitor(t, f, dir, &buf)
			m.Load = func(context.Context) (Reference, error) { return LoadReference(tc.state, testVersion, dir) }
			st := m.RunOnce(context.Background())
			if st.State != StateIncomplete || st.Cause != CauseReferenceRejected {
				t.Fatalf("state %q cause %q, want incomplete/reference-rejected", st.State, st.Cause)
			}
		})
	}
}

func TestSelfCheckUnknownFlavourIsIncomplete(t *testing.T) {
	f := newFixture(t, defaultTree())
	var buf bytes.Buffer
	m, _ := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	m.Options.Flavour = "tarball:arm64"
	st := m.RunOnce(context.Background())
	if st.State != StateIncomplete || st.Cause != CauseCheckFailed {
		t.Fatalf("state %q cause %q", st.State, st.Cause)
	}
}

func TestSelfCheckLimitIsIncompleteNotOK(t *testing.T) {
	f := newFixture(t, defaultTree())
	var buf bytes.Buffer
	m, _ := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	m.Options.MaxFiles = 2
	st := m.RunOnce(context.Background())
	if st.State != StateIncomplete || st.Cause != string(IncompleteFiles) || st.NotChecked == 0 {
		t.Fatalf("state %q cause %q: %+v", st.State, st.Cause, st)
	}
}

func TestSelfCheckDeviationsAreCapped(t *testing.T) {
	var tree []treeFile
	for i := range MaxStatusDeviations + 5 {
		tree = append(tree, treeFile{path: "/usr/share/nebula/web/f" + string(rune('a'+i/26)) + string(rune('a'+i%26)), data: "x", mode: 0o644})
	}
	f := newFixture(t, tree)
	for _, tf := range tree {
		mustRemove(t, f.path(tf.path))
	}
	var buf bytes.Buffer
	m, _ := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	st := m.RunOnce(context.Background())
	if st.State != StateDeviations || st.Missing != len(tree) || len(st.Deviations) != MaxStatusDeviations || !st.DeviationsTruncated {
		t.Fatalf("missing %d, listed %d, truncated %v", st.Missing, len(st.Deviations), st.DeviationsTruncated)
	}
}

func TestSelfCheckRunsAtStartAndEveryInterval(t *testing.T) {
	f := newFixture(t, defaultTree())
	var buf bytes.Buffer
	m, fa := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	if got := m.Status(); got.State != StatePending {
		t.Fatalf("before the first run: %q", got.State)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()

	// The start check runs before the first wait.
	if d := <-fa.req; d != DefaultInterval {
		t.Fatalf("waited %s, want %s", d, DefaultInterval)
	}
	if got := m.Status(); got.Runs != 1 || got.State != StateOK {
		t.Fatalf("after start: %+v", got)
	}
	first := m.Status().Checked

	// Tamper, then let the interval elapse: the periodic check sees it.
	writeFile(t, f.path("/usr/bin/nebula-executor"), "executor binarY", 0o755)
	fa.ch <- time.Time{}
	if d := <-fa.req; d != DefaultInterval {
		t.Fatalf("waited %s, want %s", d, DefaultInterval)
	}
	got := m.Status()
	if got.Runs != 2 || got.State != StateDeviations || !got.Checked.After(first) {
		t.Fatalf("after one interval: %+v", got)
	}
	if got.Deviations[0].Reason != ReasonSHA256 {
		t.Fatalf("deviation %+v", got.Deviations[0])
	}

	cancel()
	<-done
	if m.Status().Runs != 2 {
		t.Fatal("ran after cancellation")
	}
}

func TestSelfCheckIntervalOption(t *testing.T) {
	f := newFixture(t, defaultTree())
	var buf bytes.Buffer
	m, fa := newTestMonitor(t, f, f.writeReferenceDir(t), &buf)
	m.Interval = 5 * time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	if d := <-fa.req; d != 5*time.Minute {
		t.Fatalf("waited %s", d)
	}
	cancel()
	<-done
}

func TestSelfCheckNoLoaderIsIncomplete(t *testing.T) {
	m := &Monitor{Log: slog.New(slog.DiscardHandler)}
	if st := m.RunOnce(context.Background()); st.State != StateIncomplete || st.Cause != CauseReferenceRejected {
		t.Fatalf("%+v", st)
	}
}

func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRemove(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}
