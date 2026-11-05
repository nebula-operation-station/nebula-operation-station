// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconfetch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
)

const (
	idOK   = "11111111111111111111111111111111"
	idDeny = "22222222222222222222222222222222"
	idErr  = "33333333333333333333333333333333"
	idSVG  = "44444444444444444444444444444444"
	idBad  = "55555555555555555555555555555555"
)

func testPNG(t *testing.T) []byte {
	t.Helper()
	m := image.NewNRGBA(image.Rect(0, 0, 32, 16))
	for x := 0; x < 32; x++ {
		m.Set(x, x%16, color.NRGBA{R: 200, A: 255})
	}
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type fakeFetch struct {
	calls []string
	resp  map[string][]byte
}

func (f *fakeFetch) fetch(_ context.Context, u string) ([]byte, error) {
	f.calls = append(f.calls, u)
	if b, ok := f.resp[u]; ok {
		return b, nil
	}
	return nil, errors.New("icon fetch: unexpected status 404\x1b[2J")
}

func newRunner(t *testing.T, f *fakeFetch) (*runner, iconjob.Spool) {
	t.Helper()
	s := iconjob.Spool{Dir: t.TempDir()}
	for _, d := range []string{s.JobsDir(), s.ResultsDir()} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return &runner{spool: s, allow: iconfetch.DefaultAllowlist(), fetch: f.fetch,
		now: func() time.Time { return time.Unix(1000, 0) }, log: slog.New(slog.NewTextHandler(io.Discard, nil))}, s
}

func job(id, u string, at int64) iconjob.Job {
	return iconjob.Job{Format: iconjob.JobFormat, ID: id, Key: "postgres", URL: u, RequestedBy: "alice", CreatedAt: at}
}

func TestRunAllAnswersEveryJob(t *testing.T) {
	good := "https://upload.wikimedia.org/postgres.png"
	f := &fakeFetch{resp: map[string][]byte{
		good:                                 testPNG(t),
		"https://upload.wikimedia.org/x.svg": []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`),
	}}
	r, s := newRunner(t, f)
	for _, j := range []iconjob.Job{
		job(idOK, good, 1),
		job(idDeny, "https://evil.example/x.png", 2),
		job(idErr, "https://upload.wikimedia.org/missing.png", 3),
		job(idSVG, "https://upload.wikimedia.org/x.svg", 4),
	} {
		if err := s.WriteJob(j); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.JobsDir(), idBad+".json"), []byte(`{"format":"x"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := r.runAll(context.Background()); err != nil {
		t.Fatal(err)
	}

	ok, err := s.ReadResult(idOK)
	if err != nil || !ok.OK {
		t.Fatalf("ok job: %+v %v", ok, err)
	}
	want, err := iconstore.Sanitize(testPNG(t))
	if err != nil {
		t.Fatal(err)
	}
	if ok.SHA256 != want.SHA256 || !bytes.Equal(ok.PNG64, want.PNG64) {
		t.Fatalf("result is not the sanitizer's output")
	}
	for id, wantErr := range map[string]string{
		idDeny: "icon URL rejected",
		idErr:  "unexpected status 404?[2J",
		idSVG:  "unsupported image format",
		idBad:  "invalid job",
	} {
		res, err := s.ReadResult(id)
		if err != nil || res.OK || !strings.Contains(res.Error, wantErr) {
			t.Errorf("job %s: %+v %v (want error %q)", id, res, err, wantErr)
		}
	}
	for _, u := range f.calls {
		if strings.Contains(u, "evil.example") {
			t.Fatalf("fetched a URL off the allowlist: %s", u)
		}
	}
	if len(f.calls) != 3 {
		t.Fatalf("fetch calls %v", f.calls)
	}
	// A second run finds nothing to do.
	f.calls = nil
	if err := r.runAll(context.Background()); err != nil || len(f.calls) != 0 {
		t.Fatalf("second run: %v %v", f.calls, err)
	}
}

func TestRunAllStopsOnCancelledContext(t *testing.T) {
	r, s := newRunner(t, &fakeFetch{})
	if err := s.WriteJob(job(idOK, "https://upload.wikimedia.org/a.png", 1)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.runAll(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

// TestRunAllBoundsWork floods the spool: every fetch queues another job.
// Each round answers at most perRound jobs (oldest first) and runAll
// gives up after rounds rounds.
func TestRunAllBoundsWork(t *testing.T) {
	r, s := newRunner(t, &fakeFetch{})
	r.rounds, r.perRound = 4, 3
	n := 0
	queue := func() {
		n++
		if err := s.WriteJob(job(fmt.Sprintf("%032x", n), fmt.Sprintf("https://upload.wikimedia.org/%d.png", n), int64(n))); err != nil {
			t.Fatal(err)
		}
	}
	for range 4 {
		queue()
	}
	var calls []string
	r.fetch = func(_ context.Context, u string) ([]byte, error) {
		calls = append(calls, u)
		queue()
		return nil, errors.New("not found")
	}
	if err := r.runAll(context.Background()); err == nil || !strings.Contains(err.Error(), "keep arriving") {
		t.Fatalf("got %v", err)
	}
	if len(calls) != 4*3 {
		t.Fatalf("%d fetches, want %d", len(calls), 4*3)
	}
	for i, u := range calls[:3] {
		if want := fmt.Sprintf("https://upload.wikimedia.org/%d.png", i+1); u != want {
			t.Fatalf("fetch %d: %s, want %s", i, u, want)
		}
	}
	if rounds, perRound := (&runner{}).limits(); rounds != maxRounds || perRound != maxJobsPerRound {
		t.Fatalf("default limits %d %d", rounds, perRound)
	}
}

// TestRunAllEndsBatchAfterTimeLimit: a run starts no new fetch after
// maxBatch, so the unit's privileged firewall check runs again before
// the next batch; the remaining jobs stay queued for the next start.
func TestRunAllEndsBatchAfterTimeLimit(t *testing.T) {
	r, s := newRunner(t, &fakeFetch{})
	clock := time.Unix(1000, 0)
	r.now = func() time.Time { return clock }
	for i := range 10 {
		if err := s.WriteJob(job(fmt.Sprintf("%032x", i+1), fmt.Sprintf("https://upload.wikimedia.org/%d.png", i), int64(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	fetches := 0
	r.fetch = func(context.Context, string) ([]byte, error) {
		fetches++
		clock = clock.Add(maxBatch / 2) // each fetch takes half a batch
		return nil, errors.New("not found")
	}
	if err := r.runAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetches != 2 {
		t.Fatalf("%d fetches in one batch, want 2", fetches)
	}
	if jobs, _, err := s.PendingJobs(); err != nil || len(jobs) != 8 {
		t.Fatalf("%d jobs left queued, want 8: %v", len(jobs), err)
	}
	// The next start runs the next batch.
	if err := r.runAll(context.Background()); err != nil || fetches != 4 {
		t.Fatalf("second batch: %d fetches, %v", fetches, err)
	}
}

// TestRunAllAnswersLongUnreadableJob: a job file the helper may not read
// stays queued with a warning, and is answered with a failed result once
// it is older than iconjob.UnreadableJobAge, so the server sees it finish.
func TestRunAllAnswersLongUnreadableJob(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file modes, so mode 0 gives no EACCES; iconjob covers the logic with a simulated EACCES")
	}
	r, s := newRunner(t, &fakeFetch{})
	var logs bytes.Buffer
	r.log = slog.New(slog.NewTextHandler(&logs, nil))
	if err := s.WriteJob(job(idOK, "https://upload.wikimedia.org/a.png", 1)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.JobsDir(), idOK+".json")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	queued := r.now()
	if err := os.Chtimes(path, queued, queued); err != nil {
		t.Fatal(err)
	}
	if err := r.runAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadResult(idOK); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("young unreadable job answered: %v", err)
	}
	if !strings.Contains(logs.String(), "left queued") {
		t.Fatalf("no warning: %s", logs.String())
	}
	r.now = func() time.Time { return queued.Add(iconjob.UnreadableJobAge) }
	if err := r.runAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := s.ReadResult(idOK)
	if err != nil || res.OK || !strings.Contains(res.Error, "unreadable job") {
		t.Fatalf("result %+v %v", res, err)
	}
	if !strings.Contains(logs.String(), "level=WARN msg=\"unreadable job\"") {
		t.Fatalf("no warning: %s", logs.String())
	}
	if ids, err := s.FinishedJobs(); err != nil || len(ids) != 1 || ids[0] != idOK {
		t.Fatalf("server does not see the job finished: %v %v", ids, err)
	}
}

func TestSplitAllow(t *testing.T) {
	got := splitAllow(" a.example , ,b.example,")
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("got %q", got)
	}
	if len(splitAllow(" , ")) != 0 {
		t.Fatal("empty allowlist accepted")
	}
}

// TestHelperLinksNoDatabaseOrVault enforces ADR 0009 D6: the fetcher
// has no access to the server database, the vault or key material.
func TestHelperLinksNoDatabaseOrVault(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go tool not found: %v", err)
	}
	out, err := exec.Command(goBin, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const mod = "github.com/nebula-operation-station/nebula-operation-station/internal/"
	allowedInternal := map[string]bool{
		mod + "iconfetch":            true,
		mod + "iconstore":            true,
		mod + "netpolicy":            true, // iconfetch's dial-time address classification
		mod + "web/ui/icons/iconjob": true,
	}
	for _, p := range strings.Fields(string(out)) {
		switch {
		case p == "database/sql" || strings.HasPrefix(p, "database/sql/"):
			t.Errorf("helper links %s", p)
		case strings.Contains(p, "sqlite"):
			t.Errorf("helper links %s", p)
		case strings.HasPrefix(p, mod) && !allowedInternal[p]:
			t.Errorf("helper links internal package %s", p)
		}
	}
}
