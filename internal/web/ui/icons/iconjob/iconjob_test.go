// SPDX-License-Identifier: AGPL-3.0-or-later

package iconjob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
)

func newSpool(t *testing.T) Spool {
	t.Helper()
	s := Spool{Dir: t.TempDir()}
	for _, d := range []string{s.JobsDir(), s.ResultsDir()} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func validJob(id string) Job {
	return Job{Format: JobFormat, ID: id, Key: "postgres", URL: "https://upload.wikimedia.org/p.png", RequestedBy: "alice", CreatedAt: 100}
}

func okResult(id string) Result {
	png128 := []byte("\x89PNG large")
	sum := sha256.Sum256(png128)
	return Result{Format: ResultFormat, Job: id, OK: true, SHA256: hex.EncodeToString(sum[:]),
		PNG64: []byte("\x89PNG small"), PNG128: png128, StartedAt: 1, FinishedAt: 2}
}

const id1 = "0123456789abcdef0123456789abcdef"
const id2 = "fedcba9876543210fedcba9876543210"

func TestNewIDIsValid(t *testing.T) {
	a, err := NewID()
	if err != nil || !ValidID(a) {
		t.Fatalf("NewID %q %v", a, err)
	}
	b, _ := NewID()
	if a == b {
		t.Fatal("IDs repeat")
	}
}

func TestValidKeyMatchesSoftwarecat(t *testing.T) {
	for _, k := range []string{"postgres", "a", "nvidia", "x.y_z-1", strings.Repeat("a", 64), strings.Repeat("a", 65),
		"", "-a", ".a", "A", "a b", "a/b", "../x", "ä", "a\x00"} {
		_, err := softwarecat.NewKey(k)
		if got, want := ValidKey(k), err == nil; got != want {
			t.Errorf("ValidKey(%q) = %v, softwarecat says %v", k, got, want)
		}
	}
}

func TestJobValidateRejectsMalformed(t *testing.T) {
	for name, mut := range map[string]func(*Job){
		"format":     func(j *Job) { j.Format = "x" },
		"id":         func(j *Job) { j.ID = "../../etc/passwd" },
		"key":        func(j *Job) { j.Key = "Bad Key" },
		"http":       func(j *Job) { j.URL = "http://upload.wikimedia.org/p.png" },
		"url space":  func(j *Job) { j.URL = "https://upload.wikimedia.org/a b" },
		"url long":   func(j *Job) { j.URL = "https://x/" + strings.Repeat("a", MaxURLLen) },
		"actor":      func(j *Job) { j.RequestedBy = "" },
		"actor ctl":  func(j *Job) { j.RequestedBy = "al\nice" },
		"created_at": func(j *Job) { j.CreatedAt = 0 },
	} {
		j := validJob(id1)
		mut(&j)
		if err := j.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	j := validJob(id1)
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestResultValidateRejectsMalformed(t *testing.T) {
	for name, mut := range map[string]func(*Result){
		"format":        func(r *Result) { r.Format = "x" },
		"job":           func(r *Result) { r.Job = "x" },
		"hash mismatch": func(r *Result) { r.SHA256 = strings.Repeat("a", 64) },
		"hash upper":    func(r *Result) { r.SHA256 = strings.ToUpper(r.SHA256) },
		"no png64":      func(r *Result) { r.PNG64 = nil },
		"big png":       func(r *Result) { r.PNG64 = make([]byte, MaxPNGBytes+1) },
		"ok with error": func(r *Result) { r.Error = "x" },
		"failed with png": func(r *Result) {
			r.OK, r.Error, r.SHA256 = false, "nope", ""
		},
		"failed no error": func(r *Result) { *r = Result{Format: ResultFormat, Job: id1} },
		"failed ctl error": func(r *Result) {
			*r = Result{Format: ResultFormat, Job: id1, Error: "a\x1b[31m"}
		},
	} {
		r := okResult(id1)
		mut(&r)
		if err := r.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestCleanErrorBoundsText(t *testing.T) {
	if got := CleanError("a\x1b[31m\u202eb"); got != "a?[31m???b" {
		t.Fatalf("got %q", got)
	}
	if got := CleanError(strings.Repeat("x", 2*MaxErrorLen)); len(got) != MaxErrorLen {
		t.Fatalf("len %d", len(got))
	}
	if CleanError("") != "failed" {
		t.Fatal("empty")
	}
}

func TestSpoolRoundTrip(t *testing.T) {
	s := newSpool(t)
	if !s.Available() {
		t.Fatal("not available")
	}
	older := validJob(id2)
	older.CreatedAt = 50
	for _, j := range []Job{validJob(id1), older} {
		if err := s.WriteJob(j); err != nil {
			t.Fatal(err)
		}
	}
	jobs, bad, err := s.PendingJobs()
	if err != nil || len(bad) != 0 || len(jobs) != 2 || jobs[0].ID != id2 {
		t.Fatalf("pending %+v %v %v", jobs, bad, err)
	}
	if err := s.WriteResult(okResult(id1)); err != nil {
		t.Fatal(err)
	}
	jobs, _, _ = s.PendingJobs()
	if len(jobs) != 1 || jobs[0].ID != id2 {
		t.Fatalf("answered job still pending: %+v", jobs)
	}
	ids, err := s.FinishedJobs()
	if err != nil || len(ids) != 1 || ids[0] != id1 {
		t.Fatalf("finished %v %v", ids, err)
	}
	r, err := s.ReadResult(id1)
	if err != nil || !r.OK || r.SHA256 != okResult(id1).SHA256 {
		t.Fatalf("result %+v %v", r, err)
	}
	if err := s.RemoveJob(id1); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.FinishedJobs(); err != nil || len(ids) != 0 {
		t.Fatalf("result of a removed job still listed: %v %v", ids, err)
	}
	if _, err := s.ReadResult(id1); err != nil {
		t.Fatalf("server must not remove the result: %v", err)
	}
	if _, err := s.ReadJob(id1); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("job after remove: %v", err)
	}
	if err := s.RemoveJob(id1); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

func TestSpoolRejectsHostileFiles(t *testing.T) {
	s := newSpool(t)
	write := func(dir, name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	// Unknown field, trailing data, ID mismatch, oversize.
	write(s.JobsDir(), id1+".json", `{"format":"nebula-iconfetch-job-v1","id":"`+id1+`","key":"a","url":"https://x/","requested_by":"a","created_at":1,"extra":1}`)
	write(s.JobsDir(), id2+".json", `{"format":"nebula-iconfetch-job-v1","id":"`+id1+`","key":"a","url":"https://x/","requested_by":"a","created_at":1}`)
	big := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	write(s.JobsDir(), big+".json", strings.Repeat(" ", MaxJobBytes+1))
	// Symlink job.
	link := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := os.Symlink("/etc/passwd", filepath.Join(s.JobsDir(), link+".json")); err != nil {
		t.Fatal(err)
	}
	// Not a job file name: ignored.
	write(s.JobsDir(), "README", "x")
	write(s.JobsDir(), "ABC.json", "{}")
	jobs, bad, err := s.PendingJobs()
	if err != nil || len(jobs) != 0 || len(bad) != 4 {
		t.Fatalf("jobs %v bad %v err %v", jobs, bad, err)
	}
	for id, e := range bad {
		if id == link {
			continue // ELOOP from O_NOFOLLOW
		}
		if !errors.Is(e, ErrInvalid) {
			t.Errorf("%s: %v", id, e)
		}
	}
	write(s.ResultsDir(), id1+".json", `{"format":"nebula-iconfetch-result-v1","job":"`+id1+`","ok":false,"error":"x"} {}`)
	if _, err := s.ReadResult(id1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing data: %v", err)
	}
	write(s.ResultsDir(), id2+".json", `{"format":"nebula-iconfetch-result-v1","job":"`+id1+`","ok":false,"error":"x"}`)
	if _, err := s.ReadResult(id2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other job: %v", err)
	}
	write(s.ResultsDir(), big+".json", strings.Repeat(" ", MaxResultBytes+1))
	if _, err := s.ReadResult(big); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize: %v", err)
	}
	if _, err := s.ReadResult("../../x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("path: %v", err)
	}
}

func TestPruneResultsRemovesOldFiles(t *testing.T) {
	s := newSpool(t)
	if err := s.WriteJob(validJob(id1)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteResult(Result{Format: ResultFormat, Job: id1, Error: "x"}); err != nil {
		t.Fatal(err)
	}
	s.PruneResults(time.Hour, time.Now())
	if ids, _ := s.FinishedJobs(); len(ids) != 1 {
		t.Fatal("fresh result pruned")
	}
	s.PruneResults(time.Hour, time.Now().Add(2*time.Hour))
	if ids, _ := s.FinishedJobs(); len(ids) != 0 {
		t.Fatal("old result kept")
	}
}

func TestReadResultClassifiesOpenErrors(t *testing.T) {
	s := newSpool(t)
	// A symlinked result (ELOOP from O_NOFOLLOW) can never be read.
	if err := os.Symlink("/etc/passwd", filepath.Join(s.ResultsDir(), id1+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadResult(id1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := s.ReadResult(id2); err == nil || errors.Is(err, ErrInvalid) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing result must stay ErrNotExist: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Log("running as root: EACCES case skipped")
		return
	}
	if err := s.WriteResult(okResult(id2)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(s.ResultsDir(), id2+".json"), 0); err != nil {
		t.Fatal(err)
	}
	// An unreadable result is transient (a permission fix may land), not a
	// format violation.
	_, err := s.ReadResult(id2)
	if !errors.Is(err, ErrUnreadable) || errors.Is(err, ErrInvalid) {
		t.Fatalf("unreadable: %v", err)
	}
}

func TestClassifyOpen(t *testing.T) {
	for name, tc := range map[string]struct {
		in   error
		want error
	}{
		"eloop":  {syscall.ELOOP, ErrInvalid},
		"eacces": {syscall.EACCES, ErrUnreadable},
		"eperm":  {syscall.EPERM, ErrUnreadable},
	} {
		if got := classifyOpen(tc.in); !errors.Is(got, tc.want) {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
	// Other errors stay as they are.
	if got := classifyOpen(os.ErrNotExist); !errors.Is(got, os.ErrNotExist) {
		t.Errorf("enoent: %v", got)
	}
}

// denyOpen makes opens of the given paths fail with EACCES, as for a file
// without read permission, independent of the test's UID (root bypasses
// mode 0). allow lifts the denial of one path.
func denyOpen(t *testing.T, paths ...string) (allow func(string)) {
	t.Helper()
	var mu sync.Mutex
	denied := map[string]bool{}
	for _, p := range paths {
		denied[p] = true
	}
	orig := openFile
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		mu.Lock()
		d := denied[name]
		mu.Unlock()
		if d {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EACCES}
		}
		return orig(name, flag, perm)
	}
	t.Cleanup(func() { openFile = orig })
	return func(p string) {
		mu.Lock()
		delete(denied, p)
		mu.Unlock()
	}
}

func TestReadFileRealEACCES(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file modes; the simulated EACCES tests below cover the logic")
	}
	s := newSpool(t)
	if err := s.WriteResult(okResult(id1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(s.ResultsDir(), id1+".json"), 0); err != nil {
		t.Fatal(err)
	}
	s.sleep = func(time.Duration) {}
	if _, err := s.ReadResult(id1); !errors.Is(err, ErrUnreadable) || errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestReadFileRetriesUnreadableBounded(t *testing.T) {
	s := newSpool(t)
	if err := s.WriteResult(okResult(id1)); err != nil {
		t.Fatal(err)
	}
	denyOpen(t, filepath.Join(s.ResultsDir(), id1+".json"))
	var sleeps int
	s.sleep = func(time.Duration) { sleeps++ }
	_, err := s.ReadResult(id1)
	if !errors.Is(err, ErrUnreadable) || errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if sleeps != openRetries-1 {
		t.Fatalf("retried after %d pauses, want %d", sleeps, openRetries-1)
	}
}

func TestReadFileRetriesUnreadableUntilFixed(t *testing.T) {
	s := newSpool(t)
	if err := s.WriteResult(okResult(id1)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.ResultsDir(), id1+".json")
	allow := denyOpen(t, path)
	s.sleep = func(time.Duration) { allow(path) }
	r, err := s.ReadResult(id1)
	if err != nil || !r.OK {
		t.Fatalf("retry after permission fix: %v", err)
	}
}

// TestRetryBudgetBoundsManyFiles: one budget bounds the retry pauses of
// many unreadable files, and a cancelled context stops retrying at once,
// without sleeping.
func TestRetryBudgetBoundsManyFiles(t *testing.T) {
	s := newSpool(t)
	var paths []string
	var ids []string
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("%032x", i+1)
		if err := s.WriteResult(okResult(id)); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		paths = append(paths, filepath.Join(s.ResultsDir(), id+".json"))
	}
	denyOpen(t, paths...)
	var sleeps int
	s.sleep = func(time.Duration) { sleeps++ }
	rb := NewRetryBudget(context.Background(), MaxRetryPauses)
	for _, id := range ids {
		if _, err := s.ReadResultWith(rb, id); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if sleeps != MaxRetryPauses {
		t.Fatalf("%d pauses for %d files, want %d", sleeps, len(ids), MaxRetryPauses)
	}

	// A cancelled context: no pause at all, and the real timer path
	// returns at once.
	s.sleep = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rb = NewRetryBudget(ctx, 1000)
	start := time.Now()
	for _, id := range ids {
		if _, err := s.ReadResultWith(rb, id); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if d := time.Since(start); d > openRetryDelay {
		t.Fatalf("cancelled budget still paused: %s", d)
	}

	// The listing shares one budget too.
	jobDir := s.JobsDir()
	var jobPaths []string
	for _, id := range ids {
		if err := s.WriteJob(validJob(id)); err != nil {
			t.Fatal(err)
		}
		jobPaths = append(jobPaths, filepath.Join(jobDir, id+".json"))
		if err := os.Remove(filepath.Join(s.ResultsDir(), id+".json")); err != nil {
			t.Fatal(err)
		}
	}
	denyOpen(t, jobPaths...)
	sleeps = 0
	s.sleep = func(time.Duration) { sleeps++ }
	p, err := s.ListPending(context.Background(), time.Now())
	if err != nil || len(p.Waiting) != len(ids) || len(p.Jobs) != 0 || len(p.Bad) != 0 {
		t.Fatalf("pending %+v %v", p, err)
	}
	if sleeps != MaxRetryPauses {
		t.Fatalf("listing paused %d times, want %d", sleeps, MaxRetryPauses)
	}
}

func TestPendingJobsKeepsUnreadableJobQueued(t *testing.T) {
	s := newSpool(t)
	if err := s.WriteJob(validJob(id1)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.JobsDir(), id1+".json")
	allow := denyOpen(t, path)
	s.sleep = func(time.Duration) {}
	// A job the helper may not read stays queued: it is not returned and
	// not answered, so no failed result drops the work.
	p, err := s.ListPending(context.Background(), time.Now())
	if err != nil || len(p.Jobs) != 0 || len(p.Bad) != 0 || len(p.Waiting) != 1 || p.Waiting[0] != id1 {
		t.Fatalf("pending %+v err %v", p, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("job file removed: %v", err)
	}
	// A permission fix before the next run makes the job readable again.
	allow(path)
	p, err = s.ListPending(context.Background(), time.Now())
	if err != nil || len(p.Bad) != 0 || len(p.Waiting) != 0 || len(p.Jobs) != 1 || p.Jobs[0].ID != id1 {
		t.Fatalf("after fix: %+v err %v", p, err)
	}
}

func TestPendingJobsAnswersLongUnreadableJob(t *testing.T) {
	s := newSpool(t)
	if err := s.WriteJob(validJob(id1)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.JobsDir(), id1+".json")
	denyOpen(t, path)
	s.sleep = func(time.Duration) {}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Just before the bound: still queued.
	p, err := s.ListPending(context.Background(), st.ModTime().Add(UnreadableJobAge-time.Second))
	if err != nil || len(p.Waiting) != 1 || len(p.Bad) != 0 {
		t.Fatalf("before bound: %+v %v", p, err)
	}
	// After the bound: reported for a failed result, as ErrUnreadable.
	p, err = s.ListPending(context.Background(), st.ModTime().Add(UnreadableJobAge))
	if err != nil || len(p.Waiting) != 0 || len(p.Jobs) != 0 || !errors.Is(p.Bad[id1], ErrUnreadable) {
		t.Fatalf("after bound: %+v %v", p, err)
	}
}

func TestFinishedJobsBoundsListing(t *testing.T) {
	s := newSpool(t)
	touch := func(dir, id string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, id+".json"), nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	// Results without a job (the helper's directory) are never listed, no
	// matter how many there are.
	for i := 0; i < MaxListEntries+10; i++ {
		touch(s.ResultsDir(), fmt.Sprintf("%032x", i+1))
	}
	if ids, err := s.FinishedJobs(); err != nil || len(ids) != 0 {
		t.Fatalf("orphan results listed: %d %v", len(ids), err)
	}
	// More finished jobs than one listing may read: the call stops at the cap.
	for i := 0; i < MaxListEntries+10; i++ {
		touch(s.JobsDir(), fmt.Sprintf("%032x", i+1))
	}
	ids, err := s.FinishedJobs()
	if err != nil || len(ids) != MaxListEntries {
		t.Fatalf("listed %d, want %d: %v", len(ids), MaxListEntries, err)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("not sorted at %d: %s %s", i, ids[i-1], ids[i])
		}
	}
}
