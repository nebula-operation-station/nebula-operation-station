// SPDX-License-Identifier: AGPL-3.0-or-later

package icons

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
)

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// auditLog collects JSON log records.
type auditLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (a *auditLog) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.buf.Write(p)
}

// events returns the audit records of the given kind.
func (a *auditLog) events(t *testing.T, kind string) []map[string]any {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(a.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if m["msg"] == "audit" && m["kind"] == kind {
			out = append(out, m)
		}
	}
	return out
}

type fixture struct {
	svc   *Service
	cat   *softwarecat.Store
	store *iconstore.Store
	dir   string
	spool iconjob.Spool
	log   *auditLog
}

func unitsDoc(units ...string) []byte {
	var lines []string
	for _, u := range units {
		lines = append(lines, u+".service loaded active running Some unit")
	}
	return []byte(fmt.Sprintf(`{"format":"systemd-units-v1","units":%q}`,
		base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))))
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := func() time.Time { return t0 }
	cat, err := softwarecat.NewStore(db, softwarecat.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	host := softwarecat.Target{Kind: softwarecat.TargetHost, HostID: "h1"}
	if _, err := cat.IngestServiceList(ctx, host, unitsDoc("widgetd", "otherd"), t0); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := iconstore.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sp := iconjob.Spool{Dir: t.TempDir()}
	for _, d := range []string{sp.JobsDir(), sp.ResultsDir()} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	al := &auditLog{}
	svc, err := New(Config{Spool: sp, Store: st, Catalog: cat, Now: now, Log: slog.New(slog.NewJSONHandler(al, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, cat: cat, store: st, dir: dir, spool: sp, log: al}
}

func testPNG(t *testing.T, c color.NRGBA) []byte {
	t.Helper()
	m := image.NewNRGBA(image.Rect(0, 0, 40, 20))
	for x := 0; x < 40; x++ {
		m.Set(x, x%20, c)
	}
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

var (
	red  = color.NRGBA{R: 220, A: 255}
	blue = color.NRGBA{B: 220, A: 255}
)

const svg = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`

func catalogIcon(t *testing.T, f *fixture, key string) string {
	t.Helper()
	e, err := f.cat.Entry(context.Background(), softwarecat.Key(key))
	if err != nil {
		t.Fatal(err)
	}
	return e.IconSHA
}

func auditActions(t *testing.T, f *fixture) map[string]int {
	t.Helper()
	recs, err := f.cat.AuditTrail(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, r := range recs {
		out[r.Action]++
	}
	return out
}

func TestQueueFetchWritesValidatedJob(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, err := f.svc.QueueFetch(ctx, "alice", "widgetd", "https://UPLOAD.wikimedia.org:443/w.png")
	if err != nil {
		t.Fatal(err)
	}
	j, err := f.spool.ReadJob(id)
	if err != nil {
		t.Fatal(err)
	}
	if j.Key != "widgetd" || j.URL != "https://upload.wikimedia.org/w.png" || j.RequestedBy != "alice" || j.CreatedAt != t0.Unix() {
		t.Fatalf("job %+v", j)
	}
	ev := f.log.events(t, "icon_fetch_queued")
	if len(ev) != 1 || ev[0]["user"] != "alice" || ev[0]["job"] != id || ev[0]["url"] != j.URL {
		t.Fatalf("audit %v", ev)
	}
}

func TestQueueFetchRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for name, tc := range map[string]struct{ key, url string }{
		"http":         {"widgetd", "http://upload.wikimedia.org/w.png"},
		"ip literal":   {"widgetd", "https://169.254.169.254/latest"},
		"off list":     {"widgetd", "https://evil.example/w.png"},
		"user info":    {"widgetd", "https://a:b@upload.wikimedia.org/w.png"},
		"port":         {"widgetd", "https://upload.wikimedia.org:8443/w.png"},
		"unknown key":  {"nosuchkey", "https://upload.wikimedia.org/w.png"},
		"invalid key":  {"../etc", "https://upload.wikimedia.org/w.png"},
		"bad actor":    {"widgetd", "https://upload.wikimedia.org/w.png"},
		"merged entry": {"otherd", "https://upload.wikimedia.org/w.png"},
	} {
		actor := "alice"
		if name == "bad actor" {
			actor = "al\nice"
		}
		if name == "merged entry" {
			if err := f.cat.Merge(ctx, "alice", "otherd", "widgetd"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.svc.QueueFetch(ctx, actor, tc.key, tc.url); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if ids, _ := os.ReadDir(f.spool.JobsDir()); len(ids) != 0 {
		t.Fatalf("rejected input queued %d jobs", len(ids))
	}
	if n := len(f.log.events(t, "icon_fetch_rejected")); n != 9 {
		t.Fatalf("rejected audit events %d", n)
	}
}

func TestQueueFetchNeedsSpool(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(f.spool.JobsDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.QueueFetch(context.Background(), "alice", "widgetd", "https://upload.wikimedia.org/w.png"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

// helperResult writes what nebula-iconfetch would write for job id.
func helperResult(t *testing.T, f *fixture, id string, png128 []byte) {
	t.Helper()
	sum := sha256.Sum256(png128)
	if err := f.spool.WriteResult(iconjob.Result{Format: iconjob.ResultFormat, Job: id, OK: true,
		SHA256: hex.EncodeToString(sum[:]), PNG64: png128, PNG128: png128, StartedAt: 1, FinishedAt: 2}); err != nil {
		t.Fatal(err)
	}
}

func TestImportResultsStoresIconAndSetsKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, err := f.svc.QueueFetch(ctx, "alice", "widgetd", "https://upload.wikimedia.org/w.png")
	if err != nil {
		t.Fatal(err)
	}
	ic, err := iconstore.Sanitize(testPNG(t, red))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.spool.WriteResult(iconjob.Result{Format: iconjob.ResultFormat, Job: id, OK: true,
		SHA256: ic.SHA256, PNG64: ic.PNG64, PNG128: ic.PNG128}); err != nil {
		t.Fatal(err)
	}
	rep, err := f.svc.ImportResults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sha := rep.Imported[id]
	if sha == "" || len(rep.Failed) != 0 {
		t.Fatalf("report %+v", rep)
	}
	// The sanitizer is idempotent on its own 128 px output.
	if sha != ic.SHA256 {
		t.Fatalf("stored %s, helper %s", sha, ic.SHA256)
	}
	if got := catalogIcon(t, f, "widgetd"); got != sha {
		t.Fatalf("catalog icon %q", got)
	}
	reg, err := f.cat.Icon(ctx, sha)
	if err != nil || reg.Kind != softwarecat.IconURL || reg.SourceURL != "https://upload.wikimedia.org/w.png" || reg.AddedBy != "alice" {
		t.Fatalf("registered %+v %v", reg, err)
	}
	for _, size := range []int{iconstore.SmallSize, iconstore.LargeSize} {
		p, _ := f.store.Path(sha, size)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("stored file: %v", err)
		}
	}
	if _, err := f.spool.ReadJob(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("job not removed: %v", err)
	}
	acts := auditActions(t, f)
	if acts["icon_register"] != 1 || acts["icon_set"] != 1 {
		t.Fatalf("catalog audit %v", acts)
	}
	ev := f.log.events(t, "icon_fetch_imported")
	if len(ev) != 1 || ev[0]["user"] != "alice" || ev[0]["sha256"] != sha || ev[0]["key"] != "widgetd" {
		t.Fatalf("audit %v", ev)
	}
	// The leftover result is not imported again.
	rep, err = f.svc.ImportResults(ctx)
	if err != nil || len(rep.Imported)+len(rep.Failed) != 0 {
		t.Fatalf("second import %+v %v", rep, err)
	}
}

// spoolJob writes a job with a chosen ID, as QueueFetch would.
func spoolJob(t *testing.T, f *fixture, id string) {
	t.Helper()
	if err := f.spool.WriteJob(iconjob.Job{Format: iconjob.JobFormat, ID: id, Key: "widgetd",
		URL: "https://upload.wikimedia.org/w.png", RequestedBy: "alice", CreatedAt: t0.Unix()}); err != nil {
		t.Fatal(err)
	}
}

func TestImportResultsSkipsHandledResultsBeforeCap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// More handled results than one run may import, all sorting ahead of
	// the new one: their job files are gone and results/ is only pruned
	// by the helper after a day.
	for i := 0; i < 2*MaxImportPerRun; i++ {
		helperResult(t, f, fmt.Sprintf("%032x", i+1), testPNG(t, red))
	}
	id := strings.Repeat("f", 32)
	spoolJob(t, f, id)
	helperResult(t, f, id, testPNG(t, blue))
	rep, err := f.svc.ImportResults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Imported) != 1 || rep.Imported[id] == "" || len(rep.Failed) != 0 {
		t.Fatalf("report %+v", rep)
	}
	if got := catalogIcon(t, f, "widgetd"); got != rep.Imported[id] {
		t.Fatalf("catalog icon %q", got)
	}
}

func TestImportResultsCapsOneRun(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := 0; i <= MaxImportPerRun; i++ {
		id := fmt.Sprintf("%032x", i+1)
		spoolJob(t, f, id)
		helperResult(t, f, id, testPNG(t, red))
	}
	rep, err := f.svc.ImportResults(ctx)
	if err != nil || len(rep.Imported)+len(rep.Failed) != MaxImportPerRun {
		t.Fatalf("first run handled %d+%d, want %d: %v", len(rep.Imported), len(rep.Failed), MaxImportPerRun, err)
	}
	rep, err = f.svc.ImportResults(ctx)
	last := fmt.Sprintf("%032x", MaxImportPerRun+1)
	if err != nil || len(rep.Imported) != 1 || rep.Imported[last] == "" {
		t.Fatalf("second run %+v %v", rep, err)
	}
	if rep, err = f.svc.ImportResults(ctx); err != nil || len(rep.Imported)+len(rep.Failed) != 0 {
		t.Fatalf("third run %+v %v", rep, err)
	}
}

func TestImportResultsDistrustsHelperOutput(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	queue := func() string {
		id, err := f.svc.QueueFetch(ctx, "alice", "widgetd", "https://upload.wikimedia.org/w.png")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	// A polyglot: a valid PNG with an HTML payload after IEND, hash
	// consistent, as a compromised helper could write it.
	poly := append(testPNG(t, blue), []byte("<html><script>alert(1)</script>")...)
	idPoly := queue()
	helperResult(t, f, idPoly, poly)
	rep, err := f.svc.ImportResults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sha := rep.Imported[idPoly]
	sum := sha256.Sum256(poly)
	if sha == "" || sha == hex.EncodeToString(sum[:]) {
		t.Fatalf("polyglot stored as is: %+v", rep)
	}
	p, _ := f.store.Path(sha, iconstore.LargeSize)
	stored, err := os.ReadFile(p)
	if err != nil || bytes.Contains(stored, []byte("script")) {
		t.Fatalf("stored icon keeps the payload (%v)", err)
	}

	// SVG bytes, an invalid result file and a failed fetch: no icon.
	idSVG := queue()
	helperResult(t, f, idSVG, []byte(svg))
	idBad := queue()
	if err := os.WriteFile(filepath.Join(f.spool.ResultsDir(), idBad+".json"), []byte(`{"format":"x"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	idFail := queue()
	if err := f.spool.WriteResult(iconjob.Result{Format: iconjob.ResultFormat, Job: idFail, Error: "icon fetch: unexpected status 404"}); err != nil {
		t.Fatal(err)
	}
	// A result whose job the server never queued is ignored.
	stray := "99999999999999999999999999999999"
	helperResult(t, f, stray, testPNG(t, red))

	rep, err = f.svc.ImportResults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Imported) != 0 || len(rep.Failed) != 3 {
		t.Fatalf("report %+v", rep)
	}
	for id, want := range map[string]string{idSVG: "unsupported image format", idBad: "invalid helper result", idFail: "404"} {
		if !strings.Contains(rep.Failed[id], want) {
			t.Errorf("job %s: %q, want %q", id, rep.Failed[id], want)
		}
	}
	if got := catalogIcon(t, f, "widgetd"); got != sha {
		t.Fatalf("catalog icon changed to %q", got)
	}
	if n := len(f.log.events(t, "icon_fetch_failed")); n != 3 {
		t.Fatalf("failed audit events %d", n)
	}
}

func TestUploadUsesSanitizer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	subj := softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}
	want, err := iconstore.Sanitize(testPNG(t, red))
	if err != nil {
		t.Fatal(err)
	}
	sha, err := f.svc.Upload(ctx, "alice", subj, testPNG(t, red))
	if err != nil || sha != want.SHA256 {
		t.Fatalf("upload %q %v", sha, err)
	}
	if got := catalogIcon(t, f, "widgetd"); got != sha {
		t.Fatalf("catalog icon %q", got)
	}
	reg, err := f.cat.Icon(ctx, sha)
	if err != nil || reg.Kind != softwarecat.IconUpload || reg.SourceURL != "" {
		t.Fatalf("registered %+v %v", reg, err)
	}
	if ev := f.log.events(t, "icon_uploaded"); len(ev) != 1 || ev[0]["sha256"] != sha {
		t.Fatalf("audit %v", ev)
	}

	for name, tc := range map[string]struct {
		subj softwarecat.IconSubject
		data []byte
	}{
		"svg":           {subj, []byte(svg)},
		"webp":          {subj, append([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "), make([]byte, 32)...)},
		"oversize":      {subj, make([]byte, iconstore.MaxInputBytes+1)},
		"empty":         {subj, nil},
		"unknown key":   {softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "nosuchkey"}, testPNG(t, blue)},
		"unknown asset": {softwarecat.IconSubject{Kind: softwarecat.SubjectAsset, ID: "a1"}, testPNG(t, blue)},
		"bad kind":      {softwarecat.IconSubject{Kind: "x", ID: "a1"}, testPNG(t, blue)},
	} {
		if _, err := f.svc.Upload(ctx, "alice", tc.subj, tc.data); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if got := catalogIcon(t, f, "widgetd"); got != sha {
		t.Fatalf("rejected upload changed the icon to %q", got)
	}
	if n := len(f.log.events(t, "icon_upload_rejected")); n != 7 {
		t.Fatalf("rejected audit events %d", n)
	}
}

func TestRollbackRestoresPreviousIcon(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	subj := softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}
	shaA, err := f.svc.Upload(ctx, "alice", subj, testPNG(t, red))
	if err != nil {
		t.Fatal(err)
	}
	shaB, err := f.svc.Upload(ctx, "bob", subj, testPNG(t, blue))
	if err != nil || shaB == shaA {
		t.Fatalf("second upload %q %v", shaB, err)
	}
	hist, err := f.cat.IconHistory(ctx, subj, 10)
	if err != nil || len(hist) != 2 || hist[0].SHA != shaB {
		t.Fatalf("history %+v %v", hist, err)
	}
	if err := f.svc.Rollback(ctx, "carol", subj, hist[0].ID); err != nil {
		t.Fatal(err)
	}
	if got := catalogIcon(t, f, "widgetd"); got != shaA {
		t.Fatalf("after rollback %q, want %q", got, shaA)
	}
	if ev := f.log.events(t, "icon_rolled_back"); len(ev) != 1 || ev[0]["user"] != "carol" ||
		ev[0]["sha256"] != shaA || ev[0]["replaced_sha256"] != shaB {
		t.Fatalf("audit %v", ev)
	}
	if acts := auditActions(t, f); acts["icon_rollback"] != 1 {
		t.Fatalf("catalog audit %v", acts)
	}
	if err := f.svc.Rollback(ctx, "carol", subj, 9999); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown change: %v", err)
	}
	if n := len(f.log.events(t, "icon_rollback_rejected")); n != 1 {
		t.Fatalf("rejected rollback audit %d", n)
	}
}

func TestNewRequiresStores(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("no error")
	}
}

func TestImportResultsDropsUnreadableResults(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// A full run's worth of results that can never be read (symlinks,
	// ELOOP under O_NOFOLLOW), all sorting ahead of a good one.
	for i := 0; i < MaxImportPerRun; i++ {
		id := fmt.Sprintf("%032x", i+1)
		spoolJob(t, f, id)
		if err := os.Symlink("/etc/passwd", filepath.Join(f.spool.ResultsDir(), id+".json")); err != nil {
			t.Fatal(err)
		}
	}
	good := strings.Repeat("f", 32)
	spoolJob(t, f, good)
	helperResult(t, f, good, testPNG(t, blue))
	rep, err := f.svc.ImportResults(ctx)
	if err != nil || len(rep.Failed) != MaxImportPerRun || len(rep.Imported) != 0 {
		t.Fatalf("first run %d failed, %d imported: %v", len(rep.Failed), len(rep.Imported), err)
	}
	for id := range rep.Failed {
		if _, err := f.spool.ReadJob(id); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("job %s with unreadable result kept: %v", id, err)
		}
	}
	if ev := f.log.events(t, "icon_fetch_failed"); len(ev) != MaxImportPerRun {
		t.Fatalf("audit %d failures", len(ev))
	}
	rep, err = f.svc.ImportResults(ctx)
	if err != nil || len(rep.Imported) != 1 || rep.Imported[good] == "" {
		t.Fatalf("second run %+v %v", rep, err)
	}
}

// TestImportResultsBoundsUnreadableResults: results the server may not
// read (EACCES) are kept for a permission fix, but they neither crowd out
// later results nor stay forever.
func TestImportResultsBoundsUnreadableResults(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file modes, so mode 0 gives no EACCES; runs in `make test` (unprivileged)")
	}
	f := newFixture(t)
	ctx := context.Background()
	n := MaxImportPerRun + 1
	var unreadable []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%032x", i+1)
		spoolJob(t, f, id)
		helperResult(t, f, id, testPNG(t, red))
		if err := os.Chmod(filepath.Join(f.spool.ResultsDir(), id+".json"), 0); err != nil {
			t.Fatal(err)
		}
		unreadable = append(unreadable, id)
	}
	good := strings.Repeat("f", 32)
	spoolJob(t, f, good)
	helperResult(t, f, good, testPNG(t, blue))

	// First run: a full run of unreadable results, kept (transient).
	start := time.Now()
	rep, err := f.svc.ImportResults(ctx)
	if !errors.Is(err, iconjob.ErrUnreadable) || len(rep.Failed) != 0 || len(rep.Imported) != 0 {
		t.Fatalf("first run %+v %v", rep, err)
	}
	// One shared retry budget, not 2 pauses per file.
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("first run took %s", d)
	}
	// Second run: the known-unreadable results go last, the good one is
	// imported.
	rep, err = f.svc.ImportResults(ctx)
	if !errors.Is(err, iconjob.ErrUnreadable) || rep.Imported[good] == "" || len(rep.Failed) != 0 {
		t.Fatalf("second run %+v %v", rep, err)
	}
	// A permission fix within the grace time loses no work.
	fixed := unreadable[0]
	if err := os.Chmod(filepath.Join(f.spool.ResultsDir(), fixed+".json"), 0o640); err != nil {
		t.Fatal(err)
	}
	// More attempts within the grace time fail nothing.
	for range unreadableAttempts {
		rep, err = f.svc.ImportResults(ctx)
		if len(rep.Failed) != 0 {
			t.Fatalf("failed within grace: %+v %v", rep, err)
		}
		if rep.Imported[fixed] != "" {
			break
		}
	}
	if _, err := f.spool.ReadJob(fixed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixed result not imported: %v", err)
	}
	// After the grace time each still unreadable job fails once it has
	// enough attempts; all are gone after a bounded number of runs.
	f.svc.now = func() time.Time { return t0.Add(unreadableGrace) }
	failed := map[string]bool{}
	for run := 0; run < 2*unreadableAttempts+2; run++ {
		rep, _ = f.svc.ImportResults(ctx)
		for id, msg := range rep.Failed {
			if !strings.Contains(msg, "unreadable helper result") {
				t.Fatalf("job %s: %s", id, msg)
			}
			failed[id] = true
		}
	}
	if len(failed) != n-1 {
		t.Fatalf("%d unreadable jobs failed, want %d", len(failed), n-1)
	}
	if ids, err := f.spool.FinishedJobs(); err != nil || len(ids) != 0 {
		t.Fatalf("jobs left: %v %v", ids, err)
	}
	if ev := f.log.events(t, "icon_fetch_failed"); len(ev) != n-1 {
		t.Fatalf("audit %d failures", len(ev))
	}
	f.svc.mu.Lock()
	left := len(f.svc.unreadable)
	f.svc.mu.Unlock()
	if left != 0 {
		t.Fatalf("unreadable state kept for %d jobs", left)
	}
}
