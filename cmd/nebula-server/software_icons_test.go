// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
)

// auditCapture records the kind of every "audit" log event and the
// message of every error.
type auditCapture struct {
	mu     sync.Mutex
	kinds  []string
	errors []string
}

func (c *auditCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *auditCapture) WithAttrs([]slog.Attr) slog.Handler       { return c }
func (c *auditCapture) WithGroup(string) slog.Handler            { return c }
func (c *auditCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Level >= slog.LevelError {
		c.errors = append(c.errors, r.Message)
	}
	if r.Message == "audit" {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "kind" {
				c.kinds = append(c.kinds, a.Value.String())
			}
			return true
		})
	}
	return nil
}

func (c *auditCapture) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := c.kinds
	c.kinds = nil
	return k
}

// iconFixture is the server's HTTP chain with the icon service wired as
// in run, on a real database, icon store and spool.
type iconFixture struct {
	srv      *http.Server
	cat      *softwarecat.Store
	wiring   *iconWiring
	audit    *auditCapture
	token    string // session of the admin
	nameless string // session without a user name
}

func newIconFixture(t *testing.T) *iconFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	cat, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		t.Fatal(err)
	}
	units := base64.StdEncoding.EncodeToString([]byte("widgetd.service loaded active running Some unit"))
	doc := []byte(fmt.Sprintf(`{"format":"systemd-units-v1","units":%q}`, units))
	if _, err := cat.IngestServiceList(ctx, softwarecat.Target{Kind: softwarecat.TargetHost, HostID: "h1"}, doc, time.Now()); err != nil {
		t.Fatal(err)
	}
	spool := iconjob.Spool{Dir: filepath.Join(dir, "iconfetch")}
	for _, d := range []string{spool.Dir, spool.JobsDir(), spool.ResultsDir()} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	rec := &auditCapture{}
	log := slog.New(rec)
	w, err := newIconWiring(db, dir, spool.Dir, log)
	if err != nil {
		t.Fatal(err)
	}
	sw, err := softwarePagesWith(db, log, w)
	if err != nil {
		t.Fatal(err)
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	sw.Register(pages)
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(ctx, "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	nameless, _, err := sessions.Create(ctx, "cred-2", "")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := webServer(swOrigin, login, pages, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &iconFixture{srv: srv, cat: cat, wiring: w, audit: rec, token: token, nameless: nameless}
}

// send runs one request through the whole chain.
func (f *iconFixture) send(t *testing.T, method, path, token, origin, ctype string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, swOrigin+path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	f.srv.Handler.ServeHTTP(rec, req)
	return rec
}

func (f *iconFixture) form(t *testing.T, path string, v url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return f.send(t, http.MethodPost, path, f.token, swOrigin, formType, []byte(v.Encode()))
}

func (f *iconFixture) upload(t *testing.T, img []byte) *httptest.ResponseRecorder {
	t.Helper()
	return f.send(t, http.MethodPost, uploadPath, f.token, swOrigin, "image/png", img)
}

func (f *iconFixture) current(t *testing.T) string {
	t.Helper()
	e, err := f.cat.Entry(context.Background(), "widgetd")
	if err != nil {
		t.Fatal(err)
	}
	return e.IconSHA
}

// checkNothingQueued fails when a job file exists.
func (f *iconFixture) checkNothingQueued(t *testing.T, what string) {
	t.Helper()
	jobs, err := os.ReadDir(f.wiring.spool.JobsDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Errorf("%s: %d jobs queued", what, len(jobs))
	}
}

const (
	formType   = "application/x-www-form-urlencoded"
	uploadPath = "/software/icon/upload?kind=catalog&id=widgetd"
)

func iconPNG(t *testing.T, c color.NRGBA) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			img.SetNRGBA(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

var (
	iconRed  = color.NRGBA{R: 200, A: 255}
	iconBlue = color.NRGBA{B: 200, A: 255}
)

// checkServedPNG checks that /icons/ serves sha as an inert 128 px PNG.
func (f *iconFixture) checkServedPNG(t *testing.T, sha string) {
	t.Helper()
	rec := f.send(t, http.MethodGet, "/icons/"+sha+".png", f.token, "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET icon: status %d", rec.Code)
	}
	for k, want := range map[string]string{"Content-Type": "image/png", "X-Content-Type-Options": "nosniff",
		"Content-Security-Policy": "default-src 'none'", "Content-Disposition": "inline"} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s %q, want %q", k, got, want)
		}
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(rec.Body.Bytes()))
	if err != nil || cfg.Width != iconstore.LargeSize || cfg.Height != iconstore.LargeSize {
		t.Errorf("served icon: %+v, %v", cfg, err)
	}
}

// TestIconUploadThroughServerServesSanitizedPNG: an upload through the full
// chain sets the icon, the stored bytes are re-encoded, /icons/ serves them
// with the inert headers, and the change is exactly one audit event.
func TestIconUploadThroughServerServesSanitizedPNG(t *testing.T) {
	f := newIconFixture(t)
	img := iconPNG(t, iconRed)
	if rec := f.upload(t, img); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/software/icon/widgetd?done=uploaded" {
		t.Fatalf("upload: %d %q %q", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	sha := f.current(t)
	if sha == "" {
		t.Fatal("upload did not set the icon")
	}
	f.checkServedPNG(t, sha)
	if got := f.audit.take(); len(got) != 1 || got[0] != "icon_uploaded" {
		t.Errorf("audit events %v, want one icon_uploaded", got)
	}
}

// TestIconFetchQueuesThroughSpoolAndImports: a fetch only queues a job for
// the helper; the icon is set when the server imports the helper's result,
// and it is served as the server's own encoding.
func TestIconFetchQueuesThroughSpoolAndImports(t *testing.T) {
	f := newIconFixture(t)
	const src = "https://upload.wikimedia.org/w/a.png"
	rec := f.form(t, "/software/icon/fetch", url.Values{"key": {"widgetd"}, "url": {src}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/software/icon/widgetd?done=queued" {
		t.Fatalf("fetch: %d %q", rec.Code, rec.Body.String())
	}
	if f.current(t) != "" {
		t.Fatal("queueing a fetch set the icon")
	}
	pending, _, err := f.wiring.spool.PendingJobs()
	if err != nil || len(pending) != 1 || pending[0].URL != src || pending[0].Key != "widgetd" || pending[0].RequestedBy != "admin" {
		t.Fatalf("pending %+v, %v", pending, err)
	}
	ic, err := iconstore.Sanitize(iconPNG(t, iconBlue))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.wiring.spool.WriteResult(iconjob.Result{Format: iconjob.ResultFormat, Job: pending[0].ID, OK: true,
		SHA256: ic.SHA256, PNG64: ic.PNG64, PNG128: ic.PNG128, StartedAt: 1, FinishedAt: 2}); err != nil {
		t.Fatal(err)
	}
	f.wiring.importResults(context.Background())
	sha := f.current(t)
	if sha == "" {
		t.Fatal("import did not set the icon")
	}
	f.checkServedPNG(t, sha)
	if got := f.audit.take(); len(got) != 2 || got[0] != "icon_fetch_queued" || got[1] != "icon_fetch_imported" {
		t.Errorf("audit events %v, want the queued fetch and its one import", got)
	}
	if left, _ := f.wiring.spool.FinishedJobs(); len(left) != 0 {
		t.Errorf("job not removed after import: %v", left)
	}
}

// TestIconRollbackRestoresPreviousIcon: rolling back the newest change puts
// the previous icon back, as one audit event.
func TestIconRollbackRestoresPreviousIcon(t *testing.T) {
	f := newIconFixture(t)
	f.upload(t, iconPNG(t, iconRed))
	first := f.current(t)
	f.upload(t, iconPNG(t, iconBlue))
	if f.current(t) == first {
		t.Fatal("second upload did not change the icon")
	}
	f.audit.take()
	hist, err := f.cat.IconHistory(context.Background(), softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}, 1)
	if err != nil || len(hist) != 1 {
		t.Fatalf("history %+v, %v", hist, err)
	}
	rec := f.form(t, "/software/icon/rollback", url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {fmt.Sprint(hist[0].ID)}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("rollback: %d %q", rec.Code, rec.Body.String())
	}
	if f.current(t) != first {
		t.Error("rollback did not restore the previous icon")
	}
	if got := f.audit.take(); len(got) != 1 || got[0] != "icon_rolled_back" {
		t.Errorf("audit events %v, want one icon_rolled_back", got)
	}
}

// TestIconChangeRefusals: every refusal through the full chain changes
// nothing, queues nothing and stores nothing.
func TestIconChangeRefusals(t *testing.T) {
	f := newIconFixture(t)
	good := iconPNG(t, iconRed)
	fetch := func(u string) []byte {
		return []byte(url.Values{"key": {"widgetd"}, "url": {u}}.Encode())
	}
	rollback := []byte(url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {"1"}}.Encode())
	okFetch := fetch("https://upload.wikimedia.org/w/a.png")
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)
	const fetchPath, rollbackPath = "/software/icon/fetch", "/software/icon/rollback"
	cases := []struct {
		name         string
		path         string
		token        string
		origin       string
		ctype        string
		body         []byte
		want         int
		wantRejected bool // the refusal is audited
	}{
		{"non-allowlisted host", fetchPath, f.token, swOrigin, formType, fetch("https://evil.example/a.png"), http.StatusBadRequest, true},
		{"subdomain of an allowlisted host", fetchPath, f.token, swOrigin, formType, fetch("https://x.upload.wikimedia.org/a.png"), http.StatusBadRequest, true},
		{"IP literal", fetchPath, f.token, swOrigin, formType, fetch("https://169.254.169.254/a.png"), http.StatusBadRequest, true},
		{"plain http", fetchPath, f.token, swOrigin, formType, fetch("http://upload.wikimedia.org/a.png"), http.StatusBadRequest, true},
		{"query string", fetchPath, f.token, swOrigin, formType, fetch("https://upload.wikimedia.org/a.png?token=x"), http.StatusBadRequest, true},
		{"oversize upload", uploadPath, f.token, swOrigin, "image/png", make([]byte, iconstore.MaxInputBytes+1), http.StatusRequestEntityTooLarge, false},
		{"upload over the body limit", uploadPath, f.token, swOrigin, "image/png", make([]byte, 2<<20), http.StatusRequestEntityTooLarge, false},
		{"SVG type", uploadPath, f.token, swOrigin, "image/svg+xml", svg, http.StatusUnsupportedMediaType, false},
		{"SVG bytes labelled PNG", uploadPath, f.token, swOrigin, "image/png", svg, http.StatusBadRequest, true},
		{"WebP type", uploadPath, f.token, swOrigin, "image/webp", good, http.StatusUnsupportedMediaType, false},
		{"upload without Origin", uploadPath, f.token, "", "image/png", good, http.StatusForbidden, false},
		{"upload from a foreign Origin", uploadPath, f.token, "https://evil.example", "image/png", good, http.StatusForbidden, false},
		{"fetch without Origin", fetchPath, f.token, "", formType, okFetch, http.StatusForbidden, false},
		{"rollback without Origin", rollbackPath, f.token, "", formType, rollback, http.StatusForbidden, false},
		{"upload without a session", uploadPath, "", swOrigin, "image/png", good, http.StatusUnauthorized, false},
		{"fetch without a session", fetchPath, "", swOrigin, formType, okFetch, http.StatusUnauthorized, false},
		{"rollback without a session", rollbackPath, "", swOrigin, formType, rollback, http.StatusUnauthorized, false},
		{"upload without an admin name", uploadPath, f.nameless, swOrigin, "image/png", good, http.StatusForbidden, false},
		{"fetch without an admin name", fetchPath, f.nameless, swOrigin, formType, okFetch, http.StatusForbidden, false},
		{"rollback without an admin name", rollbackPath, f.nameless, swOrigin, formType, rollback, http.StatusForbidden, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := f.send(t, http.MethodPost, c.path, c.token, c.origin, c.ctype, c.body)
			if rec.Code != c.want {
				t.Errorf("status %d, want %d (%q)", rec.Code, c.want, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "evil.example") {
				t.Errorf("refusal echoes the URL: %q", rec.Body.String())
			}
			if f.current(t) != "" {
				t.Error("refused request set an icon")
			}
			f.checkNothingQueued(t, c.name)
			got := f.audit.take()
			for _, k := range got {
				if !strings.HasSuffix(k, "_rejected") {
					t.Errorf("refused request logged the change event %q", k)
				}
			}
			if c.wantRejected && len(got) != 1 {
				t.Errorf("audit events %v, want one refusal", got)
			}
		})
	}
	stored, err := filepath.Glob(filepath.Join(filepath.Dir(f.wiring.spool.Dir), iconStoreDirName, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Errorf("refused requests stored %v", stored)
	}
}

// TestIconFilesNeedSession: stored icons sit behind the web login.
func TestIconFilesNeedSession(t *testing.T) {
	f := newIconFixture(t)
	rec := f.send(t, http.MethodGet, "/icons/"+strings.Repeat("a", 64)+".png", "", "", "", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("without session: %d %q, want 303 to /login", rec.Code, rec.Header().Get("Location"))
	}
}

// TestIconPageOffersChangeForms: with the service wired, the page has the
// upload and fetch forms (without it, TestSoftwareIconChangesOffWithoutIconService).
func TestIconPageOffersChangeForms(t *testing.T) {
	f := newIconFixture(t)
	body := f.send(t, http.MethodGet, "/software/icon/widgetd", f.token, "", "", nil).Body.String()
	for _, want := range []string{`action="/software/icon/fetch"`, `data-sw-upload`, "upload.wikimedia.org"} {
		if !strings.Contains(body, want) {
			t.Errorf("icon page lacks %q", want)
		}
	}
}

// TestIconImportLoopWaitsForSpool: without an installed spool the import
// loop logs no error every round, and it ends with its context.
func TestIconImportLoopWaitsForSpool(t *testing.T) {
	f := newIconFixture(t)
	if err := os.RemoveAll(f.wiring.spool.Dir); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.wiring.run(ctx, time.Millisecond)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("import loop did not end with its context")
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	if len(f.audit.errors) != 0 {
		t.Errorf("errors without a spool: %v", f.audit.errors)
	}
}

// TestNewIconWiringCreatesPrivateStore: the icon store directory is created
// below the data directory, private to the server, and a data directory
// that cannot hold it is an error.
func TestNewIconWiringCreatesPrivateStore(t *testing.T) {
	dir := t.TempDir()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	log := slog.New(slog.DiscardHandler)
	for i := 0; i < 2; i++ { // a restart finds the directory
		if _, err := newIconWiring(db, dir, filepath.Join(dir, "spool"), log); err != nil {
			t.Fatal(err)
		}
	}
	st, err := os.Stat(filepath.Join(dir, iconStoreDirName))
	if err != nil || st.Mode().Perm() != iconStoreDirMode {
		t.Fatalf("store directory: %v, %v", st, err)
	}
	if _, err := newIconWiring(db, filepath.Join(dir, "server.db"), "", log); err == nil {
		t.Error("a file as data directory was accepted")
	}
}
