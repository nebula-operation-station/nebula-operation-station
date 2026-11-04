// SPDX-License-Identifier: AGPL-3.0-or-later

package software

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
)

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

const admin = "alice"

// fakeCandidates is a crawler stub.
type fakeCandidates struct {
	byKey map[string][]Candidate
	err   error
}

func (f *fakeCandidates) Candidates(_ context.Context, key softwarecat.Key) ([]Candidate, error) {
	return f.byKey[string(key)], f.err
}

type fixture struct {
	h     http.Handler
	cat   *softwarecat.Store
	svc   *icons.Service
	spool iconjob.Spool
	db    *sql.DB
	cands *fakeCandidates
	actor string
}

func unitsDoc(units ...string) []byte {
	var lines []string
	for _, u := range units {
		lines = append(lines, u+".service loaded active running Some unit")
	}
	return []byte(fmt.Sprintf(`{"format":"systemd-units-v1","units":%q}`,
		base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))))
}

type fixtureOpt func(*Options, *fixture)

func withoutIcons() fixtureOpt { return func(o *Options, _ *fixture) { o.Icons = nil } }
func withoutCandidates() fixtureOpt {
	return func(o *Options, _ *fixture) { o.Candidates = nil }
}

func newFixture(t *testing.T, opts ...fixtureOpt) *fixture {
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
	for _, h := range []string{"h1", "h2"} {
		units := []string{"widgetd", "nginx"}
		if h == "h1" {
			units = append(units, "otherd", "thirdd")
		}
		if _, err := cat.IngestServiceList(ctx, softwarecat.Target{Kind: softwarecat.TargetHost, HostID: h}, unitsDoc(units...), t0); err != nil {
			t.Fatal(err)
		}
	}
	st, err := iconstore.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sp := iconjob.Spool{Dir: t.TempDir()}
	for _, d := range []string{sp.JobsDir(), sp.ResultsDir()} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := icons.New(icons.Config{Spool: sp, Store: st, Catalog: cat, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{cat: cat, svc: svc, spool: sp, db: db, cands: &fakeCandidates{byKey: map[string][]Candidate{}}, actor: admin}
	o := Options{
		Catalog:    cat,
		List:       SQLList(db),
		Icons:      svc,
		Candidates: f.cands,
		Actor:      func(*http.Request) (string, bool) { return f.actor, f.actor != "" },
		Log:        slog.New(slog.DiscardHandler),
	}
	for _, fn := range opts {
		fn(&o, f)
	}
	h, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	f.h = h.Handler()
	return f
}

func (f *fixture) get(t *testing.T, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func (f *fixture) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) upload(t *testing.T, kind, id, ctype string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{"kind": {kind}, "id": {id}}
	req := httptest.NewRequest(http.MethodPost, "/software/icon/upload?"+q.Encode(), bytes.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
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

func (f *fixture) iconOf(t *testing.T, key string) string {
	t.Helper()
	e, err := f.cat.Entry(context.Background(), softwarecat.Key(key))
	if err != nil {
		t.Fatal(err)
	}
	return e.IconSHA
}

func mustStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status %d, want %d; body %q", rec.Code, want, rec.Body.String())
	}
}

var (
	imgSrcRE  = regexp.MustCompile(`<img\b[^>]*\bsrc="([^"]*)"`)
	attrURLRE = regexp.MustCompile(`\b(?:src|href|action|srcset|poster|data)="([^"]*)"`)
	iconSrcRE = regexp.MustCompile(`^/icons/[0-9a-f]{64}\.png$`)
)

// checkNoExternalImages fails when a page loads an image from anywhere
// but /icons/<sha256>.png or carries an absolute URL in an attribute.
func checkNoExternalImages(t *testing.T, body string) {
	t.Helper()
	for _, m := range imgSrcRE.FindAllStringSubmatch(body, -1) {
		if !iconSrcRE.MatchString(m[1]) {
			t.Errorf("img src %q is not an /icons/ path", m[1])
		}
	}
	for _, m := range attrURLRE.FindAllStringSubmatch(body, -1) {
		v := strings.ToLower(m[1])
		if strings.Contains(v, "//") || strings.HasPrefix(v, "http") || strings.HasPrefix(v, "data:") || strings.HasPrefix(v, "javascript:") {
			t.Errorf("attribute URL %q is not a same-origin path", m[1])
		}
	}
	if strings.Contains(body, "url(") {
		t.Error("page contains a CSS url()")
	}
}

func TestCatalogListShowsKeyDisplayStateIconAndHostCount(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.upload(t, "catalog", "widgetd", "image/png", testPNG(t, red)), http.StatusSeeOther)
	sha := f.iconOf(t, "widgetd")
	code, body := f.get(t, "/software")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{
		`<td class="sw-key"><code>widgetd</code></td>`,
		`<td class="sw-state">observed</td>`,
		`<td class="sw-hosts">2</td>`,
		`<img class="sw-icon" src="/icons/` + sha + `.png"`,
		`href="/software/icon/widgetd"`,
		`<td class="sw-key"><code>otherd</code></td>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("catalog page lacks %q", want)
		}
	}
	// nginx is a seed key with a display name.
	if !strings.Contains(body, `<td class="sw-display">Nginx</td>`) {
		t.Error("catalog page lacks the nginx display name")
	}
	checkNoExternalImages(t, body)
}

func TestCatalogListFiltersByState(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.post(t, "/software/ignore", url.Values{"key": {"otherd"}}), http.StatusSeeOther)
	mustStatus(t, f.post(t, "/software/merge", url.Values{"key": {"thirdd"}, "into": {"widgetd"}}), http.StatusSeeOther)
	cases := []struct {
		state      string
		has, hasNo []string
	}{
		{"ignored", []string{"<code>otherd</code>"}, []string{"<code>widgetd</code>", "<code>thirdd</code>"}},
		{"merged", []string{"<code>thirdd</code>"}, []string{"<code>otherd</code>", "<code>widgetd</code>"}},
		{"observed", []string{"<code>widgetd</code>"}, []string{"<code>otherd</code>", "<code>thirdd</code>"}},
		{"", []string{"<code>widgetd</code>", "<code>otherd</code>", "<code>thirdd</code>"}, nil},
	}
	for _, c := range cases {
		t.Run(c.state, func(t *testing.T) {
			code, body := f.get(t, "/software?state="+c.state)
			if code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			for _, s := range c.has {
				if !strings.Contains(body, s) {
					t.Errorf("missing %s", s)
				}
			}
			for _, s := range c.hasNo {
				if strings.Contains(body, `<td class="sw-key">`+s) {
					t.Errorf("unexpected %s", s)
				}
			}
		})
	}
	if code, _ := f.get(t, "/software?state=bogus"); code != http.StatusBadRequest {
		t.Errorf("bogus state filter: status %d, want 400", code)
	}
}

func TestMergedKeysCountTowardsTargetHosts(t *testing.T) {
	f := newFixture(t)
	// otherd is seen on h1 only; widgetd on h1 and h2.
	mustStatus(t, f.post(t, "/software/merge", url.Values{"key": {"otherd"}, "into": {"thirdd"}}), http.StatusSeeOther)
	rows, _, err := SQLList(f.db)(context.Background(), MaxListRows)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Row{}
	for _, r := range rows {
		got[string(r.Key)] = r
	}
	if got["thirdd"].Hosts != 1 || got["thirdd"].Observations != 2 {
		t.Errorf("thirdd row %+v, want 1 host and 2 observations (own plus merged)", got["thirdd"])
	}
	if got["otherd"].MergedInto != "thirdd" {
		t.Errorf("otherd row %+v, want merged into thirdd", got["otherd"])
	}
	if got["widgetd"].Hosts != 2 {
		t.Errorf("widgetd row %+v, want 2 hosts", got["widgetd"])
	}
}

func TestSQLListTruncates(t *testing.T) {
	f := newFixture(t)
	rows, truncated, err := SQLList(f.db)(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || !truncated {
		t.Fatalf("got %d rows, truncated %v; want 2, true", len(rows), truncated)
	}
}

func TestUnknownQueueListsObservedEntriesWithActions(t *testing.T) {
	f := newFixture(t)
	code, body := f.get(t, "/software/unknown")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{
		`<code>widgetd</code>`,
		`action="/software/rename"`,
		`action="/software/merge"`,
		`action="/software/ignore"`,
		`href="/software/icon/widgetd"`,
		`data-fetch`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("queue page lacks %q", want)
		}
	}
	if strings.Contains(body, "<code>nginx</code>") {
		t.Error("known seed entry nginx is in the unknown queue")
	}
	checkNoExternalImages(t, body)
}

func TestUnknownQueueRenameMergeIgnore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	rec := f.post(t, "/software/rename", url.Values{"key": {"widgetd"}, "display": {"Widget Daemon"}})
	mustStatus(t, rec, http.StatusSeeOther)
	if loc := rec.Header().Get("Location"); loc != "/software/unknown?done=renamed" {
		t.Errorf("rename redirect %q", loc)
	}
	e, err := f.cat.Entry(ctx, "widgetd")
	if err != nil {
		t.Fatal(err)
	}
	if e.Display != "Widget Daemon" || e.State != softwarecat.StateKnown || e.UpdatedBy != admin {
		t.Errorf("after rename: %+v", e)
	}

	mustStatus(t, f.post(t, "/software/merge", url.Values{"key": {"otherd"}, "into": {"widgetd"}}), http.StatusSeeOther)
	if e, _ := f.cat.Entry(ctx, "otherd"); e.MergedInto != "widgetd" {
		t.Errorf("after merge: %+v", e)
	}

	mustStatus(t, f.post(t, "/software/ignore", url.Values{"key": {"thirdd"}}), http.StatusSeeOther)
	if e, _ := f.cat.Entry(ctx, "thirdd"); e.State != softwarecat.StateIgnored {
		t.Errorf("after ignore: %+v", e)
	}

	_, body := f.get(t, "/software/unknown")
	for _, k := range []string{"widgetd", "otherd", "thirdd"} {
		if strings.Contains(body, "<code>"+k+"</code>") {
			t.Errorf("%s still in the unknown queue", k)
		}
	}
	trail, err := f.cat.AuditTrail(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, a := range trail {
		actions[a.Action] = a.Actor
	}
	for _, a := range []string{"rename", "merge", "ignore"} {
		if actions[a] != admin {
			t.Errorf("audit action %s by %q, want %q", a, actions[a], admin)
		}
	}
}

func TestAdminChangesRejectBadInput(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name string
		path string
		form url.Values
		want int
	}{
		{"rename invalid key", "/software/rename", url.Values{"key": {"Bad Key"}, "display": {"x"}}, http.StatusBadRequest},
		{"rename missing key", "/software/rename", url.Values{"key": {"nosuchkey"}, "display": {"x"}}, http.StatusNotFound},
		{"rename control chars", "/software/rename", url.Values{"key": {"widgetd"}, "display": {"a\x1bb"}}, http.StatusBadRequest},
		{"rename too long", "/software/rename", url.Values{"key": {"widgetd"}, "display": {strings.Repeat("x", 129)}}, http.StatusBadRequest},
		{"rename empty", "/software/rename", url.Values{"key": {"widgetd"}, "display": {"  "}}, http.StatusBadRequest},
		{"merge into itself", "/software/merge", url.Values{"key": {"widgetd"}, "into": {"widgetd"}}, http.StatusBadRequest},
		{"merge into missing", "/software/merge", url.Values{"key": {"widgetd"}, "into": {"nosuchkey"}}, http.StatusNotFound},
		{"merge invalid target", "/software/merge", url.Values{"key": {"widgetd"}, "into": {"../x"}}, http.StatusBadRequest},
		{"ignore invalid", "/software/ignore", url.Values{"key": {""}}, http.StatusBadRequest},
		{"duplicate field", "/software/ignore", url.Values{"key": {"widgetd", "otherd"}}, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustStatus(t, f.post(t, c.path, c.form), c.want)
		})
	}
	// Renaming a merged entry is refused.
	mustStatus(t, f.post(t, "/software/merge", url.Values{"key": {"otherd"}, "into": {"widgetd"}}), http.StatusSeeOther)
	mustStatus(t, f.post(t, "/software/rename", url.Values{"key": {"otherd"}, "display": {"x"}}), http.StatusConflict)
	// Merging into a merged entry is refused.
	mustStatus(t, f.post(t, "/software/merge", url.Values{"key": {"thirdd"}, "into": {"otherd"}}), http.StatusBadRequest)
}

func TestStateChangesRequireSignedInFormPost(t *testing.T) {
	f := newFixture(t)
	// Wrong method.
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/software/ignore?key=widgetd", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on a change route: %d", rec.Code)
	}
	// Wrong content type.
	for _, ct := range []string{"", "application/json", "text/plain", "multipart/form-data; boundary=x"} {
		req := httptest.NewRequest(http.MethodPost, "/software/ignore", strings.NewReader("key=widgetd"))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("content type %q: status %d, want 415", ct, rec.Code)
		}
	}
	// Oversized body.
	big := url.Values{"key": {"widgetd"}, "display": {strings.Repeat("x", maxFormBytes)}}
	mustStatus(t, f.post(t, "/software/rename", big), http.StatusRequestEntityTooLarge)
	// No session.
	f.actor = ""
	mustStatus(t, f.post(t, "/software/ignore", url.Values{"key": {"widgetd"}}), http.StatusForbidden)
	mustStatus(t, f.upload(t, "catalog", "widgetd", "image/png", testPNG(t, red)), http.StatusForbidden)
	if e, _ := f.cat.Entry(context.Background(), "widgetd"); e.State != softwarecat.StateObserved || e.IconSHA != "" {
		t.Errorf("unauthenticated request changed the entry: %+v", e)
	}
}

func TestIconChangeableAnyTimeWithHistoryAndRollback(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// Any state: observed, known (seed), ignored.
	mustStatus(t, f.post(t, "/software/ignore", url.Values{"key": {"otherd"}}), http.StatusSeeOther)
	for _, key := range []string{"widgetd", "nginx", "otherd"} {
		rec := f.upload(t, "catalog", key, "image/png", testPNG(t, red))
		mustStatus(t, rec, http.StatusSeeOther)
		if loc := rec.Header().Get("Location"); loc != "/software/icon/"+key+"?done=uploaded" {
			t.Errorf("upload redirect %q", loc)
		}
		if f.iconOf(t, key) == "" {
			t.Errorf("%s has no icon after upload", key)
		}
	}
	redSHA := f.iconOf(t, "widgetd")
	// Replace at any time.
	mustStatus(t, f.upload(t, "catalog", "widgetd", "image/png", testPNG(t, blue)), http.StatusSeeOther)
	blueSHA := f.iconOf(t, "widgetd")
	if blueSHA == redSHA {
		t.Fatal("replacing the icon did not change it")
	}
	hist, err := f.cat.IconHistory(ctx, softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("history has %d entries, want 2", len(hist))
	}
	code, body := f.get(t, "/software/icon/widgetd")
	if code != http.StatusOK {
		t.Fatalf("icon page status %d", code)
	}
	for _, want := range []string{
		`src="/icons/` + blueSHA + `.png"`,
		`src="/icons/` + redSHA + `.png"`,
		`action="/software/icon/rollback"`,
		fmt.Sprintf(`name="change" value="%d"`, hist[0].ID),
		fmt.Sprintf(`name="change" value="%d"`, hist[1].ID),
		`action="/software/icon/upload?kind=catalog&amp;id=widgetd"`,
		`action="/software/icon/fetch"`,
		`upload.wikimedia.org`,
		`avatars.githubusercontent.com`,
		`/static/software.js`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("icon page lacks %q", want)
		}
	}
	checkNoExternalImages(t, body)

	// One-click rollback of the newest change brings red back.
	rec := f.post(t, "/software/icon/rollback", url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {fmt.Sprint(hist[0].ID)}})
	mustStatus(t, rec, http.StatusSeeOther)
	if got := f.iconOf(t, "widgetd"); got != redSHA {
		t.Errorf("after rollback icon %s, want %s", got, redSHA)
	}
	// Rolling back the first change returns to the generic symbol.
	mustStatus(t, f.post(t, "/software/icon/rollback", url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {fmt.Sprint(hist[1].ID)}}), http.StatusSeeOther)
	if got := f.iconOf(t, "widgetd"); got != "" {
		t.Errorf("after rolling back the first change icon %q, want generic", got)
	}
	_, body = f.get(t, "/software/icon/widgetd")
	if !strings.Contains(body, "Generic symbol") {
		t.Error("icon page does not say the generic symbol is in use")
	}
	// The rollback itself is in the history and can be undone.
	hist, err = f.cat.IconHistory(ctx, softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 4 || hist[0].RollbackOf != hist[3].ID {
		t.Fatalf("history after rollbacks: %+v", hist)
	}
	mustStatus(t, f.post(t, "/software/icon/rollback", url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {fmt.Sprint(hist[0].ID)}}), http.StatusSeeOther)
	if got := f.iconOf(t, "widgetd"); got != redSHA {
		t.Errorf("undoing the rollback gave %q, want %s", got, redSHA)
	}
}

func TestRollbackRejectsForeignAndBadChanges(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.upload(t, "catalog", "widgetd", "image/png", testPNG(t, red)), http.StatusSeeOther)
	hist, err := f.cat.IconHistory(context.Background(), softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}, 1)
	if err != nil || len(hist) != 1 {
		t.Fatal(hist, err)
	}
	id := fmt.Sprint(hist[0].ID)
	cases := []struct {
		name string
		form url.Values
		want int
	}{
		{"other subject", url.Values{"kind": {"catalog"}, "id": {"otherd"}, "change": {id}}, http.StatusNotFound},
		{"zero", url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {"0"}}, http.StatusBadRequest},
		{"negative", url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {"-1"}}, http.StatusBadRequest},
		{"not a number", url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {"1e3"}}, http.StatusBadRequest},
		{"bad kind", url.Values{"kind": {"host"}, "id": {"widgetd"}, "change": {id}}, http.StatusBadRequest},
		{"bad key", url.Values{"kind": {"catalog"}, "id": {"Wid get"}, "change": {id}}, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustStatus(t, f.post(t, "/software/icon/rollback", c.form), c.want)
		})
	}
}

func TestUploadRejectsUnsafeInput(t *testing.T) {
	f := newFixture(t)
	mustStatus(t, f.post(t, "/software/merge", url.Values{"key": {"otherd"}, "into": {"widgetd"}}), http.StatusSeeOther)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	polyglot := append(testPNG(t, red), []byte("<script>alert(1)</script>")...)
	cases := []struct {
		name, kind, id, ctype string
		body                  []byte
		want                  int
	}{
		{"svg content type", "catalog", "widgetd", "image/svg+xml", svg, http.StatusUnsupportedMediaType},
		{"webp content type", "catalog", "widgetd", "image/webp", []byte("RIFF....WEBPVP8 "), http.StatusUnsupportedMediaType},
		{"form content type", "catalog", "widgetd", "application/x-www-form-urlencoded", testPNG(t, red), http.StatusUnsupportedMediaType},
		{"svg bytes as png", "catalog", "widgetd", "image/png", svg, http.StatusBadRequest},
		{"garbage", "catalog", "widgetd", "image/gif", []byte("GIF89a garbage"), http.StatusBadRequest},
		{"empty", "catalog", "widgetd", "image/png", nil, http.StatusBadRequest},
		{"too large", "catalog", "widgetd", "image/png", make([]byte, iconstore.MaxInputBytes+1), http.StatusRequestEntityTooLarge},
		{"invalid key", "catalog", "../etc", "image/png", testPNG(t, red), http.StatusBadRequest},
		{"unknown key", "catalog", "nosuchkey", "image/png", testPNG(t, red), http.StatusNotFound},
		{"merged key", "catalog", "otherd", "image/png", testPNG(t, red), http.StatusConflict},
		{"bad subject kind", "host", "widgetd", "image/png", testPNG(t, red), http.StatusBadRequest},
		{"bad asset id", "asset", "a b", "image/png", testPNG(t, red), http.StatusBadRequest},
		{"missing asset", "asset", "nas-9", "image/png", testPNG(t, red), http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := f.upload(t, c.kind, c.id, c.ctype, c.body)
			mustStatus(t, rec, c.want)
			if strings.Contains(rec.Body.String(), "<") {
				t.Errorf("error body contains markup: %q", rec.Body.String())
			}
		})
	}
	if got := f.iconOf(t, "widgetd"); got != "" {
		t.Errorf("rejected uploads set an icon: %s", got)
	}
	// A polyglot is accepted only as its re-encoded PNG.
	mustStatus(t, f.upload(t, "catalog", "widgetd", "image/png", polyglot), http.StatusSeeOther)
	if got, plain := f.iconOf(t, "widgetd"), testPNG(t, red); got == "" || bytes.Contains(plain, []byte(got)) {
		t.Errorf("polyglot upload: icon %q", got)
	}
}

func TestFetchFromAllowlistedURLOnly(t *testing.T) {
	f := newFixture(t)
	bad := []string{
		"http://upload.wikimedia.org/a.png",
		"https://evil.example/a.png",
		"https://127.0.0.1/a.png",
		"https://user:pw@upload.wikimedia.org/a.png",
		"https://upload.wikimedia.org:8443/a.png",
		"javascript:alert(1)",
		"",
	}
	for _, u := range bad {
		rec := f.post(t, "/software/icon/fetch", url.Values{"key": {"widgetd"}, "url": {u}})
		mustStatus(t, rec, http.StatusBadRequest)
		if u != "" && strings.Contains(rec.Body.String(), u) {
			t.Errorf("error for %q echoes the URL: %q", u, rec.Body.String())
		}
	}
	pending, _, err := f.spool.PendingJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("rejected URLs queued %d jobs", len(pending))
	}
	rec := f.post(t, "/software/icon/fetch", url.Values{"key": {"widgetd"}, "url": {"https://upload.wikimedia.org/w/a.png"}})
	mustStatus(t, rec, http.StatusSeeOther)
	if loc := rec.Header().Get("Location"); loc != "/software/icon/widgetd?done=queued" {
		t.Errorf("fetch redirect %q", loc)
	}
	pending, _, err = f.spool.PendingJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Key != "widgetd" || pending[0].RequestedBy != admin {
		t.Fatalf("pending jobs %+v", pending)
	}
	_, body := f.get(t, "/software/icon/widgetd?done=queued")
	if !strings.Contains(body, "Fetch queued") {
		t.Error("icon page does not confirm the queued fetch")
	}
	checkNoExternalImages(t, body)
	if strings.Contains(body, "https://upload.wikimedia.org/w/a.png") {
		t.Error("icon page renders the queued source URL")
	}
}

func TestFetchUnavailableWithoutSpool(t *testing.T) {
	f := newFixture(t)
	if err := os.RemoveAll(f.spool.JobsDir()); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, f.post(t, "/software/icon/fetch", url.Values{"key": {"widgetd"}, "url": {"https://upload.wikimedia.org/w/a.png"}}), http.StatusServiceUnavailable)
}

func TestIconPageShowsSourceHostButNeverTheURL(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// Register an icon as if it had been fetched from a URL.
	st, err := iconstore.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ic, err := iconstore.Sanitize(testPNG(t, red))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(ctx, ic); err != nil {
		t.Fatal(err)
	}
	src := "https://upload.wikimedia.org/wikipedia/commons/x/secret-path.png"
	if _, err := f.cat.RegisterIcon(ctx, admin, ic.SHA256, softwarecat.IconURL, src); err != nil {
		t.Fatal(err)
	}
	if err := f.cat.SetIcon(ctx, admin, softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}, ic.SHA256); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/software/icon/widgetd", "/software", "/software/unknown"} {
		_, body := f.get(t, p)
		if strings.Contains(body, "wikipedia/commons") || strings.Contains(body, "https://") {
			t.Errorf("%s renders the icon source URL", p)
		}
		checkNoExternalImages(t, body)
	}
	_, body := f.get(t, "/software/icon/widgetd")
	if !strings.Contains(body, "upload.wikimedia.org") {
		t.Error("icon page does not name the source host")
	}
}

func TestCrawlerCandidatesNeedConfirmation(t *testing.T) {
	f := newFixture(t)
	f.cands.byKey["widgetd"] = []Candidate{
		{ID: "c1", URL: "https://avatars.githubusercontent.com/u/123", Source: "github", FoundAt: t0},
		{ID: "c2", URL: "https://evil.example/logo.png", Source: "web", FoundAt: t0},
		{ID: "c3", URL: "https://upload.wikimedia.org/a/<b>x.png", Source: "wiki<script>", FoundAt: t0},
		{ID: "Bad ID", URL: "https://upload.wikimedia.org/a/y.png", Source: "wiki", FoundAt: t0},
	}
	code, body := f.get(t, "/software/icon/widgetd")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if !strings.Contains(body, `name="candidate" value="c1"`) {
		t.Error("valid candidate c1 not offered")
	}
	for _, bad := range []string{`value="c2"`, "evil.example", "<script>", `value="Bad ID"`} {
		if strings.Contains(body, bad) {
			t.Errorf("icon page contains %q", bad)
		}
	}
	if strings.Contains(body, "https://avatars.githubusercontent.com/u/123") {
		t.Error("candidate URL rendered")
	}
	if !strings.Contains(body, "avatars.githubusercontent.com") {
		t.Error("candidate host not shown")
	}
	checkNoExternalImages(t, body)

	// Nothing is queued until an admin confirms.
	if p, _, _ := f.spool.PendingJobs(); len(p) != 0 {
		t.Fatalf("candidates queued %d jobs without confirmation", len(p))
	}
	mustStatus(t, f.post(t, "/software/icon/candidate", url.Values{"key": {"widgetd"}, "candidate": {"c2"}}), http.StatusBadRequest)
	mustStatus(t, f.post(t, "/software/icon/candidate", url.Values{"key": {"widgetd"}, "candidate": {"nope"}}), http.StatusNotFound)
	mustStatus(t, f.post(t, "/software/icon/candidate", url.Values{"key": {"otherd"}, "candidate": {"c1"}}), http.StatusNotFound)
	if p, _, _ := f.spool.PendingJobs(); len(p) != 0 {
		t.Fatalf("rejected confirmations queued %d jobs", len(p))
	}
	mustStatus(t, f.post(t, "/software/icon/candidate", url.Values{"key": {"widgetd"}, "candidate": {"c1"}}), http.StatusSeeOther)
	p, _, err := f.spool.PendingJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 || p[0].URL != "https://avatars.githubusercontent.com/u/123" || p[0].Key != "widgetd" {
		t.Fatalf("confirmed candidate jobs %+v", p)
	}
}

func TestCandidateSourceErrorAndAbsence(t *testing.T) {
	f := newFixture(t)
	f.cands.err = errors.New("crawler down")
	code, body := f.get(t, "/software/icon/widgetd")
	if code != http.StatusOK || !strings.Contains(body, "Candidates unavailable") || strings.Contains(body, "crawler down") {
		t.Errorf("crawler error: status %d", code)
	}
	g := newFixture(t, withoutCandidates())
	_, body = g.get(t, "/software/icon/widgetd")
	if !strings.Contains(body, "No crawler is configured") {
		t.Error("no-crawler note missing")
	}
	mustStatus(t, g.post(t, "/software/icon/candidate", url.Values{"key": {"widgetd"}, "candidate": {"c1"}}), http.StatusNotFound)
}

func TestAssetOverride(t *testing.T) {
	f := newFixture(t)
	if _, err := f.db.Exec(`INSERT INTO assets (id, name, kind, updated_at) VALUES ('nas-1', 'NAS', 'nas', 1)`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rec := f.upload(t, "asset", "nas-1", "image/gif", gifBytes(t))
	mustStatus(t, rec, http.StatusSeeOther)
	if loc := rec.Header().Get("Location"); loc != "/software/assets/icon?id=nas-1&done=uploaded" {
		t.Errorf("asset upload redirect %q", loc)
	}
	sha, err := f.cat.AssetIcon(ctx, "nas-1")
	if err != nil || sha == "" {
		t.Fatalf("asset override %q, %v", sha, err)
	}
	code, body := f.get(t, "/software/assets/icon?id=nas-1")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{
		`src="/icons/` + sha + `.png"`,
		`action="/software/icon/upload?kind=asset&amp;id=nas-1"`,
		`action="/software/icon/rollback"`,
		`name="kind" value="asset"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("asset page lacks %q", want)
		}
	}
	// URL fetch and candidates are for catalog keys only.
	if strings.Contains(body, `action="/software/icon/fetch"`) || strings.Contains(body, `action="/software/icon/candidate"`) {
		t.Error("asset page offers a URL fetch or candidates")
	}
	checkNoExternalImages(t, body)
	hist, err := f.cat.IconHistory(ctx, softwarecat.IconSubject{Kind: softwarecat.SubjectAsset, ID: "nas-1"}, 1)
	if err != nil || len(hist) != 1 {
		t.Fatal(hist, err)
	}
	mustStatus(t, f.post(t, "/software/icon/rollback", url.Values{"kind": {"asset"}, "id": {"nas-1"}, "change": {fmt.Sprint(hist[0].ID)}}), http.StatusSeeOther)
	if sha, _ := f.cat.AssetIcon(ctx, "nas-1"); sha != "" {
		t.Errorf("override after rollback %q, want none", sha)
	}
	if code, _ := f.get(t, "/software/assets/icon?id=a%20b"); code != http.StatusBadRequest {
		t.Errorf("bad asset ID page: %d", code)
	}
}

func gifBytes(t *testing.T) []byte {
	t.Helper()
	// 1x1 GIF.
	b, err := base64.StdEncoding.DecodeString("R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIconPagesForMissingAndMergedKeys(t *testing.T) {
	f := newFixture(t)
	if code, _ := f.get(t, "/software/icon/nosuchkey"); code != http.StatusNotFound {
		t.Errorf("missing key: %d", code)
	}
	if code, _ := f.get(t, "/software/icon/Bad%20Key"); code != http.StatusBadRequest {
		t.Errorf("bad key: %d", code)
	}
	mustStatus(t, f.post(t, "/software/merge", url.Values{"key": {"otherd"}, "into": {"widgetd"}}), http.StatusSeeOther)
	code, body := f.get(t, "/software/icon/otherd")
	if code != http.StatusOK {
		t.Fatalf("merged key page: %d", code)
	}
	if !strings.Contains(body, `href="/software/icon/widgetd"`) || strings.Contains(body, `action="/software/icon/upload`) {
		t.Error("merged key page must point to the merge target and offer no icon change")
	}
}

func TestReadOnlyWithoutIconService(t *testing.T) {
	f := newFixture(t, withoutIcons())
	_, body := f.get(t, "/software/icon/widgetd")
	for _, s := range []string{`action="/software/icon/upload`, `action="/software/icon/fetch"`, `action="/software/icon/rollback"`} {
		if strings.Contains(body, s) {
			t.Errorf("read-only page offers %s", s)
		}
	}
	mustStatus(t, f.upload(t, "catalog", "widgetd", "image/png", testPNG(t, red)), http.StatusNotFound)
	mustStatus(t, f.post(t, "/software/icon/fetch", url.Values{"key": {"widgetd"}, "url": {"https://upload.wikimedia.org/a.png"}}), http.StatusNotFound)
	mustStatus(t, f.post(t, "/software/icon/rollback", url.Values{"kind": {"catalog"}, "id": {"widgetd"}, "change": {"1"}}), http.StatusNotFound)
}

func TestHostileDisplayNameRenderedAsText(t *testing.T) {
	f := newFixture(t)
	hostile := `<img src=https://evil.example/x onerror=alert(1)>`
	mustStatus(t, f.post(t, "/software/rename", url.Values{"key": {"widgetd"}, "display": {hostile}}), http.StatusSeeOther)
	for _, p := range []string{"/software", "/software/icon/widgetd"} {
		_, body := f.get(t, p)
		if strings.Contains(body, hostile) || strings.Contains(body, "<img src=https") {
			t.Errorf("%s renders the display name as markup", p)
		}
		if !strings.Contains(body, "&lt;img src=https://evil.example/x onerror=alert(1)&gt;") {
			t.Errorf("%s does not show the escaped display name", p)
		}
	}
}

func TestNoticeIsFixedText(t *testing.T) {
	f := newFixture(t)
	_, body := f.get(t, "/software?done=%3Cscript%3E")
	if strings.Contains(body, "script%3E") || strings.Contains(body, "&lt;script&gt;") {
		t.Error("unknown notice code reflected")
	}
	_, body = f.get(t, "/software/unknown?done=merged")
	if !strings.Contains(body, "Merged.") {
		t.Error("merge notice missing")
	}
}

func TestNewRequiresCatalogAndList(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("New without a catalog succeeded")
	}
}

// TestTemplatesAndScriptAreCSPSafe checks the files this package owns:
// no inline script or style, no inline handlers, no external URLs, and a
// script that never parses HTML.
func TestTemplatesAndScriptAreCSPSafe(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	tmpls, err := filepath.Glob(filepath.Join(root, "web", "templates", "software*.html"))
	if err != nil || len(tmpls) == 0 {
		t.Fatalf("templates: %v %v", tmpls, err)
	}
	inlineHandler := regexp.MustCompile(`(?i)\son[a-z]+=`)
	for _, p := range tmpls {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, bad := range []string{"<script", "<style", "style=", "javascript:", "http://", "https://", "url("} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", p, bad)
			}
		}
		if inlineHandler.MatchString(s) {
			t.Errorf("%s has an inline event handler", p)
		}
		for _, m := range imgSrcRE.FindAllStringSubmatch(s, -1) {
			if m[1] != "{{.IconSrc}}" && m[1] != "{{$v.Current}}" && m[1] != "{{.Src}}" && m[1] != "{{.PrevSrc}}" {
				t.Errorf("%s: img src %q is not a server-built icon path", p, m[1])
			}
		}
	}
	// Read the script from the embedded FS the server serves, not from
	// disk, so a file missing from the //go:embed list fails here.
	js, err := static.FS.ReadFile("software.js")
	if err != nil {
		t.Fatalf("software.js is not embedded in web/static: %v", err)
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "createElement('img'", "createElement(\"img\"", ".src", "http://", "https://", "setAttribute('href'", "DOMParser"} {
		if bytes.Contains(js, []byte(bad)) {
			t.Errorf("software.js contains %q", bad)
		}
	}
	if !bytes.Contains(js, []byte("textContent")) {
		t.Error("software.js does not use textContent for messages")
	}
}

// TestCatalogTruncatedSaysFilterAndCountArePartial checks that a
// truncated catalog marks the unknown count as a lower bound and does
// not claim a state has no entries at all.
func TestCatalogTruncatedSaysFilterAndCountArePartial(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *fixture) {
		o.List = func(context.Context, int) ([]Row, bool, error) {
			return []Row{{Key: "aaa", Display: "aaa", State: softwarecat.StateObserved}}, true, nil
		}
	})
	code, body := f.get(t, "/software")
	if code != http.StatusOK {
		t.Fatalf("GET /software: %d", code)
	}
	if !strings.Contains(body, "Unknown software (1+)") {
		t.Error("truncated catalog does not mark the unknown count as a lower bound")
	}
	if !strings.Contains(body, "cover only these rows") {
		t.Error("truncated catalog does not say the filter and count are partial")
	}
	code, body = f.get(t, "/software?state=ignored")
	if code != http.StatusOK {
		t.Fatalf("GET /software?state=ignored: %d", code)
	}
	if !strings.Contains(body, "No catalog entries in this state among the rows read.") {
		t.Error("truncated filtered view claims the state has no entries")
	}
}

// longHistoryCatalog reports more icon history than one page holds.
type longHistoryCatalog struct {
	Catalog
	n int
}

func (c longHistoryCatalog) IconHistory(_ context.Context, subject softwarecat.IconSubject, limit int) ([]softwarecat.IconChange, error) {
	var out []softwarecat.IconChange
	for i := c.n; i > 0 && len(out) < limit; i-- {
		out = append(out, softwarecat.IconChange{ID: int64(i), Subject: subject, ChangedBy: admin, ChangedAt: t0})
	}
	return out, nil
}

func TestIconHistorySaysWhenCutOff(t *testing.T) {
	for _, tc := range []struct {
		n        int
		wantMore bool
	}{{historyPage, false}, {historyPage + 5, true}} {
		f := newFixture(t, func(o *Options, _ *fixture) {
			o.Catalog = longHistoryCatalog{Catalog: o.Catalog, n: tc.n}
		})
		code, body := f.get(t, "/software/icon/widgetd")
		if code != http.StatusOK {
			t.Fatalf("n=%d: GET icon page: %d", tc.n, code)
		}
		if got := strings.Count(body, `name="change"`); got != historyPage {
			t.Errorf("n=%d: %d rollback forms, want %d", tc.n, got, historyPage)
		}
		if more := strings.Contains(body, "older changes exist"); more != tc.wantMore {
			t.Errorf("n=%d: cut-off notice shown %v, want %v", tc.n, more, tc.wantMore)
		}
	}
}

// longQueueCatalog reports n unknown entries and, like softwarecat.Store,
// never returns more than softwarecat.MaxQueuePage of them.
type longQueueCatalog struct {
	Catalog
	n      int
	limits *[]int
}

func (c longQueueCatalog) UnknownQueue(_ context.Context, limit int) ([]softwarecat.QueueEntry, error) {
	*c.limits = append(*c.limits, limit)
	if limit <= 0 || limit > softwarecat.MaxQueuePage {
		limit = softwarecat.MaxQueuePage
	}
	var out []softwarecat.QueueEntry
	for i := 0; i < c.n && len(out) < limit; i++ {
		out = append(out, softwarecat.QueueEntry{Entry: softwarecat.Entry{Key: softwarecat.Key(fmt.Sprintf("unit%04d", i)),
			Display: "x", State: softwarecat.StateObserved}, Hosts: 1, Observations: 1, LastSeen: t0})
	}
	return out, nil
}

// TestUnknownQueueSaysWhenCutOff checks the cut-off notice in both
// directions: a queue that fits the page shows every entry and no notice,
// one entry more shows the notice. The page asks for at most what the
// store returns, so the look-ahead row is not silently capped away.
func TestUnknownQueueSaysWhenCutOff(t *testing.T) {
	for _, tc := range []struct {
		n        int
		wantRows int
		wantCut  bool
	}{
		{0, 0, false},
		{queuePage - 1, queuePage - 1, false},
		{queuePage, queuePage, false},
		{queuePage + 1, queuePage, true},
		{softwarecat.MaxQueuePage + 100, queuePage, true},
	} {
		var limits []int
		f := newFixture(t, func(o *Options, _ *fixture) {
			o.Catalog = longQueueCatalog{Catalog: o.Catalog, n: tc.n, limits: &limits}
		})
		code, body := f.get(t, "/software/unknown")
		if code != http.StatusOK {
			t.Fatalf("n=%d: GET /software/unknown: %d", tc.n, code)
		}
		if got := strings.Count(body, `action="/software/rename"`); got != tc.wantRows {
			t.Errorf("n=%d: %d rows shown, want %d", tc.n, got, tc.wantRows)
		}
		if cut := strings.Contains(body, "Only the most recently seen entries are shown"); cut != tc.wantCut {
			t.Errorf("n=%d: cut-off notice shown %v, want %v", tc.n, cut, tc.wantCut)
		}
		for _, l := range limits {
			if l <= queuePage || l > softwarecat.MaxQueuePage {
				t.Errorf("n=%d: queue read with limit %d, want %d < limit <= %d", tc.n, l, queuePage, softwarecat.MaxQueuePage)
			}
		}
	}
}
