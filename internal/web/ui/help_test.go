// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

func helpServer(t *testing.T) http.Handler {
	t.Helper()
	srv, err := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Server()
	if err != nil {
		t.Fatalf("Server: %v", err)
	}
	return srv.Handler
}

func helpGet(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

var (
	helpHrefRE = regexp.MustCompile(`href="(/help[^"]*)"`)
	helpIDRE   = regexp.MustCompile(` id="([^"]+)"`)
)

// Every embedded handbook page is reachable under /help, and every
// handbook link on every page leads to a page and section that exist.
func TestHelpEveryHandbookPageReachable(t *testing.T) {
	h := helpServer(t)
	docs, err := docsembed.Pages()
	if err != nil {
		t.Fatalf("Pages: %v", err)
	}
	bodies := map[string]string{}
	index := helpGet(t, h, http.MethodGet, "/help")
	if index.Code != http.StatusOK {
		t.Fatalf("GET /help: %d", index.Code)
	}
	bodies["/help"] = index.Body.String()
	for _, d := range docs {
		if d.Slug == docsembed.IndexSlug {
			continue
		}
		path := "/help/" + d.Slug
		rec := helpGet(t, h, http.MethodGet, path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: %d", path, rec.Code)
			continue
		}
		body := rec.Body.String()
		if !strings.Contains(bodies["/help"], `href="`+path+`"`) {
			t.Errorf("/help does not link %s", path)
		}
		bodies[path] = body
	}
	if !strings.Contains(bodies["/help/faq"], "<h1") {
		t.Errorf("/help/faq has no heading")
	}
	for from, body := range bodies {
		for _, m := range helpHrefRE.FindAllStringSubmatch(body, -1) {
			target, frag, _ := strings.Cut(m[1], "#")
			tb, ok := bodies[target]
			if !ok {
				t.Errorf("%s links unknown help page %q", from, m[1])
				continue
			}
			if frag == "" {
				continue
			}
			found := false
			for _, id := range helpIDRE.FindAllStringSubmatch(tb, -1) {
				if id[1] == frag {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s links %q, but %s has no id %q", from, m[1], target, frag)
			}
		}
	}
}

// The help pages answer with the same strict CSP as the other pages.
func TestHelpSameCSP(t *testing.T) {
	h := helpServer(t)
	want := helpGet(t, h, http.MethodGet, "/dashboard").Header().Get("Content-Security-Policy")
	if want == "" || !strings.Contains(want, "script-src 'self'") || strings.Contains(want, "unsafe-inline") {
		t.Fatalf("dashboard CSP unexpected: %q", want)
	}
	for _, path := range []string{"/help", "/help?q=unlock", "/help/faq", "/help/missing"} {
		if got := helpGet(t, h, http.MethodGet, path).Header().Get("Content-Security-Policy"); got != want {
			t.Errorf("GET %s: CSP = %q, want %q", path, got, want)
		}
	}
}

func TestHelpPageInertAndInLayout(t *testing.T) {
	h := helpServer(t)
	body := helpGet(t, h, http.MethodGet, "/help/getting-started").Body.String()
	for _, want := range []string{
		`<title>Getting started — Nebula Operation Station</title>`,
		`<h1 id="getting-started">Getting started</h1>`,
		`href="/help" aria-current="page"`, // sidebar entry is active
		`<code>nebula_&lt;version&gt;_linux_&lt;arch&gt;.tar.gz</code>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/help/getting-started lacks %q", want)
		}
	}
	// The layout's scripts are the only scripts; no inline handlers or styles.
	if n := strings.Count(body, "<script"); n != strings.Count(body, `<script src="/static/`) {
		t.Errorf("inline script on help page")
	}
	if bad := regexp.MustCompile(`(?i)\s(style|on[a-z]+)=`).FindString(body); bad != "" {
		t.Errorf("inline attribute on help page: %q", bad)
	}
	// Links outside the handbook (admin guide) are text, not broken links.
	if strings.Contains(body, `href="../`) || strings.Contains(body, `.md"`) {
		t.Errorf("help page contains a raw relative .md link")
	}
}

func TestHelpSidebarEntry(t *testing.T) {
	h := helpServer(t)
	body := helpGet(t, h, http.MethodGet, "/dashboard").Body.String()
	if !regexp.MustCompile(`<a class="sidebar__item" href="/help"[^>]*>\s*<svg[^>]*>.*</svg>\s*<span>Help</span>`).MatchString(body) {
		t.Errorf("sidebar has no Help entry")
	}
}

func TestHelpSearch(t *testing.T) {
	h := helpServer(t)
	for _, tc := range []struct {
		name, query string
		want        []string
		notWant     []string
	}{
		{name: "section title", query: "unlock",
			want: []string{`href="/help/getting-started#unlock-the-executor"`, "Unlock the executor"}},
		{name: "case and several terms", query: "PIN host",
			want: []string{`href="/help/hosts#`}},
		{name: "page title", query: "faq",
			want: []string{`href="/help/faq"`}},
		{name: "nothing found", query: "zzzqqq-nothing",
			want: []string{"Nothing found for “zzzqqq-nothing”."}},
		{name: "hostile query is escaped", query: `<script>alert(1)</script>`,
			want: []string{"&lt;script&gt;alert(1)&lt;/script&gt;"}, notWant: []string{"<script>alert"}},
		{name: "too long", query: strings.Repeat("a", 101),
			want: []string{"The search text is too long or not valid text."}, notWant: []string{"Nothing found"}},
		{name: "invalid UTF-8", query: "%ff%fe",
			want: []string{"The search text is too long or not valid text."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := tc.query
			if !strings.HasPrefix(q, "%") {
				q = url.QueryEscape(q)
			}
			rec := helpGet(t, h, http.MethodGet, "/help?q="+q)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			body := rec.Body.String()
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("search %q: body lacks %q", tc.query, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(body, w) {
					t.Errorf("search %q: body contains %q", tc.query, w)
				}
			}
		})
	}
}

func TestHelpRejectsUnknownPagesAndMethods(t *testing.T) {
	// The bare handler: the middleware would refuse a POST without a
	// matching Origin before it reaches the help pages.
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, "/help/missing", http.StatusNotFound},
		{http.MethodGet, "/help/FAQ", http.StatusNotFound},
		{http.MethodGet, "/help/faq.md", http.StatusNotFound},
		{http.MethodGet, "/help/..%2f..%2fgo.mod", http.StatusNotFound},
		{http.MethodGet, "/help/de", http.StatusNotFound},
		{http.MethodGet, "/help/" + strings.Repeat("a", 200), http.StatusNotFound},
		{http.MethodGet, "/help/readme", http.StatusSeeOther},
		{http.MethodPost, "/help", http.StatusMethodNotAllowed},
		{http.MethodPost, "/help/faq", http.StatusMethodNotAllowed},
		{http.MethodHead, "/help/faq", http.StatusOK},
	} {
		if rec := helpGet(t, h, tc.method, tc.path); rec.Code != tc.code {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, rec.Code, tc.code)
		}
	}
}
