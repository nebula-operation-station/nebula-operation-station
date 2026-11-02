// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

var leaseDigest = strings.Repeat("c0", 32)

// leaseClock is a settable clock for the preview throttle.
type leaseClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *leaseClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *leaseClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// leasePreview is a browser-approved preview of n hosts.
func leasePreview(n int) executions.ReadGrantPreview {
	v := executions.ReadGrantPreview{
		ID: leaseID, Digest: leaseDigest, ScopeKind: "tag", ScopeValue: "tier=front",
		Issuer: "nebula-server", Created: time.Unix(1_800_000_000, 0).UTC(), Expiry: time.Unix(1_800_000_000+7*86400, 0).UTC(),
		Trigger: "both", RateProfile: "ordinary", MinInterval: 15 * time.Minute, RunBudget: 24,
		Actions: []executions.ReadGrantPreviewAction{
			{ActionID: "core.facts", ModuleVersion: "1.0.0", ArtifactSHA256: strings.Repeat("a", 64), ParametersHash: strings.Repeat("b", 64)},
			{ActionID: "package.list_updates", ModuleVersion: "1.0.0", ArtifactSHA256: strings.Repeat("d", 64), ParametersHash: strings.Repeat("b", 64)},
		},
		Options:         []byte(`{"publicKey":{"challenge":"abc"}}`),
		ChallengeExpiry: time.Unix(1_800_000_300, 0).UTC(),
	}
	for i := 0; i < n; i++ {
		v.Targets = append(v.Targets, executions.ReadGrantPreviewTarget{
			HostID: fmt.Sprintf("host-%03d", i), HostKeyFingerprint: fmt.Sprintf("SHA256:hostkey%03d", i),
			CredentialRef: "default", CredentialVersion: "SHA256:credversion",
		})
	}
	return v
}

func leaseNewHandler(t *testing.T, f *fakeLeases, clock *leaseClock) http.Handler {
	t.Helper()
	o := ui.Options{PublicOrigin: leaseOrigin, Leases: f}
	if clock != nil {
		o.Now = clock.Now
	}
	return newTestHandler(t, o).Handler()
}

const leaseForm = "scope=tag&value=tier%3Dfront&action=core.facts&action=package.list_updates&days=7"

// previewThrough posts the form and follows the redirect to the proposal
// page, returning that page.
func previewThrough(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/leases/preview", strings.NewReader(leaseForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /leases/preview = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/leases/proposals/"+leaseDigest {
		t.Fatalf("redirect to %q", loc)
	}
	return getBody(t, h, loc)
}

func TestLeaseNewFormOffersReadOnlyActions(t *testing.T) {
	page := getBody(t, leaseNewHandler(t, &fakeLeases{}, nil), "/leases/new")
	for _, want := range []string{
		`action="/leases/preview"`, `data-fetch`,
		`name="scope" value="all" checked`, `name="scope" value="tag"`, `name="scope" value="environment"`,
		`<option value="7" selected>7 days</option>`, `<option value="30">30 days</option>`,
		`value="core.facts"`, `/static/formpost.js`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("form misses %q", want)
		}
	}
	for _, id := range executions.ReadGrantActionIDs() {
		if !strings.Contains(page, `name="action" value="`+id+`"`) {
			t.Errorf("form misses action %s", id)
		}
	}
	for _, never := range []string{`value="package.refresh"`, `value="docker.logs"`, `value="system.reboot"`} {
		if strings.Contains(page, never) {
			t.Errorf("form offers %s", never)
		}
	}
}

func TestLeaseRefreshPrefillsForm(t *testing.T) {
	now := time.Now()
	f := &fakeLeases{grants: []executions.ReadGrantView{
		{ID: leaseID, State: "active", ScopeKind: "tag", ScopeValue: "tier=front", Hosts: []string{"web"},
			Actions: []string{"core.facts"}, Created: now.Add(-time.Hour), Expiry: now.Add(30*24*time.Hour - time.Hour)},
		{ID: "11111111-2222-4333-8444-555555555555", State: "expired", ScopeKind: "all", Hosts: []string{"web"},
			Actions: []string{"docker.list"}, Created: now.Add(-8 * 24 * time.Hour), Expiry: now.Add(-24 * time.Hour)},
		{ID: "22222222-2222-4333-8444-555555555555", State: "revoked", ScopeKind: "all", Hosts: []string{"web"}, Actions: []string{"core.facts"}},
		{ID: "33333333-2222-4333-8444-555555555555", State: "legacy", ScopeKind: "all", Hosts: []string{"web"}, Actions: []string{"core.facts"}},
		{ID: "44444444-2222-4333-8444-555555555555", State: "active", ScopeKind: "hosts", Hosts: []string{"web"}, Actions: []string{"core.facts"}},
	}}
	h := leaseNewHandler(t, f, nil)
	list := getBody(t, h, "/leases")
	links := regexp.MustCompile(`href="(/leases/new\?[^"]*)"`).FindAllStringSubmatch(list, -1)
	if len(links) != 2 {
		t.Fatalf("refresh links %v, want one for the active tag lease and one for the expired all lease", links)
	}
	activeLink := strings.ReplaceAll(links[0][1], "&amp;", "&")
	for _, want := range []string{"scope=tag", "value=tier%3Dfront", "action=core.facts", "days=30", "refresh=" + leaseID} {
		if !strings.Contains(activeLink, want) {
			t.Errorf("refresh link %q misses %q", activeLink, want)
		}
	}
	if !strings.Contains(links[1][1], "days=7") || !strings.Contains(links[1][1], "action=docker.list") {
		t.Errorf("expired refresh link %q", links[1][1])
	}
	if !strings.Contains(list, `href="/leases/new"`) {
		t.Error("list misses the New read lease link")
	}

	form := getBody(t, h, activeLink)
	for _, want := range []string{
		`name="scope" value="tag" checked`, `name="value" value="tier=front"`,
		`name="action" value="core.facts" checked`, `<option value="30" selected>30 days</option>`,
		"refresh of 0a1b2c3d", "stays until it expires or is revoked",
	} {
		if !strings.Contains(form, want) {
			t.Errorf("pre-filled form misses %q", want)
		}
	}
	if strings.Contains(form, `value="docker.list" checked`) {
		t.Error("an action outside the refreshed lease is checked")
	}

	// The detail page of the active lease offers Refresh too.
	detail := getBody(t, h, "/leases/"+leaseID)
	if !strings.Contains(detail, ">Refresh</a>") {
		t.Error("detail page misses Refresh")
	}
}

func TestLeaseFormIgnoresUnusablePrefill(t *testing.T) {
	page := getBody(t, leaseNewHandler(t, &fakeLeases{}, nil),
		"/leases/new?scope=hosts&value=x&action=package.refresh&action=system.reboot&days=90&refresh=..%2F..")
	if !strings.Contains(page, `name="scope" value="all" checked`) || !strings.Contains(page, `<option value="7" selected>`) {
		t.Error("unusable pre-fill was not reset to the defaults")
	}
	for _, never := range []string{"package.refresh", "system.reboot", "refresh of"} {
		if strings.Contains(page, never) {
			t.Errorf("form shows %q", never)
		}
	}
}

func TestLeasePreviewListsEveryHostAndDigest(t *testing.T) {
	f := &fakeLeases{preview: leasePreview(250)}
	page := previewThrough(t, leaseNewHandler(t, f, nil))
	if got := strings.Count(page, `<tr class="lease-host">`); got != 250 {
		t.Errorf("preview lists %d hosts, want all 250", got)
	}
	for i := 0; i < 250; i++ {
		if !strings.Contains(page, fmt.Sprintf(`<td class="mono">host-%03d</td><td class="mono">SHA256:hostkey%03d</td>`, i, i)) {
			t.Fatalf("preview misses host-%03d with its host key", i)
		}
	}
	for _, want := range []string{
		`id="lease-digest">` + leaseDigest + `<`,
		"250 hosts", "2 actions", "core.facts", "package.list_updates", strings.Repeat("a", 64),
		"tag: tier=front", "SHA256:credversion", "15 min", "at most 24 runs",
		`class="button schedule-approve" data-id="` + leaseDigest + `"`,
		`data-commit="/leases/commit"`,
		`data-options="{&#34;publicKey&#34;:{&#34;challenge&#34;:&#34;abc&#34;}}"`,
		`/static/webauthn.js`, `/static/schedules.js`, "Approve before",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("preview misses %q", want)
		}
	}
	if strings.Contains(page, "nebula lease approve") {
		t.Error("browser preview shows the CLI command")
	}
	// No new script: only scripts that exist already.
	for _, m := range regexp.MustCompile(`src="/static/([^"]+)"`).FindAllStringSubmatch(page, -1) {
		switch m[1] {
		case "htmx.min.js", "nav.js", "time.js", "webauthn.js", "schedules.js":
		default:
			t.Errorf("preview loads unexpected script %s", m[1])
		}
	}
	if len(f.proposed) != 1 {
		t.Fatalf("proposed %d times", len(f.proposed))
	}
	in := f.proposed[0]
	if in.ScopeKind != "tag" || in.ScopeValue != "tier=front" || in.Days != 7 || len(in.Actions) != 2 {
		t.Errorf("request %+v", in)
	}
}

func TestLeasePreviewHardenedShowsCLI(t *testing.T) {
	v := leasePreview(3)
	v.CLI, v.Options = true, nil
	page := previewThrough(t, leaseNewHandler(t, &fakeLeases{preview: v}, nil))
	if !strings.Contains(page, `<pre class="mono" id="lease-cli">nebula lease approve `+leaseDigest+`</pre>`) {
		t.Error("hardened preview misses the CLI command with the full digest")
	}
	for _, never := range []string{"schedule-approve", "Approve with security key", "/static/webauthn.js", "/static/schedules.js"} {
		if strings.Contains(page, never) {
			t.Errorf("hardened preview shows %q", never)
		}
	}
	if got := strings.Count(page, `<tr class="lease-host">`); got != 3 {
		t.Errorf("hardened preview lists %d hosts, want 3", got)
	}
}

func TestLeasePreviewThrottle(t *testing.T) {
	clock := &leaseClock{t: time.Unix(1_800_000_000, 0)}
	f := &fakeLeases{preview: leasePreview(1)}
	h := leaseNewHandler(t, f, clock)
	previewThrough(t, h)

	clock.Add(9 * time.Second)
	code, body := postLeaseForm(t, h, "/leases/preview", leaseForm)
	if code != http.StatusTooManyRequests {
		t.Fatalf("second preview within 10 s = %d, want 429", code)
	}
	if !strings.Contains(body, "10 seconds") {
		t.Errorf("429 body %q", body)
	}
	if len(f.proposed) != 1 {
		t.Fatalf("a throttled preview reached the executor (%d proposals)", len(f.proposed))
	}

	clock.Add(time.Second)
	previewThrough(t, h)
	if len(f.proposed) != 2 {
		t.Fatalf("preview after 10 s not proposed (%d proposals)", len(f.proposed))
	}
}

func TestLeasePreviewThrottleRetryAfter(t *testing.T) {
	clock := &leaseClock{t: time.Unix(1_800_000_000, 0)}
	h := leaseNewHandler(t, &fakeLeases{preview: leasePreview(1)}, clock)
	previewThrough(t, h)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/leases/preview", strings.NewReader(leaseForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "10" {
		t.Fatalf("= %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestLeasePreviewEscapesUntrustedText(t *testing.T) {
	evil := `<script>alert(1)</script>`
	v := leasePreview(1)
	v.Targets[0].HostID = evil
	v.Targets[0].CredentialRef = `"><img src=x onerror=alert(1)>`
	v.ScopeValue = "tier=" + evil
	v.Actions[0].ModuleVersion = evil
	v.Excluded = []executions.ReadGrantExcluded{{HostID: evil, Reason: "not enrolled"}}
	page := previewThrough(t, leaseNewHandler(t, &fakeLeases{preview: v}, nil))
	if strings.Contains(page, evil) || strings.Contains(page, "<img") {
		t.Fatal("untrusted text rendered as HTML")
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped host id missing")
	}

	// The form escapes pre-filled values and inventory suggestions.
	form := getBody(t, leaseNewHandler(t, &fakeLeases{}, nil), `/leases/new?scope=tag&value=%22%3E%3Cscript%3Ex%3C%2Fscript%3E`)
	if strings.Contains(form, `"><script>x</script>`) {
		t.Fatal("pre-filled value rendered as HTML")
	}
}

func TestLeasePreviewErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
		text string
	}{
		{"input", &executions.ReadGrantInputError{Reason: "choose 1 to 32 actions"}, http.StatusBadRequest, "choose 1 to 32 actions"},
		{"executor", executions.ErrReadGrantProposeFailed, http.StatusBadGateway, executions.ErrReadGrantProposeFailed.Error()},
		{"credentials", executions.ErrReadGrantCredentials, http.StatusBadGateway, executions.ErrReadGrantCredentials.Error()},
		{"mismatch", executions.ErrReadGrantProposalMismatch, http.StatusBadGateway, executions.ErrReadGrantProposalMismatch.Error()},
		{"other", errors.New("database secret path"), http.StatusInternalServerError, "internal error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := postLeaseForm(t, leaseNewHandler(t, &fakeLeases{proposeErr: tc.err}, nil), "/leases/preview", leaseForm)
			if code != tc.code || !strings.Contains(body, tc.text) {
				t.Fatalf("= %d %q, want %d %q", code, body, tc.code, tc.text)
			}
			if strings.Contains(body, "secret") {
				t.Error("internal error detail reached the user")
			}
		})
	}
}

func TestLeaseProposalPageNeedsKnownDigest(t *testing.T) {
	h := leaseNewHandler(t, &fakeLeases{}, nil)
	for _, p := range []string{"/leases/proposals/" + leaseDigest, "/leases/proposals/xyz", "/leases/proposals/" + strings.ToUpper(leaseDigest)} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
}

func postLeaseJSON(t *testing.T, h http.Handler, path, body string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestLeaseCommit(t *testing.T) {
	f := &fakeLeases{preview: leasePreview(2)}
	h := leaseNewHandler(t, f, nil)
	previewThrough(t, h)
	code, body := postLeaseJSON(t, h, "/leases/commit", `{"id":"`+leaseDigest+`","assertion":{"id":"cred"}}`)
	if code != http.StatusOK {
		t.Fatalf("commit = %d %s", code, body)
	}
	if len(f.committed) != 1 || f.committed[0] != leaseDigest+` {"id":"cred"}` {
		t.Fatalf("committed %v", f.committed)
	}
	// The page reload after approval goes back to the list.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/leases/proposals/"+leaseDigest, nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/leases" {
		t.Fatalf("proposal page after approval = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// A second commit of the same proposal is refused before the executor.
	if code, _ := postLeaseJSON(t, h, "/leases/commit", `{"id":"`+leaseDigest+`","assertion":{}}`); code != http.StatusNotFound {
		t.Errorf("second commit = %d, want 404", code)
	}
	if len(f.committed) != 1 {
		t.Errorf("second commit reached the executor")
	}
}

func TestLeaseCommitRejections(t *testing.T) {
	t.Run("unknown digest", func(t *testing.T) {
		f := &fakeLeases{}
		code, _ := postLeaseJSON(t, leaseNewHandler(t, f, nil), "/leases/commit", `{"id":"`+leaseDigest+`","assertion":{}}`)
		if code != http.StatusNotFound || len(f.committed) != 0 {
			t.Fatalf("= %d committed %v", code, f.committed)
		}
	})
	t.Run("malformed id", func(t *testing.T) {
		f := &fakeLeases{}
		code, _ := postLeaseJSON(t, leaseNewHandler(t, f, nil), "/leases/commit", `{"id":"../x","assertion":{}}`)
		if code != http.StatusNotFound || len(f.committed) != 0 {
			t.Fatalf("= %d", code)
		}
	})
	t.Run("not json", func(t *testing.T) {
		code, _ := postLeaseForm(t, leaseNewHandler(t, &fakeLeases{}, nil), "/leases/commit", "id=x")
		if code != http.StatusUnsupportedMediaType {
			t.Fatalf("= %d, want 415", code)
		}
	})
	t.Run("hardened proposal", func(t *testing.T) {
		v := leasePreview(1)
		v.CLI, v.Options = true, nil
		f := &fakeLeases{preview: v}
		h := leaseNewHandler(t, f, nil)
		previewThrough(t, h)
		code, _ := postLeaseJSON(t, h, "/leases/commit", `{"id":"`+leaseDigest+`","assertion":{}}`)
		if code != http.StatusNotFound || len(f.committed) != 0 {
			t.Fatalf("browser commit of a CLI proposal = %d", code)
		}
	})
	t.Run("refused", func(t *testing.T) {
		f := &fakeLeases{preview: leasePreview(1), commitErr: executions.ErrReadGrantApprovalRefused}
		h := leaseNewHandler(t, f, nil)
		previewThrough(t, h)
		code, body := postLeaseJSON(t, h, "/leases/commit", `{"id":"`+leaseDigest+`","assertion":{}}`)
		if code != http.StatusForbidden || !strings.Contains(body, "not accepted") {
			t.Fatalf("= %d %s", code, body)
		}
		// Still pending: the page keeps the button.
		if page := getBody(t, h, "/leases/proposals/"+leaseDigest); !strings.Contains(page, "schedule-approve") {
			t.Error("refused proposal lost its approval button")
		}
	})
}

// TestLeasePreviewThroughMiddleware posts the preview through the real
// middleware chain: a plain form post (Origin: null) is refused, the fetch
// post from formpost.js passes.
func TestLeasePreviewThroughMiddleware(t *testing.T) {
	for _, tc := range []struct {
		origin string
		want   int
	}{
		{"null", http.StatusForbidden},
		{"https://evil.example.org", http.StatusForbidden},
		{leaseOrigin, http.StatusSeeOther},
	} {
		f := &fakeLeases{preview: leasePreview(1)}
		u := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Leases: f})
		srv, err := u.Server()
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(srv.Handler)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/leases/preview", strings.NewReader(leaseForm))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", tc.origin)
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		ts.Close()
		if res.StatusCode != tc.want {
			t.Errorf("Origin %q = %d, want %d", tc.origin, res.StatusCode, tc.want)
		}
		if tc.want == http.StatusForbidden && len(f.proposed) != 0 {
			t.Errorf("Origin %q reached the executor", tc.origin)
		}
	}
}

func TestLeaseProposalRoutesNeedLeases(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin}).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/leases/new", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /leases/new without leases = %d", rec.Code)
	}
	if code, _ := postLeaseForm(t, h, "/leases/preview", leaseForm); code != http.StatusNotFound {
		t.Errorf("POST /leases/preview without leases = %d", code)
	}
}
