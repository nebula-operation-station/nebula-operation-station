// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// providerMetas are the registry remotes the provider lease form offers:
// remote-a and remote-c are active, remote-b is blocked.
func providerMetas() []ui.PVERemoteMeta {
	return []ui.PVERemoteMeta{
		{RemoteID: "remote-a", Name: "Lab <b>cluster</b>", Kind: "cluster", TrustPin: pvePin(0), TrustGeneration: 1, State: "active"},
		{RemoteID: "remote-b", Name: "Blocked", Kind: "standalone", TrustPin: pvePin(1), TrustGeneration: 2, State: "blocked"},
		{RemoteID: "remote-c", Name: "Edge", Kind: "standalone", TrustPin: pvePin(2), TrustGeneration: 1, State: "active"},
	}
}

func providerLeaseHandler(t *testing.T, f *fakeLeases, metas []ui.PVERemoteMeta) http.Handler {
	t.Helper()
	o := ui.Options{PublicOrigin: leaseOrigin, Leases: f}
	if metas != nil {
		o.PVERemotes = func(context.Context) ([]ui.PVERemoteMeta, error) { return metas, nil }
	}
	return newTestHandler(t, o).Handler()
}

// providerPreview is a browser-approved provider lease preview.
func providerPreview() executions.ReadGrantPreview {
	return executions.ReadGrantPreview{
		ID: leaseID, Digest: leaseDigest, ScopeKind: executions.ScopeProvider,
		Issuer: "nebula-server", Created: time.Unix(1_800_000_000, 0).UTC(), Expiry: time.Unix(1_800_000_000+30*86400, 0).UTC(),
		Trigger: "both", RateProfile: "provider", MinInterval: time.Minute, RunBudget: 600,
		Providers: []executions.ReadGrantPreviewProvider{
			{RemoteID: "remote-a", TrustPin: pvePin(0), TrustGeneration: 3, CredentialVersion: 2, Methods: []string{"guests", "nodes"}},
		},
		Options:         []byte(`{"publicKey":{"challenge":"abc"}}`),
		ChallengeExpiry: time.Unix(1_800_000_300, 0).UTC(),
	}
}

const providerForm = "scope=provider&remote=remote-a&method=nodes&method=guests&days=30"

func TestProviderLeaseFormOffersActiveRemotesAndMethods(t *testing.T) {
	page := getBody(t, providerLeaseHandler(t, &fakeLeases{}, providerMetas()), "/leases/new")
	for _, want := range []string{
		`name="scope" value="provider"`, `<select name="remote"`,
		`<option value="remote-a">`, `<option value="remote-c">`,
		// The registry name is rendered as text.
		"Lab &lt;b&gt;cluster&lt;/b&gt;",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("form misses %q", want)
		}
	}
	if strings.Contains(page, `value="remote-b"`) {
		t.Error("form offers a blocked remote")
	}
	if strings.Contains(page, "<b>cluster</b>") {
		t.Error("registry name rendered as HTML")
	}
	defaults := executions.DefaultProviderReadMethods()
	for _, m := range []string{"nodes", "guests", "storage", "cluster", "tasks"} {
		if !strings.Contains(page, `name="method" value="`+m+`" checked`) {
			t.Errorf("default method %s is not checked", m)
		}
		if !slices.Contains(defaults, m) {
			t.Errorf("%s is not a service default", m)
		}
	}
	for _, m := range []string{"guest_config", "guest_agent", "snapshots", "backups"} {
		if !strings.Contains(page, `name="method" value="`+m+`"`) {
			t.Errorf("form misses optional method %s", m)
		}
		if strings.Contains(page, `name="method" value="`+m+`" checked`) {
			t.Errorf("optional method %s is checked by default", m)
		}
	}
	// Every offered method is a valid provider method, each with a line
	// on what it reads.
	re := regexp.MustCompile(`name="method" value="([^"]+)"`)
	got := re.FindAllStringSubmatch(page, -1)
	if len(got) != 9 {
		t.Errorf("form offers %d methods, want 9", len(got))
	}
	for _, m := range got {
		if !permit.ValidProviderMethod(m[1]) {
			t.Errorf("form offers unknown method %q", m[1])
		}
	}
	if n := strings.Count(page, `class="hint provider-method"`); n != 9 {
		t.Errorf("%d method descriptions, want 9", n)
	}
}

func TestProviderLeaseFormHiddenWithoutRemoteRegistry(t *testing.T) {
	page := getBody(t, providerLeaseHandler(t, &fakeLeases{}, nil), "/leases/new")
	if strings.Contains(page, `value="provider"`) || strings.Contains(page, `name="method"`) {
		t.Error("provider scope offered without the PVE remote registry")
	}
}

func TestProviderLeaseFormPrefill(t *testing.T) {
	f := &fakeLeases{}
	h := providerLeaseHandler(t, f, providerMetas())
	page := getBody(t, h, "/leases/new?scope=provider&remote=remote-a")
	for _, want := range []string{
		`name="scope" value="provider" checked`, `<option value="remote-a" selected>`,
		`name="method" value="nodes" checked`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("pre-filled form misses %q", want)
		}
	}
	if strings.Contains(page, `<option value="remote-c" selected>`) {
		t.Error("a remote that was not chosen is selected")
	}

	// A blocked, unknown or hostile remote and unknown methods are not
	// pre-filled; explicit methods replace the defaults.
	page = getBody(t, h, "/leases/new?scope=provider&remote=remote-b&remote=nope&remote=%22%3E%3Cscript%3E&method=snapshots&method=metrics&days=30")
	if !strings.Contains(page, `<option value="30" selected>`) {
		t.Error("days not pre-filled")
	}
	for _, never := range []string{`value="remote-b"`, `value="nope"`, `"><script>`, `value="metrics"`, `value="nodes" checked`} {
		if strings.Contains(page, never) {
			t.Errorf("pre-filled form shows %q", never)
		}
	}
	if !strings.Contains(page, `name="method" value="snapshots" checked`) {
		t.Error("pre-filled method snapshots is not checked")
	}
	if strings.Count(page, `<option value="remote-`) != 2 || strings.Contains(page, `remote-a" selected`) {
		t.Error("remote options changed by an unusable pre-fill")
	}
	if len(f.providerProposed) != 0 || len(f.proposed) != 0 {
		t.Error("GET /leases/new proposed a lease")
	}
}

func TestProviderLeasePreviewProposesExactlyTheChosenScope(t *testing.T) {
	f := &fakeLeases{providerPreview: providerPreview()}
	h := providerLeaseHandler(t, f, providerMetas())
	// Host-lease fields posted with the provider scope are ignored.
	code, body := postLeaseForm(t, h, "/leases/preview", providerForm+"&action=core.facts&value=tier%3Dfront&remote=remote-c")
	if code != http.StatusSeeOther {
		t.Fatalf("POST = %d (%s), want 303", code, body)
	}
	if len(f.proposed) != 0 {
		t.Fatal("a provider form proposed a host lease")
	}
	if len(f.providerProposed) != 1 {
		t.Fatalf("proposed %d provider leases", len(f.providerProposed))
	}
	in := f.providerProposed[0]
	if !slices.Equal(in.RemoteIDs, []string{"remote-a", "remote-c"}) || !slices.Equal(in.Methods, []string{"nodes", "guests"}) || in.Days != 30 {
		t.Errorf("request %+v", in)
	}
}

func TestProviderLeasePreviewRejections(t *testing.T) {
	many := "scope=provider&method=nodes&days=7"
	var metas []ui.PVERemoteMeta
	for i := 0; i <= permit.MaxProviderTargets; i++ {
		id := fmt.Sprintf("r-%02d", i)
		metas = append(metas, ui.PVERemoteMeta{RemoteID: id, State: "active"})
		many += "&remote=" + id
	}
	for _, tc := range []struct {
		name, form string
		metas      []ui.PVERemoteMeta
		code       int
	}{
		{"no remote", "scope=provider&method=nodes&days=7", nil, http.StatusBadRequest},
		{"blocked remote", "scope=provider&remote=remote-b&method=nodes&days=7", nil, http.StatusBadRequest},
		{"unknown remote", "scope=provider&remote=remote-x&method=nodes&days=7", nil, http.StatusBadRequest},
		{"malformed remote", "scope=provider&remote=%3Cx%3E&method=nodes&days=7", nil, http.StatusBadRequest},
		{"remote twice", "scope=provider&remote=remote-a&remote=remote-a&method=nodes&days=7", nil, http.StatusBadRequest},
		{"too many remotes", many, metas, http.StatusBadRequest},
		{"no method", "scope=provider&remote=remote-a&days=7", nil, http.StatusBadRequest},
		{"metrics method", "scope=provider&remote=remote-a&method=metrics&days=7", nil, http.StatusBadRequest},
		{"unknown method", "scope=provider&remote=remote-a&method=shell&days=7", nil, http.StatusBadRequest},
		{"method twice", "scope=provider&remote=remote-a&method=nodes&method=nodes&days=7", nil, http.StatusBadRequest},
		{"days 90", "scope=provider&remote=remote-a&method=nodes&days=90", nil, http.StatusBadRequest},
		{"days missing", "scope=provider&remote=remote-a&method=nodes", nil, http.StatusBadRequest},
		{"days zero", "scope=provider&remote=remote-a&method=nodes&days=0", nil, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.metas
			if m == nil {
				m = providerMetas()
			}
			f := &fakeLeases{providerPreview: providerPreview()}
			code, body := postLeaseForm(t, providerLeaseHandler(t, f, m), "/leases/preview", tc.form)
			if code != tc.code {
				t.Errorf("= %d %q, want %d", code, body, tc.code)
			}
			if len(f.providerProposed) != 0 || len(f.proposed) != 0 {
				t.Error("a rejected form reached the service")
			}
			if strings.Contains(body, "<") {
				t.Errorf("error echoes markup: %q", body)
			}
		})
	}
}

func TestProviderLeasePreviewWithoutRegistryIsRefused(t *testing.T) {
	f := &fakeLeases{providerPreview: providerPreview()}
	code, _ := postLeaseForm(t, providerLeaseHandler(t, f, nil), "/leases/preview", providerForm)
	if code != http.StatusBadRequest || len(f.providerProposed) != 0 {
		t.Errorf("= %d, %d proposals; want 400 and none", code, len(f.providerProposed))
	}
}

func TestProviderLeasePreviewServiceErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
		text string
	}{
		{"input", &executions.ReadGrantInputError{Reason: "PVE remote remote-a has no read credential"}, http.StatusBadRequest, "no read credential"},
		{"remotes", executions.ErrProviderRemotesUnavailable, http.StatusBadGateway, executions.ErrProviderRemotesUnavailable.Error()},
		{"executor", executions.ErrReadGrantProposeFailed, http.StatusBadGateway, executions.ErrReadGrantProposeFailed.Error()},
		{"other", fmt.Errorf("database secret path"), http.StatusInternalServerError, "internal error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLeases{providerErr: tc.err}
			code, body := postLeaseForm(t, providerLeaseHandler(t, f, providerMetas()), "/leases/preview", providerForm)
			if code != tc.code || !strings.Contains(body, tc.text) || strings.Contains(body, "secret") {
				t.Fatalf("= %d %q, want %d %q", code, body, tc.code, tc.text)
			}
		})
	}
}

// TestProviderLeasePreviewNeedsSameOriginPost checks that only a same-origin
// POST through the real middleware proposes a provider lease: a GET, a
// plain form post (Origin: null) and a cross-origin post do not.
func TestProviderLeasePreviewNeedsSameOriginPost(t *testing.T) {
	for _, tc := range []struct {
		method, origin string
		want           int
	}{
		// GET matches the lease detail route: "preview" is no lease id.
		{http.MethodGet, leaseOrigin, http.StatusNotFound},
		{http.MethodPost, "null", http.StatusForbidden},
		{http.MethodPost, "https://evil.example.org", http.StatusForbidden},
		{http.MethodPost, leaseOrigin, http.StatusSeeOther},
	} {
		f := &fakeLeases{providerPreview: providerPreview()}
		metas := providerMetas()
		u := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Leases: f,
			PVERemotes: func(context.Context) ([]ui.PVERemoteMeta, error) { return metas, nil }})
		srv, err := u.Server()
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(srv.Handler)
		target := ts.URL + "/leases/preview"
		var body *strings.Reader
		if tc.method == http.MethodGet {
			target += "?" + providerForm
			body = strings.NewReader("")
		} else {
			body = strings.NewReader(providerForm)
		}
		req, _ := http.NewRequest(tc.method, target, body)
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
			t.Errorf("%s Origin %q = %d, want %d", tc.method, tc.origin, res.StatusCode, tc.want)
		}
		if wantProposal := tc.want == http.StatusSeeOther; (len(f.providerProposed) == 1) != wantProposal {
			t.Errorf("%s Origin %q: %d proposals", tc.method, tc.origin, len(f.providerProposed))
		}
	}
}

func TestProviderLeaseProposalPageShowsFrozenRemotes(t *testing.T) {
	v := providerPreview()
	v.Providers = append(v.Providers, executions.ReadGrantPreviewProvider{
		RemoteID: `x"><script>alert(1)</script>`, TrustPin: pvePin(2), TrustGeneration: 9, CredentialVersion: 4, Methods: []string{"snapshots"},
	})
	v.Issuer = "<i>issuer</i>"
	f := &fakeLeases{providerPreview: v}
	h := providerLeaseHandler(t, f, providerMetas())
	code, body := postLeaseForm(t, h, "/leases/preview", providerForm)
	if code != http.StatusSeeOther {
		t.Fatalf("POST = %d (%s)", code, body)
	}
	page := getBody(t, h, "/leases/proposals/"+leaseDigest)
	if got := strings.Count(page, `<tr class="lease-remote">`); got != 2 {
		t.Errorf("proposal lists %d remotes, want 2", got)
	}
	for _, want := range []string{
		`<td class="mono">remote-a</td><td class="mono">` + pvePin(0) + `</td><td class="mono">3</td><td class="mono">2</td><td class="mono">guests, nodes</td>`,
		"2 Proxmox remotes", "Trigger", "both", "provider", "at most 600 requests per remote per hour",
		`id="lease-digest">` + leaseDigest + `<`,
		`class="button schedule-approve" data-id="` + leaseDigest + `"`,
		"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;i&gt;issuer&lt;/i&gt;",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("proposal page misses %q", want)
		}
	}
	for _, never := range []string{"<script>alert(1)", "<i>issuer", "0 hosts", "0 actions"} {
		if strings.Contains(page, never) {
			t.Errorf("proposal page shows %q", never)
		}
	}
	// The proposal itself approves nothing.
	if len(f.committed) != 0 {
		t.Error("the proposal was committed without an approval")
	}
}

// providerGrant is a listed provider lease over remote-a and remote-c.
func providerGrant(state string) executions.ReadGrantView {
	now := time.Now()
	return executions.ReadGrantView{
		ID: leaseID, Digest: leaseDigest, ScopeKind: executions.ScopeProvider, State: state,
		RateProfile: "provider", Remotes: []string{"remote-a", "remote-c"},
		Providers: []executions.ReadGrantProviderView{
			{RemoteID: "remote-a", PinPrefix: "aaaaaaaaaaaaaaaa", TrustGeneration: 3, CredentialVersion: 2, Methods: []string{"guests", "nodes"}},
			{RemoteID: "remote-c", PinPrefix: "cccccccccccccccc", TrustGeneration: 1, CredentialVersion: 5, Methods: []string{"nodes", "snapshots"}},
		},
		ApprovedBy: "<b>alice</b>", Created: now.Add(-time.Hour), Expiry: now.Add(30*24*time.Hour - time.Hour),
	}
}

func TestProviderLeaseListAndDetail(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{providerGrant("active")}}
	h := providerLeaseHandler(t, f, providerMetas())
	list := getBody(t, h, "/leases")
	for _, want := range []string{"Proxmox remotes: remote-a, remote-c", "3 methods", "2 remotes"} {
		if !strings.Contains(list, want) {
			t.Errorf("list misses %q", want)
		}
	}
	links := regexp.MustCompile(`href="(/leases/new\?[^"]*)"`).FindAllStringSubmatch(list, -1)
	if len(links) != 1 {
		t.Fatalf("refresh links %v, want one", links)
	}
	refresh := strings.ReplaceAll(links[0][1], "&amp;", "&")
	q, err := url.ParseQuery(strings.TrimPrefix(refresh, "/leases/new?"))
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("scope") != "provider" || !slices.Equal(q["remote"], []string{"remote-a", "remote-c"}) ||
		!slices.Equal(q["method"], []string{"guests", "nodes", "snapshots"}) || q.Get("days") != "30" || q.Get("refresh") != leaseID {
		t.Errorf("refresh link %q", refresh)
	}

	detail := getBody(t, h, "/leases/"+leaseID)
	for _, want := range []string{
		`<tr class="lease-remote"><td class="mono">remote-a</td><td class="mono">aaaaaaaaaaaaaaaa…</td><td class="mono">3</td><td class="mono">2</td><td class="mono">guests, nodes</td></tr>`,
		`<td class="mono">remote-c</td>`, "Rate profile", "&lt;b&gt;alice&lt;/b&gt;",
		`action="/leases/revoke"`, ">Refresh</a>",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail misses %q", want)
		}
	}
	if strings.Contains(detail, "<b>alice</b>") || strings.Contains(detail, "no host list") {
		t.Error("detail renders approved-by as HTML or a host-list note for a provider lease")
	}

	// Refresh pre-fills the provider form; nothing is proposed by it.
	form := getBody(t, h, refresh)
	for _, want := range []string{
		`name="scope" value="provider" checked`, `<option value="remote-a" selected>`, `<option value="remote-c" selected>`,
		`name="method" value="snapshots" checked`, `name="method" value="guests" checked`, `<option value="30" selected>`,
		"refresh of 0a1b2c3d",
	} {
		if !strings.Contains(form, want) {
			t.Errorf("refresh form misses %q", want)
		}
	}
	if strings.Contains(form, `name="method" value="storage" checked`) {
		t.Error("a method outside the refreshed lease is checked")
	}
	if len(f.providerProposed) != 0 {
		t.Error("refresh proposed a lease")
	}

	// Revoke works on a provider lease.
	if code, body := postLeaseForm(t, h, "/leases/revoke", "id="+leaseID); code != http.StatusSeeOther {
		t.Fatalf("revoke = %d %q", code, body)
	}
	if !slices.Equal(f.revoked, []string{leaseID}) {
		t.Errorf("revoked %v", f.revoked)
	}
}

func TestProviderLeaseHostileRemoteIDIsText(t *testing.T) {
	g := providerGrant("active")
	g.Remotes = []string{`<img src=x>`}
	g.Providers = []executions.ReadGrantProviderView{{RemoteID: `<img src=x>`, PinPrefix: "<p>", TrustGeneration: 1, CredentialVersion: 1, Methods: []string{"<m>"}}}
	h := providerLeaseHandler(t, &fakeLeases{grants: []executions.ReadGrantView{g}}, providerMetas())
	for _, p := range []string{"/leases", "/leases/" + leaseID} {
		page := getBody(t, h, p)
		if strings.Contains(page, "<img") || strings.Contains(page, "<p>…") || strings.Contains(page, "<m>") {
			t.Errorf("%s renders executor text as HTML", p)
		}
		if !strings.Contains(page, "&lt;img src=x&gt;") {
			t.Errorf("%s misses the escaped remote", p)
		}
	}
}

func TestProviderLeaseNotRefreshableWhenRevoked(t *testing.T) {
	h := providerLeaseHandler(t, &fakeLeases{grants: []executions.ReadGrantView{providerGrant("revoked")}}, providerMetas())
	if list := getBody(t, h, "/leases"); strings.Contains(list, "/leases/new?") {
		t.Error("a revoked provider lease offers Refresh")
	}
}
