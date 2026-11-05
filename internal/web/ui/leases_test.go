// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const leaseID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"

// fakeLeases is a fake read-grant store for the lease pages.
type fakeLeases struct {
	grants    []executions.ReadGrantView
	err       error
	revokeErr error
	revoked   []string

	preview    executions.ReadGrantPreview
	proposeErr error
	proposed   []executions.ReadGrantRequest
	commitErr  error
	committed  []string

	providerPreview  executions.ReadGrantPreview
	providerErr      error
	providerProposed []executions.ProviderReadGrantRequest
}

// ProposeProviderReadGrant records the request and returns the configured
// provider preview.
func (f *fakeLeases) ProposeProviderReadGrant(_ context.Context, _ string, in executions.ProviderReadGrantRequest) (executions.ReadGrantPreview, error) {
	f.providerProposed = append(f.providerProposed, in)
	return f.providerPreview, f.providerErr
}

// ReadGrants returns the configured grants.
func (f *fakeLeases) ReadGrants(context.Context) ([]executions.ReadGrantView, error) {
	return f.grants, f.err
}

// RevokeReadGrant records the id and returns the configured error.
func (f *fakeLeases) RevokeReadGrant(_ context.Context, _, id string) error {
	f.revoked = append(f.revoked, id)
	return f.revokeErr
}

// ProposeReadGrant records the request and returns the configured preview.
func (f *fakeLeases) ProposeReadGrant(_ context.Context, _ string, in executions.ReadGrantRequest) (executions.ReadGrantPreview, error) {
	f.proposed = append(f.proposed, in)
	return f.preview, f.proposeErr
}

// CommitReadGrant records the digest and assertion.
func (f *fakeLeases) CommitReadGrant(_ context.Context, _, digest string, assertion []byte) error {
	f.committed = append(f.committed, digest+" "+string(assertion))
	return f.commitErr
}

func leaseHandler(t *testing.T, f *fakeLeases) http.Handler {
	t.Helper()
	return newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Leases: f}).Handler()
}

func postLeaseForm(t *testing.T, h http.Handler, path, form string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestLeaseListRendersStateLabels(t *testing.T) {
	now := time.Now()
	f := &fakeLeases{grants: []executions.ReadGrantView{
		{ID: leaseID, State: "active", ScopeKind: "all", Hosts: []string{"web"}, Actions: []string{"core.facts"}, Expiry: now.Add(time.Hour), Digest: strings.Repeat("a", 64), ApprovedBy: "webauthn:abcd"},
		{ID: "11111111-2222-4333-8444-555555555555", State: "expired", ScopeKind: "tag", ScopeValue: "rack=a1", Hosts: []string{"web"}, Actions: []string{"core.facts"}, Expiry: now.Add(-time.Hour)},
		{ID: "22222222-2222-4333-8444-555555555555", State: "revoked", ScopeKind: "environment", ScopeValue: "prod", Hosts: []string{"web"}, Actions: []string{"core.facts"}, Revoked: now.Add(-time.Hour)},
		{ID: "33333333-2222-4333-8444-555555555555", State: "legacy", Legacy: true, ScopeKind: "hosts", Hosts: []string{"web"}, Actions: []string{"core.facts"}},
		{State: "invalid"},
	}}
	page := getBody(t, leaseHandler(t, f), "/leases")
	for _, want := range []string{
		`<span class="badge badge--ok">active</span>`,
		`<span class="badge badge--expired">expired</span>`,
		`<span class="badge badge--warning">revoked</span>`,
		`<span class="badge badge--unknown">legacy</span>`,
		`<span class="badge badge--critical">invalid</span>`,
		"tag: rack=a1",
		"environment: prod",
		">all<",
		"<td>hosts</td>",
		"/leases/" + leaseID,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("lease list misses %q", want)
		}
	}
}

func TestLeaseDetailShowsFullDocument(t *testing.T) {
	now := time.Now()
	f := &fakeLeases{grants: []executions.ReadGrantView{{
		ID: leaseID, State: "active", ScopeKind: "all",
		Hosts: []string{"web", "db"}, Actions: []string{"core.facts", "net.info"},
		ApprovedBy: "webauthn:abcd", Created: now.Add(-time.Hour),
		Expiry: now.Add(time.Hour), Digest: strings.Repeat("b", 64),
	}}}
	page := getBody(t, leaseHandler(t, f), "/leases/"+leaseID)
	for _, want := range []string{
		strings.Repeat("b", 64),
		"webauthn:abcd",
		"core.facts",
		"net.info",
		">web<",
		">db<",
		"2 hosts",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("lease detail misses %q", want)
		}
	}
}

func TestLeaseDetailLegacyNote(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{
		ID: leaseID, State: "legacy", Legacy: true, ScopeKind: "hosts",
		Hosts: []string{"web"}, Actions: []string{"core.facts"},
	}}}
	page := getBody(t, leaseHandler(t, f), "/leases/"+leaseID)
	if !strings.Contains(page, "legacy read-schedule-v1 - no on-demand read authority") {
		t.Error("legacy lease detail misses the legacy note")
	}
}

func TestLeaseDetailEscapesHostNames(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{
		ID: leaseID, State: "active", ScopeKind: "hosts",
		Hosts:   []string{`<script>alert(1)</script>`},
		Actions: []string{"core.facts"}, Expiry: time.Now().Add(time.Hour),
	}}}
	page := getBody(t, leaseHandler(t, f), "/leases/"+leaseID)
	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Error("unescaped host name rendered into the lease detail")
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped host name missing from the lease detail")
	}
}

func TestLeaseDetailHostsOpenAtMostTwenty(t *testing.T) {
	mk := func(n int) []string {
		hosts := make([]string, n)
		for i := range hosts {
			hosts[i] = "host-" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		}
		return hosts
	}
	for _, tc := range []struct {
		name  string
		hosts []string
		open  bool
	}{
		{"twenty", mk(20), true},
		{"twenty-one", mk(21), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLeases{grants: []executions.ReadGrantView{{
				ID: leaseID, State: "active", ScopeKind: "hosts",
				Hosts: tc.hosts, Actions: []string{"core.facts"},
				Expiry: time.Now().Add(time.Hour),
			}}}
			page := getBody(t, leaseHandler(t, f), "/leases/"+leaseID)
			openTag := "<details open>"
			if tc.open && !strings.Contains(page, openTag) {
				t.Error("host list should be open by default")
			}
			if !tc.open && strings.Contains(page, openTag) {
				t.Error("host list should be collapsed by default")
			}
			for _, h := range tc.hosts {
				if !strings.Contains(page, ">"+h+"<") {
					t.Errorf("host %q missing from the frozen host list", h)
				}
			}
		})
	}
}

func TestLeaseDetailUnknownIDIs404(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "active"}}}
	if code := statusOf(t, leaseHandler(t, f), "/leases/99999999-9999-4999-8999-999999999999"); code != http.StatusNotFound {
		t.Fatalf("unknown lease detail = %d, want 404", code)
	}
}

func TestLeaseRevokeActive(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "active", Expiry: time.Now().Add(time.Hour)}}}
	h := leaseHandler(t, f)
	code, _ := postLeaseForm(t, h, "/leases/revoke", "id="+leaseID)
	if code != http.StatusSeeOther {
		t.Fatalf("revoke of active lease = %d, want 303", code)
	}
	if len(f.revoked) != 1 || f.revoked[0] != leaseID {
		t.Fatalf("revoked = %v, want [%s]", f.revoked, leaseID)
	}
}

func TestLeaseRevokeNonRevocableRefused(t *testing.T) {
	for _, state := range []string{"expired", "revoked"} {
		t.Run(state, func(t *testing.T) {
			f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: state, Expiry: time.Now().Add(-time.Hour)}}}
			code, _ := postLeaseForm(t, leaseHandler(t, f), "/leases/revoke", "id="+leaseID)
			if code != http.StatusConflict {
				t.Fatalf("revoke of %s lease = %d, want 409", state, code)
			}
			if len(f.revoked) != 0 {
				t.Fatalf("%s lease must not be revoked", state)
			}
		})
	}
}

// TestLeaseRevokeInvalid checks that a grant the server cannot decode is
// still revocable by its id (it may be live on the executor).
func TestLeaseRevokeInvalid(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "invalid"}}}
	code, _ := postLeaseForm(t, leaseHandler(t, f), "/leases/revoke", "id="+leaseID)
	if code != http.StatusSeeOther {
		t.Fatalf("revoke of invalid lease = %d, want 303", code)
	}
	if len(f.revoked) != 1 || f.revoked[0] != leaseID {
		t.Fatalf("revoked = %v, want [%s]", f.revoked, leaseID)
	}
}

func TestLeaseRevokeLegacy(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "legacy", Legacy: true, ScopeKind: "hosts", Hosts: []string{"web"}}}}
	code, _ := postLeaseForm(t, leaseHandler(t, f), "/leases/revoke", "id="+leaseID)
	if code != http.StatusSeeOther {
		t.Fatalf("revoke of legacy lease = %d, want 303", code)
	}
	if len(f.revoked) != 1 || f.revoked[0] != leaseID {
		t.Fatalf("revoked = %v, want [%s]", f.revoked, leaseID)
	}
}

// TestLeaseDetailRevokeFormOnlyWhenRevocable checks that the detail page
// offers the fetch-submitted Revoke form for active and legacy grants and
// leaves it out for the other states.
func TestLeaseDetailRevokeFormOnlyWhenRevocable(t *testing.T) {
	const form = `<form method="post" action="/leases/revoke" data-fetch>`
	for _, tc := range []struct {
		state string
		want  bool
	}{
		{"active", true},
		{"legacy", true},
		{"expired", false},
		{"revoked", false},
		{"invalid", true},
	} {
		t.Run(tc.state, func(t *testing.T) {
			f := &fakeLeases{grants: []executions.ReadGrantView{{
				ID: leaseID, State: tc.state, Legacy: tc.state == "legacy",
				ScopeKind: "hosts", Hosts: []string{"web"}, Actions: []string{"core.facts"},
			}}}
			page := getBody(t, leaseHandler(t, f), "/leases/"+leaseID)
			if got := strings.Contains(page, form); got != tc.want {
				t.Errorf("%s lease detail has revoke form = %v, want %v", tc.state, got, tc.want)
			}
			if !strings.Contains(page, "/static/formpost.js") {
				t.Errorf("%s lease detail does not load formpost.js", tc.state)
			}
		})
	}
}

func TestLeaseRevokeInvalidIDIs400(t *testing.T) {
	for _, id := range []string{
		"",
		"not-a-uuid",
		"0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D", // uppercase
		"0a1b2c3d-4e5f-1a6b-8c7d-9e0f1a2b3c4d", // not version 4
		strings.Repeat("a", 4096),
	} {
		f := &fakeLeases{err: errors.New("must not be called")}
		code, _ := postLeaseForm(t, leaseHandler(t, f), "/leases/revoke", "id="+id)
		if code != http.StatusBadRequest {
			t.Errorf("revoke with id %.20q = %d, want 400", id, code)
		}
		if len(f.revoked) != 0 {
			t.Errorf("revoke with id %.20q reached the service", id)
		}
	}
}

func TestLeaseRevokeUnknownIDIs404(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "active", Expiry: time.Now().Add(time.Hour)}}}
	h := leaseHandler(t, f)
	code, _ := postLeaseForm(t, h, "/leases/revoke", "id=99999999-9999-4999-8999-999999999999")
	if code != http.StatusNotFound {
		t.Fatalf("revoke of unknown lease = %d, want 404", code)
	}
}

func TestLeaseRevokeErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{executions.ErrReadGrantNotFound, http.StatusNotFound},
		{executions.ErrReadGrantRevokeFailed, http.StatusBadGateway},
		{errors.New("unexpected"), http.StatusInternalServerError},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			f := &fakeLeases{
				grants:    []executions.ReadGrantView{{ID: leaseID, State: "active", Expiry: time.Now().Add(time.Hour)}},
				revokeErr: tc.err,
			}
			code, _ := postLeaseForm(t, leaseHandler(t, f), "/leases/revoke", "id="+leaseID)
			if code != tc.want {
				t.Fatalf("revoke with %v = %d, want %d", tc.err, code, tc.want)
			}
		})
	}
}

// TestLeaseRevokeWrongMethod verifies that a non-POST request to the
// revoke endpoint is refused. The mux restricts the route to POST and
// the catch-all answers 404 for the other methods, like the other
// state-changing routes in this app.
func TestLeaseRevokeWrongMethod(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "active"}}}
	h := leaseHandler(t, f)
	req := httptest.NewRequest(http.MethodPut, "/leases/revoke", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT /leases/revoke = %d, want 404", rec.Code)
	}
	if len(f.revoked) != 0 {
		t.Fatalf("revoked %v, want none", f.revoked)
	}
}

func TestLeasesDisabledIs404(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	for _, path := range []string{"/leases", "/leases/" + leaseID, "/leases/revoke"} {
		if code := statusOf(t, h, path); code != http.StatusNotFound {
			t.Fatalf("%s without leases = %d, want 404", path, code)
		}
	}
	if code, _ := postLeaseForm(t, h, "/leases/revoke", "id="+leaseID); code != http.StatusNotFound {
		t.Fatalf("POST /leases/revoke without leases = %d, want 404", code)
	}
}

// leaseServer serves the lease pages through the same security middleware
// chain the UI server uses (ui.Handler.Server): headers, origin check and
// body limit.
func leaseServer(t *testing.T, f *fakeLeases) *httptest.Server {
	t.Helper()
	u := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Leases: f})
	srv, err := u.Server()
	if err != nil {
		t.Fatalf("ui server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts
}

const leaseOrigin = "https://nebula.example.org"

func postThrough(t *testing.T, ts *httptest.Server, origin, form string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/leases/revoke", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /leases/revoke: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res
}

// TestLeaseRevokeThroughMiddleware posts the revoke through the real
// middleware chain. A plain browser form post under Referrer-Policy:
// no-referrer sends "Origin: null" and must be refused; the fetch post
// from formpost.js sends the real Origin and must pass.
func TestLeaseRevokeThroughMiddleware(t *testing.T) {
	grant := func() *fakeLeases {
		return &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "active", Expiry: time.Now().Add(time.Hour)}}}
	}
	for _, tc := range []struct {
		name, origin string
		want         int
	}{
		{"plain form post", "null", http.StatusForbidden},
		{"no origin", "", http.StatusForbidden},
		{"cross origin", "https://evil.example.org", http.StatusForbidden},
		{"fetch post", leaseOrigin, http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := grant()
			res := postThrough(t, leaseServer(t, f), tc.origin, "id="+leaseID)
			if res.StatusCode != tc.want {
				t.Fatalf("POST with Origin %q = %d, want %d", tc.origin, res.StatusCode, tc.want)
			}
			if got := res.Header.Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q, want no-referrer", got)
			}
			wantRevoked := 0
			if tc.want == http.StatusSeeOther {
				wantRevoked = 1
				if loc := res.Header.Get("Location"); loc != "/leases/"+leaseID {
					t.Errorf("redirect Location = %q, want /leases/%s", loc, leaseID)
				}
			}
			if len(f.revoked) != wantRevoked {
				t.Fatalf("revoked = %v, want %d revokes", f.revoked, wantRevoked)
			}
		})
	}
}

// TestLeaseRevokeBodyTooLargeIs413 sends a chunked body over the
// middleware body limit, so the declared-size check does not catch it
// and ParseForm hits the MaxBytesReader backstop.
func TestLeaseRevokeBodyTooLargeIs413(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "active"}}}
	ts := leaseServer(t, f)
	body := "id=" + leaseID + "&pad=" + strings.Repeat("a", int(middleware.DefaultMaxBodyBytes)+1)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/leases/revoke", io.MultiReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1 // chunked: only the MaxBytesReader can stop it
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", leaseOrigin)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /leases/revoke: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized revoke = %d, want 413", res.StatusCode)
	}
	if len(f.revoked) != 0 {
		t.Fatalf("oversized revoke reached the service: %v", f.revoked)
	}
}
