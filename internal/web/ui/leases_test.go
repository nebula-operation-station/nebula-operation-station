// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const leaseID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"

// fakeLeases is a fake read-grant store for the lease pages.
type fakeLeases struct {
	grants    []executions.ReadGrantView
	err       error
	revokeErr error
	revoked   []string
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
		"hosts",
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

func TestLeaseRevokeExpiredRefused(t *testing.T) {
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "expired", Expiry: time.Now().Add(-time.Hour)}}}
	h := leaseHandler(t, f)
	code, _ := postLeaseForm(t, h, "/leases/revoke", "id="+leaseID)
	if code != http.StatusConflict {
		t.Fatalf("revoke of expired lease = %d, want 409", code)
	}
	if len(f.revoked) != 0 {
		t.Fatal("expired lease must not be revoked")
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
}
