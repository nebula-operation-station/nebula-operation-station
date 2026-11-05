// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// pveLeaseHandler serves the PVE pages with remote-a (active), remote-b
// (blocked) and remote-c (active) stored, and f as the lease source (nil:
// no leases configured).
func pveLeaseHandler(t *testing.T, f *fakeLeases) http.Handler {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := pveinventory.New(db)
	metas := providerMetas()
	for _, m := range metas {
		seedRemote(t, store, pvecontract.Remote{
			RemoteID: m.RemoteID, Name: m.RemoteID, Kind: pvecontract.Kind(m.Kind),
			Endpoints: []pvecontract.Endpoint{{Host: m.RemoteID + ".lab", Port: 8006}},
			TrustPin:  m.TrustPin, TrustGeneration: m.TrustGeneration,
		})
	}
	o := ui.Options{
		PublicOrigin: pveOrigin,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		PVE:          store,
		PVERemotes:   func(context.Context) ([]ui.PVERemoteMeta, error) { return metas, nil },
	}
	if f != nil {
		o.Leases = f
	}
	u, err := ui.New(o)
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	return u.Handler()
}

const pveLeaseLink = `href="/leases/new?remote=remote-a&amp;scope=provider"`

func TestPVEDetailOffersReadLeaseWithoutActiveProviderLease(t *testing.T) {
	other := providerGrant("active")
	other.Remotes = []string{"remote-c"}
	other.Providers = other.Providers[1:]
	hostLease := executions.ReadGrantView{ID: leaseID, State: "active", ScopeKind: "all", Hosts: []string{"remote-a"}, Actions: []string{"core.facts"}}
	for _, tc := range []struct {
		name   string
		grants []executions.ReadGrantView
	}{
		{"no leases", nil},
		{"lease for another remote", []executions.ReadGrantView{other}},
		{"expired lease", []executions.ReadGrantView{providerGrant("expired")}},
		{"revoked lease", []executions.ReadGrantView{providerGrant("revoked")}},
		{"host lease only", []executions.ReadGrantView{hostLease}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLeases{grants: tc.grants}
			h := pveLeaseHandler(t, f)
			page := getBody(t, h, "/pve/remote-a")
			if !strings.Contains(page, pveLeaseLink) || !strings.Contains(page, ">Request read lease</a>") {
				t.Errorf("page misses the Request read lease link")
			}
			if !strings.Contains(page, "no approved read lease") {
				t.Error("page misses the reason it has no data")
			}
			// The link only opens the form; nothing is proposed.
			form := getBody(t, h, "/leases/new?remote=remote-a&scope=provider")
			if !strings.Contains(form, `name="scope" value="provider" checked`) || !strings.Contains(form, `<option value="remote-a" selected>`) {
				t.Error("form is not pre-filled with the remote")
			}
			if len(f.providerProposed) != 0 || len(f.proposed) != 0 || len(f.committed) != 0 {
				t.Error("viewing the pages proposed or approved a lease")
			}
		})
	}
}

func TestPVEDetailHidesReadLeaseRequest(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		leases     *fakeLeases
	}{
		{"active provider lease", "/pve/remote-a", &fakeLeases{grants: []executions.ReadGrantView{providerGrant("active")}}},
		{"blocked remote", "/pve/remote-b", &fakeLeases{}},
		{"no lease service", "/pve/remote-a", nil},
		{"leases unavailable", "/pve/remote-a", &fakeLeases{err: errors.New("executor down")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := getBody(t, pveLeaseHandler(t, tc.leases), tc.path)
			if strings.Contains(page, "Request read lease") || strings.Contains(page, "/leases/new") {
				t.Error("page offers Request read lease")
			}
			if strings.Contains(page, "no approved read lease") {
				t.Error("page claims no approved read lease")
			}
		})
	}
}

func TestPVEDetailReadLeaseLinkNeedsGet(t *testing.T) {
	h := pveLeaseHandler(t, &fakeLeases{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/pve/remote-a", nil))
	if rec.Code == http.StatusOK {
		t.Errorf("POST /pve/remote-a = %d", rec.Code)
	}
}
