// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

func TestInventoryRefreshCreatesOneOperationPerReadForPinnedHosts(t *testing.T) {
	f := &fakeOps{}
	inv := newFakeInventory()
	for _, id := range []string{"web", "db", "new"} {
		inv.hosts[id] = inventory.Host{ID: id}
	}
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Operations:   f,
		Inventory:    inv,
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:x"}, {HostId: "db", Fingerprint: "SHA256:y"}}, nil
		},
	}).Handler()
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/inventory/refresh", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := post("host=web&host=db&host=new&host=web")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/operations" {
		t.Fatalf("refresh: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	want := []string{"core.facts", "package.list_updates", "docker.list", "service.list"}
	if len(f.createdCalls) != len(want) {
		t.Fatalf("calls: %v", f.createdCalls)
	}
	for i, a := range want {
		// One operation per read, for the pinned hosts only (new is not
		// enrolled, the duplicate web counts once).
		if c := f.createdCalls[i]; c[1] != a || strings.Join(c[2:], ",") != "web,db" {
			t.Fatalf("call %d: %v", i, c)
		}
	}

	for name, body := range map[string]string{
		"empty selection":   "",
		"invalid host ID":   "host=..%2Fx",
		"unknown host":      "host=web&host=ghost",
		"none enrolled":     "host=new",
		"too many selected": strings.Repeat("host=web&", 201),
	} {
		f.createdCalls = nil
		if rec := post(body); rec.Code != http.StatusBadRequest || len(f.createdCalls) != 0 {
			t.Errorf("%s: %d, %d operations", name, rec.Code, len(f.createdCalls))
		}
	}

	// GET is not a refresh.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inventory/refresh", nil))
	if rec.Code == http.StatusSeeOther || len(f.createdCalls) != 0 {
		t.Fatalf("GET: %d", rec.Code)
	}
}
