// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"fmt"
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
	ep := []inventory.Endpoint{{Address: "192.0.2.1", Port: 22}}
	for _, id := range []string{"web", "db", "new", "moved"} {
		inv.hosts[id] = inventory.Host{ID: id, Endpoints: ep}
	}
	inv.hosts["noaddr"] = inventory.Host{ID: "noaddr"}
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Operations:   f,
		Inventory:    inv,
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:x"}, {HostId: "db", Fingerprint: "SHA256:y"},
				{HostId: "moved", Fingerprint: "SHA256:z", Blocked: true}, {HostId: "noaddr", Fingerprint: "SHA256:w"}}, nil
		},
	}).Handler()
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/inventory/refresh", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := post("host=web&host=db&host=new&host=moved&host=noaddr&host=web")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/operations" {
		t.Fatalf("refresh: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	want := []string{"core.facts", "package.list_updates", "docker.list", "service.list"}
	if len(f.createdCalls) != len(want) {
		t.Fatalf("calls: %v", f.createdCalls)
	}
	for i, a := range want {
		// One operation per read, for the hosts an operation can run on
		// only (new is not enrolled, moved is blocked, noaddr has no
		// endpoint; the duplicate web counts once).
		if c := f.createdCalls[i]; c[1] != a || strings.Join(c[2:], ",") != "web,db" {
			t.Fatalf("call %d: %v", i, c)
		}
	}

	for name, body := range map[string]string{
		"empty selection":   "",
		"invalid host ID":   "host=..%2Fx",
		"unknown host":      "host=web&host=ghost",
		"none usable":       "host=new&host=moved&host=noaddr",
		"too many selected": strings.Repeat("host=web&", 201),
	} {
		f.createdCalls = nil
		if rec := post(body); rec.Code != http.StatusBadRequest || len(f.createdCalls) != 0 {
			t.Errorf("%s: %d, %d operations", name, rec.Code, len(f.createdCalls))
		}
	}

	// More hosts than one operation takes: split into operations of at
	// most 100 hosts, each with all four reads.
	var pins []*pb.HostKeyPin
	var body []string
	for i := range 150 {
		id := fmt.Sprintf("h%03d", i)
		inv.hosts[id] = inventory.Host{ID: id, Endpoints: ep}
		pins = append(pins, &pb.HostKeyPin{HostId: id, Fingerprint: "SHA256:" + id})
		body = append(body, "host="+id)
	}
	big := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org", Operations: f, Inventory: inv,
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) { return pins, nil },
	}).Handler()
	f.createdCalls = nil
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/inventory/refresh", strings.NewReader(strings.Join(body, "&")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	big.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || len(f.createdCalls) != 8 {
		t.Fatalf("150 hosts: %d, %d operations", rec.Code, len(f.createdCalls))
	}
	if n0, n4 := len(f.createdCalls[0])-2, len(f.createdCalls[4])-2; n0 != 100 || n4 != 50 {
		t.Fatalf("150 hosts: chunks of %d and %d", n0, n4)
	}
	f.createdCalls = nil

	// GET is not a refresh.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inventory/refresh", nil))
	if rec.Code == http.StatusSeeOther || len(f.createdCalls) != 0 {
		t.Fatalf("GET: %d", rec.Code)
	}
}
