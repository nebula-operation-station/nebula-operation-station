// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

func getInventoryBody(t *testing.T, h *ui.Handler) string {
	t.Helper()
	req := httptest.NewRequest("GET", "https://nebula.example.org/inventory", nil)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET /inventory status = %d", rec.Code)
	}
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func sortTestHost(id, name, addr string) inventory.Host {
	return inventory.Host{
		ID:          id,
		DisplayName: name,
		Endpoints:   []inventory.Endpoint{{Address: addr, Port: 22}},
	}
}

// TestInventoryDefaultOrderIsNaturalIPAware checks that the table is
// rendered in natural IP-aware order no matter which order the store
// returns the hosts in: 192.168.0.25 before 192.168.0.221, 10.0.0.9
// before 10.0.0.10, IPv4 before IPv6, IPs before hostnames, node2
// before node10.
func TestInventoryDefaultOrderIsNaturalIPAware(t *testing.T) {
	// The store returns plain string order, which is wrong for IPs.
	hosts := []inventory.Host{
		sortTestHost("h-221", "192.168.0.221", "192.168.0.221"),
		sortTestHost("h-25", "192.168.0.25", "192.168.0.25"),
		sortTestHost("h-10", "10.0.0.10", "10.0.0.10"),
		sortTestHost("h-9", "10.0.0.9", "10.0.0.9"),
		sortTestHost("h-node10", "node10", "10.1.1.10"),
		sortTestHost("h-node2", "node2", "10.1.1.2"),
		sortTestHost("h-v6", "2001:db8::1", "2001:db8::1"),
	}
	h, err := ui.New(ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Hosts:        func(context.Context) ([]inventory.Host, error) { return hosts, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := getInventoryBody(t, h)
	// Rendered row order, by data-id.
	wantOrder := []string{"h-9", "h-10", "h-25", "h-221", "h-v6", "h-node2", "h-node10"}
	prevIdx, prevID := -1, ""
	for _, id := range wantOrder {
		idx := strings.Index(body, `data-id="`+id+`"`)
		if idx < 0 {
			t.Fatalf("row %q not rendered", id)
		}
		if idx <= prevIdx {
			t.Fatalf("row %q rendered out of order (after %s)", id, prevID)
		}
		prevIdx, prevID = idx, id
	}
}

// TestInventoryDefaultOrderTiebreaksOnPrimaryAddress checks that two
// rows with the same shown name are ordered by their primary endpoint
// address, numerically.
func TestInventoryDefaultOrderTiebreaksOnPrimaryAddress(t *testing.T) {
	hosts := []inventory.Host{
		sortTestHost("h-b", "web", "10.0.0.10"),
		sortTestHost("h-a", "web", "10.0.0.9"),
	}
	h, err := ui.New(ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Hosts:        func(context.Context) ([]inventory.Host, error) { return hosts, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := getInventoryBody(t, h)
	if i9, i10 := strings.Index(body, `data-id="h-a"`), strings.Index(body, `data-id="h-b"`); i9 < 0 || i10 < 0 || i9 > i10 {
		t.Fatalf("same-name rows not ordered by primary address (h-a=%d h-b=%d)", i9, i10)
	}
}

// TestInventoryDefaultOrderFallsBackToID checks that a host without a
// display name is ordered by its ID.
func TestInventoryDefaultOrderFallsBackToID(t *testing.T) {
	hosts := []inventory.Host{
		sortTestHost("zeta", "", "10.0.0.2"),
		sortTestHost("alpha", "", "10.0.0.1"),
	}
	h, err := ui.New(ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Hosts:        func(context.Context) ([]inventory.Host, error) { return hosts, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := getInventoryBody(t, h)
	if ia, iz := strings.Index(body, `data-id="alpha"`), strings.Index(body, `data-id="zeta"`); ia < 0 || iz < 0 || ia > iz {
		t.Fatalf("ID-ordered rows out of order (alpha=%d zeta=%d)", ia, iz)
	}
}
