// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
)

// The list tells the three states apart: a store that cannot be read is
// unavailable, a store with no devices is empty, and a stored device the
// collector has not reported for a while is stale and still listed.
const (
	netdevUnavailableText = "Stored device inventory unavailable"
	netdevEmptyText       = "No network devices observed yet."
	netdevReportedBadge   = `<span class="badge badge--ok">reported by collector</span>`
	netdevStaleBadge      = `<span class="badge badge--warning">stale</span>`
)

// TestNetDevListMarksCollectorReportedRows: a row written from a collector
// report carries the reported marker; a row without one does not.
func TestNetDevListMarksCollectorReportedRows(t *testing.T) {
	e := newNetDevEnv(t)
	e.store.devices = []netdevinventory.Device{
		{DeviceID: "sw1", Family: netdevcontract.FamilyCBS, Label: "Core switch", TrustGeneration: 3,
			LastSeen: netdevNow.Add(-5 * time.Minute), State: netdevinventory.DeviceFresh,
			Origin: netdevinventory.OriginCollectorReported},
		{DeviceID: "fw1", Family: netdevcontract.FamilyPANOS, Label: "Edge firewall", TrustGeneration: 1,
			State: netdevinventory.DeviceFresh, Origin: netdevinventory.OriginUnreported},
	}
	code, body := e.get("/netdev")
	if code != 200 {
		t.Fatalf("GET /netdev = %d", code)
	}
	if n := strings.Count(body, netdevReportedBadge); n != 1 {
		t.Fatalf("reported marker shown %d times, want once (for the collector row only)", n)
	}
	if strings.Contains(body, netdevUnavailableText) || strings.Contains(body, netdevEmptyText) {
		t.Fatal("a populated list shows an unavailable or empty state")
	}
}

// TestNetDevStaleRowIsListedNotRemoved: a device the collector has not
// reported recently is still listed, with the stale badge and its link.
func TestNetDevStaleRowIsListedNotRemoved(t *testing.T) {
	e := newNetDevEnv(t)
	e.store.devices = []netdevinventory.Device{
		{DeviceID: "sw1", Family: netdevcontract.FamilyCBS, Label: "Core switch", TrustGeneration: 3,
			State: netdevinventory.DeviceStale, Origin: netdevinventory.OriginCollectorReported},
	}
	_, body := e.get("/netdev")
	if !strings.Contains(body, `href="/netdev/sw1"`) {
		t.Fatal("stale device is not listed")
	}
	if !strings.Contains(body, netdevStaleBadge) {
		t.Fatal("stale device has no stale badge")
	}
	if strings.Contains(body, netdevEmptyText) || strings.Contains(body, netdevUnavailableText) {
		t.Fatal("a listed stale device shows an empty or unavailable state")
	}
}

// TestNetDevEmptyAndUnavailableAreDistinct: an unreadable store is not an
// empty inventory (ND-04), and an empty inventory is not an error.
func TestNetDevEmptyAndUnavailableAreDistinct(t *testing.T) {
	e := newNetDevEnv(t)
	_, body := e.get("/netdev")
	if !strings.Contains(body, netdevEmptyText) {
		t.Fatal("empty store does not show the empty state")
	}
	if strings.Contains(body, netdevUnavailableText) {
		t.Fatal("empty store shows the unavailable state")
	}

	e.store.listErr = errors.New("store is closed")
	_, body = e.get("/netdev")
	if !strings.Contains(body, netdevUnavailableText) {
		t.Fatal("unreadable store does not show the unavailable state")
	}
	if strings.Contains(body, netdevEmptyText) {
		t.Fatal("unreadable store shows the empty state; it must not read as no devices")
	}
}

// netdevStrictCSP is the content security policy of docs/spec/09 that the
// security middleware sets on every response.
const netdevStrictCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// TestNetDevPagesSetCSPHeader: the list is served with the strict content
// security policy: exactly the policy of the middleware, so no unsafe-inline,
// no wildcard and default-src limited to 'self'.
func TestNetDevPagesSetCSPHeader(t *testing.T) {
	e := newNetDevEnv(t)
	res, _ := e.getAs(e.cookie, "/netdev")
	if res.StatusCode != 200 {
		t.Fatalf("GET /netdev = %d", res.StatusCode)
	}
	csp := res.Header.Get("Content-Security-Policy")
	if csp != netdevStrictCSP {
		t.Fatalf("Content-Security-Policy = %q, want %q", csp, netdevStrictCSP)
	}
	for _, weak := range []string{"unsafe-inline", "unsafe-eval", "'*'", " * ", "default-src *"} {
		if strings.Contains(csp, weak) {
			t.Fatalf("Content-Security-Policy allows %q", weak)
		}
	}
}
