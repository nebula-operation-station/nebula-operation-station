// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"strings"
	"testing"
)

// TestStoredFindingShapesAreAccepted pins real finding shapes that the stored
// finding schema (internal/vulnfinding) accepts: Go modules with '/', scoped
// npm packages with '@', IDs with ':', distro versions with '~' and npm
// prereleases with '+'. Each must enter a group: a rejected shape would fail
// closed for the whole fleet before this was fixed.
func TestStoredFindingShapesAreAccepted(t *testing.T) {
	tests := []struct {
		name      string
		vulnID    string
		pkg       string
		installed string
		fixed     string
	}{
		{"go module", "GO-2024-3333", "github.com/prometheus/client_golang", "v1.19.0", "v1.20.0"},
		{"go pseudo version", "GO-2025-0001", "golang.org/x/net", "v0.0.0-20240101000000-abcdef123456", "v0.23.0"},
		{"npm scoped", "GHSA-7x5f-q6vh-xq6c", "@angular/core", "17.0.0-rc.1+sha.1", "17.0.1"},
		{"npm unscoped", "GHSA-abcd-efgh-ijkl", "lodash", "4.17.20", "4.17.21"},
		{"maven group:artifact", "CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.15.0"},
		{"debian tilde version", "DSA-5428-1", "openssl", "3.0.11-1~deb12u2", "3.0.13-1~deb12u1"},
		{"id with colon", "RHSA:2024:1234", "kernel", "5.14.0-1", "5.14.0-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := osFinding(tt.vulnID, TierHigh, 80)
			f.Package = tt.pkg
			f.Installed = tt.installed
			f.Fixed = tt.fixed
			p, audit := newProjectorWith(t, Sources{
				Inventory: fakeInventory{hosts: []Host{webHost()}},
				Listeners: fakeListeners{},
				Findings:  fakeFindings{fs: []Finding{f}},
				Catalog:   fullCatalog(),
			})
			g := oneGroup(t, p)
			if got := g.Projection.Findings[0]; got.Package != tt.pkg || got.VulnID != tt.vulnID || got.Installed != tt.installed {
				t.Fatalf("listed finding = %+v, want the stored values unchanged", got)
			}
			if len(audit.skips) != 0 {
				t.Fatalf("audit = %+v, want no skip", audit.skips)
			}
		})
	}
}

// TestSchemaLengthLimits checks the bounds of each field at the schema limit
// and one byte over it: the limit is accepted, one more byte is skipped.
func TestSchemaLengthLimits(t *testing.T) {
	tests := []struct {
		name      string
		vulnID    string
		pkg       string
		installed string
		ok        bool
	}{
		{"package at limit", "CVE-2026-0001", "a" + strings.Repeat("b", MaxPackageBytes-1), "1.0", true},
		{"package over limit", "CVE-2026-0001", "a" + strings.Repeat("b", MaxPackageBytes), "1.0", false},
		{"version at limit", "CVE-2026-0001", "openssl", "1" + strings.Repeat("0", MaxVersionBytes-1), true},
		{"version over limit", "CVE-2026-0001", "openssl", "1" + strings.Repeat("0", MaxVersionBytes), false},
		{"vuln id at limit", "C" + strings.Repeat("V", MaxVulnIDBytes-1), "openssl", "1.0", true},
		{"vuln id over limit", "C" + strings.Repeat("V", MaxVulnIDBytes), "openssl", "1.0", false},
		{"vuln id one byte", "X", "openssl", "1.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := osFinding(tt.vulnID, TierHigh, 80)
			f.Package = tt.pkg
			f.Installed = tt.installed
			p, audit := newProjectorWith(t, Sources{
				Inventory: fakeInventory{hosts: []Host{webHost()}},
				Listeners: fakeListeners{},
				Findings:  fakeFindings{fs: []Finding{f}},
				Catalog:   fullCatalog(),
			})
			gs, err := p.EligibleGroups(t.Context())
			if err != nil {
				t.Fatalf("EligibleGroups: %v", err)
			}
			if tt.ok != (len(gs) == 1) || tt.ok != (len(audit.skips) == 0) {
				t.Fatalf("accepted = %v (groups %d, skips %d), want accepted %v", len(gs) == 1, len(gs), len(audit.skips), tt.ok)
			}
		})
	}
}
