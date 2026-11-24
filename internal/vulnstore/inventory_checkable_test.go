// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// TestCheckableFollowsBasisAndEcosystem pins the D4 rule that decides which
// findings NOS re-checks against its own inventory: only distro_tracker or
// osv_range matches on Debian, Ubuntu or Alpine.
func TestCheckableFollowsBasisAndEcosystem(t *testing.T) {
	tests := []struct {
		name  string
		basis vulnfinding.MatchBasis
		eco   string
		want  bool
	}{
		{"distro tracker on debian", vulnfinding.MatchDistroTracker, "debian:12", true},
		{"distro tracker on ubuntu", vulnfinding.MatchDistroTracker, "ubuntu:24.04", true},
		{"osv range on alpine", vulnfinding.MatchOSVRange, "alpine:3.20", true},
		{"osv range on debian", vulnfinding.MatchOSVRange, "debian:11", true},
		{"vendor advisory on debian", vulnfinding.MatchVendorAdvisory, "debian:12", false},
		{"cpe on debian", vulnfinding.MatchCPE, "debian:12", false},
		{"distro tracker on rhel", vulnfinding.MatchDistroTracker, "rhel:9", false},
		{"osv range on pypi", vulnfinding.MatchOSVRange, "PyPI", false},
		{"osv range without ecosystem", vulnfinding.MatchOSVRange, "", false},
		{"empty basis on debian", "", "debian:12", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := vulnfinding.Record{MatchBasis: tt.basis, Ecosystem: tt.eco}
			if got := Checkable(r); got != tt.want {
				t.Fatalf("Checkable(basis=%q, ecosystem=%q) = %v, want %v", tt.basis, tt.eco, got, tt.want)
			}
		})
	}
}

// TestInventoryCloseHoldsMalformedFixedVersion: a finding whose episode fixed
// version does not parse closes nothing by inventory, even when a complete
// read no longer names its package (path 2, fail closed). The control is the
// same finding on another host with a well-formed fixed version, which closes.
func TestInventoryCloseHoldsMalformedFixedVersion(t *testing.T) {
	e := newEnv(t)
	bad := item(t, "web01", cve(1), withPackage("zlib"))
	good := item(t, "web02", cve(2), withPackage("zlib"))
	r := e.start(t)
	e.submit(t, r, 0, nil, bad, good)
	e.complete(t, r)
	// The submit path rejects a malformed fixed version, so the stored episode
	// is corrupted directly to reach the guard in CloseByInventory.
	if _, err := e.st.db.ExecContext(e.ctx, `UPDATE vuln_findings SET episode_fixed_version = ? WHERE subject = ?`,
		"x:1.0-2", hostSubj("web01").String()); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(time.Minute)
	read := func(host string) InventoryRead {
		return InventoryRead{Subject: hostSubj(host), Complete: true, ReadAt: e.clk.Now(),
			Ecosystem: "ubuntu:24.04", SourceVersions: map[string]string{"bash": "5.0-1"}}
	}
	if k, err := e.st.CloseByInventory(e.ctx, read("web01")); err != nil || len(k) != 0 {
		t.Fatalf("malformed fixed version closed %d (%v), want none", len(k), err)
	}
	e.wantState(t, bad.Finding.Key, StateOpen, "")
	if k, err := e.st.CloseByInventory(e.ctx, read("web02")); err != nil || len(k) != 1 {
		t.Fatalf("control closed %d (%v), want one", len(k), err)
	}
	e.wantState(t, good.Finding.Key, StateFixed, ClosedByNOSInventory)
}
