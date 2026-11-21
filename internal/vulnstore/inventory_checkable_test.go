// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"testing"

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
