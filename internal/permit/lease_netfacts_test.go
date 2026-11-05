// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// net.facts is the read-only snapshot of ADR 0009 D1 and runs under a
// read lease; nothing that merely shares its prefix is admitted.
func TestNetFactsInReadOnlyAllowlist(t *testing.T) {
	if !InReadOnlyAllowlist("net.facts") {
		t.Fatal("net.facts is not in the read-only allowlist")
	}
	for _, id := range []string{"net.facts.p", "net.fact", "Net.facts", "net.facts ", "net.sockets", "net.conntrack"} {
		if InReadOnlyAllowlist(id) {
			t.Errorf("%q is in the read-only allowlist", id)
		}
	}
}

// A read grant that names net.facts parses; one that names an unlisted
// net.* action is still refused.
func TestReadGrantAcceptsNetFacts(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	ph, err := canonical.HashParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	d := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	d.Actions = append(d.Actions, ReadGrantAction{ActionID: "net.facts", ModuleVersion: "1.0.0",
		ArtifactSHA256: hexSum(artifact), ParametersHash: ph})
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
		t.Fatalf("net.facts grant refused: %v", err)
	}
	d = readGrantDocAt(t, now, DefaultReadGrantLifetime)
	d.Actions = append(d.Actions, ReadGrantAction{ActionID: "net.sockets", ModuleVersion: "1.0.0",
		ArtifactSHA256: hexSum(artifact), ParametersHash: ph})
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
		t.Fatal("net.sockets grant accepted")
	}
}
