// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// image.packages (ADR 0011 D3, VU-06) runs under a read lease; nothing
// that merely shares its prefix is admitted.
func TestImagePackagesInReadOnlyAllowlist(t *testing.T) {
	if !InReadOnlyAllowlist("image.packages") {
		t.Fatal("image.packages is not in the read-only allowlist")
	}
	for _, id := range []string{"image.packages.x", "image.package", "image.packages ", "Image.packages", "image.pull", "image.scan"} {
		if InReadOnlyAllowlist(id) {
			t.Errorf("%q is in the read-only allowlist", id)
		}
	}
	if schedgrant.IsTelemetryAction("image.packages") {
		t.Fatal("image.packages must not ride the telemetry rate profile")
	}
	// The allowlist entry does not admit the CVE observation: that read
	// is not part of this change.
	if InReadOnlyAllowlist("image.vulnerabilities") {
		t.Fatal("image.vulnerabilities was admitted along with image.packages")
	}
}

// ADR 0011 gives image.packages no per-host floor of its own: it is pinned
// to one image digest per grant entry, so the grant's interval applies.
func TestImagePackagesHasNoOwnMinInterval(t *testing.T) {
	if got := ReadActionMinInterval("image.packages"); got != 0 {
		t.Fatalf("image.packages floor %s, want 0", got)
	}
}

// A read grant that names image.packages with a pinned digest parameter
// parses under the ordinary profile and is refused under the telemetry one.
func TestReadGrantAcceptsImagePackages(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	ph, err := canonical.HashParameters([]byte(`{"image":"nginx@sha256:` + strings.Repeat("a", 64) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	d := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	d.Actions = append(d.Actions, ReadGrantAction{ActionID: "image.packages", ModuleVersion: "1.0.0",
		ArtifactSHA256: hexSum(artifact), ParametersHash: ph})
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
		t.Fatalf("image.packages grant refused: %v", err)
	}
	d.RateProfile = schedgrant.TelemetryReadProfile
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
		t.Fatal("image.packages accepted under the telemetry profile")
	}
}

// A lease run of image.packages is authorized like any allowlisted read,
// and the grant's own interval still applies per host.
func TestImagePackagesLeaseRun(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID, e.clk.Now(), DefaultReadGrantLifetime, 24, []string{"image.packages"})))
	run := readRun("dockerflux", fpA)
	run.ActionID = "image.packages"
	if _, err := e.auth.AuthorizeReadRun(g.ID, "p1", TriggerOnDemand, run); err != nil {
		t.Fatalf("image.packages run refused: %v", err)
	}
	_, err := e.auth.AuthorizeReadRun(g.ID, "p2", TriggerOnDemand, run)
	wantCode(t, err, CodeLeaseBudget)
	if n := len(le.hostRes["dockerflux"]); n != 1 {
		t.Fatalf("%d reservations, want 1", n)
	}
}
