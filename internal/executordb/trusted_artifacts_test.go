// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

func builtinRow(sum, action, version string, r canonical.Risk) TrustedArtifact {
	return TrustedArtifact{SHA256: sum, ActionID: action, ModuleVersion: version, Risk: r,
		Label: "built-in release 2026.11.0", TrustedBy: "admin:uid1000"}
}

// Committed built-in trust is the same exact (sha256, action, version)
// trust that `nebula artifact trust` writes: ArtifactRisk answers it at the
// declared risk, and nothing else (other bytes, versions or actions) is
// trusted by it.
func TestApplyBuiltinTrustIsExactArtifactTrust(t *testing.T) {
	db := openT(t, privateDir(t))
	change := BuiltinTrustChange{Trust: []TrustedArtifact{builtinRow(sumA, "docker.restart", "1.0.0", canonical.RiskLow)}}
	if err := db.CheckBuiltinTrust(change); err != nil {
		t.Fatal(err)
	}
	revoked, err := db.ApplyBuiltinTrust(change)
	if err != nil || len(revoked) != 0 {
		t.Fatalf("apply = %v, %v", revoked, err)
	}
	got, ok, err := db.ArtifactRisk(sumA, "docker.restart", "1.0.0")
	if err != nil || !ok || got != canonical.RiskLow {
		t.Fatalf("ArtifactRisk = %v %v %v; want LOW trusted", got, ok, err)
	}
	for _, c := range [][3]string{
		{sumB, "docker.restart", "1.0.0"},
		{sumA, "docker.restart", "1.0.1"},
		{sumA, "docker.stop", "1.0.0"},
	} {
		if _, ok, err := db.ArtifactRisk(c[0], c[1], c[2]); ok || err != nil {
			t.Errorf("%v: trusted=%v err=%v; built-in trust must be exact", c, ok, err)
		}
	}
	// The same row through the individual path gives the same answer.
	db2 := openT(t, privateDir(t))
	if err := db2.TrustArtifact(builtinRow(sumA, "docker.restart", "1.0.0", canonical.RiskLow)); err != nil {
		t.Fatal(err)
	}
	got2, ok2, err := db2.ArtifactRisk(sumA, "docker.restart", "1.0.0")
	if err != nil || ok2 != ok || got2 != got {
		t.Fatalf("individual trust %v %v %v differs from built-in %v %v", got2, ok2, err, got, ok)
	}
}

// Retiring a built-in version revokes every trust entry of that module
// family and version, whoever wrote it, and reports the revoked tuples;
// other families, other versions and a family that merely shares a prefix
// keep their trust. Retirement and new trust are one transaction.
func TestApplyBuiltinTrustRetiresVersion(t *testing.T) {
	db := openT(t, privateDir(t))
	for _, a := range []TrustedArtifact{
		builtinRow(sumA, "docker.restart", "1.0.0", canonical.RiskLow),
		builtinRow(sumB, "docker.stop", "1.0.0", canonical.RiskMedium),
		builtinRow(sumA, "docker.restart", "0.9.0", canonical.RiskLow),
		builtinRow(sumB, "docker-compose.up", "1.0.0", canonical.RiskMedium),
		builtinRow(sumB, "service.restart", "1.0.0", canonical.RiskMedium),
	} {
		if err := db.TrustArtifact(a); err != nil {
			t.Fatal(err)
		}
	}
	sumC := strings.Repeat("c", 64)
	change := BuiltinTrustChange{
		Trust:  []TrustedArtifact{builtinRow(sumC, "docker.restart", "1.1.0", canonical.RiskLow)},
		Retire: []BuiltinVersion{{Module: "docker", Version: "1.0.0"}},
	}
	revoked, err := db.ApplyBuiltinTrust(change)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 || revoked[0].ActionID != "docker.restart" || revoked[1].ActionID != "docker.stop" ||
		revoked[0].SHA256 != sumA || revoked[0].ModuleVersion != "1.0.0" || revoked[0].Risk != canonical.RiskLow {
		t.Fatalf("revoked = %+v", revoked)
	}
	for _, c := range []struct {
		sum, action, version string
		want                 bool
	}{
		{sumA, "docker.restart", "1.0.0", false},
		{sumB, "docker.stop", "1.0.0", false},
		{sumA, "docker.restart", "0.9.0", true},
		{sumB, "docker-compose.up", "1.0.0", true},
		{sumB, "service.restart", "1.0.0", true},
		{sumC, "docker.restart", "1.1.0", true},
	} {
		if _, ok, err := db.ArtifactRisk(c.sum, c.action, c.version); err != nil || ok != c.want {
			t.Errorf("%s@%s: trusted=%v err=%v, want %v", c.action, c.version, ok, err, c.want)
		}
	}
}

// A retired version that is also the committed new version (its exact
// bytes were missing and reviewed in full again) ends up trusted: the
// retirement runs before the new trust in the same transaction.
func TestApplyBuiltinTrustRetireThenTrustSameVersion(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.TrustArtifact(builtinRow(sumA, "docker.restart", "1.0.0", canonical.RiskLow)); err != nil {
		t.Fatal(err)
	}
	_, err := db.ApplyBuiltinTrust(BuiltinTrustChange{
		Trust:  []TrustedArtifact{builtinRow(sumA, "docker.restart", "1.0.0", canonical.RiskLow)},
		Retire: []BuiltinVersion{{Module: "docker", Version: "1.0.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.ArtifactRisk(sumA, "docker.restart", "1.0.0"); err != nil || !ok {
		t.Fatalf("trusted=%v err=%v; want trusted", ok, err)
	}
}

// Malformed tuples are rejected before anything is written: one bad entry
// leaves the table unchanged, retirements included.
func TestApplyBuiltinTrustRejectsMalformedAtomically(t *testing.T) {
	good := builtinRow(sumA, "docker.restart", "1.1.0", canonical.RiskLow)
	cases := map[string]BuiltinTrustChange{
		"sha256":        {Trust: []TrustedArtifact{good, builtinRow("ABC", "docker.restart", "1.1.0", canonical.RiskLow)}},
		"action":        {Trust: []TrustedArtifact{good, builtinRow(sumB, "Docker restart", "1.1.0", canonical.RiskLow)}},
		"version":       {Trust: []TrustedArtifact{good, builtinRow(sumB, "docker.stop", "v1", canonical.RiskLow)}},
		"risk":          {Trust: []TrustedArtifact{good, builtinRow(sumB, "docker.stop", "1.1.0", "low")}},
		"label":         {Trust: []TrustedArtifact{good, {SHA256: sumB, ActionID: "docker.stop", ModuleVersion: "1.1.0", Risk: canonical.RiskLow, Label: "x\u202ey", TrustedBy: "admin:uid1"}}},
		"actor":         {Trust: []TrustedArtifact{good, {SHA256: sumB, ActionID: "docker.stop", ModuleVersion: "1.1.0", Risk: canonical.RiskLow}}},
		"retire module": {Trust: []TrustedArtifact{good}, Retire: []BuiltinVersion{{Module: "docker.x", Version: "1.0.0"}}},
		"retire empty":  {Trust: []TrustedArtifact{good}, Retire: []BuiltinVersion{{Module: "", Version: "1.0.0"}}},
		"retire ver":    {Trust: []TrustedArtifact{good}, Retire: []BuiltinVersion{{Module: "docker", Version: "1.0"}}},
		"too many":      {Trust: make([]TrustedArtifact, MaxBuiltinTrustEntries+1)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			db := openT(t, privateDir(t))
			if err := db.TrustArtifact(builtinRow(sumB, "docker.restart", "1.0.0", canonical.RiskLow)); err != nil {
				t.Fatal(err)
			}
			if err := db.CheckBuiltinTrust(c); !errors.Is(err, ErrInvalid) {
				t.Fatalf("check err = %v, want ErrInvalid", err)
			}
			if _, err := db.ApplyBuiltinTrust(c); !errors.Is(err, ErrInvalid) {
				t.Fatalf("apply err = %v, want ErrInvalid", err)
			}
			list, err := db.ListTrustedArtifacts()
			if err != nil || len(list) != 1 || list[0].ModuleVersion != "1.0.0" {
				t.Fatalf("table changed: %+v %v", list, err)
			}
		})
	}
}

// BuiltinTrustRows lists exactly the entries a retirement would revoke and
// writes nothing; a malformed version is rejected.
func TestBuiltinTrustRowsListsWithoutWriting(t *testing.T) {
	db := openT(t, privateDir(t))
	if _, err := db.ApplyBuiltinTrust(BuiltinTrustChange{Trust: []TrustedArtifact{
		builtinRow(sumA, "docker.restart", "1.0.0", canonical.RiskLow),
		builtinRow(sumB, "docker.stop", "1.1.0", canonical.RiskLow),
		builtinRow(sumA, "dockerx.restart", "1.0.0", canonical.RiskLow),
	}}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.BuiltinTrustRows([]BuiltinVersion{{Module: "docker", Version: "1.0.0"}})
	if err != nil || len(rows) != 1 || rows[0].ActionID != "docker.restart" || rows[0].SHA256 != sumA {
		t.Fatalf("rows = %+v, %v", rows, err)
	}
	if list, err := db.ListTrustedArtifacts(); err != nil || len(list) != 3 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if _, err := db.BuiltinTrustRows([]BuiltinVersion{{Module: "Docker!", Version: "1.0.0"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed version err = %v", err)
	}
}
