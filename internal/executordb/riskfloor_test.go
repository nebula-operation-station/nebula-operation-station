// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
)

var _ riskpolicy.Source = (*DB)(nil)

var (
	sumA = strings.Repeat("a", 64)
	sumB = strings.Repeat("b", 64)
	fpA  = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB  = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	fpC  = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func trusted(sum, action, version string, r canonical.Risk) TrustedArtifact {
	return TrustedArtifact{SHA256: sum, ActionID: action, ModuleVersion: version, Risk: r, Label: "test", TrustedBy: "admin:uid1000"}
}

func TestTrustedArtifactsAreDurableAndExact(t *testing.T) {
	dir := privateDir(t)
	db := openAtT(t, dir, t0)
	if err := db.TrustArtifact(trusted(sumA, "patching.install_security", "1.0.0", canonical.RiskMedium)); err != nil {
		t.Fatal(err)
	}
	// Same bytes, another action: a separate entry.
	if err := db.TrustArtifact(trusted(sumA, "patching.install_all", "1.0.0", canonical.RiskHigh)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db = openT(t, dir)

	// The same bytes are also trusted as HIGH under another action, so they
	// count as HIGH whichever action the server presents.
	got, ok, err := db.ArtifactRisk(sumA, "patching.install_security", "1.0.0")
	if err != nil || !ok || got != canonical.RiskHigh {
		t.Fatalf("after restart: %v %v %v; want HIGH (highest level of these bytes)", got, ok, err)
	}
	for _, c := range [][3]string{
		{sumB, "patching.install_security", "1.0.0"},
		{sumA, "patching.install_security", "1.0.1"},
		{sumA, "system.reboot", "1.0.0"},
	} {
		if _, ok, err := db.ArtifactRisk(c[0], c[1], c[2]); ok || err != nil {
			t.Errorf("%v: trusted=%v err=%v; trust must be exact", c, ok, err)
		}
	}

	list, err := db.ListTrustedArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ActionID != "patching.install_all" || list[1].Risk != canonical.RiskMedium ||
		list[1].SHA256 != sumA || !list[1].TrustedAt.Equal(t0.Truncate(time.Second)) || list[1].TrustedBy != "admin:uid1000" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestRetrustReplacesAndUntrustRemoves(t *testing.T) {
	db := openT(t, privateDir(t))
	a := trusted(sumA, "patching.install_security", "1.0.0", canonical.RiskLow)
	if err := db.TrustArtifact(a); err != nil {
		t.Fatal(err)
	}
	a.Risk = canonical.RiskHigh
	if err := db.TrustArtifact(a); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := db.ArtifactRisk(sumA, a.ActionID, a.ModuleVersion); got != canonical.RiskHigh {
		t.Fatalf("re-trust did not replace the risk: %s", got)
	}
	removed, err := db.UntrustArtifact(sumA, a.ActionID, a.ModuleVersion)
	if err != nil || !removed {
		t.Fatalf("untrust: %v %v", removed, err)
	}
	if _, ok, _ := db.ArtifactRisk(sumA, a.ActionID, a.ModuleVersion); ok {
		t.Fatal("still trusted after untrust")
	}
	if removed, _ := db.UntrustArtifact(sumA, a.ActionID, a.ModuleVersion); removed {
		t.Fatal("second untrust reported a removal")
	}
}

func TestTrustArtifactValidation(t *testing.T) {
	db := openT(t, privateDir(t))
	good := trusted(sumA, "patching.install_security", "1.0.0", canonical.RiskLow)
	for name, mut := range map[string]func(*TrustedArtifact){
		"short sha":        func(a *TrustedArtifact) { a.SHA256 = "abc" },
		"upper-case sha":   func(a *TrustedArtifact) { a.SHA256 = strings.Repeat("A", 64) },
		"bad action":       func(a *TrustedArtifact) { a.ActionID = "Patching" },
		"bad version":      func(a *TrustedArtifact) { a.ModuleVersion = "1.0" },
		"unknown risk":     func(a *TrustedArtifact) { a.Risk = "SEVERE" },
		"long label":       func(a *TrustedArtifact) { a.Label = strings.Repeat("x", 201) },
		"control in label": func(a *TrustedArtifact) { a.Label = "ok\x1b[2Jgone" },
		"bidi in label":    func(a *TrustedArtifact) { a.Label = "safe\u202eexe.hs" },
		"no actor":         func(a *TrustedArtifact) { a.TrustedBy = "" },
	} {
		a := good
		mut(&a)
		if err := db.TrustArtifact(a); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if list, _ := db.ListTrustedArtifacts(); len(list) != 0 {
		t.Fatalf("invalid entries stored: %+v", list)
	}
}

func TestHostCriticalityDurable(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	if err := db.SetHostCriticality("dockerflux", fpA, canonical.RiskCritical, "admin:uid1000"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetHostCriticality("strompi", fpB, canonical.RiskLow, "admin:uid1000"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetHostCriticality("strompi", fpB, canonical.RiskMedium, "admin:uid1001"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db = openT(t, dir)
	if c, ok, err := db.HostCriticality("dockerflux", fpA); err != nil || !ok || c != canonical.RiskCritical {
		t.Fatalf("dockerflux: %v %v %v", c, ok, err)
	}
	if _, ok, err := db.HostCriticality("unknown", fpC); ok || err != nil {
		t.Fatalf("unknown host: ok=%v err=%v", ok, err)
	}
	list, err := db.ListHostCriticality()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[1].HostID != "strompi" || list[1].HostKeyFingerprint != fpB ||
		list[1].Criticality != canonical.RiskMedium || list[1].UpdatedBy != "admin:uid1001" {
		t.Fatalf("unexpected list: %+v", list)
	}
	removed, err := db.ClearHostCriticality("dockerflux")
	if err != nil || !removed {
		t.Fatalf("clear: %v %v", removed, err)
	}
	if _, ok, _ := db.HostCriticality("dockerflux", fpA); ok {
		t.Fatal("criticality survived clear")
	}
}

func TestHostCriticalityValidation(t *testing.T) {
	db := openT(t, privateDir(t))
	for name, c := range map[string]struct {
		host  string
		fp    string
		crit  canonical.Risk
		actor string
	}{
		"bad host":        {"Docker Flux", fpA, canonical.RiskLow, "a"},
		"bad fingerprint": {"dockerflux", "SHA256:short", canonical.RiskLow, "a"},
		"md5 fingerprint": {"dockerflux", "MD5:aa:bb", canonical.RiskLow, "a"},
		"unknown crit":    {"dockerflux", fpA, "", "a"},
		"no actor":        {"dockerflux", fpA, canonical.RiskLow, ""},
	} {
		err := db.SetHostCriticality(c.host, c.fp, c.crit, c.actor)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

// The CHECK constraints hold even if a caller bypasses the Go validation.
func TestRiskConstraintsInSchema(t *testing.T) {
	db := openT(t, privateDir(t))
	if _, err := db.sql.Exec(`INSERT INTO host_criticality VALUES ('x', 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 5, 0, 'a')`); err == nil {
		t.Error("criticality 5 stored")
	}
	if _, err := db.sql.Exec(`INSERT INTO trusted_artifacts VALUES (x'00', 'a.b', '1.0.0', 1, '', 0, 'a')`); err == nil {
		t.Error("1-byte artifact hash stored")
	}
}

// A record applies only to its own pinned key, and a key belongs to one
// host: the server cannot relabel a critical host as a harmless one.
func TestHostRecordIsBoundToItsKey(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SetHostCriticality("dockerflux", fpA, canonical.RiskLow, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetHostCriticality("strompi", fpB, canonical.RiskCritical, "admin"); err != nil {
		t.Fatal(err)
	}
	// A partial match is not exact; it reports the highest related record.
	for _, c := range [][2]string{{"dockerflux", fpB}, {"strompi", fpC}, {"other", fpB}} {
		got, exact, err := db.HostCriticality(c[0], c[1])
		if exact || err != nil || got != canonical.RiskCritical {
			t.Fatalf("%v: got %q exact=%v err=%v; want related CRITICAL, not exact", c, got, exact, err)
		}
	}
	if got, exact, _ := db.HostCriticality("other", fpC); exact || got != "" {
		t.Fatalf("unrelated target: %q %v", got, exact)
	}
	// One key, one record: a second host name for strompi's key is refused.
	err := db.SetHostCriticality("strompi-alias", fpB, canonical.RiskLow, "admin")
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "strompi") {
		t.Fatalf("key reused for another host: %v", err)
	}
	// Re-keying a host (after a legitimate key change) replaces its record.
	if err := db.SetHostCriticality("dockerflux", fpC, canonical.RiskMedium, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.HostCriticality("dockerflux", fpA); ok {
		t.Fatal("old key still matches after re-keying")
	}
	if c, ok, _ := db.HostCriticality("dockerflux", fpC); !ok || c != canonical.RiskMedium {
		t.Fatalf("new key: %v %v", c, ok)
	}
}

func TestActionIDLengthIsValidated(t *testing.T) {
	db := openT(t, privateDir(t))
	a := trusted(sumA, strings.Repeat("a", 64)+"."+strings.Repeat("b", 64)+".c", "1.0.0", canonical.RiskLow)
	if err := db.TrustArtifact(a); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-long action_id: want ErrInvalid, got %v", err)
	}
}
