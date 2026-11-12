// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// fimScanScript reads the shipped fim.scan script. internal/fimscan
// depends on this package, so the bytes are read from the file here; the
// external test lease_fimscan_ext_test.go checks the embedded copy.
func fimScanScript(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "fimscan", "scripts", "fim_scan.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fimScanParams(mode, profile string) []byte {
	return []byte(`{"mode":"` + mode + `","profile":"` + profile + `"}`)
}

func fimScanGrantAction(t *testing.T, artifactSHA, mode, profile string) ReadGrantAction {
	t.Helper()
	ph, err := canonical.HashParameters(fimScanParams(mode, profile))
	if err != nil {
		t.Fatal(err)
	}
	return ReadGrantAction{ActionID: FimScanActionID, ModuleVersion: FimScanModuleVersion, ArtifactSHA256: artifactSHA, ParametersHash: ph}
}

func fimScanDoc(t *testing.T, now time.Time, act ReadGrantAction) ReadGrantDoc {
	t.Helper()
	d := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	d.Actions = []ReadGrantAction{act}
	return d
}

// fimScanScannerVerdict fixes the executor's Safety Scanner result for the
// pinned script. The shipped script names authorized_keys (it reads them),
// which the scanner rates MEDIUM; the authorization tests below set LOW to
// exercise the lease path, and TestFimScanScannerFloorStillApplies shows a
// MEDIUM verdict refusing the lease.
func fimScanScannerVerdict(e *env, risk canonical.Risk) {
	e.auth.scanMu.Lock()
	defer e.auth.scanMu.Unlock()
	e.auth.scans[FimScanArtifactSHA256] = scanResult{risk: risk}
}

func fimScanRun(t *testing.T, mode string) Run {
	t.Helper()
	r := readRun("dockerflux", fpA)
	r.ActionID, r.ModuleVersion = FimScanActionID, FimScanModuleVersion
	r.Artifact, r.ParametersJSON = fimScanScript(t), fimScanParams(mode, "fim-default-v1")
	return r
}

// The pinned contract matches the shipped script and the exact canonical
// parameter documents of both modes.
func TestFimScanPinsMatchScriptAndParameters(t *testing.T) {
	sum := sha256.Sum256(fimScanScript(t))
	if got := hex.EncodeToString(sum[:]); got != FimScanArtifactSHA256 {
		t.Fatalf("script hash %s, pinned %s", got, FimScanArtifactSHA256)
	}
	for mode, want := range map[string]string{"incremental": FimScanIncrementalParametersHash, "full": FimScanFullParametersHash} {
		got, err := canonical.HashParameters(fimScanParams(mode, "fim-default-v1"))
		if err != nil || got != want {
			t.Errorf("%s: hash %s (%v), pinned %s", mode, got, err, want)
		}
	}
}

// fim.scan (ADR 0015 D5) is on the read-only allowlist, nothing that only
// shares its prefix is, and it never rides the telemetry profile.
func TestFimScanInReadOnlyAllowlist(t *testing.T) {
	if !InReadOnlyAllowlist("fim.scan") {
		t.Fatal("fim.scan is not in the read-only allowlist")
	}
	for _, id := range []string{"fim.scan.full", "fim.sca", "fim", "Fim.scan", "fim.scan ", "fim.restore"} {
		if InReadOnlyAllowlist(id) {
			t.Errorf("%q is in the read-only allowlist", id)
		}
	}
	if schedgrant.IsTelemetryAction("fim.scan") {
		t.Fatal("fim.scan must not ride the telemetry rate profile")
	}
	if got := ReadActionMinInterval("fim.scan"); got != FimScanIncrementalMinInterval {
		t.Fatalf("fim.scan floor %s, want %s", got, FimScanIncrementalMinInterval)
	}
	if FimScanFullMinInterval > schedgrant.MaxInterval || FimScanIncrementalMinInterval < schedgrant.MinInterval {
		t.Fatal("fim.scan floors outside what the read store retains")
	}
}

// A lease binds exactly the pinned script, version, profile and mode; any
// other profile, a free path, extra or missing parameters, another script
// or version, or the telemetry profile is refused at parse time.
func TestFimScanReadGrantBindsExactContract(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"incremental", "full"} {
		d := fimScanDoc(t, now, fimScanGrantAction(t, FimScanArtifactSHA256, mode, "fim-default-v1"))
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
			t.Fatalf("%s lease refused: %v", mode, err)
		}
	}
	hash := func(raw string) string {
		h, err := canonical.HashParameters([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	good := fimScanGrantAction(t, FimScanArtifactSHA256, "full", "fim-default-v1")
	cases := map[string]func(*ReadGrantAction){
		"other profile": func(a *ReadGrantAction) { a.ParametersHash = hash(`{"mode":"full","profile":"fim-other-v1"}`) },
		"other mode":    func(a *ReadGrantAction) { a.ParametersHash = hash(`{"mode":"weekly","profile":"fim-default-v1"}`) },
		"free path": func(a *ReadGrantAction) {
			a.ParametersHash = hash(`{"mode":"full","path":"/","profile":"fim-default-v1"}`)
		},
		"path only":       func(a *ReadGrantAction) { a.ParametersHash = hash(`{"path":"/root/.ssh"}`) },
		"no parameters":   func(a *ReadGrantAction) { a.ParametersHash = hash(`{}`) },
		"missing profile": func(a *ReadGrantAction) { a.ParametersHash = hash(`{"mode":"full"}`) },
		"look-back override": func(a *ReadGrantAction) {
			a.ParametersHash = hash(`{"lookback":"1","mode":"incremental","profile":"fim-default-v1"}`)
		},
		"changed script": func(a *ReadGrantAction) { a.ArtifactSHA256 = hexSum(append(fimScanScript(t), '\n')) },
		"other version":  func(a *ReadGrantAction) { a.ModuleVersion = "1.0.1" },
	}
	for name, mutate := range cases {
		a := good
		mutate(&a)
		_, _, _, err := ParseReadGrant(readGrantRaw(t, fimScanDoc(t, now, a)), now)
		if err == nil {
			t.Errorf("%s: lease accepted", name)
		}
	}
	d := fimScanDoc(t, now, good)
	d.RateProfile = schedgrant.TelemetryReadProfile
	d.MinIntervalS = int64(schedgrant.TelemetryLiveInterval / time.Second)
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
		t.Error("fim.scan accepted under the telemetry profile")
	}
}

// A run must present the pinned bytes and the lease's exact parameters: a
// changed script, another profile, another mode or a free path is denied
// before any budget is spent.
func TestFimScanRunRejectsChangedScriptOrParameters(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	fimScanScannerVerdict(e, canonical.RiskLow)
	g := approveReadGrant(t, e, readGrantRaw(t, fimScanDoc(t, e.clk.Now(),
		fimScanGrantAction(t, FimScanArtifactSHA256, "incremental", "fim-default-v1"))))
	changed := fimScanRun(t, "incremental")
	changed.Artifact = []byte(strings.Replace(string(changed.Artifact), "WIN=1560", "WIN=99999", 1))
	_, err := e.auth.AuthorizeReadRun(g.ID, "x1", TriggerOnDemand, changed)
	wantCode(t, err, CodeArtifactMismatch)
	for name, raw := range map[string]string{
		"other profile": `{"mode":"incremental","profile":"fim-other-v1"}`,
		"other mode":    `{"mode":"full","profile":"fim-default-v1"}`,
		"free path":     `{"mode":"incremental","path":"/","profile":"fim-default-v1"}`,
	} {
		r := fimScanRun(t, "incremental")
		r.ParametersJSON = []byte(raw)
		_, err := e.auth.AuthorizeReadRun(g.ID, "p-"+name, TriggerOnDemand, r)
		wantCode(t, err, CodeParametersMismatch)
	}
	if n := len(le.hostRes["dockerflux"]); n != 0 {
		t.Fatalf("%d reservations, want 0 (denials spend nothing)", n)
	}
	got, err := e.auth.AuthorizeReadRun(g.ID, "ok", TriggerOnDemand, fimScanRun(t, "incremental"))
	if err != nil {
		t.Fatalf("exact run: %v", err)
	}
	if string(got.Parameters) != `{"mode":"incremental","profile":"fim-default-v1"}` {
		t.Fatalf("parameters %s", got.Parameters)
	}
}

// Incremental runs have a 1 h floor per host (hourly on crown jewels is the
// fastest approved schedule), full runs a weekly floor of their own; both
// count in the ordinary per-host rolling-hour budget.
func TestFimScanIntervalsAndBudget(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	fimScanScannerVerdict(e, canonical.RiskLow)
	now := e.clk.Now()
	inc := fimScanDoc(t, now, fimScanGrantAction(t, FimScanArtifactSHA256, "incremental", "fim-default-v1"))
	inc.ID = rgID
	full := fimScanDoc(t, now, fimScanGrantAction(t, FimScanArtifactSHA256, "full", "fim-default-v1"))
	full.ID = rgID2
	// A weekly full schedule needs a lease that outlives one week.
	full.ExpiryUnix = now.Add(ReadGrantMaxLifetime).Unix()
	inc.ExpiryUnix = full.ExpiryUnix
	gi := approveReadGrant(t, e, readGrantRaw(t, inc))
	gf := approveReadGrant(t, e, readGrantRaw(t, full))

	if _, err := e.auth.AuthorizeReadRun(gi.ID, "i1", TriggerOnDemand, fimScanRun(t, "incremental")); err != nil {
		t.Fatal(err)
	}
	// A full run keeps its own floor and is not blocked by the incremental one.
	if _, err := e.auth.AuthorizeReadRun(gf.ID, "f1", TriggerOnDemand, fimScanRun(t, "full")); err != nil {
		t.Fatalf("full after incremental: %v", err)
	}
	// 16 minutes clear the lease's 15-minute interval but not the 1 h floor.
	e.clk.Add(16 * time.Minute)
	_, err := e.auth.AuthorizeReadRun(gi.ID, "i2", TriggerOnDemand, fimScanRun(t, "incremental"))
	wantCode(t, err, CodeLeaseBudget)
	e.clk.Add(time.Hour - 16*time.Minute)
	if _, err := e.auth.AuthorizeReadRun(gi.ID, "i3", TriggerScheduled, fimScanRun(t, "incremental")); err != nil {
		t.Fatalf("incremental after 1 h: %v", err)
	}
	// The full floor is weekly, also for scheduled runs.
	e.clk.Add(6 * 24 * time.Hour)
	_, err = e.auth.AuthorizeReadRun(gf.ID, "f2", TriggerScheduled, fimScanRun(t, "full"))
	wantCode(t, err, CodeLeaseBudget)
	e.clk.Add(24*time.Hour - time.Hour)
	if _, err := e.auth.AuthorizeReadRun(gf.ID, "f3", TriggerScheduled, fimScanRun(t, "full")); err != nil {
		t.Fatalf("full after 7 days: %v", err)
	}
	// The two modes keep separate interval keys; the full key never
	// shadows another action ID.
	for _, key := range []string{"fim.scan|dockerflux", fimScanFullIntervalKey + "|dockerflux"} {
		if _, ok := le.actionLast[key]; !ok {
			t.Errorf("no interval entry %q", key)
		}
	}
	if canonical.ValidActionID(fimScanFullIntervalKey) {
		t.Errorf("interval key %q could collide with an action ID", fimScanFullIntervalKey)
	}
}

// fim.scan runs share the per-host rolling-hour budget with every other
// read; an exhausted budget denies them.
func TestFimScanBudgetExhaustedDenies(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	fimScanScannerVerdict(e, canonical.RiskLow)
	d := fimScanDoc(t, e.clk.Now(), fimScanGrantAction(t, FimScanArtifactSHA256, "incremental", "fim-default-v1"))
	cf := readGrantDocWith(t, rgID, e.clk.Now(), DefaultReadGrantLifetime, 1, []string{"core.facts"})
	d.Actions = append(d.Actions, cf.Actions...)
	d.RunBudget = 1
	g := approveReadGrant(t, e, readGrantRaw(t, d))
	if _, err := e.auth.AuthorizeReadRun(g.ID, "c1", TriggerOnDemand, readRun("dockerflux", fpA)); err != nil {
		t.Fatal(err)
	}
	_, err := e.auth.AuthorizeReadRun(g.ID, "f1", TriggerOnDemand, fimScanRun(t, "incremental"))
	wantCode(t, err, CodeLeaseBudget)
	if n := len(le.hostRes["dockerflux"]); n != 1 {
		t.Fatalf("%d reservations, want 1", n)
	}
	// Another host has its own budget.
	other := fimScanRun(t, "incremental")
	other.HostID, other.HostKeyFingerprint = "strompi", fpB
	if _, err := e.auth.AuthorizeReadRun(g.ID, "f2", TriggerOnDemand, other); err != nil {
		t.Fatalf("other host: %v", err)
	}
}

// The pinned contract does not bypass the executor's risk floor (spec 10:
// scanner and host floors still apply): with a MEDIUM scanner verdict for
// the script a fim.scan lease is refused, and runs of an approved lease are
// denied once the verdict rises.
func TestFimScanScannerFloorStillApplies(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	raw := readGrantRaw(t, fimScanDoc(t, e.clk.Now(), fimScanGrantAction(t, FimScanArtifactSHA256, "full", "fim-default-v1")))
	fimScanScannerVerdict(e, canonical.RiskMedium)
	_, err := e.auth.ProposeReadGrant(raw)
	wantCode(t, err, CodeGrantInvalid)

	fimScanScannerVerdict(e, canonical.RiskLow)
	g := approveReadGrant(t, e, raw)
	fimScanScannerVerdict(e, canonical.RiskMedium)
	_, err = e.auth.AuthorizeReadRun(g.ID, "f1", TriggerOnDemand, fimScanRun(t, "full"))
	wantCode(t, err, CodeGrantInvalid)
	if n := len(le.hostRes["dockerflux"]); n != 0 {
		t.Fatalf("%d reservations, want 0", n)
	}
}
