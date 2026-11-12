// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
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

// observeFimScan lets the executor's own Safety Scanner scan the real
// pinned script, so approvals and runs below see its actual verdict.
func observeFimScan(t *testing.T, e *env) {
	t.Helper()
	sha, err := e.auth.ObserveArtifact(fimScanScript(t))
	if err != nil || sha != FimScanArtifactSHA256 {
		t.Fatalf("observe: %s %v", sha, err)
	}
}

// fimScanScannerVerdict replaces the executor's Safety Scanner result for
// the pinned script with one that differs from the reviewed result, as a
// changed scanner would produce.
func fimScanScannerVerdict(e *env, risk canonical.Risk, findings []scanner.Finding) {
	e.auth.scanMu.Lock()
	defer e.auth.scanMu.Unlock()
	e.auth.scans[FimScanArtifactSHA256] = scanResult{risk: risk, findings: findings, categories: scanner.Categories(findings)}
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
	observeFimScan(t, e)
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
	observeFimScan(t, e)
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
	gfStart := e.clk.Now()
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
	// The full floor is weekly less the scheduler slack, also for
	// scheduled runs: a second full run in the same week is denied ...
	e.clk.Add(6 * 24 * time.Hour) // f1 + 6 d 1 h
	_, err = e.auth.AuthorizeReadRun(gf.ID, "f2", TriggerScheduled, fimScanRun(t, "full"))
	wantCode(t, err, CodeLeaseBudget)
	e.clk.Add(17*time.Hour - time.Second) // one second below the floor
	_, err = e.auth.AuthorizeReadRun(gf.ID, "f2b", TriggerScheduled, fimScanRun(t, "full"))
	wantCode(t, err, CodeLeaseBudget)
	// ... while a weekly schedule that fires up to 6 h early is not
	// pushed to the slot after (review ig05c: weekly became fortnightly).
	e.clk.Add(time.Second)
	if got := e.clk.Now().Sub(gfStart); got != 7*24*time.Hour-FimScanFullScheduleSlack {
		t.Fatalf("full run at %s after f1", got)
	}
	if _, err := e.auth.AuthorizeReadRun(gf.ID, "f3", TriggerScheduled, fimScanRun(t, "full")); err != nil {
		t.Fatalf("full %s early: %v", FimScanFullScheduleSlack, err)
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
	observeFimScan(t, e)
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
// scanner and host floors still apply): a scanner result for the script
// that differs from the reviewed one (here: one extra finding) refuses a
// fim.scan lease, and denies runs of an approved lease once it appears.
func TestFimScanScannerFloorStillApplies(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	raw := readGrantRaw(t, fimScanDoc(t, e.clk.Now(), fimScanGrantAction(t, FimScanArtifactSHA256, "full", "fim-default-v1")))
	other := append(slices.Clone(fimScanReviewedFindings),
		scanner.Finding{Category: scanner.UsersGroups, Risk: canonical.RiskMedium, Line: 200, Excerpt: "authorized_keys"})
	fimScanScannerVerdict(e, canonical.RiskMedium, other)
	_, err := e.auth.ProposeReadGrant(raw)
	wantCode(t, err, CodeGrantInvalid)

	clear(e.auth.scans)
	observeFimScan(t, e)
	g := approveReadGrant(t, e, raw)
	fimScanScannerVerdict(e, canonical.RiskMedium, other)
	_, err = e.auth.AuthorizeReadRun(g.ID, "f1", TriggerOnDemand, fimScanRun(t, "full"))
	wantCode(t, err, CodeGrantInvalid)
	if n := len(le.hostRes["dockerflux"]); n != 0 {
		t.Fatalf("%d reservations, want 0", n)
	}
}

// The real pinned script, scanned by the executor's own Safety Scanner,
// passes floor() as LOW for fim.scan and runs under a read lease; the
// approver still sees the scanner's findings. The same bytes under any
// other action or version keep the scanner's MEDIUM (review ig05c: the
// lease could never be approved in production).
func TestFimScanRealScriptPassesFloor(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	script := fimScanScript(t)
	findings, risk := scanner.Scan(script)
	if risk != canonical.RiskMedium || !slices.Equal(findings, fimScanReviewedFindings) || scanner.Version != fimScanReviewedScannerVersion {
		t.Fatalf("scanner %s rates the pinned script %s with %+v; the reviewed result is %+v under %s: review the change and update fimScanReviewedFindings",
			scanner.Version, risk, findings, fimScanReviewedFindings, fimScanReviewedScannerVersion)
	}
	observeFimScan(t, e)
	shown, _, ok := e.auth.ScanInfo(FimScanArtifactSHA256)
	if !ok || !slices.Equal(shown, fimScanReviewedFindings) {
		t.Fatalf("approver sees %+v (%v), want the scanner's findings", shown, ok)
	}
	tgt := []canonical.Target{{HostID: "dockerflux"}}
	floorOf := func(id, version, sha string) canonical.Risk {
		t.Helper()
		f, _, err := e.auth.floor(canonical.Request{ActionID: id, ModuleVersion: version, ArtifactSHA256: sha}, tgt, nil)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	if f := floorOf(FimScanActionID, FimScanModuleVersion, FimScanArtifactSHA256); f != canonical.RiskLow {
		t.Fatalf("fim.scan floor %s, want LOW", f)
	}
	for _, c := range [][2]string{{"core.facts", FimScanModuleVersion}, {"net.facts", FimScanModuleVersion}, {FimScanActionID, "1.0.1"}} {
		if f := floorOf(c[0], c[1], FimScanArtifactSHA256); f != canonical.RiskMedium {
			t.Errorf("%s@%s with the fim.scan bytes: floor %s, want MEDIUM", c[0], c[1], f)
		}
	}

	g := approveReadGrant(t, e, readGrantRaw(t, fimScanDoc(t, e.clk.Now(),
		fimScanGrantAction(t, FimScanArtifactSHA256, "incremental", "fim-default-v1"))))
	got, err := e.auth.AuthorizeReadRun(g.ID, "r1", TriggerScheduled, fimScanRun(t, "incremental"))
	if err != nil {
		t.Fatalf("real script under the lease: %v", err)
	}
	if string(got.Parameters) != `{"mode":"incremental","profile":"fim-default-v1"}` {
		t.Fatalf("parameters %s", got.Parameters)
	}
	if n := len(le.hostRes["dockerflux"]); n != 1 {
		t.Fatalf("%d reservations, want 1", n)
	}

	// A lease proposed before the executor saw the bytes is approved
	// without the scanner; the run then scans the real bytes and passes.
	e2, _ := newLeaseEnv(t, ModeStandard)
	g2 := approveReadGrant(t, e2, readGrantRaw(t, fimScanDoc(t, e2.clk.Now(),
		fimScanGrantAction(t, FimScanArtifactSHA256, "full", "fim-default-v1"))))
	if _, err := e2.auth.AuthorizeReadRun(g2.ID, "r1", TriggerOnDemand, fimScanRun(t, "full")); err != nil {
		t.Fatalf("run that triggers the scan: %v", err)
	}
	if _, _, ok := e2.auth.ScanInfo(FimScanArtifactSHA256); !ok {
		t.Fatal("the run did not scan the artifact")
	}
}

// Only exactly the reviewed scanner result for exactly the pinned action,
// version and bytes is exempt; any other result keeps its floor.
func TestFimScanReviewedScanIsExact(t *testing.T) {
	pinned := canonical.Request{ActionID: FimScanActionID, ModuleVersion: FimScanModuleVersion, ArtifactSHA256: FimScanArtifactSHA256}
	reviewed := scanResult{risk: canonical.RiskMedium, findings: slices.Clone(fimScanReviewedFindings)}
	if !fimScanReviewedScan(pinned, reviewed) {
		t.Fatal("reviewed result of the pinned script not recognised")
	}
	withFindings := func(f ...scanner.Finding) scanResult { return scanResult{risk: canonical.RiskHigh, findings: f} }
	r0, r1 := fimScanReviewedFindings[0], fimScanReviewedFindings[1]
	moved := r1
	moved.Line++
	other := r1
	other.Excerpt = "/etc/sudoers"
	high := r1
	high.Risk = canonical.RiskHigh
	destructive := scanner.Finding{Category: scanner.DestructiveFS, Risk: canonical.RiskHigh, Line: 300, Excerpt: "rm -rf /"}
	many := make([]scanner.Finding, scanner.MaxFindings)
	for name, c := range map[string]struct {
		r canonical.Request
		s scanResult
	}{
		"other action":       {canonical.Request{ActionID: "core.facts", ModuleVersion: FimScanModuleVersion, ArtifactSHA256: FimScanArtifactSHA256}, reviewed},
		"other version":      {canonical.Request{ActionID: FimScanActionID, ModuleVersion: "1.0.1", ArtifactSHA256: FimScanArtifactSHA256}, reviewed},
		"other bytes":        {canonical.Request{ActionID: FimScanActionID, ModuleVersion: FimScanModuleVersion, ArtifactSHA256: hexSum([]byte("x"))}, reviewed},
		"extra finding":      {pinned, withFindings(r0, r1, destructive)},
		"missing finding":    {pinned, withFindings(r0)},
		"moved finding":      {pinned, withFindings(r0, moved)},
		"other excerpt":      {pinned, withFindings(r0, other)},
		"higher risk":        {pinned, withFindings(r0, high)},
		"verdict, no detail": {pinned, withFindings()},
		"cut-off findings":   {pinned, withFindings(many...)},
	} {
		if fimScanReviewedScan(c.r, c.s) {
			t.Errorf("%s: exempt", name)
		}
	}
}

// The AuthorizeReadRun guard behind the lease's parameters hash: a fim.scan
// run whose canonical parameters are not one of the pinned modes is denied
// before any reservation, whatever the lease says.
func TestFimScanReservationDeniesUnpinnedParameters(t *testing.T) {
	d := fimScanDoc(t, time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC),
		fimScanGrantAction(t, FimScanArtifactSHA256, "incremental", "fim-default-v1"))
	for _, raw := range []string{
		`{"mode":"incremental","path":"/","profile":"fim-default-v1"}`,
		`{"mode":"incremental","profile":"fim-other-v1"}`,
		`{"mode":"weekly","profile":"fim-default-v1"}`,
		`{}`,
		``,
	} {
		_, _, err := readRunReservation(d, TriggerScheduled, FimScanActionID, []byte(raw))
		wantCode(t, err, CodeParametersMismatch)
	}
	for mode, want := range map[string]struct {
		key   string
		floor time.Duration
	}{
		"incremental": {FimScanActionID, FimScanIncrementalMinInterval},
		"full":        {fimScanFullIntervalKey, FimScanFullMinInterval},
	} {
		key, iv, err := readRunReservation(d, TriggerScheduled, FimScanActionID, fimScanParams(mode, "fim-default-v1"))
		if err != nil || key != want.key || iv != max(want.floor, time.Duration(d.MinIntervalS)*time.Second) {
			t.Errorf("%s: key %q interval %s (%v)", mode, key, iv, err)
		}
	}
	// Other actions keep their own key and floor.
	key, iv, err := readRunReservation(d, TriggerScheduled, "package.list_installed", []byte(`{}`))
	if err != nil || key != "package.list_installed" || iv != PackageListInstalledMinInterval {
		t.Errorf("package.list_installed: key %q interval %s (%v)", key, iv, err)
	}
}
