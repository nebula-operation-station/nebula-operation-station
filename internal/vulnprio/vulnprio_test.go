// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnprio

import (
	"errors"
	"math"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func cvss(base float64) *vulnfinding.CVSS {
	return &vulnfinding.CVSS{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: base, Source: vulnfinding.CVSSSourceNVD}
}

func kev() *vulnfinding.KEV { return &vulnfinding.KEV{DateAdded: "2026-01-02"} }

func epss(p float64) *vulnfinding.EPSS {
	return &vulnfinding.EPSS{Probability: p, Percentile: 0.5, Date: "2026-11-08"}
}

// base is a neutral input: CVSS 10, no exploit data, internet-facing,
// CRITICAL host. Tests change one field at a time.
func base() Input {
	return Input{
		Scores:      vulnfinding.Scores{CVSS: cvss(10)},
		Exposure:    ExposureInternet,
		Criticality: inventory.CriticalityCritical,
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestFormulaVersionIsVuPrioV1(t *testing.T) {
	if FormulaVersion != "vu-prio-v1" {
		t.Fatalf("FormulaVersion = %q, want vu-prio-v1", FormulaVersion)
	}
}

func TestCVSSTerm(t *testing.T) {
	tests := []struct {
		name     string
		cvss     *vulnfinding.CVSS
		want     float64
		unknownF bool
	}{
		{"unknown counts 0.5 and is flagged", nil, 0.5, true},
		{"zero", cvss(0), 0, false},
		{"9.8", cvss(9.8), 0.98, false},
		{"5.0", cvss(5.0), 0.5, false},
		{"maximum", cvss(10), 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			in.Scores.CVSS = tc.cvss
			r, err := Compute(in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if !near(r.Terms.CVSS, tc.want) {
				t.Errorf("cvss term = %v, want %v", r.Terms.CVSS, tc.want)
			}
			if r.CVSSUnknown != tc.unknownF {
				t.Errorf("CVSSUnknown = %v, want %v", r.CVSSUnknown, tc.unknownF)
			}
		})
	}
}

func TestExploitTerm(t *testing.T) {
	tests := []struct {
		name string
		kev  *vulnfinding.KEV
		epss *vulnfinding.EPSS
		want float64
	}{
		{"no data uses floor 0.1", nil, nil, 0.1},
		{"EPSS below floor uses floor", nil, epss(0.05), 0.1},
		{"EPSS zero uses floor", nil, epss(0), 0.1},
		{"EPSS above floor", nil, epss(0.5), 0.5},
		{"EPSS one", nil, epss(1), 1},
		{"KEV alone is 0.9", kev(), nil, 0.9},
		{"KEV beats lower EPSS", kev(), epss(0.3), 0.9},
		{"higher EPSS beats KEV", kev(), epss(0.95), 0.95},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			in.Scores.KEV = tc.kev
			in.Scores.EPSS = tc.epss
			r, err := Compute(in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if !near(r.Terms.Exploit, tc.want) {
				t.Errorf("expl term = %v, want %v", r.Terms.Exploit, tc.want)
			}
		})
	}
}

func TestExposureTerm(t *testing.T) {
	tests := []struct {
		name string
		expo Exposure
		want float64
	}{
		{"internet-facing", ExposureInternet, 1.0},
		{"NetBird/VPN entry", ExposureVPNEntry, 0.7},
		{"unknown", ExposureUnknown, 0.7},
		{"unset counts as unknown", "", 0.7},
		{"internal only", ExposureInternal, 0.4},
		{"no listening service", ExposureNoListener, 0.2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			in.Exposure = tc.expo
			r, err := Compute(in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if !near(r.Terms.Exposure, tc.want) {
				t.Errorf("expo term = %v, want %v", r.Terms.Exposure, tc.want)
			}
		})
	}
}

func TestUnknownExposureIsNeverInternal(t *testing.T) {
	for _, e := range []Exposure{ExposureUnknown, ""} {
		in := base()
		in.Exposure = e
		r, err := Compute(in)
		if err != nil {
			t.Fatalf("Compute(%q): %v", e, err)
		}
		if r.Terms.Exposure != 0.7 {
			t.Errorf("exposure %q = %v, want 0.7", e, r.Terms.Exposure)
		}
		if r.Exposure != ExposureUnknown {
			t.Errorf("recorded exposure %q, want %q", r.Exposure, ExposureUnknown)
		}
	}
}

func TestCriticalityTerm(t *testing.T) {
	tests := []struct {
		name string
		crit inventory.Criticality
		want float64
	}{
		{"CRITICAL", inventory.CriticalityCritical, 1.0},
		{"HIGH", inventory.CriticalityHigh, 0.85},
		{"MEDIUM", inventory.CriticalityMedium, 0.7},
		{"LOW", inventory.CriticalityLow, 0.5},
		{"unset counts as HIGH", "", 0.85},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			in.Criticality = tc.crit
			r, err := Compute(in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if !near(r.Terms.Criticality, tc.want) {
				t.Errorf("crit term = %v, want %v", r.Terms.Criticality, tc.want)
			}
		})
	}
}

func TestScoreAndTier(t *testing.T) {
	tests := []struct {
		name      string
		in        Input
		wantScore int
		wantTier  Tier
	}{
		{
			name:      "KEV internet critical host",
			in:        Input{vulnfinding.Scores{CVSS: cvss(10), KEV: kev()}, ExposureInternet, inventory.CriticalityCritical},
			wantScore: 94, wantTier: TierCritical,
		},
		{
			name:      "all unknown: 100*0.5*0.46*0.7*0.85 = 13.685",
			in:        Input{vulnfinding.Scores{}, ExposureUnknown, ""},
			wantScore: 14, wantTier: TierLow,
		},
		{
			name:      "internal HIGH host with EPSS: 100*0.98*0.52*0.4*0.85 = 17.33",
			in:        Input{vulnfinding.Scores{CVSS: cvss(9.8), EPSS: epss(0.2)}, ExposureInternal, inventory.CriticalityHigh},
			wantScore: 17, wantTier: TierMedium,
		},
		{
			name:      "VPN entry without exploit data: 32.2",
			in:        Input{vulnfinding.Scores{CVSS: cvss(10)}, ExposureVPNEntry, inventory.CriticalityCritical},
			wantScore: 32, wantTier: TierMedium,
		},
		{
			name:      "rounds half up: 100*0.5*0.46*1*0.5 = 11.5",
			in:        Input{vulnfinding.Scores{CVSS: cvss(5.0)}, ExposureInternet, inventory.CriticalityLow},
			wantScore: 12, wantTier: TierLow,
		},
		{
			name:      "score 60 is critical",
			in:        Input{vulnfinding.Scores{CVSS: cvss(6.0), EPSS: epss(1)}, ExposureInternet, inventory.CriticalityCritical},
			wantScore: 60, wantTier: TierCritical,
		},
		{
			name:      "score 59 is high",
			in:        Input{vulnfinding.Scores{CVSS: cvss(5.9), EPSS: epss(1)}, ExposureInternet, inventory.CriticalityCritical},
			wantScore: 59, wantTier: TierHigh,
		},
		{
			name:      "score 35 is high",
			in:        Input{vulnfinding.Scores{CVSS: cvss(3.5), EPSS: epss(1)}, ExposureInternet, inventory.CriticalityCritical},
			wantScore: 35, wantTier: TierHigh,
		},
		{
			name:      "score 34 is medium",
			in:        Input{vulnfinding.Scores{CVSS: cvss(3.4), EPSS: epss(1)}, ExposureInternet, inventory.CriticalityCritical},
			wantScore: 34, wantTier: TierMedium,
		},
		{
			name:      "score 15 is medium",
			in:        Input{vulnfinding.Scores{CVSS: cvss(1.5), EPSS: epss(1)}, ExposureInternet, inventory.CriticalityCritical},
			wantScore: 15, wantTier: TierMedium,
		},
		{
			name:      "score 14 is low",
			in:        Input{vulnfinding.Scores{CVSS: cvss(1.4), EPSS: epss(1)}, ExposureInternet, inventory.CriticalityCritical},
			wantScore: 14, wantTier: TierLow,
		},
		{
			name:      "CVSS zero scores zero",
			in:        Input{vulnfinding.Scores{CVSS: cvss(0)}, ExposureInternet, inventory.CriticalityCritical},
			wantScore: 0, wantTier: TierLow,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Compute(tc.in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if r.Score != tc.wantScore || r.Tier != tc.wantTier {
				t.Errorf("got score %d tier %s, want %d %s", r.Score, r.Tier, tc.wantScore, tc.wantTier)
			}
			if r.Formula != FormulaVersion {
				t.Errorf("Formula = %q, want %q", r.Formula, FormulaVersion)
			}
		})
	}
}

// TestKEVTierRule covers "critical if KEV and expo ≥ 0.7" independent of the
// score.
func TestKEVTierRule(t *testing.T) {
	tests := []struct {
		name      string
		expo      Exposure
		wantScore int
		wantTier  Tier
	}{
		// CVSS 5.0, KEV, LOW host: 100*0.5*0.94*expo*0.5.
		{"internet", ExposureInternet, 24, TierCritical},
		{"VPN entry (0.7)", ExposureVPNEntry, 16, TierCritical},
		{"unknown (0.7)", ExposureUnknown, 16, TierCritical},
		{"internal (0.4) falls to the KEV floor", ExposureInternal, 9, TierHigh},
		{"no listener (0.2) falls to the KEV floor", ExposureNoListener, 5, TierHigh},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := Input{vulnfinding.Scores{CVSS: cvss(5.0), KEV: kev()}, tc.expo, inventory.CriticalityLow}
			r, err := Compute(in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if r.Score != tc.wantScore || r.Tier != tc.wantTier {
				t.Errorf("got score %d tier %s, want %d %s", r.Score, r.Tier, tc.wantScore, tc.wantTier)
			}
		})
	}
	// The same inputs without KEV stay below critical.
	in := Input{vulnfinding.Scores{CVSS: cvss(5.0), EPSS: epss(0.9)}, ExposureUnknown, inventory.CriticalityLow}
	r, err := Compute(in)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if r.Tier == TierCritical {
		t.Errorf("non-KEV finding with score %d is critical", r.Score)
	}
}

// TestKEVLocalPrivescOnHostWithoutListenersIsHigh is the case the ADR names
// for the KEV floor: a KEV-listed local kernel CVE on a host without a
// listening service.
func TestKEVLocalPrivescOnHostWithoutListenersIsHigh(t *testing.T) {
	local := &vulnfinding.CVSS{Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", BaseScore: 7.8, Source: vulnfinding.CVSSSourceDistro}
	in := Input{vulnfinding.Scores{CVSS: local, KEV: kev()}, ExposureNoListener, inventory.CriticalityMedium}
	r, err := Compute(in)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	// 100*0.78*0.94*0.2*0.7 = 10.26 → 10, low by score.
	if r.Score != 10 {
		t.Errorf("score = %d, want 10", r.Score)
	}
	if r.Tier != TierHigh {
		t.Errorf("tier = %s, want high (KEV floor)", r.Tier)
	}
}

func TestKEVNeverBelowHigh(t *testing.T) {
	exposures := []Exposure{ExposureInternet, ExposureVPNEntry, ExposureUnknown, ExposureInternal, ExposureNoListener}
	crits := []inventory.Criticality{"", inventory.CriticalityLow, inventory.CriticalityMedium, inventory.CriticalityHigh, inventory.CriticalityCritical}
	cvssVals := []*vulnfinding.CVSS{nil, cvss(0), cvss(0.1), cvss(3.3), cvss(10)}
	epssVals := []*vulnfinding.EPSS{nil, epss(0), epss(1)}
	for _, e := range exposures {
		for _, c := range crits {
			for _, cv := range cvssVals {
				for _, ep := range epssVals {
					in := Input{vulnfinding.Scores{CVSS: cv, KEV: kev(), EPSS: ep}, e, c}
					r, err := Compute(in)
					if err != nil {
						t.Fatalf("Compute: %v", err)
					}
					if r.Tier.Rank() < TierHigh.Rank() {
						t.Errorf("KEV finding %+v got tier %s (score %d)", in, r.Tier, r.Score)
					}
				}
			}
		}
	}
}

func TestRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Input)
	}{
		{"CVSS NaN", func(in *Input) { in.Scores.CVSS = cvss(math.NaN()) }},
		{"CVSS +Inf", func(in *Input) { in.Scores.CVSS = cvss(math.Inf(1)) }},
		{"CVSS negative", func(in *Input) { in.Scores.CVSS = cvss(-0.1) }},
		{"CVSS above 10", func(in *Input) { in.Scores.CVSS = cvss(10.1) }},
		{"EPSS NaN", func(in *Input) { in.Scores.EPSS = epss(math.NaN()) }},
		{"EPSS -Inf", func(in *Input) { in.Scores.EPSS = epss(math.Inf(-1)) }},
		{"EPSS negative", func(in *Input) { in.Scores.EPSS = epss(-0.01) }},
		{"EPSS above 1", func(in *Input) { in.Scores.EPSS = epss(1.01) }},
		{"unknown exposure name", func(in *Input) { in.Exposure = "public" }},
		{"exposure wrong case", func(in *Input) { in.Exposure = "Internet" }},
		{"unknown criticality", func(in *Input) { in.Criticality = "medium" }},
		{"criticality garbage", func(in *Input) { in.Criticality = "VERY HIGH" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mod(&in)
			r, err := Compute(in)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
			if r != (Result{}) {
				t.Errorf("result on error = %+v, want zero", r)
			}
		})
	}
}

func TestComputeIsPureAndDeterministic(t *testing.T) {
	in := Input{vulnfinding.Scores{CVSS: cvss(7.5), KEV: kev(), EPSS: epss(0.42)}, ExposureVPNEntry, inventory.CriticalityHigh}
	snapshotCVSS, snapshotKEV, snapshotEPSS := *in.Scores.CVSS, *in.Scores.KEV, *in.Scores.EPSS
	first, err := Compute(in)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	for i := 0; i < 100; i++ {
		r, err := Compute(in)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if r != first {
			t.Fatalf("run %d: %+v != %+v", i, r, first)
		}
	}
	if *in.Scores.CVSS != snapshotCVSS || *in.Scores.KEV != snapshotKEV || *in.Scores.EPSS != snapshotEPSS {
		t.Error("Compute modified its input")
	}
}

func TestResultCarriesFormulaVersionAndInputs(t *testing.T) {
	in := Input{vulnfinding.Scores{}, "", ""}
	r, err := Compute(in)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if r.Formula != "vu-prio-v1" {
		t.Errorf("Formula = %q", r.Formula)
	}
	if !r.CVSSUnknown || r.Exposure != ExposureUnknown || r.CriticalityUnset != true || r.KEV {
		t.Errorf("result flags = %+v", r)
	}
}

func TestTierRank(t *testing.T) {
	order := []Tier{TierLow, TierMedium, TierHigh, TierCritical}
	for i, tier := range order {
		if tier.Rank() != i+1 {
			t.Errorf("%s.Rank() = %d, want %d", tier, tier.Rank(), i+1)
		}
	}
	if Tier("bogus").Rank() != 0 {
		t.Error("unknown tier has non-zero rank")
	}
}

// TestWeightsMatchADR pins the vu-prio-v1 weights to ADR 0011 D7. Changing
// any of them requires a new formula version.
func TestWeightsMatchADR(t *testing.T) {
	got := []float64{
		cvssUnknown, exploitKEV, exploitFloor, exploitBase, exploitWeight,
		exposureInternetW, exposureVPNEntryW, exposureUnknownW, exposureInternalW, exposureNoListenerW,
		critCriticalW, critHighW, critMediumW, critLowW, critUnsetW,
	}
	want := []float64{
		0.5, 0.9, 0.1, 0.4, 0.6,
		1.0, 0.7, 0.7, 0.4, 0.2,
		1.0, 0.85, 0.7, 0.5, 0.85,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("weight %d = %v, want %v", i, got[i], want[i])
		}
	}
	if tierCriticalMin != 60 || tierHighMin != 35 || tierMediumMin != 15 || kevCriticalExposureMin != 0.7 {
		t.Error("tier thresholds differ from ADR 0011 D7")
	}
}

func FuzzCompute(f *testing.F) {
	f.Add(9.8, true, true, 0.3, true, "internet", "HIGH")
	f.Add(0.0, false, false, 0.0, false, "", "")
	f.Fuzz(func(t *testing.T, cv float64, hasCVSS, hasKEV bool, ep float64, hasEPSS bool, expo, crit string) {
		var s vulnfinding.Scores
		if hasCVSS {
			s.CVSS = cvss(cv)
		}
		if hasKEV {
			s.KEV = kev()
		}
		if hasEPSS {
			s.EPSS = epss(ep)
		}
		r, err := Compute(Input{s, Exposure(expo), inventory.Criticality(crit)})
		if err != nil {
			return
		}
		if r.Score < 0 || r.Score > 100 || r.Tier.Rank() == 0 || r.Formula != FormulaVersion {
			t.Fatalf("bad result %+v", r)
		}
		if hasKEV && r.Tier.Rank() < TierHigh.Rank() {
			t.Fatalf("KEV below high: %+v", r)
		}
	})
}
