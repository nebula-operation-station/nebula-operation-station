// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnprio

import (
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// cleanVerdicts: every source denied, own segment trusted. Tests change
// one source at a time.
func cleanVerdicts() Verdicts {
	return Verdicts{
		Internet:   VerdictDenied,
		NetBird:    VerdictDenied,
		Zones:      []ZoneVerdict{{Zone: "lan", Class: ClassTrusted, Verdict: VerdictDenied}},
		OwnSegment: OwnSegmentVerdict{Class: ClassTrusted, Verdict: VerdictDenied},
	}
}

// freshRecord is a complete, valid mitigation record for v.
func freshRecord(v Verdicts) MitigationRecord {
	return MitigationRecord{InputsFresh: true, PortKnown: true, HostAddressesKnown: true, Verdicts: v}
}

// v2Input combines the neutral v1 base input with a record.
func v2Input(m MitigationRecord) InputV2 {
	return InputV2{Base: base(), Mitigation: m}
}

func mustV2(t *testing.T, in InputV2) ResultV2 {
	t.Helper()
	r, err := ComputeV2(in)
	if err != nil {
		t.Fatalf("ComputeV2: %v", err)
	}
	return r
}

func TestFormulaVersionV2IsVuPrioV2(t *testing.T) {
	if FormulaVersionV2 != "vu-prio-v2" {
		t.Fatalf("FormulaVersionV2 = %q, want vu-prio-v2", FormulaVersionV2)
	}
	if FormulaVersion != "vu-prio-v1" {
		t.Fatalf("v1 FormulaVersion changed to %q", FormulaVersion)
	}
}

func TestV2ExposureLevelsFromVerdicts(t *testing.T) {
	tests := []struct {
		name      string
		verdicts  func() Verdicts
		wantExpo  float64
		wantLevel Exposure
		mitigated bool
		notFilt   bool
	}{
		{"internet allowed is 1.0", func() Verdicts {
			v := cleanVerdicts()
			v.Internet = VerdictAllowed
			return v
		}, 1.0, ExposureInternet, false, false},
		{"internet conditional is 1.0", func() Verdicts {
			v := cleanVerdicts()
			v.Internet = VerdictConditional
			return v
		}, 1.0, ExposureInternet, false, false},
		{"internet not_filtered is 1.0 and never mitigated", func() Verdicts {
			v := cleanVerdicts()
			v.Internet = VerdictNotFiltered
			return v
		}, 1.0, ExposureInternet, false, true},
		{"internet denied, netbird allowed is 0.7", func() Verdicts {
			v := cleanVerdicts()
			v.NetBird = VerdictAllowed
			return v
		}, 0.7, ExposureVPNEntry, true, false},
		{"internet and netbird denied is 0.4 and mitigated", func() Verdicts {
			return cleanVerdicts()
		}, 0.4, ExposureInternal, true, false},
		{"all zones denied, own segment not_filtered is 0.4, not mitigated", func() Verdicts {
			v := cleanVerdicts()
			v.OwnSegment = OwnSegmentVerdict{Class: ClassTrusted, Verdict: VerdictNotFiltered}
			return v
		}, 0.4, ExposureInternal, false, true},
		{"own segment untrusted reachable: 0.4, no mitigation", func() Verdicts {
			v := cleanVerdicts()
			v.OwnSegment = OwnSegmentVerdict{Class: ClassUntrusted, Verdict: VerdictAllowed}
			return v
		}, 0.4, ExposureInternal, false, false},
		{"own segment unknown class reachable: 0.4, no mitigation", func() Verdicts {
			v := cleanVerdicts()
			v.OwnSegment = OwnSegmentVerdict{Class: ClassUnknown, Verdict: VerdictConditional}
			return v
		}, 0.4, ExposureInternal, false, false},
		{"own segment unset class reachable: 0.4, no mitigation", func() Verdicts {
			v := cleanVerdicts()
			v.OwnSegment = OwnSegmentVerdict{Verdict: VerdictAllowed}
			return v
		}, 0.4, ExposureInternal, false, false},
		{"own segment untrusted and denied is mitigated", func() Verdicts {
			v := cleanVerdicts()
			v.OwnSegment = OwnSegmentVerdict{Class: ClassUntrusted, Verdict: VerdictDenied}
			return v
		}, 0.4, ExposureInternal, true, false},
		{"netbird bypass not_filtered stays 0.7, never mitigated", func() Verdicts {
			v := cleanVerdicts()
			v.NetBird = VerdictNotFiltered
			return v
		}, 0.7, ExposureVPNEntry, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mustV2(t, v2Input(freshRecord(tc.verdicts())))
			if !near(r.Terms.Exposure, tc.wantExpo) {
				t.Fatalf("exposure = %v, want %v", r.Terms.Exposure, tc.wantExpo)
			}
			if r.Exposure != tc.wantLevel {
				t.Fatalf("level = %q, want %q", r.Exposure, tc.wantLevel)
			}
			if r.Mitigated != tc.mitigated {
				t.Fatalf("Mitigated = %v, want %v", r.Mitigated, tc.mitigated)
			}
			if r.NotFiltered != tc.notFilt {
				t.Fatalf("NotFiltered = %v, want %v", r.NotFiltered, tc.notFilt)
			}
			if r.Reason != "" {
				t.Fatalf("valid record got reason %q", r.Reason)
			}
		})
	}
}

func TestV2NotFilteredSummaryFlag(t *testing.T) {
	v := cleanVerdicts()
	v.OwnSegment = OwnSegmentVerdict{Class: ClassTrusted, Verdict: VerdictNotFiltered}
	r := mustV2(t, v2Input(freshRecord(v)))
	if !r.NotFiltered {
		t.Fatal("own segment not_filtered must set NotFiltered (summary 'not filtered')")
	}
	if r.Mitigated {
		t.Fatal("own segment not_filtered must never count as mitigated")
	}
}

func TestV2PortForwardFromInternetStaysAtOneAndIsNeverMitigated(t *testing.T) {
	// A port forward from internet makes the source allowed (ADR 0012 D2
	// reverse-NAT lookup); the internal address alone would be denied.
	v := cleanVerdicts()
	v.Internet = VerdictAllowed
	r := mustV2(t, v2Input(freshRecord(v)))
	if !near(r.Terms.Exposure, 1.0) || r.Exposure != ExposureInternet {
		t.Fatalf("port forward: exposure %v level %q, want 1.0 internet", r.Terms.Exposure, r.Exposure)
	}
	if r.Mitigated {
		t.Fatal("port forward from internet must never be mitigated")
	}
	if r.Score != r.V1.Score {
		t.Fatalf("port forward score %d differs from v1 %d", r.Score, r.V1.Score)
	}
}

func TestV2NetBirdBypassStaysAtSevenTenths(t *testing.T) {
	v := cleanVerdicts()
	v.NetBird = VerdictNotFiltered
	r := mustV2(t, v2Input(freshRecord(v)))
	if !near(r.Terms.Exposure, 0.7) {
		t.Fatalf("netbird bypass exposure = %v, want 0.7", r.Terms.Exposure)
	}
	if r.Mitigated {
		t.Fatal("netbird bypass must not count as mitigated")
	}
}

func TestV2KEVFloorStillApplies(t *testing.T) {
	in := v2Input(freshRecord(cleanVerdicts()))
	in.Base.Scores.KEV = kev()
	in.Base.Criticality = inventory.CriticalityLow
	in.Base.Scores.CVSS = cvss(1)
	r := mustV2(t, in)
	if r.Tier.Rank() < TierHigh.Rank() {
		t.Fatalf("KEV tier = %q, want at least high", r.Tier)
	}
	if !r.V1.KEV {
		t.Fatal("KEV flag must carry through to the result")
	}
}

func TestV2KEVReachableFromInternetIsCritical(t *testing.T) {
	in := v2Input(freshRecord(Verdicts{
		Internet:   VerdictAllowed,
		NetBird:    VerdictDenied,
		Zones:      []ZoneVerdict{{Zone: "lan", Class: ClassTrusted, Verdict: VerdictDenied}},
		OwnSegment: OwnSegmentVerdict{Class: ClassTrusted, Verdict: VerdictDenied},
	}))
	in.Base.Scores.KEV = kev()
	r := mustV2(t, in)
	if r.Tier != TierCritical {
		t.Fatalf("KEV internet tier = %q, want critical", r.Tier)
	}
}

func TestV2FailClosedReasonsFallBackToV1(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MitigationRecord)
		want   string
	}{
		{"stale input", func(m *MitigationRecord) { m.InputsFresh = false }, "mitigation unknown: input stale or incomplete"},
		{"port unknown", func(m *MitigationRecord) { m.PortKnown = false }, "mitigation unknown: port unknown"},
		{"host addresses unknown", func(m *MitigationRecord) { m.HostAddressesKnown = false }, "mitigation unknown: host addresses unknown"},
		{"policy or object changed", func(m *MitigationRecord) { m.Reasons = []FailReason{ReasonPolicyChanged} }, "mitigation unknown: policy or object changed"},
		{"raw digest only", func(m *MitigationRecord) { m.Reasons = []FailReason{ReasonRawDigestOnly} }, "mitigation unknown: policy changed outside collected elements"},
		{"contradiction by flow or log", func(m *MitigationRecord) { m.Reasons = []FailReason{ReasonFlowContradiction} }, "mitigation unknown: contradicted by flow or log"},
		{"conditional deny then allow", func(m *MitigationRecord) { m.Reasons = []FailReason{ReasonConditionalDenyAllow} }, "mitigation unknown: conditional deny followed by allow"},
		{"unknown on netbird path", func(m *MitigationRecord) { m.Verdicts.NetBird = VerdictUnknown }, "mitigation unknown: unknown verdict on a mitigating path"},
		{"unknown in zone", func(m *MitigationRecord) { m.Verdicts.Zones[0].Verdict = VerdictUnknown }, "mitigation unknown: unknown verdict on a mitigating path"},
		{"unknown on own segment", func(m *MitigationRecord) { m.Verdicts.OwnSegment.Verdict = VerdictUnknown }, "mitigation unknown: unknown verdict on a mitigating path"},
		{"unrecognised verdict is unknown", func(m *MitigationRecord) { m.Verdicts.Internet = Verdict("bogus") }, "mitigation unknown: unknown verdict on a mitigating path"},
		{"empty verdict is unknown", func(m *MitigationRecord) { m.Verdicts.Internet = "" }, "mitigation unknown: unknown verdict on a mitigating path"},
		{"zone list missing", func(m *MitigationRecord) { m.Verdicts.Zones = nil }, "mitigation unknown: input stale or incomplete"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := freshRecord(cleanVerdicts())
			tc.mutate(&m)
			r := mustV2(t, v2Input(m))
			v1 := r.V1
			if r.Reason != tc.want {
				t.Fatalf("Reason = %q, want %q", r.Reason, tc.want)
			}
			if !near(r.Terms.Exposure, v1.Terms.Exposure) || r.Exposure != v1.Exposure {
				t.Fatalf("fallback exposure %v/%q, want v1 %v/%q", r.Terms.Exposure, r.Exposure, v1.Terms.Exposure, v1.Exposure)
			}
			if r.Score != v1.Score || r.Tier != v1.Tier {
				t.Fatalf("fallback score/tier %d/%q, want v1 %d/%q", r.Score, r.Tier, v1.Score, v1.Tier)
			}
			if r.Mitigated {
				t.Fatal("fallback must never be mitigated")
			}
		})
	}
}

func TestV2MultipleFailReasonsAreListedDeterministically(t *testing.T) {
	m := freshRecord(cleanVerdicts())
	m.PortKnown = false
	m.InputsFresh = false
	m.Reasons = []FailReason{ReasonPolicyChanged, ReasonPolicyChanged}
	r := mustV2(t, v2Input(m))
	want := "mitigation unknown: input stale or incomplete; policy or object changed; port unknown"
	if r.Reason != want {
		t.Fatalf("Reason = %q, want %q", r.Reason, want)
	}
}

func TestV2ReachabilityAboveV1FallsBackToV1(t *testing.T) {
	// v1 says internal (0.4) but the model finds internet reachable: the
	// v2 exposure never rises above v1 (ADR 0012 D3 lowers only).
	in := v2Input(freshRecord(Verdicts{
		Internet:   VerdictAllowed,
		NetBird:    VerdictDenied,
		Zones:      []ZoneVerdict{{Zone: "lan", Class: ClassTrusted, Verdict: VerdictDenied}},
		OwnSegment: OwnSegmentVerdict{Class: ClassTrusted, Verdict: VerdictDenied},
	}))
	in.Base.Exposure = ExposureInternal
	r := mustV2(t, in)
	if r.Reason != "mitigation unknown: reachability above v1 exposure" {
		t.Fatalf("Reason = %q", r.Reason)
	}
	if !near(r.Terms.Exposure, 0.4) || r.Score != r.V1.Score {
		t.Fatalf("exposure %v score %d, want v1 0.4 and %d", r.Terms.Exposure, r.Score, r.V1.Score)
	}
}

func TestV2NoListenerKeepsTwoTenths(t *testing.T) {
	// Fail-closed reasons do not matter without a listening service.
	in := v2Input(freshRecord(cleanVerdicts()))
	in.Base.Exposure = ExposureNoListener
	r := mustV2(t, in)
	if !near(r.Terms.Exposure, 0.2) || r.Exposure != ExposureNoListener {
		t.Fatalf("no listener: exposure %v level %q, want 0.2 no_listener", r.Terms.Exposure, r.Exposure)
	}
	if r.Mitigated || r.Reason != "" {
		t.Fatalf("no listener: Mitigated %v Reason %q, want false and empty", r.Mitigated, r.Reason)
	}
}

func TestV2ZeroRecordFailsClosed(t *testing.T) {
	// A zero MitigationRecord must never produce a mitigation.
	r := mustV2(t, InputV2{Base: base()})
	if r.Mitigated || !strings.HasPrefix(r.Reason, "mitigation unknown: ") {
		t.Fatalf("zero record: Mitigated %v Reason %q", r.Mitigated, r.Reason)
	}
	if !near(r.Terms.Exposure, 1.0) {
		t.Fatalf("zero record exposure = %v, want v1 1.0", r.Terms.Exposure)
	}
}

func TestV2RejectsInvalidBaseInput(t *testing.T) {
	in := v2Input(freshRecord(cleanVerdicts()))
	in.Base.Exposure = Exposure("bogus")
	_, err := ComputeV2(in)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestV2ResultCarriesFormulaAndV1Side(t *testing.T) {
	r := mustV2(t, v2Input(freshRecord(cleanVerdicts())))
	if r.Formula != FormulaVersionV2 {
		t.Fatalf("Formula = %q, want %q", r.Formula, FormulaVersionV2)
	}
	v1, err := Compute(base())
	if err != nil {
		t.Fatal(err)
	}
	if r.V1 != v1 {
		t.Fatalf("V1 side = %+v, want %+v", r.V1, v1)
	}
	if v1.Formula != FormulaVersion {
		t.Fatalf("v1 Formula = %q", v1.Formula)
	}
}

func TestV2IsPureAndDeterministic(t *testing.T) {
	in := v2Input(freshRecord(cleanVerdicts()))
	a := mustV2(t, in)
	for i := 0; i < 5; i++ {
		if b := mustV2(t, in); b.Score != a.Score || b.Tier != a.Tier || b.Reason != a.Reason || b.Mitigated != a.Mitigated {
			t.Fatalf("run %d differs", i)
		}
	}
}

func TestV2ExposureTermUsesV2OnlyForDenials(t *testing.T) {
	// Non-exposure terms come from v1 unchanged.
	in := v2Input(freshRecord(cleanVerdicts()))
	in.Base.Scores = vulnfinding.Scores{CVSS: cvss(7.5), EPSS: epss(0.3)}
	in.Base.Criticality = inventory.CriticalityMedium
	r := mustV2(t, in)
	if !near(r.Terms.CVSS, r.V1.Terms.CVSS) || !near(r.Terms.Exploit, r.V1.Terms.Exploit) || !near(r.Terms.Criticality, r.V1.Terms.Criticality) {
		t.Fatalf("v2 terms %+v differ from v1 %+v", r.Terms, r.V1.Terms)
	}
}

// FuzzComputeV2: a listening service is never below 0.4, v2 is never above
// v1, and KEV is never below high.
func FuzzComputeV2(f *testing.F) {
	f.Add(byte(255), byte(0), false, byte(0), byte(0), byte(0), byte(0), byte(0), true, true, true)
	f.Add(byte(200), byte(128), true, byte(3), byte(1), byte(2), byte(3), byte(4), true, true, false)
	f.Add(byte(10), byte(255), true, byte(5), byte(4), byte(5), byte(1), byte(0), false, false, true)
	f.Fuzz(func(t *testing.T, cvssB, eprB byte, isKEV bool, exB, critB, netB, intB, ownB byte, fresh, portKnown, hostKnown bool) {
		in := InputV2{Base: Input{
			Scores:      vulnfinding.Scores{CVSS: cvss(float64(cvssB) / 25.5)},
			Exposure:    fuzzExposure(exB),
			Criticality: fuzzCriticality(critB),
		}}
		if eprB != 0 {
			in.Base.Scores.EPSS = epss(float64(eprB) / 255)
		}
		if isKEV {
			in.Base.Scores.KEV = kev()
		}
		v := Verdicts{
			Internet:   fuzzVerdict(intB),
			NetBird:    fuzzVerdict(netB),
			Zones:      []ZoneVerdict{{Zone: "z", Class: ClassUntrusted, Verdict: fuzzVerdict(ownB)}},
			OwnSegment: OwnSegmentVerdict{Class: fuzzClass(ownB), Verdict: fuzzVerdict(intB ^ netB)},
		}
		in.Mitigation = MitigationRecord{InputsFresh: fresh, PortKnown: portKnown, HostAddressesKnown: hostKnown, Verdicts: v}

		r, err := ComputeV2(in)
		if err != nil {
			t.Fatalf("valid base rejected: %v", err)
		}
		if r.Terms.Exposure > r.V1.Terms.Exposure {
			t.Fatalf("v2 exposure %v above v1 %v", r.Terms.Exposure, r.V1.Terms.Exposure)
		}
		if in.Base.Exposure != ExposureNoListener && r.Terms.Exposure < exposureInternalW {
			t.Fatalf("listening service exposure %v below 0.4", r.Terms.Exposure)
		}
		if r.Score > r.V1.Score {
			t.Fatalf("v2 score %d above v1 %d", r.Score, r.V1.Score)
		}
		if isKEV && r.Tier.Rank() < TierHigh.Rank() {
			t.Fatalf("KEV tier %q below high", r.Tier)
		}
		if r.Mitigated && r.Reason != "" {
			t.Fatalf("mitigated result carries reason %q", r.Reason)
		}
		again, err := ComputeV2(in)
		if err != nil || again != r {
			t.Fatalf("not deterministic: %+v vs %+v (%v)", r, again, err)
		}
	})
}

func fuzzExposure(b byte) Exposure {
	all := []Exposure{ExposureInternet, ExposureVPNEntry, ExposureUnknown, ExposureInternal, ExposureNoListener, ""}
	return all[int(b)%len(all)]
}

func fuzzCriticality(b byte) inventory.Criticality {
	all := []inventory.Criticality{inventory.CriticalityCritical, inventory.CriticalityHigh, inventory.CriticalityMedium, inventory.CriticalityLow, ""}
	return all[int(b)%len(all)]
}

func fuzzVerdict(b byte) Verdict {
	all := []Verdict{VerdictAllowed, VerdictConditional, VerdictNotFiltered, VerdictUnknown, VerdictDenied, Verdict("bogus")}
	return all[int(b)%len(all)]
}

func fuzzClass(b byte) TrustClass {
	all := []TrustClass{ClassTrusted, ClassGuest, ClassIoT, ClassUntrusted, ClassUnknown, ""}
	return all[int(b)%len(all)]
}
