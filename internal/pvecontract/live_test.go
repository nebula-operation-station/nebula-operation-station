// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"bytes"
	"math"
	"testing"
)

func mkLiveWant(written, expires int64, targets ...LiveTarget) LiveWant {
	return LiveWant{
		Version:     LiveWantVersion,
		WrittenUnix: written,
		ExpiresUnix: expires,
		Targets:     targets,
	}
}

func mkLiveSample(kind, node string, vmid uint64, cpu float64) LiveSample {
	return LiveSample{
		Kind: kind, Node: node, VMID: vmid, CPU: cpu,
		MemUsed: 100, MemTotal: 200, DiskUsed: 1000, DiskTotal: 2000,
		NetIn: 10, NetOut: 20, ObservedUnix: 1000,
	}
}

func mkLiveSamples(remote string, written int64, samples ...LiveSample) LiveSamples {
	return LiveSamples{
		Version:     LiveSamplesVersion,
		Remote:      remote,
		WrittenUnix: written,
		Samples:     samples,
	}
}

func TestLiveWantRoundTrip(t *testing.T) {
	w := mkLiveWant(1000, 1030,
		LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "pve1"},
		LiveTarget{Remote: "remote-a", Kind: LiveKindQEMU, Node: "pve1", VMID: 101},
		LiveTarget{Remote: "remote-b", Kind: LiveKindLXC, Node: "pve2", VMID: 100},
	)
	raw, err := MarshalLiveWant(w)
	if err != nil {
		t.Fatalf("MarshalLiveWant: %v", err)
	}
	got, err := DecodeLiveWant(raw)
	if err != nil {
		t.Fatalf("DecodeLiveWant: %v", err)
	}
	if got.WrittenUnix != 1000 || got.ExpiresUnix != 1030 || len(got.Targets) != 3 {
		t.Fatalf("round trip = %+v", got)
	}
	if got.Targets[1].VMID != 101 || got.Targets[1].Kind != LiveKindQEMU {
		t.Fatalf("target 1 = %+v", got.Targets[1])
	}
}

func TestLiveWantDeduplicates(t *testing.T) {
	w := mkLiveWant(1000, 1030,
		LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "pve1"},
		LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "pve1"}, // duplicate
		LiveTarget{Remote: "remote-a", Kind: LiveKindQEMU, Node: "pve1", VMID: 101},
	)
	raw, err := MarshalLiveWant(w)
	if err != nil {
		t.Fatalf("MarshalLiveWant: %v", err)
	}
	got, err := DecodeLiveWant(raw)
	if err != nil {
		t.Fatalf("DecodeLiveWant: %v", err)
	}
	if len(got.Targets) != 2 {
		t.Fatalf("deduped targets = %d, want 2: %+v", len(got.Targets), got.Targets)
	}
}

func TestLiveWantRejectsLimits(t *testing.T) {
	valid := mkLiveWant(1000, 1030, LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "pve1"})
	cases := []struct {
		name string
		mut  func(*LiveWant)
	}{
		{"wrong version", func(w *LiveWant) { w.Version = 2 }},
		{"negative written", func(w *LiveWant) { w.WrittenUnix = -1 }},
		{"negative expires", func(w *LiveWant) { w.ExpiresUnix = -1 }},
		{"expires before written", func(w *LiveWant) { w.ExpiresUnix = w.WrittenUnix - 1 }},
		{"expires too far", func(w *LiveWant) { w.ExpiresUnix = w.WrittenUnix + LiveWantMaxExpiry + 1 }},
		{"bad remote", func(w *LiveWant) { w.Targets[0].Remote = "Bad_Remote" }},
		{"bad node", func(w *LiveWant) { w.Targets[0].Node = "bad node" }},
		{"bad kind", func(w *LiveWant) { w.Targets[0].Kind = "bogus" }},
		{"node vmid nonzero", func(w *LiveWant) { w.Targets[0].VMID = 101 }},
		{"qemu vmid low", func(w *LiveWant) { w.Targets[0].Kind = LiveKindQEMU; w.Targets[0].VMID = MinVMID - 1 }},
		{"qemu vmid high", func(w *LiveWant) { w.Targets[0].Kind = LiveKindQEMU; w.Targets[0].VMID = MaxVMID + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := valid
			tc.mut(&w)
			if _, err := ValidateLiveWant(w); err == nil {
				t.Fatal("ValidateLiveWant accepted an invalid want-list")
			}
		})
	}
}

func TestLiveWantRejectsTooManyTargets(t *testing.T) {
	targets := make([]LiveTarget, 0, MaxLiveTargets+1)
	for i := 0; i <= MaxLiveTargets; i++ {
		targets = append(targets, LiveTarget{Remote: "remote-a", Kind: LiveKindQEMU, Node: "pve1", VMID: MinVMID + uint64(i)})
	}
	if _, err := ValidateLiveWant(mkLiveWant(1000, 1030, targets...)); err == nil {
		t.Fatalf("ValidateLiveWant accepted %d targets", len(targets))
	}
}

func TestLiveWantRejectsOversizeRaw(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), MaxLiveWantBytes+1)
	if _, err := DecodeLiveWant(raw); err == nil {
		t.Fatal("DecodeLiveWant accepted an oversize document")
	}
}

func TestLiveWantRejectsUnknownField(t *testing.T) {
	top := []byte(`{"bogus":true,`)
	valid, err := MarshalLiveWant(mkLiveWant(1000, 1030))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLiveWant(append(top, valid[1:]...)); err == nil {
		t.Fatal("DecodeLiveWant accepted an unknown top-level field")
	}
	nested := []byte(`{"version":1,"written_unix":1000,"expires_unix":1030,"targets":[{"remote":"remote-a","kind":"node","node":"pve1","vmid":0,"extra":1}]}`)
	if _, err := DecodeLiveWant(nested); err == nil {
		t.Fatal("DecodeLiveWant accepted an unknown target field")
	}
}

func TestLiveWantExpired(t *testing.T) {
	w := mkLiveWant(1000, 1030)
	if w.Expired(1029) {
		t.Fatal("want-list expired before the deadline")
	}
	if !w.Expired(1030) {
		t.Fatal("want-list not expired at the deadline")
	}
	if !w.Expired(1031) {
		t.Fatal("want-list not expired after the deadline")
	}
}

func TestLiveSamplesRoundTrip(t *testing.T) {
	s := mkLiveSamples("remote-a", 1000,
		mkLiveSample(LiveKindNode, "pve1", 0, 0.5),
		mkLiveSample(LiveKindQEMU, "pve1", 101, 0.9),
	)
	raw, err := MarshalLiveSamples(s)
	if err != nil {
		t.Fatalf("MarshalLiveSamples: %v", err)
	}
	got, err := DecodeLiveSamples(raw)
	if err != nil {
		t.Fatalf("DecodeLiveSamples: %v", err)
	}
	if got.Remote != "remote-a" || len(got.Samples) != 2 {
		t.Fatalf("round trip = %+v", got)
	}
	if got.Samples[1].CPU != 0.9 || got.Samples[1].VMID != 101 {
		t.Fatalf("sample 1 = %+v", got.Samples[1])
	}
}

func TestLiveSamplesRejectsLimits(t *testing.T) {
	valid := mkLiveSamples("remote-a", 1000, mkLiveSample(LiveKindNode, "pve1", 0, 0.5))
	cases := []struct {
		name string
		mut  func(*LiveSamples)
	}{
		{"wrong version", func(s *LiveSamples) { s.Version = 2 }},
		{"bad remote", func(s *LiveSamples) { s.Remote = "Bad_Remote" }},
		{"negative written", func(s *LiveSamples) { s.WrittenUnix = -1 }},
		{"bad node", func(s *LiveSamples) { s.Samples[0].Node = "bad node" }},
		{"bad kind", func(s *LiveSamples) { s.Samples[0].Kind = "bogus" }},
		{"node vmid nonzero", func(s *LiveSamples) { s.Samples[0].VMID = 101 }},
		{"cpu negative", func(s *LiveSamples) { s.Samples[0].CPU = -0.1 }},
		{"cpu above one", func(s *LiveSamples) { s.Samples[0].CPU = 1.1 }},
		{"mem negative", func(s *LiveSamples) { s.Samples[0].MemUsed = -1 }},
		{"observed negative", func(s *LiveSamples) { s.Samples[0].ObservedUnix = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := valid
			tc.mut(&s)
			if _, err := ValidateLiveSamples(s); err == nil {
				t.Fatal("ValidateLiveSamples accepted an invalid document")
			}
		})
	}
}

func TestLiveSamplesRejectsTooManySamples(t *testing.T) {
	samples := make([]LiveSample, 0, MaxLiveSamples+1)
	for i := 0; i <= MaxLiveSamples; i++ {
		samples = append(samples, mkLiveSample(LiveKindQEMU, "pve1", MinVMID+uint64(i), 0.5))
	}
	if _, err := ValidateLiveSamples(mkLiveSamples("remote-a", 1000, samples...)); err == nil {
		t.Fatalf("ValidateLiveSamples accepted %d samples", len(samples))
	}
}

func TestLiveSamplesRejectsOversizeRaw(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), MaxLiveSamplesBytes+1)
	if _, err := DecodeLiveSamples(raw); err == nil {
		t.Fatal("DecodeLiveSamples accepted an oversize document")
	}
}

func TestLiveSamplesRejectsUnknownField(t *testing.T) {
	raw := []byte(`{"version":1,"remote":"remote-a","written_unix":1000,"samples":[{"kind":"node","node":"pve1","vmid":0,"cpu":0.5,"mem_used":1,"mem_total":2,"disk_used":1,"disk_total":2,"net_in":1,"net_out":1,"observed_unix":1,"extra":true}]}`)
	if _, err := DecodeLiveSamples(raw); err == nil {
		t.Fatal("DecodeLiveSamples accepted an unknown sample field")
	}
}

func TestLiveSamplesRejectsNonFinite(t *testing.T) {
	mk := func(mut func(*LiveSample)) LiveSample {
		s := mkLiveSample(LiveKindNode, "pve1", 0, 0.5)
		mut(&s)
		return s
	}
	cases := []struct {
		name string
		s    LiveSample
	}{
		{"cpu nan", mk(func(s *LiveSample) { s.CPU = math.NaN() })},
		{"cpu +inf", mk(func(s *LiveSample) { s.CPU = math.Inf(1) })},
		{"cpu -inf", mk(func(s *LiveSample) { s.CPU = math.Inf(-1) })},
		{"mem nan", mk(func(s *LiveSample) { s.MemUsed = math.NaN() })},
		{"mem +inf", mk(func(s *LiveSample) { s.MemTotal = math.Inf(1) })},
		{"disk -inf", mk(func(s *LiveSample) { s.DiskUsed = math.Inf(-1) })},
		{"net_in nan", mk(func(s *LiveSample) { s.NetIn = math.NaN() })},
		{"net_out +inf", mk(func(s *LiveSample) { s.NetOut = math.Inf(1) })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateLiveSamples(mkLiveSamples("remote-a", 1000, tc.s)); err == nil {
				t.Fatal("ValidateLiveSamples accepted a non-finite sample")
			}
		})
	}
}

func TestLiveSamplesRejectsInfFromJSON(t *testing.T) {
	raw := []byte(`{"version":1,"remote":"remote-a","written_unix":1000,"samples":[{"kind":"node","node":"pve1","vmid":0,"cpu":1e999,"mem_used":1,"mem_total":2,"disk_used":1,"disk_total":2,"net_in":1,"net_out":1,"observed_unix":1}]}`)
	if _, err := DecodeLiveSamples(raw); err == nil {
		t.Fatal("DecodeLiveSamples accepted an infinite cpu value")
	}
}
