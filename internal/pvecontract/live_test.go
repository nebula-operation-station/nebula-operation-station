// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"bytes"
	"errors"
	"math"
	"strings"
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

// validLiveWantFixture returns a fresh, valid want-list on every call, so
// mutations in one test case can never leak into another through a shared
// Targets backing array.
func validLiveWantFixture() LiveWant {
	return mkLiveWant(1000, 1030, LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "pve1"})
}

func TestLiveWantRejectsLimits(t *testing.T) {
	if _, err := ValidateLiveWant(validLiveWantFixture()); err != nil {
		t.Fatalf("ValidateLiveWant rejected the base fixture: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*LiveWant)
		want string // problem text the rejection must contain
	}{
		{"wrong version", func(w *LiveWant) { w.Version = 2 }, "version must be"},
		{"negative written", func(w *LiveWant) { w.WrittenUnix = -1 }, "written_unix must be non-negative"},
		{"negative expires", func(w *LiveWant) { w.ExpiresUnix = -1 }, "expires_unix must be non-negative"},
		{"expires before written", func(w *LiveWant) { w.ExpiresUnix = w.WrittenUnix - 1 }, "expires_unix must be at least written_unix"},
		{"expires too far", func(w *LiveWant) { w.ExpiresUnix = w.WrittenUnix + LiveWantMaxExpiry + 1 }, "after written_unix"},
		{"bad remote", func(w *LiveWant) { w.Targets[0].Remote = "Bad_Remote" }, "remote \"Bad_Remote\" is malformed"},
		{"bad node", func(w *LiveWant) { w.Targets[0].Node = "bad node" }, "node \"bad node\" is malformed"},
		{"bad kind", func(w *LiveWant) { w.Targets[0].Kind = "bogus" }, "kind \"bogus\" is unknown"},
		{"node vmid nonzero", func(w *LiveWant) { w.Targets[0].VMID = 101 }, "vmid must be 0 for kind node"},
		{"qemu vmid low", func(w *LiveWant) { w.Targets[0].Kind = LiveKindQEMU; w.Targets[0].VMID = MinVMID - 1 }, "out of range"},
		{"qemu vmid high", func(w *LiveWant) { w.Targets[0].Kind = LiveKindQEMU; w.Targets[0].VMID = MaxVMID + 1 }, "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := validLiveWantFixture()
			tc.mut(&w)
			_, err := ValidateLiveWant(w)
			if err == nil {
				t.Fatal("ValidateLiveWant accepted an invalid want-list")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) || len(ve.Problems) != 1 || !strings.Contains(ve.Problems[0], tc.want) {
				t.Fatalf("ValidateLiveWant error = %v, want exactly one problem containing %q", err, tc.want)
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

// validLiveSamplesFixture returns a fresh, valid samples document on every
// call, so mutations in one test case can never leak into another through a
// shared Samples backing array.
func validLiveSamplesFixture() LiveSamples {
	return mkLiveSamples("remote-a", 1000, mkLiveSample(LiveKindNode, "pve1", 0, 0.5))
}

func TestLiveSamplesRejectsLimits(t *testing.T) {
	if _, err := ValidateLiveSamples(validLiveSamplesFixture()); err != nil {
		t.Fatalf("ValidateLiveSamples rejected the base fixture: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*LiveSamples)
		want string // problem text the rejection must contain
	}{
		{"wrong version", func(s *LiveSamples) { s.Version = 2 }, "version must be"},
		{"bad remote", func(s *LiveSamples) { s.Remote = "Bad_Remote" }, "remote \"Bad_Remote\" is malformed"},
		{"negative written", func(s *LiveSamples) { s.WrittenUnix = -1 }, "written_unix must be non-negative"},
		{"bad node", func(s *LiveSamples) { s.Samples[0].Node = "bad node" }, "node \"bad node\" is malformed"},
		{"bad kind", func(s *LiveSamples) { s.Samples[0].Kind = "bogus" }, "kind \"bogus\" is unknown"},
		{"node vmid nonzero", func(s *LiveSamples) { s.Samples[0].VMID = 101 }, "vmid must be 0 for kind node"},
		{"qemu vmid low", func(s *LiveSamples) { s.Samples[0].Kind = LiveKindQEMU; s.Samples[0].VMID = MinVMID - 1 }, "out of range"},
		{"qemu vmid high", func(s *LiveSamples) { s.Samples[0].Kind = LiveKindQEMU; s.Samples[0].VMID = MaxVMID + 1 }, "out of range"},
		{"cpu negative", func(s *LiveSamples) { s.Samples[0].CPU = -0.1 }, "cpu must be in [0,1]"},
		{"cpu above one", func(s *LiveSamples) { s.Samples[0].CPU = 1.1 }, "cpu must be in [0,1]"},
		{"mem negative", func(s *LiveSamples) { s.Samples[0].MemUsed = -1 }, "mem_used must be finite"},
		{"observed negative", func(s *LiveSamples) { s.Samples[0].ObservedUnix = -1 }, "observed_unix must be non-negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validLiveSamplesFixture()
			tc.mut(&s)
			_, err := ValidateLiveSamples(s)
			if err == nil {
				t.Fatal("ValidateLiveSamples accepted an invalid document")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) || len(ve.Problems) != 1 || !strings.Contains(ve.Problems[0], tc.want) {
				t.Fatalf("ValidateLiveSamples error = %v, want exactly one problem containing %q", err, tc.want)
			}
		})
	}
}

func TestLiveSamplesAcceptsMaxSamples(t *testing.T) {
	samples := make([]LiveSample, 0, MaxLiveSamples)
	for i := 0; i < MaxLiveSamples; i++ {
		samples = append(samples, mkLiveSample(LiveKindQEMU, "pve1", MinVMID+uint64(i), 0.5))
	}
	if _, err := ValidateLiveSamples(mkLiveSamples("remote-a", 1000, samples...)); err != nil {
		t.Fatalf("ValidateLiveSamples rejected %d samples: %v", MaxLiveSamples, err)
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

func TestLiveWantRejectsFutureDated(t *testing.T) {
	const now = 1000
	cases := []struct {
		name             string
		written, expires int64
		live             bool
	}{
		{"current", now, now + LiveWantMaxExpiry, true},
		{"written within skew", now + LiveClockSkew, now + LiveWantMaxExpiry, true},
		{"written beyond skew", now + LiveClockSkew + 1, now + LiveClockSkew + 1, false},
		{"far future", now + 1_000_000, now + 1_000_000 + LiveWantMaxExpiry, false},
		{"expires beyond cap", now, now + LiveWantMaxExpiry + 1, false},
		{"skew does not extend the cap", now + LiveClockSkew, now + LiveClockSkew + LiveWantMaxExpiry, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := mkLiveWant(tc.written, tc.expires)
			err := w.CheckClock(now)
			if tc.live {
				if err != nil || !w.Live(now) {
					t.Fatalf("CheckClock = %v, Live = %v; want accepted", err, w.Live(now))
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("CheckClock = %v, want ErrInvalid", err)
			}
			if w.Live(now) {
				t.Fatal("Live accepted a future-dated want-list")
			}
		})
	}
}

func TestLiveWantCheckClockExpiresAlone(t *testing.T) {
	// written_unix is within skew, only expires_unix is too far ahead. The
	// format check alone would reject this too, so build the document
	// without ValidateLiveWant to isolate the clock check.
	w := LiveWant{Version: LiveWantVersion, WrittenUnix: 1000, ExpiresUnix: 1000 + LiveWantMaxExpiry + 1}
	if err := w.CheckClock(1000); err == nil || !strings.Contains(err.Error(), "expires_unix is more than") {
		t.Fatalf("CheckClock = %v, want expires_unix rejection", err)
	}
}

func TestLiveSamplesRejectsFutureDated(t *testing.T) {
	const now = 1000
	cases := []struct {
		name     string
		mut      func(*LiveSamples)
		accepted bool
	}{
		{"current", func(*LiveSamples) {}, true},
		{"written within skew", func(s *LiveSamples) { s.WrittenUnix = now + LiveClockSkew }, true},
		{"written beyond skew", func(s *LiveSamples) { s.WrittenUnix = now + LiveClockSkew + 1 }, false},
		{"written far future", func(s *LiveSamples) { s.WrittenUnix = now + 1_000_000 }, false},
		{"observed within skew", func(s *LiveSamples) { s.Samples[0].ObservedUnix = now + LiveClockSkew }, true},
		{"observed beyond skew", func(s *LiveSamples) { s.Samples[0].ObservedUnix = now + LiveClockSkew + 1 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validLiveSamplesFixture()
			tc.mut(&s)
			err := s.CheckClock(now)
			if tc.accepted && err != nil {
				t.Fatalf("CheckClock rejected a current document: %v", err)
			}
			if !tc.accepted && !errors.Is(err, ErrInvalid) {
				t.Fatalf("CheckClock = %v, want ErrInvalid", err)
			}
		})
	}
}
