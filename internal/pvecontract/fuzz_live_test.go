// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

// checkLiveWantOracle asserts the decoder's success contract on w: every
// named bound of the package holds, re-encoding and decoding again yields the
// same value, and validating the decoded value changes nothing.
func checkLiveWantOracle(t *testing.T, w LiveWant) {
	t.Helper()
	if w.Version != LiveWantVersion {
		t.Fatalf("accepted version %d", w.Version)
	}
	if w.WrittenUnix < 0 || w.ExpiresUnix < w.WrittenUnix || w.ExpiresUnix-w.WrittenUnix > LiveWantMaxExpiry {
		t.Fatalf("accepted expiry window written=%d expires=%d", w.WrittenUnix, w.ExpiresUnix)
	}
	if len(w.Targets) > MaxLiveTargets {
		t.Fatalf("accepted %d targets (max %d)", len(w.Targets), MaxLiveTargets)
	}
	for i, tg := range w.Targets {
		if !ValidRemoteID(tg.Remote) || !ValidNodeName(tg.Node) {
			t.Fatalf("target %d accepted with remote %q node %q", i, tg.Remote, tg.Node)
		}
		switch tg.Kind {
		case LiveKindNode:
			if tg.VMID != 0 {
				t.Fatalf("target %d: node target with vmid %d", i, tg.VMID)
			}
		case LiveKindQEMU, LiveKindLXC:
			if tg.VMID < MinVMID || tg.VMID > MaxVMID {
				t.Fatalf("target %d: vmid %d out of range", i, tg.VMID)
			}
		default:
			t.Fatalf("target %d: kind %q accepted", i, tg.Kind)
		}
	}
	again, err := ValidateLiveWant(w)
	if err != nil || !reflect.DeepEqual(again, w) {
		t.Fatalf("validation of a decoded want-list changed it: %+v -> %+v (%v)", w, again, err)
	}
	raw, err := MarshalLiveWant(w)
	if err != nil {
		t.Fatalf("re-encode of an accepted want-list: %v", err)
	}
	back, err := DecodeLiveWant(raw)
	if err != nil {
		t.Fatalf("decode of re-encoded want-list: %v", err)
	}
	if !reflect.DeepEqual(back, w) {
		t.Fatalf("round trip changed the value: %+v -> %+v", w, back)
	}
}

// FuzzDecodeLiveWant feeds arbitrary bytes to the want-list decoder. It must
// never panic, and an accepted document must satisfy every named bound and
// survive a re-encode round trip unchanged.
func FuzzDecodeLiveWant(f *testing.F) {
	for _, w := range []LiveWant{
		mkLiveWant(1000, 1030,
			LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "pve1"},
			LiveTarget{Remote: "remote-a", Kind: LiveKindQEMU, Node: "pve1", VMID: 101},
			LiveTarget{Remote: "remote-b", Kind: LiveKindLXC, Node: "pve2", VMID: 100},
		),
		mkLiveWant(1000, 1030,
			LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "pve1"},
			LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "pve1"},
		),
		mkLiveWant(1000, 1000),
	} {
		raw, err := MarshalLiveWant(w)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{"version":1,"written_unix":1000,"expires_unix":1030,"targets":null}`))
	f.Add([]byte(`{"version":1,"written_unix":1000,"expires_unix":1031,"targets":[]}`))
	f.Add([]byte(`{"version":1.0,"written_unix":1e3,"expires_unix":1030,"targets":[]}`))
	f.Add([]byte(`{"version":1,"written_unix":-1,"expires_unix":1030}`))
	f.Add([]byte(`{"version":1,"written_unix":1000,"expires_unix":1030,"targets":[{"remote":"a","kind":"qemu","node":"n","vmid":1e3}]}`))
	f.Add([]byte(`{"version":1,"written_unix":1000,"expires_unix":1030,"targets":[]}{}`))
	f.Add([]byte(`{"version":1,"written_unix":1000,"expires_unix":1030,"targets":[{"remote":"a\u0000","kind":"node","node":"n"}]}`))
	f.Add([]byte(strings.Repeat(`{"a":`, MaxNesting+5) + `1` + strings.Repeat(`}`, MaxNesting+5)))
	f.Fuzz(func(t *testing.T, data []byte) {
		w, err := DecodeLiveWant(data)
		if err != nil {
			return
		}
		checkLiveWantOracle(t, w)
	})
}

// checkLiveSamplesOracle asserts the decoder's success contract on s: every
// number is finite and within its range, text is ASCII that the validators
// accept, every named bound holds, and a re-encode round trip is exact.
func checkLiveSamplesOracle(t *testing.T, s LiveSamples) {
	t.Helper()
	if s.Version != LiveSamplesVersion || !ValidRemoteID(s.Remote) || s.WrittenUnix < 0 {
		t.Fatalf("accepted header version=%d remote=%q written=%d", s.Version, s.Remote, s.WrittenUnix)
	}
	if len(s.Samples) > MaxLiveSamples {
		t.Fatalf("accepted %d samples (max %d)", len(s.Samples), MaxLiveSamples)
	}
	for i, smp := range s.Samples {
		if !ValidNodeName(smp.Node) {
			t.Fatalf("sample %d accepted with node %q", i, smp.Node)
		}
		switch smp.Kind {
		case LiveKindNode:
			if smp.VMID != 0 {
				t.Fatalf("sample %d: node sample with vmid %d", i, smp.VMID)
			}
		case LiveKindQEMU, LiveKindLXC:
			if smp.VMID < MinVMID || smp.VMID > MaxVMID {
				t.Fatalf("sample %d: vmid %d out of range", i, smp.VMID)
			}
		default:
			t.Fatalf("sample %d: kind %q accepted", i, smp.Kind)
		}
		if math.IsNaN(smp.CPU) || math.IsInf(smp.CPU, 0) || smp.CPU < 0 || smp.CPU > 1 {
			t.Fatalf("sample %d: cpu %v accepted", i, smp.CPU)
		}
		for name, v := range map[string]float64{
			"mem_used": smp.MemUsed, "mem_total": smp.MemTotal,
			"disk_used": smp.DiskUsed, "disk_total": smp.DiskTotal,
			"net_in": smp.NetIn, "net_out": smp.NetOut,
		} {
			if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
				t.Fatalf("sample %d: %s = %v accepted", i, name, v)
			}
		}
		if smp.ObservedUnix < 0 {
			t.Fatalf("sample %d: observed_unix %d accepted", i, smp.ObservedUnix)
		}
	}
	again, err := ValidateLiveSamples(s)
	if err != nil || !reflect.DeepEqual(again, s) {
		t.Fatalf("validation of a decoded samples document changed it (%v)", err)
	}
	raw, err := MarshalLiveSamples(s)
	if err != nil {
		t.Fatalf("re-encode of an accepted samples document: %v", err)
	}
	back, err := DecodeLiveSamples(raw)
	if err != nil {
		t.Fatalf("decode of re-encoded samples document: %v", err)
	}
	if !reflect.DeepEqual(back, s) {
		t.Fatalf("round trip changed the value: %+v -> %+v", s, back)
	}
}

// FuzzDecodeLiveSamples feeds arbitrary bytes to the samples decoder. It must
// never panic; an accepted document holds no NaN or Inf, its text is valid
// ASCII identifiers, every bound holds, and it round-trips exactly.
func FuzzDecodeLiveSamples(f *testing.F) {
	for _, s := range []LiveSamples{
		mkLiveSamples("remote-a", 1000,
			mkLiveSample(LiveKindNode, "pve1", 0, 0.5),
			mkLiveSample(LiveKindQEMU, "pve1", 101, 0.9),
		),
		mkLiveSamples("remote-a", 1000),
		mkLiveSamples("remote-a", 1000, mkLiveSample(LiveKindLXC, "pve.lab-1", MinVMID, 0)),
	} {
		raw, err := MarshalLiveSamples(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{"version":1,"remote":"remote-a","written_unix":1000,"samples":null}`))
	f.Add([]byte(`{"version":1,"remote":"remote-a","written_unix":1000,"samples":[{"kind":"node","node":"pve1","vmid":0,"cpu":1e999,"mem_used":1,"mem_total":2,"disk_used":1,"disk_total":2,"net_in":1,"net_out":1,"observed_unix":1}]}`))
	f.Add([]byte(`{"version":1,"remote":"remote-a","written_unix":1000,"samples":[{"kind":"node","node":"pve1\n","vmid":0,"cpu":-0,"mem_used":-0,"mem_total":2,"disk_used":1,"disk_total":2,"net_in":1,"net_out":1,"observed_unix":1}]}`))
	f.Add([]byte(`{"version":1,"remote":"remote-a","written_unix":1000,"samples":[{"kind":"node","node":"pve1","vmid":0,"cpu":NaN}]}`))
	f.Add([]byte(`{"version":1,"remote":"remote-a","written_unix":1000,"samples":[{"kind":"qemu","node":"pve1","vmid":1e300,"cpu":0.5}]}`))
	f.Add([]byte(strings.Repeat(`{"a":`, MaxNesting+5) + `1` + strings.Repeat(`}`, MaxNesting+5)))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := DecodeLiveSamples(data)
		if err != nil {
			return
		}
		checkLiveSamplesOracle(t, s)
	})
}
