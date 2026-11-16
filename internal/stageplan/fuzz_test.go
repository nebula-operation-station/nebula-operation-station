// SPDX-License-Identifier: AGPL-3.0-or-later

package stageplan

import (
	"errors"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// fuzzTargets is the fixed target list every fuzzed document is parsed
// against.
var fuzzTargets = []string{"a", "b", "c"}

// FuzzParse checks that Parse never panics, refuses every malformed document
// with ErrInvalid, and that every accepted plan is consistent with its
// document: it covers the targets once, stays within the limits, hashes to
// the value of its canonical encoding and survives a round trip.
func FuzzParse(f *testing.F) {
	valid, err := Encode([]Stage{
		{Name: "canary", Hosts: []string{"a"}, Continue: ContinueAuto, TimeoutS: 60},
		{Name: "rest", Hosts: []string{"b", "c"}, MaxFailed: 1, MaxUnreachable: 2, Continue: ContinueManual, TimeoutS: 600},
	})
	if err != nil {
		f.Fatal(err)
	}
	seeds := [][]byte{
		valid,
		valid[:len(valid)-1],
		append(append([]byte{}, valid...), " x"...),
		[]byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b","c"],"max_failed":0,"max_unreachable":0,"continue":"manual","timeout_s":60,"extra":1}]}`),
		[]byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b","c"],"max_failed":0,"max_failed":2,"max_unreachable":0,"continue":"manual","timeout_s":60}]}`),
		[]byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b","c"],"max_failed":0,"MAX_FAILED":2,"max_unreachable":0,"continue":"manual","timeout_s":60}]}`),
		[]byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b","c"],"max_failed":1.0,"max_unreachable":0,"continue":"manual","timeout_s":60}]}`),
		[]byte(`{"plan":"stages-v1","stages":[]}`),
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(``),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Parse(raw, fuzzTargets)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			return
		}
		checkAccepted(t, p)
		_ = p.AutoContinue()
	})
}

// checkAccepted asserts the invariants of a plan that Parse has accepted for
// fuzzTargets.
func checkAccepted(t *testing.T, p Plan) {
	t.Helper()
	if n := len(p.Stages); n < 1 || n > MaxStages {
		t.Fatalf("accepted plan has %d stages, want 1 to %d", n, MaxStages)
	}
	covered := map[string]int{}
	for _, s := range p.Stages {
		for _, h := range s.Hosts {
			covered[h]++
		}
	}
	for _, target := range fuzzTargets {
		if covered[target] != 1 {
			t.Fatalf("target %q is in %d stages, want 1", target, covered[target])
		}
	}
	if len(covered) != len(fuzzTargets) {
		t.Fatalf("stages name %d hosts, want %d", len(covered), len(fuzzTargets))
	}
	enc, err := Encode(p.Stages)
	if err != nil {
		t.Fatalf("Encode of accepted stages: %v", err)
	}
	if h, err := canonical.HashParameters(enc); err != nil || h != p.Hash {
		t.Fatalf("hash of Encode output = %q (%v), want %q", h, err, p.Hash)
	}
	again, err := Parse(enc, fuzzTargets)
	if err != nil {
		t.Fatalf("Parse of Encode output: %v", err)
	}
	if again.Hash != p.Hash {
		t.Fatalf("round trip changed hash: %q, want %q", again.Hash, p.Hash)
	}
	if d := p.Duration(); d < MinTimeout || d > MaxStages*MaxTimeout {
		t.Fatalf("Duration() = %d, want %d to %d", d, MinTimeout, MaxStages*MaxTimeout)
	}
}
