// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// near reports whether got equals the hand-computed want up to float
// rounding of a handful of operations.
func near(got, want float64) bool {
	return math.Abs(got-want) <= 1e-12*math.Max(1, math.Abs(want))
}

func TestParseCVSS3ExploitabilityHandComputed(t *testing.T) {
	// X = 8.22 × AV × AC × PR × UI, values from CVSS v3.1 section 7.4,
	// multiplied out by hand.
	cases := []struct {
		vector string
		av     AttackVector
		x      float64
	}{
		// 8.22 × 0.85 × 0.77 × 0.85 × 0.85
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", AVNetwork, 3.887042775},
		// 8.22 × 0.55 × 0.77 × 0.62 × 0.85
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", AVLocal, 1.83457659},
		// changed scope: PR:L is 0.68. 8.22 × 0.85 × 0.44 × 0.68 × 0.62
		{"CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N", AVNetwork, 1.296116448},
		// 8.22 × 0.62 × 0.77 × 0.85 × 0.85
		{"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", AVAdjacent, 2.83525473},
		// 8.22 × 0.2 × 0.44 × 0.27 × 0.62; temporal metrics are ignored
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N/E:P/RL:O/RC:C", AVPhysical, 0.121090464},
		// metric order does not matter
		{"CVSS:3.1/S:U/UI:N/PR:N/AC:L/AV:N/A:H/I:H/C:H", AVNetwork, 3.887042775},
	}
	for _, c := range cases {
		got, ok := parseCVSS3(c.vector)
		if !ok {
			t.Fatalf("%s: rejected", c.vector)
		}
		if got.av != c.av || !near(got.x, c.x) {
			t.Fatalf("%s: av %v x %v, want %v %v", c.vector, got.av, got.x, c.av, c.x)
		}
	}
}

func TestParseCVSS3RejectsMalformedVectors(t *testing.T) {
	base := "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	for name, v := range map[string]string{
		"empty":            "",
		"no prefix":        base,
		"v2":               "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"v4":               "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"missing metric":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
		"duplicate metric": "CVSS:3.1/" + base + "/AV:L",
		"unknown metric":   "CVSS:3.1/" + base + "/XX:N",
		"environmental":    "CVSS:3.1/" + base + "/MAV:N",
		"bad value":        "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"long value":       "CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"empty part":       "CVSS:3.1/" + base + "/",
		"no colon":         "CVSS:3.1/" + base + "/E",
		"non-ascii":        "CVSS:3.1/AV:Ν/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"too long":         "CVSS:3.1/" + base + strings.Repeat("/E:X", 70),
	} {
		if _, ok := parseCVSS3(v); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStepValueHandComputed(t *testing.T) {
	const xMax = 3.887042775 // AV:N/AC:L/PR:N/UI:N
	cases := []struct {
		name      string
		kev       bool
		epss      float64
		epssKnown bool
		x         float64
		assumed   bool
		want      float64
	}{
		// KEV dominates EPSS: max(0.9, 0.5, 0.299…) = 0.9
		{"kev", true, 0.5, true, xMax, false, 0.9},
		// EPSS above KEV term: max(0.9, 0.95, …) = 0.95
		{"epss above kev", true, 0.95, true, xMax, false, 0.95},
		// EPSS dominates the CVSS prior: max(0, 0.42, 0.299…) = 0.42
		{"epss", false, 0.42, true, xMax, false, 0.42},
		// EPSS missing: 0.3 × 3.887042775 / 3.9 = 0.2990032903846154
		{"cvss prior", false, 0, false, xMax, false, 0.2990032903846154},
		// EPSS known but below the prior: the prior wins.
		{"low epss", false, 0.01, true, xMax, false, 0.2990032903846154},
		// assumed edge halves: 0.42 × 0.5
		{"assumed", false, 0.42, true, xMax, true, 0.21},
		// KEV over an assumed edge: 0.9 × 0.5
		{"assumed kev", true, 0, false, xMax, true, 0.45},
		// weakest vector: 0.3 × 0.121090464 / 3.9 = 0.009314651076923077
		{"weak prior", false, 0, false, 0.121090464, false, 0.009314651076923077},
	}
	for _, c := range cases {
		s := scoredFinding{
			f:    Finding{KEV: c.kev, EPSS: c.epss, EPSSKnown: c.epssKnown},
			cvss: cvss3{av: AVNetwork, x: c.x},
		}
		s.base = baseE(c.kev, c.epss, c.epssKnown, c.x)
		got := s.terms(c.assumed)
		if !near(got.E, c.want) {
			t.Errorf("%s: e = %.17g, want %.17g", c.name, got.E, c.want)
		}
		if got.Assumed != c.assumed || got.KEV != c.kev || got.Exploitability != c.x {
			t.Errorf("%s: terms not explained: %+v", c.name, got)
		}
	}
}

// rlo is U+202E RIGHT-TO-LEFT OVERRIDE, spelled as a rune so the source
// holds no bidi control.
var rlo = string(rune(0x202e))

func TestValidateFindingRejects(t *testing.T) {
	good := Finding{Node: "host:a", Key: "CVE-2024-0001", State: FindingOpen, EPSS: 0.1, EPSSKnown: true,
		Ports: []Port{{ProtoTCP, 443}}}
	if err := validateFinding(good); err != nil {
		t.Fatalf("good finding rejected: %v", err)
	}
	many := make([]Port, MaxPortsPerFinding+1)
	for i := range many {
		many[i] = Port{ProtoTCP, uint16(i + 1)}
	}
	cases := map[string]func(*Finding){
		"bad node":         func(f *Finding) { f.Node = "host a" },
		"empty key":        func(f *Finding) { f.Key = "" },
		"long key":         func(f *Finding) { f.Key = strings.Repeat("k", MaxIDBytes+1) },
		"control in key":   func(f *Finding) { f.Key = "CVE\n1" },
		"no state":         func(f *Finding) { f.State = 0 },
		"unknown state":    func(f *Finding) { f.State = FindingFalsePositive + 1 },
		"epss nan":         func(f *Finding) { f.EPSS = math.NaN() },
		"epss above 1":     func(f *Finding) { f.EPSS = 1.0001 },
		"epss negative":    func(f *Finding) { f.EPSS = -0.1 },
		"epss inf":         func(f *Finding) { f.EPSS = math.Inf(1) },
		"epss not known":   func(f *Finding) { f.EPSSKnown = false },
		"port zero":        func(f *Finding) { f.Ports = []Port{{ProtoTCP, 0}} },
		"port no proto":    func(f *Finding) { f.Ports = []Port{{0, 80}} },
		"too many ports":   func(f *Finding) { f.Ports = many },
		"port bad proto":   func(f *Finding) { f.Ports = []Port{{ProtoUDP + 1, 80}} },
		"bidi in node id":  func(f *Finding) { f.Node = "host:" + rlo },
		"node over bounds": func(f *Finding) { f.Node = "host:" + strings.Repeat("a", MaxIDBytes) },
	}
	for name, mut := range cases {
		f := good
		mut(&f)
		err := validateFinding(f)
		if !errors.Is(err, ErrInvalidFinding) {
			t.Errorf("%s: err = %v, want ErrInvalidFinding", name, err)
			continue
		}
		if strings.Contains(err.Error(), "\n") || strings.Contains(err.Error(), rlo) {
			t.Errorf("%s: error echoes the rejected value: %q", name, err)
		}
	}
}
