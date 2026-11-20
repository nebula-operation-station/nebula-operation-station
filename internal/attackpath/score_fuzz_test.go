// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// fuzzCVSSValid are vectors the grammar of parseCVSS3 accepts. They are fuzz
// seeds and the acceptance half of the table test.
var fuzzCVSSValid = []string{
	"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	"CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N",
	"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
	"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
	"CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N/E:X/RL:X/RC:X",
	"CVSS:3.1/S:U/UI:N/PR:N/AC:L/AV:N/A:H/I:H/C:H",
	"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N",
}

// fuzzCVSSRejectCase is a vector the grammar rejects, with a name for the
// failure message.
type fuzzCVSSRejectCase struct {
	name string
	v    string
}

// fuzzCVSSBase is a complete set of base metrics with a v3.1 prefix.
const fuzzCVSSBase = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

// fuzzCVSSReject are rejected vectors. The two length cases pad a base-metric
// vector to exactly MaxVectorBytes and to one byte more; both are rejected,
// the first for an unknown segment, because no valid vector is that long
// (every metric is at most once, so the longest valid vector is 58 bytes).
var fuzzCVSSReject = []fuzzCVSSRejectCase{
	{"empty", ""},
	{"no prefix", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	{"v2 vector", "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
	{"v4 prefix", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
	{"duplicate base metric", fuzzCVSSBase + "/AV:L"},
	{"duplicate temporal metric", fuzzCVSSBase + "/E:P/E:X"},
	{"missing base metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
	{"unknown metric", fuzzCVSSBase + "/XX:N"},
	{"environmental metric", fuzzCVSSBase + "/MAV:N"},
	{"two-character value", "CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	{"lower-case metric", "CVSS:3.1/av:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	{"lower-case value", "CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	{"leading slash", "/" + fuzzCVSSBase},
	{"trailing slash", fuzzCVSSBase + "/"},
	{"empty segment", "CVSS:3.1/AV:N//AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	{"segment without colon", fuzzCVSSBase + "/E"},
	{"bad temporal value", fuzzCVSSBase + "/E:Q"},
	{"non-ascii value", "CVSS:3.1/AV:Ν/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	{"length equal to MaxVectorBytes", fuzzCVSSBase + "/" + strings.Repeat("Z", MaxVectorBytes-len(fuzzCVSSBase)-1)},
	{"length MaxVectorBytes+1", fuzzCVSSBase + "/" + strings.Repeat("Z", MaxVectorBytes-len(fuzzCVSSBase))},
}

// Documented CVSS v3.1 section 7.4 metric values, transcribed here for the
// reference model; they are not read from score.go.
var (
	refAV = map[byte]float64{'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
	refAC = map[byte]float64{'L': 0.77, 'H': 0.44}
	// refPR is the unchanged-scope table, refPRChanged the changed-scope one.
	refPR        = map[byte]float64{'N': 0.85, 'L': 0.62, 'H': 0.27}
	refPRChanged = map[byte]float64{'N': 0.85, 'L': 0.68, 'H': 0.5}
	refUI        = map[byte]float64{'N': 0.85, 'R': 0.62}
)

// refCVSS3 is the reference model of the documented grammar: a CVSS:3.0/ or
// CVSS:3.1/ prefix, then "/"-separated K:V segments where K is one of the
// eleven known metrics and V one of its letters, each metric at most once,
// every base metric present, and at most MaxVectorBytes bytes. It returns the
// metric values of an accepted vector.
func refCVSS3(v string) (map[string]string, bool) {
	if len(v) > MaxVectorBytes {
		return nil, false
	}
	var body string
	switch {
	case strings.HasPrefix(v, "CVSS:3.1/"):
		body = v[len("CVSS:3.1/"):]
	case strings.HasPrefix(v, "CVSS:3.0/"):
		body = v[len("CVSS:3.0/"):]
	default:
		return nil, false
	}
	letters := map[string]string{
		"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
		"C": "HLN", "I": "HLN", "A": "HLN",
		"E": "XUPFH", "RL": "XOTWU", "RC": "XURC",
	}
	m := map[string]string{}
	for _, seg := range strings.Split(body, "/") {
		i := strings.IndexByte(seg, ':')
		if i < 0 {
			return nil, false
		}
		k, val := seg[:i], seg[i+1:]
		allowed, known := letters[k]
		if !known || len(val) != 1 || strings.IndexByte(allowed, val[0]) < 0 {
			return nil, false
		}
		if _, dup := m[k]; dup {
			return nil, false
		}
		m[k] = val
	}
	for _, k := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if _, ok := m[k]; !ok {
			return nil, false
		}
	}
	return m, true
}

// refExploitability multiplies the documented tables for the metrics m.
func refExploitability(m map[string]string) float64 {
	pr := refPR
	if m["S"] == "C" {
		pr = refPRChanged
	}
	return 8.22 * refAV[m["AV"][0]] * refAC[m["AC"][0]] * pr[m["PR"][0]] * refUI[m["UI"][0]]
}

// refExploitabilityBounds returns the smallest and largest product over all
// combinations of the tables, unchanged and changed scope together.
func refExploitabilityBounds() (lo, hi float64) {
	lo, hi = math.Inf(1), math.Inf(-1)
	for _, pr := range []map[byte]float64{refPR, refPRChanged} {
		for _, av := range refAV {
			for _, ac := range refAC {
				for _, p := range pr {
					for _, ui := range refUI {
						x := 8.22 * av * ac * p * ui
						lo = math.Min(lo, x)
						hi = math.Max(hi, x)
					}
				}
			}
		}
	}
	return lo, hi
}

// refIDOK is the documented ID rule: 1..MaxIDBytes of [A-Za-z0-9._:/@-].
func refIDOK(id string) bool {
	if len(id) < 1 || len(id) > MaxIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			strings.IndexByte("._:/@-", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

// TestCVSSSeedsAreDecidedByGrammar checks without the fuzzer that every
// valid seed is accepted and every rejected seed is rejected, and that the
// reference model agrees.
func TestCVSSSeedsAreDecidedByGrammar(t *testing.T) {
	for _, v := range fuzzCVSSValid {
		if _, ok := parseCVSS3(v); !ok {
			t.Errorf("%s: rejected", v)
		}
		if _, ok := refCVSS3(v); !ok {
			t.Errorf("%s: reference model rejects a valid seed", v)
		}
	}
	for _, c := range fuzzCVSSReject {
		if _, ok := parseCVSS3(c.v); ok {
			t.Errorf("%s: accepted", c.name)
		}
		if _, ok := refCVSS3(c.v); ok {
			t.Errorf("%s: reference model accepts a rejected seed", c.name)
		}
	}
	if got := len(fuzzCVSSReject[len(fuzzCVSSReject)-2].v); got != MaxVectorBytes {
		t.Errorf("seed at the limit has %d bytes, want %d", got, MaxVectorBytes)
	}
	if got := len(fuzzCVSSReject[len(fuzzCVSSReject)-1].v); got != MaxVectorBytes+1 {
		t.Errorf("seed over the limit has %d bytes, want %d", got, MaxVectorBytes+1)
	}
}

// fuzzCVSSSegments splits an accepted vector into its prefix and segments.
// Both prefixes are nine bytes long.
func fuzzCVSSSegments(v string) (string, []string) {
	return v[:9], strings.Split(v[9:], "/")
}

// FuzzParseCVSS3 checks parseCVSS3 against the reference model of the
// documented grammar, and the exploitability and exec properties of accepted
// vectors.
func FuzzParseCVSS3(f *testing.F) {
	for _, v := range fuzzCVSSValid {
		f.Add(v)
	}
	for _, c := range fuzzCVSSReject {
		f.Add(c.v)
	}
	lo, hi := refExploitabilityBounds()
	f.Fuzz(func(t *testing.T, v string) {
		got, ok := parseCVSS3(v)
		if ok && len(v) > MaxVectorBytes {
			t.Fatalf("accepted %d bytes, limit %d", len(v), MaxVectorBytes)
		}
		metrics, want := refCVSS3(v)
		if ok != want {
			t.Fatalf("parseCVSS3 accepts %v, reference accepts %v", ok, want)
		}
		if !ok {
			return
		}
		if x := refExploitability(metrics); !near(got.x, x) {
			t.Fatalf("exploitability %.17g, reference %.17g", got.x, x)
		}
		if math.IsNaN(got.x) || math.IsInf(got.x, 0) || got.x < lo || got.x > hi || got.x > 3.9 {
			t.Fatalf("exploitability %v outside [%v, %v] or above 3.9", got.x, lo, hi)
		}
		if got.av.String() != metrics["AV"] {
			t.Fatalf("attack vector %q, vector says %q", got.av.String(), metrics["AV"])
		}
		if got.exec != (metrics["I"] != "N") {
			t.Fatalf("exec %v with I:%s", got.exec, metrics["I"])
		}
		// Metric order must not change the result: reversed and rotated
		// segment orders are parsed as well.
		prefix, segs := fuzzCVSSSegments(v)
		reversed := make([]string, len(segs))
		for i, s := range segs {
			reversed[len(segs)-1-i] = s
		}
		rotated := append(append([]string{}, segs[1:]...), segs[0])
		for name, order := range map[string][]string{"reversed": reversed, "rotated": rotated} {
			p := prefix + strings.Join(order, "/")
			g, ok := parseCVSS3(p)
			if !ok || g != got {
				t.Fatalf("%s order of %q: accepted %v, result %+v, want %+v", name, v, ok, g, got)
			}
		}
	})
}

// fuzzPorts decodes ports from 3-byte records: protocol, then a big-endian
// port number. A trailing partial record is ignored.
func fuzzPorts(b []byte) []Port {
	var ports []Port
	for i := 0; i+3 <= len(b); i += 3 {
		ports = append(ports, Port{Proto: Proto(b[i]), Number: uint16(b[i+1])<<8 | uint16(b[i+2])})
	}
	return ports
}

// FuzzValidateFinding builds findings from fuzzed fields and checks that an
// accepted finding has valid IDs, a valid state, EPSS within 0..1 when known
// and zero otherwise, and at most MaxPortsPerFinding TCP or UDP ports with
// non-zero numbers. Vectors are not checked here: a finding without a
// parseable v3 vector is counted as unscored, not rejected (see Finding).
func FuzzValidateFinding(f *testing.F) {
	const vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	f.Add("host:a", "CVE-2024-0001", vec, true, math.Float64bits(0.5), true, uint8(FindingOpen), []byte{1, 0, 80})
	f.Add("host:a", "CVE-2024-0001", vec, false, math.Float64bits(math.NaN()), true, uint8(FindingOpen), []byte{})
	f.Add("host:a", "CVE-2024-0001", vec, false, math.Float64bits(math.Inf(1)), true, uint8(FindingAcceptedRisk), []byte{2, 0, 53})
	f.Add("host:a", "CVE-2024-0001", vec, false, math.Float64bits(1.5), true, uint8(FindingFalsePositive), []byte{})
	f.Add("host:a", "CVE-2024-0001", vec, false, math.Float64bits(0.3), false, uint8(FindingOpen), []byte{1, 0, 0})
	f.Add("host:a", "CVE-2024-0001", vec, false, math.Float64bits(0.3), false, uint8(0), []byte{})
	f.Add("", "", "", false, uint64(0), false, uint8(0), []byte{})
	f.Add("host:"+strings.Repeat("a", MaxIDBytes), "k", "not a vector", false, math.Float64bits(math.Copysign(0, -1)), false, uint8(FindingOpen), []byte{9, 255, 255})
	f.Fuzz(func(t *testing.T, node, key, vector string, kev bool, epssBits uint64, epssKnown bool, state uint8, ports []byte) {
		fd := Finding{
			Node:      node,
			Key:       key,
			Vector:    vector,
			KEV:       kev,
			EPSS:      math.Float64frombits(epssBits),
			EPSSKnown: epssKnown,
			Ports:     fuzzPorts(ports),
			State:     FindingState(state),
		}
		_, _ = parseCVSS3(vector) // must not panic on any vector
		err := validateFinding(fd)
		if err != nil {
			if !errors.Is(err, ErrInvalidFinding) {
				t.Fatalf("rejection %v does not wrap ErrInvalidFinding", err)
			}
			for _, r := range err.Error() {
				if r < 0x20 || r == 0x7f || r == 0x202e {
					t.Fatalf("error text has control or bidi rune %U: %q", r, err)
				}
			}
			return
		}
		if !refIDOK(node) || !refIDOK(key) {
			t.Fatalf("accepted node %q key %q", node, key)
		}
		if state < uint8(FindingOpen) || state > uint8(FindingFalsePositive) {
			t.Fatalf("accepted state %d", state)
		}
		if epssKnown {
			if !(fd.EPSS >= 0 && fd.EPSS <= 1) {
				t.Fatalf("accepted EPSS %v with epss_known", fd.EPSS)
			}
		} else if fd.EPSS != 0 {
			t.Fatalf("accepted EPSS %v without epss_known", fd.EPSS)
		}
		if len(fd.Ports) > MaxPortsPerFinding {
			t.Fatalf("accepted %d ports, limit %d", len(fd.Ports), MaxPortsPerFinding)
		}
		for _, p := range fd.Ports {
			if (p.Proto != ProtoTCP && p.Proto != ProtoUDP) || p.Number == 0 {
				t.Fatalf("accepted port %+v", p)
			}
		}
	})
}
