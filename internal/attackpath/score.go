// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// FormulaVersion names the path score formula of ADR 0011 D10. It changes
// whenever a number this package computes could change for the same input.
const FormulaVersion = "ap-v1"

// Score constants of ap-v1 (ADR 0011 D10).
const (
	// kevTerm is the e term of a KEV-listed finding.
	kevTerm = 0.9
	// cvssWeight scales the CVSS v3 exploitability term, a weak prior.
	cvssWeight = 0.3
	// exploitabilityMax is the divisor of the exploitability term (the
	// largest CVSS v3 exploitability sub-score is about 3.9).
	exploitabilityMax = 3.9
	// assumedFactor scales e for a step over an "assumed" edge.
	assumedFactor = 0.5
)

// Limits on findings.
const (
	// MaxFindings bounds the findings one computation uses. Beyond it the
	// findings with the highest e are kept and the result is truncated.
	MaxFindings = 100000
	// MaxVectorBytes bounds a CVSS vector string.
	MaxVectorBytes = 255
	// MaxPortsPerFinding bounds the listening ports a finding maps to.
	MaxPortsPerFinding = 64
)

// ErrInvalidFinding reports a structurally invalid finding. A finding that
// is only unscorable (no CVSS v3 vector) is counted, not rejected.
var ErrInvalidFinding = errors.New("invalid finding")

// FindingState is the human state of a finding that matters for paths.
type FindingState uint8

// Finding states (ADR 0011 D10, usable step).
const (
	// FindingOpen is an open finding: usable.
	FindingOpen FindingState = iota + 1
	// FindingAcceptedRisk stays usable: accepting a risk does not fix it.
	FindingAcceptedRisk
	// FindingFalsePositive is not usable.
	FindingFalsePositive
)

func (s FindingState) valid() bool { return s >= FindingOpen && s <= FindingFalsePositive }

// AttackVector is the CVSS v3 attack vector of a finding.
type AttackVector uint8

// Attack vectors (CVSS v3 AV metric).
const (
	// AVNetwork is AV:N.
	AVNetwork AttackVector = iota + 1
	// AVAdjacent is AV:A.
	AVAdjacent
	// AVLocal is AV:L.
	AVLocal
	// AVPhysical is AV:P; never usable in a path.
	AVPhysical
)

var avNames = [...]string{AVNetwork: "N", AVAdjacent: "A", AVLocal: "L", AVPhysical: "P"}

// String returns the CVSS letter of v, or "" for an invalid value.
func (v AttackVector) String() string {
	if v >= AVNetwork && v <= AVPhysical {
		return avNames[v]
	}
	return ""
}

// Port is a listening port of the service a finding affects.
type Port struct {
	Proto  Proto
	Number uint16
}

// Finding is one vulnerability finding on one node, as far as attack paths
// need it. All fields come from the findings store and are untrusted.
type Finding struct {
	// Node is the ID of the graph node the finding is on.
	Node string
	// Key is the finding key, unique per node; same rules as a node ID.
	Key string
	// Vector is the CVSS v3.0 or v3.1 vector string. Without a parseable
	// v3 vector the finding cannot be scored and is counted as unscored.
	Vector string
	// KEV is set when the CVE is KEV-listed.
	KEV bool
	// EPSS is the EPSS probability, 0..1; meaningful only if EPSSKnown.
	EPSS float64
	// EPSSKnown says whether EPSS is set.
	EPSSKnown bool
	// Ports are the listening ports of the affected service. Empty means
	// the package-to-port mapping is unknown: network steps over policy or
	// observed edges are then "possible" and flagged, not dropped.
	Ports []Port
	// State is the human state; false positives are not usable.
	State FindingState
}

// Terms are the inputs and the value of e for one step, so every number can
// be explained.
type Terms struct {
	// KEV is set when the finding is KEV-listed.
	KEV bool
	// EPSS is the EPSS probability; meaningful only if EPSSKnown.
	EPSS float64
	// EPSSKnown says whether EPSS was set.
	EPSSKnown bool
	// Exploitability is the CVSS v3 exploitability sub-score X.
	Exploitability float64
	// Vector is the CVSS attack vector of the finding.
	Vector AttackVector
	// Assumed is set when e was halved for an assumed edge.
	Assumed bool
	// E is the step value e(step).
	E float64
}

// cvss3 is the part of a CVSS v3 vector ap-v1 uses.
type cvss3 struct {
	av AttackVector
	x  float64 // exploitability sub-score
	// exec is set when the vector's integrity impact is low or high, so the
	// finding may grant code execution. Code execution modifies the system,
	// so I:N rules it out; I:L or I:H is read as "may", the reading that
	// finds more paths.
	exec bool
}

// CVSS v3.1 specification, section 7.4, metric values.
var (
	cvssAV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssAC = map[string]float64{"L": 0.77, "H": 0.44}
	// cvssPR holds the unchanged-scope values; changed scope is cvssPRChanged.
	cvssPR        = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvssPRChanged = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	cvssUI        = map[string]float64{"N": 0.85, "R": 0.62}
	avOf          = map[string]AttackVector{"N": AVNetwork, "A": AVAdjacent, "L": AVLocal, "P": AVPhysical}
	// cvssMetrics lists every metric accepted in a vector with its values;
	// base metrics are required, temporal ones optional and ignored.
	cvssMetrics = map[string]string{
		"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
		"C": "HLN", "I": "HLN", "A": "HLN",
		"E": "XUPFH", "RL": "XOTWU", "RC": "XURC",
	}
	cvssBase = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
)

// parseCVSS3 parses a CVSS v3.0 or v3.1 vector strictly: every base metric
// exactly once, temporal metrics at most once, nothing else. It returns the
// attack vector and the exploitability sub-score 8.22 × AV × AC × PR × UI
// (unrounded, as in the specification).
func parseCVSS3(v string) (cvss3, bool) {
	if len(v) > MaxVectorBytes {
		return cvss3{}, false
	}
	rest, ok := strings.CutPrefix(v, "CVSS:3.1/")
	if !ok {
		if rest, ok = strings.CutPrefix(v, "CVSS:3.0/"); !ok {
			return cvss3{}, false
		}
	}
	got := make(map[string]string, len(cvssMetrics))
	for _, part := range strings.Split(rest, "/") {
		k, val, ok := strings.Cut(part, ":")
		allowed, known := cvssMetrics[k]
		if !ok || !known || len(val) != 1 || !strings.Contains(allowed, val) {
			return cvss3{}, false
		}
		if _, dup := got[k]; dup {
			return cvss3{}, false
		}
		got[k] = val
	}
	for _, k := range cvssBase {
		if _, ok := got[k]; !ok {
			return cvss3{}, false
		}
	}
	pr := cvssPR
	if got["S"] == "C" {
		pr = cvssPRChanged
	}
	x := 8.22 * cvssAV[got["AV"]] * cvssAC[got["AC"]] * pr[got["PR"]] * cvssUI[got["UI"]]
	return cvss3{av: avOf[got["AV"]], x: x, exec: got["I"] != "N"}, true
}

// scoredFinding is a validated, scorable finding.
type scoredFinding struct {
	f    Finding
	cvss cvss3
	// base is e before the assumed factor.
	base float64
}

// baseE returns max(KEV ? 0.9 : 0, EPSS, 0.3 × X / 3.9).
func baseE(kev bool, epss float64, epssKnown bool, x float64) float64 {
	e := cvssWeight * x / exploitabilityMax
	if epssKnown {
		e = math.Max(e, epss)
	}
	if kev {
		e = math.Max(e, kevTerm)
	}
	return e
}

// terms returns the explained e of a step using f; assumed halves it.
func (s scoredFinding) terms(assumed bool) Terms {
	t := Terms{
		KEV:            s.f.KEV,
		EPSS:           s.f.EPSS,
		EPSSKnown:      s.f.EPSSKnown,
		Exploitability: s.cvss.x,
		Vector:         s.cvss.av,
		E:              s.base,
	}
	if assumed {
		t.Assumed = true
		t.E = s.base * assumedFactor
	}
	return t
}

// validateFinding checks the structure of f. Error messages name the field
// and, where safe, the node; never the rejected value.
func validateFinding(f Finding) error {
	bad := func(field string) error { return fmt.Errorf("finding %s: %w", field, ErrInvalidFinding) }
	if !validID(f.Node) {
		return bad("node")
	}
	if !validID(f.Key) {
		return fmt.Errorf("finding on %s: key: %w", f.Node, ErrInvalidFinding)
	}
	if !f.State.valid() {
		return fmt.Errorf("finding %s on %s: state: %w", f.Key, f.Node, ErrInvalidFinding)
	}
	if f.EPSSKnown && !(f.EPSS >= 0 && f.EPSS <= 1) { // also rejects NaN
		return fmt.Errorf("finding %s on %s: epss: %w", f.Key, f.Node, ErrInvalidFinding)
	}
	if !f.EPSSKnown && f.EPSS != 0 {
		return fmt.Errorf("finding %s on %s: epss without epss_known: %w", f.Key, f.Node, ErrInvalidFinding)
	}
	if len(f.Ports) > MaxPortsPerFinding {
		return fmt.Errorf("finding %s on %s: ports: %w", f.Key, f.Node, ErrInvalidFinding)
	}
	for _, p := range f.Ports {
		if (p.Proto != ProtoTCP && p.Proto != ProtoUDP) || p.Number == 0 {
			return fmt.Errorf("finding %s on %s: port: %w", f.Key, f.Node, ErrInvalidFinding)
		}
	}
	return nil
}

// hasPort reports whether f lists (proto, port).
func (f Finding) hasPort(proto Proto, port uint16) bool {
	for _, p := range f.Ports {
		if p.Proto == proto && p.Number == port {
			return true
		}
	}
	return false
}
