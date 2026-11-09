// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnprio computes the priority score and tier of a vulnerability
// finding with the versioned formula vu-prio-v1 (ADR 0011 D7).
//
// The computation is pure and deterministic: it reads only its input, does
// no I/O, keeps no state and returns the same result for the same input on
// every platform. Hermes supplies the inputs (scores); NOS computes the
// priority. Every result carries the formula version so a stored score
// always names the formula that produced it.
//
//	cvss  = CVSS base score / 10                 (unknown → 0.5, flagged)
//	expl  = max(KEV ? 0.9 : 0, EPSS probability, 0.1)
//	expo  = 1.0 internet-facing, 0.7 NetBird/VPN entry or unknown,
//	        0.4 reachable only internally, 0.2 no listening service
//	crit  = 1.0 CRITICAL, 0.85 HIGH, 0.7 MEDIUM, 0.5 LOW (unset → 0.85)
//	score = round(100 × cvss × (0.4 + 0.6 × expl) × expo × crit)
//	tier  = critical if KEV and expo ≥ 0.7, or score ≥ 60
//	        high ≥ 35, medium ≥ 15, otherwise low
//	        a KEV finding is never below high
//
// Devices and images inherit the criticality of their host; the caller
// passes the host's criticality.
package vulnprio

import (
	"errors"
	"fmt"
	"math"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// FormulaVersion names this formula. It is stored with every computed
// score; changing any weight or threshold below requires a new version.
const FormulaVersion = "vu-prio-v1"

// ErrInvalidInput is returned for scores out of range, non-finite numbers
// and unknown exposure or criticality names.
var ErrInvalidInput = errors.New("vulnprio: invalid input")

// Weights and thresholds of vu-prio-v1 (ADR 0011 D7).
const (
	cvssMax     = 10.0 // CVSS base scores range 0..10
	cvssUnknown = 0.5  // cvss term when no CVSS score is known

	exploitKEV    = 0.9 // expl term of a KEV-listed finding
	exploitFloor  = 0.1 // minimum expl term
	exploitBase   = 0.4 // likelihood factor = exploitBase + exploitWeight × expl
	exploitWeight = 0.6

	exposureInternetW   = 1.0
	exposureVPNEntryW   = 0.7
	exposureUnknownW    = 0.7
	exposureInternalW   = 0.4
	exposureNoListenerW = 0.2

	critCriticalW = 1.0
	critHighW     = 0.85
	critMediumW   = 0.7
	critLowW      = 0.5
	critUnsetW    = 0.85

	scoreScale = 100.0

	tierCriticalMin        = 60
	tierHighMin            = 35
	tierMediumMin          = 15
	kevCriticalExposureMin = 0.7 // KEV with expo at or above this is critical

	// roundDigits removes binary floating-point noise before rounding to
	// an integer, so a product that is exactly x.5 in decimal arithmetic
	// (for example 11.5) rounds up even if its float64 is 11.4999999…
	roundDigits = 1e9
)

// Exposure is the network exposure of the affected subject, derived by the
// caller from the traffic map (ADR 0009) and firewall rules (ADR 0010).
type Exposure string

// Exposure levels. The zero value "" counts as ExposureUnknown, never as
// internal.
const (
	ExposureInternet   Exposure = "internet"
	ExposureVPNEntry   Exposure = "vpn_entry"
	ExposureUnknown    Exposure = "unknown"
	ExposureInternal   Exposure = "internal"
	ExposureNoListener Exposure = "no_listener"
)

// Tier is the priority tier of a finding.
type Tier string

// Tiers, from lowest to highest.
const (
	TierLow      Tier = "low"
	TierMedium   Tier = "medium"
	TierHigh     Tier = "high"
	TierCritical Tier = "critical"
)

// Rank returns the order of a tier (low = 1 … critical = 4); 0 means
// unknown.
func (t Tier) Rank() int {
	switch t {
	case TierLow:
		return 1
	case TierMedium:
		return 2
	case TierHigh:
		return 3
	case TierCritical:
		return 4
	}
	return 0
}

// Input is everything the formula reads.
type Input struct {
	// Scores are the finding's scores as validated by vulnfinding.
	Scores vulnfinding.Scores
	// Exposure of the subject; "" means unknown.
	Exposure Exposure
	// Criticality of the host (devices and images: of their host); ""
	// means unset.
	Criticality inventory.Criticality
}

// Terms are the four factors of the formula, kept for display and audit.
type Terms struct {
	CVSS        float64
	Exploit     float64
	Exposure    float64
	Criticality float64
}

// Result is a computed priority. Store Formula together with Score and
// Tier.
type Result struct {
	// Formula is always FormulaVersion.
	Formula string
	// Score is 0..100.
	Score int
	// Tier is the priority tier.
	Tier Tier
	// Terms are the factors the score was computed from.
	Terms Terms
	// CVSSUnknown is set when no CVSS score was known and 0.5 was used.
	CVSSUnknown bool
	// KEV is set when the finding is KEV-listed.
	KEV bool
	// Exposure is the exposure level used; "" input is recorded as
	// ExposureUnknown.
	Exposure Exposure
	// CriticalityUnset is set when no host criticality was given and the
	// HIGH default was used.
	CriticalityUnset bool
}

// Compute applies vu-prio-v1 to in. It returns a zero Result and an error
// wrapping ErrInvalidInput for out-of-range or non-finite scores and for
// unknown exposure or criticality names.
func Compute(in Input) (Result, error) {
	cvss, cvssUnknownFlag, err := cvssTerm(in.Scores.CVSS)
	if err != nil {
		return Result{}, err
	}
	isKEV := in.Scores.KEV != nil
	expl, err := exploitTerm(isKEV, in.Scores.EPSS)
	if err != nil {
		return Result{}, err
	}
	expoLevel, expo, err := exposureTerm(in.Exposure)
	if err != nil {
		return Result{}, err
	}
	crit, critUnset, err := criticalityTerm(in.Criticality)
	if err != nil {
		return Result{}, err
	}

	score := computeScore(cvss, expl, expo, crit)
	return Result{
		Formula:          FormulaVersion,
		Score:            score,
		Tier:             tierFor(score, isKEV, expo),
		Terms:            Terms{CVSS: cvss, Exploit: expl, Exposure: expo, Criticality: crit},
		CVSSUnknown:      cvssUnknownFlag,
		KEV:              isKEV,
		Exposure:         expoLevel,
		CriticalityUnset: critUnset,
	}, nil
}

func finiteIn(v, lo, hi float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= lo && v <= hi
}

func cvssTerm(c *vulnfinding.CVSS) (float64, bool, error) {
	if c == nil {
		return cvssUnknown, true, nil
	}
	if !finiteIn(c.BaseScore, 0, cvssMax) {
		return 0, false, fmt.Errorf("%w: CVSS base score out of range 0..10", ErrInvalidInput)
	}
	return c.BaseScore / cvssMax, false, nil
}

func exploitTerm(isKEV bool, e *vulnfinding.EPSS) (float64, error) {
	expl := exploitFloor
	if isKEV {
		expl = math.Max(expl, exploitKEV)
	}
	if e != nil {
		if !finiteIn(e.Probability, 0, 1) {
			return 0, fmt.Errorf("%w: EPSS probability out of range 0..1", ErrInvalidInput)
		}
		expl = math.Max(expl, e.Probability)
	}
	return expl, nil
}

func exposureTerm(e Exposure) (Exposure, float64, error) {
	switch e {
	case ExposureInternet:
		return e, exposureInternetW, nil
	case ExposureVPNEntry:
		return e, exposureVPNEntryW, nil
	case ExposureUnknown, "":
		return ExposureUnknown, exposureUnknownW, nil
	case ExposureInternal:
		return e, exposureInternalW, nil
	case ExposureNoListener:
		return e, exposureNoListenerW, nil
	}
	return "", 0, fmt.Errorf("%w: unknown exposure level", ErrInvalidInput)
}

func criticalityTerm(c inventory.Criticality) (float64, bool, error) {
	switch c {
	case inventory.CriticalityCritical:
		return critCriticalW, false, nil
	case inventory.CriticalityHigh:
		return critHighW, false, nil
	case inventory.CriticalityMedium:
		return critMediumW, false, nil
	case inventory.CriticalityLow:
		return critLowW, false, nil
	case "":
		return critUnsetW, true, nil
	}
	return 0, false, fmt.Errorf("%w: unknown host criticality", ErrInvalidInput)
}

// computeScore evaluates the product in a fixed order. Each intermediate
// is converted with float64() explicitly, which the Go specification
// guarantees prevents fused multiply-add, so the result is the same on
// every architecture.
func computeScore(cvss, expl, expo, crit float64) int {
	likelihood := float64(exploitBase + float64(exploitWeight*expl))
	p := float64(scoreScale * cvss)
	p = float64(p * likelihood)
	p = float64(p * expo)
	p = float64(p * crit)
	p = float64(math.Round(float64(p*roundDigits)) / roundDigits)
	return int(math.Round(p))
}

func tierFor(score int, isKEV bool, expo float64) Tier {
	var t Tier
	switch {
	case isKEV && expo >= kevCriticalExposureMin, score >= tierCriticalMin:
		t = TierCritical
	case score >= tierHighMin:
		t = TierHigh
	case score >= tierMediumMin:
		t = TierMedium
	default:
		t = TierLow
	}
	if isKEV && t.Rank() < TierHigh.Rank() {
		t = TierHigh
	}
	return t
}
