// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnprio

import (
	"sort"
	"strings"
)

// FormulaVersionV2 names formula vu-prio-v2 (ADR 0012 D3). It differs from
// vu-prio-v1 only in the exposure term, which the reachability model
// determines when a valid mitigation record exists. All other terms, the
// tier thresholds and the KEV floor are computed by the v1 code.
const FormulaVersionV2 = "vu-prio-v2"

// Verdict is the reachability verdict of the model (ADR 0012 D2) for one
// source. Any value other than the four decided verdicts is not usable and
// fails closed.
type Verdict string

// Verdicts of the reachability model.
const (
	VerdictAllowed     Verdict = "allowed"
	VerdictConditional Verdict = "conditional"
	VerdictNotFiltered Verdict = "not_filtered"
	VerdictUnknown     Verdict = "unknown"
	VerdictDenied      Verdict = "denied"
)

// reachable reports whether the verdict counts as reachable: everything
// except denied, including not_filtered and unknown (D3).
func (v Verdict) reachable() bool { return v != VerdictDenied }

// usable reports whether v is one of the four decided verdicts. Unknown,
// empty and unrecognised values are not usable.
func (v Verdict) usable() bool {
	switch v {
	case VerdictAllowed, VerdictConditional, VerdictNotFiltered, VerdictDenied:
		return true
	}
	return false
}

// TrustClass is the trust class of a zone or of the finding host's own
// segment (ADR 0012 D4).
type TrustClass string

// Trust classes.
const (
	ClassTrusted   TrustClass = "trusted"
	ClassGuest     TrustClass = "guest"
	ClassIoT       TrustClass = "iot"
	ClassUntrusted TrustClass = "untrusted"
	ClassUnknown   TrustClass = "unknown"
)

// blocksMitigation reports whether a reachable own segment of this class
// prevents the mitigation label (ADR 0012 Q7). Unknown, empty and
// unrecognised classes count as untrusted (Q9).
func (c TrustClass) blocksMitigation() bool {
	switch c {
	case ClassTrusted, ClassGuest, ClassIoT:
		return false
	}
	return true
}

// FailReason names why a mitigation record is not valid (ADR 0012 D3,
// "Fail closed"). Any reason makes the finding use its v1 exposure and
// show "mitigation unknown: <reason>".
type FailReason string

// Fail-closed reasons. The text is the fixed reason shown to the user.
const (
	ReasonInputStale           FailReason = "input stale or incomplete"
	ReasonPolicyChanged        FailReason = "policy or object changed"
	ReasonRawDigestOnly        FailReason = "policy changed outside collected elements"
	ReasonVerdictUnknown       FailReason = "unknown verdict on a mitigating path"
	ReasonFlowContradiction    FailReason = "contradicted by flow or log"
	ReasonPortUnknown          FailReason = "port unknown"
	ReasonConditionalDenyAllow FailReason = "conditional deny followed by allow"
	ReasonHostAddressesUnknown FailReason = "host addresses unknown"

	// reasonAboveV1 is set when the reachability model would raise the
	// exposure above the v1 exposure. v2 only lowers exposure, so the v1
	// value is used and the disagreement is reported.
	reasonAboveV1 FailReason = "reachability above v1 exposure"
)

// ZoneVerdict is the verdict from one zone.
type ZoneVerdict struct {
	// Zone is the zone name, shown in the summary.
	Zone string
	// Class is the zone's trust class.
	Class TrustClass
	// Verdict is the reachability verdict from this zone.
	Verdict Verdict
}

// OwnSegmentVerdict is the verdict from the finding host's own segment.
type OwnSegmentVerdict struct {
	// Class is the trust class of the own segment; "" counts as unknown.
	Class TrustClass
	// Verdict is the reachability verdict from the own segment.
	Verdict Verdict
}

// Verdicts holds the verdict per source (ADR 0012 D3).
type Verdicts struct {
	// Internet is the verdict from the internet zone.
	Internet Verdict
	// NetBird is the verdict from the NetBird overlay.
	NetBird Verdict
	// Zones holds one verdict per zone. An empty list is incomplete.
	Zones []ZoneVerdict
	// OwnSegment is the verdict from the finding host's own segment.
	OwnSegment OwnSegmentVerdict
}

// MitigationRecord is the caller-supplied mitigation data for one finding.
// The zero value is invalid: every flag must be set by the caller once the
// inputs are known to be fresh, complete and matching.
type MitigationRecord struct {
	// InputsFresh is true when every input dataset of the snapshot is
	// fresh and not incomplete.
	InputsFresh bool
	// PortKnown is true when the affected service maps to a listening port.
	PortKnown bool
	// HostAddressesKnown is true when every address of the finding host is
	// known from fresh data.
	HostAddressesKnown bool
	// Reasons holds the further fail-closed reasons the caller detected,
	// for example ReasonPolicyChanged or ReasonFlowContradiction.
	Reasons []FailReason
	// Verdicts holds the verdict per source.
	Verdicts Verdicts
}

// InputV2 is the v1 input plus the mitigation record.
type InputV2 struct {
	// Base is the v1 input.
	Base Input
	// Mitigation is the mitigation record of the finding.
	Mitigation MitigationRecord
}

// ResultV2 is a vu-prio-v2 priority. Store Formula together with Score and
// Tier.
type ResultV2 struct {
	// Formula is always FormulaVersionV2.
	Formula string
	// Score is 0..100.
	Score int
	// Tier is the priority tier.
	Tier Tier
	// Terms are the factors; Terms.Exposure is the v2 exposure.
	Terms Terms
	// Exposure is the exposure level used.
	Exposure Exposure
	// Mitigated is true only when the reachability model lowered the
	// exposure from v1 by denials, with a valid record, and no source is
	// not_filtered and no reachable own segment blocks the label.
	Mitigated bool
	// NotFiltered is true when some source is not_filtered; the summary
	// shows "not filtered (firewall not on path)".
	NotFiltered bool
	// Reason is "mitigation unknown: <reason>" when the v1 exposure was
	// used; empty for a valid record.
	Reason string
	// V1 is the vu-prio-v1 result of the same input, shown beside v2.
	V1 Result
}

// ComputeV2 applies vu-prio-v2 to in. It is pure and deterministic.
//
// A listening service never gets less than 0.4 and never more than its v1
// exposure. Any uncertainty (see FailReason) yields the v1 exposure and a
// reason. A service without a listener keeps its v1 exposure (0.2).
func ComputeV2(in InputV2) (ResultV2, error) {
	v1, err := Compute(in.Base)
	if err != nil {
		return ResultV2{}, err
	}
	v := in.Mitigation.Verdicts
	res := ResultV2{
		Formula:     FormulaVersionV2,
		Exposure:    v1.Exposure,
		NotFiltered: anyNotFiltered(v),
		V1:          v1,
	}
	expo := v1.Terms.Exposure

	if v1.Exposure != ExposureNoListener {
		if reasons := failReasons(in.Mitigation); len(reasons) > 0 {
			res.Reason = mitigationUnknown(reasons)
		} else if tableExpo, tableLevel := reachabilityLevel(v); tableExpo > expo {
			res.Reason = mitigationUnknown([]string{string(reasonAboveV1)})
		} else {
			if tableExpo < expo {
				expo = tableExpo
				res.Exposure = tableLevel
			}
			ownBlocks := v.OwnSegment.Class.blocksMitigation() && v.OwnSegment.Verdict.reachable()
			res.Mitigated = expo < v1.Terms.Exposure && !res.NotFiltered && !ownBlocks
		}
	}

	res.Terms = v1.Terms
	res.Terms.Exposure = expo
	res.Score = computeScore(v1.Terms.CVSS, v1.Terms.Exploit, expo, v1.Terms.Criticality)
	res.Tier = tierFor(res.Score, v1.KEV, expo)
	return res, nil
}

// reachabilityLevel is the exposure the verdicts give for a listening
// service (D3): 1.0 if internet is reachable, 0.7 if NetBird is reachable,
// otherwise 0.4. Zones and the own segment never lower it below 0.4.
func reachabilityLevel(v Verdicts) (float64, Exposure) {
	switch {
	case v.Internet.reachable():
		return exposureInternetW, ExposureInternet
	case v.NetBird.reachable():
		return exposureVPNEntryW, ExposureVPNEntry
	}
	return exposureInternalW, ExposureInternal
}

// anyNotFiltered reports whether any source has verdict not_filtered.
// not_filtered is never a compensating control (D3).
func anyNotFiltered(v Verdicts) bool {
	if v.Internet == VerdictNotFiltered || v.NetBird == VerdictNotFiltered || v.OwnSegment.Verdict == VerdictNotFiltered {
		return true
	}
	for _, z := range v.Zones {
		if z.Verdict == VerdictNotFiltered {
			return true
		}
	}
	return false
}

// failReasons returns the sorted, unique fail-closed reasons of m. Empty
// means the record is valid.
func failReasons(m MitigationRecord) []string {
	var out []string
	add := func(r FailReason) { out = append(out, string(r)) }

	if !m.InputsFresh {
		add(ReasonInputStale)
	}
	if !m.PortKnown {
		add(ReasonPortUnknown)
	}
	if !m.HostAddressesKnown {
		add(ReasonHostAddressesUnknown)
	}
	for _, r := range m.Reasons {
		if r != "" {
			add(r)
		}
	}
	v := m.Verdicts
	if len(v.Zones) == 0 {
		add(ReasonInputStale)
	}
	unusable := !v.Internet.usable() || !v.NetBird.usable() || !v.OwnSegment.Verdict.usable()
	for _, z := range v.Zones {
		unusable = unusable || !z.Verdict.usable()
	}
	if unusable {
		add(ReasonVerdictUnknown)
	}

	sort.Strings(out)
	n := 0
	for i, r := range out {
		if i == 0 || r != out[n-1] {
			out[n] = r
			n++
		}
	}
	return out[:n]
}

// mitigationUnknown formats the fixed reason text for the given sorted
// reasons.
func mitigationUnknown(reasons []string) string {
	return "mitigation unknown: " + strings.Join(reasons, "; ")
}
