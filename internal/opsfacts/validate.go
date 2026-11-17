// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"fmt"
	"sort"
)

// The messages below are the rules of a Skip. They are constant text: no
// input value is ever formatted into them (ADR 0016 D4, T1).

// validSubjectID reports whether id has the shape of a subject ID.
func validSubjectID(id string) bool {
	return len(id) <= MaxSubjectIDBytes && subjectIDRe.MatchString(id)
}

// displayID returns id when it is a valid subject ID, and "" otherwise. It is
// the only form in which a host ID reaches an error or an audit record.
func displayID(id string) string {
	if validSubjectID(id) {
		return id
	}
	return ""
}

// validateHost checks and cleans one inventory host.
func validateHost(h Host) (Host, error) {
	if !validSubjectID(h.ID) {
		return Host{}, fmt.Errorf("host id: %w", ErrInvalidField)
	}
	h.Label = cleanText(h.Label, MaxLabelBytes)
	h.Environment = cleanText(h.Environment, MaxEnvironmentBytes)
	switch h.Criticality {
	case CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical:
	default:
		return Host{}, fmt.Errorf("criticality: %w", ErrInvalidField)
	}
	switch h.Exposure {
	case "":
		h.Exposure = ExposureUnknown
	case ExposureInternet, ExposureVPNEntry, ExposureUnknown, ExposureInternal, ExposureNoListener:
	default:
		return Host{}, fmt.Errorf("exposure: %w", ErrInvalidField)
	}
	return h, nil
}

// labHost returns the lab host part of a validated host.
func (h Host) labHost() LabHost {
	return LabHost{ID: h.ID, Label: h.Label, Environment: h.Environment, Criticality: string(h.Criticality)}
}

// validateFinding checks one finding. A value that does not have its strict
// shape rejects the finding only; the caller records a Skip and goes on.
func validateFinding(f Finding) (Finding, error) {
	if !validSubjectID(f.HostID) {
		return Finding{}, fmt.Errorf("host id: %w", ErrInvalidField)
	}
	switch f.Subject {
	case SubjectOS:
		if f.ImageSubject != "" {
			return Finding{}, fmt.Errorf("image subject on os finding: %w", ErrInvalidField)
		}
	case SubjectImage:
		if !validSubjectID(f.ImageSubject) {
			return Finding{}, fmt.Errorf("image subject: %w", ErrInvalidField)
		}
	default:
		return Finding{}, fmt.Errorf("subject kind: %w", ErrInvalidField)
	}
	switch f.State {
	case StateOpen, StateAcceptedRisk, StateFalsePositive:
	default:
		return Finding{}, ErrInvalidState
	}
	switch f.Tier {
	case TierCritical, TierHigh, TierMedium, TierLow:
	default:
		return Finding{}, ErrInvalidTier
	}
	if f.Score < 0 || f.Score > MaxScore {
		return Finding{}, fmt.Errorf("score: %w", ErrInvalidField)
	}
	if len(f.VulnID) > MaxVulnIDBytes || !vulnIDRe.MatchString(f.VulnID) {
		return Finding{}, fmt.Errorf("vulnerability id: %w", ErrInvalidField)
	}
	// Control and format characters are removed, but the name is never cut:
	// a cut name would be stored as a different package. The pattern then
	// rejects a name over MaxPackageBytes.
	f.Package = cleanText(f.Package, len(f.Package))
	if !packageRe.MatchString(f.Package) {
		return Finding{}, fmt.Errorf("package name: %w", ErrInvalidField)
	}
	if !versionRe.MatchString(f.Installed) {
		return Finding{}, fmt.Errorf("installed version: %w", ErrInvalidField)
	}
	if f.Fixed != "" && !versionRe.MatchString(f.Fixed) {
		return Finding{}, fmt.Errorf("fixed version: %w", ErrInvalidField)
	}
	if err := validateDecision(f.Fix); err != nil {
		return Finding{}, err
	}
	return f, nil
}

// validateDecision checks the enumerations of a "fix with" decision.
func validateDecision(d FixDecision) error {
	switch d.Outcome {
	case OutcomeNone, OutcomeVerified, OutcomeNotVerified, OutcomeBelowFixed,
		OutcomeNoCandidate, OutcomeNoFixYet, OutcomeWontFix, OutcomeUnknown,
		OutcomeImageCandidate, OutcomeImageNoCandidate, OutcomeDeviceNoPatch:
	default:
		return ErrInvalidOutcome
	}
	switch d.Link {
	case LinkNone, LinkInstallSecurity, LinkInstallAll, LinkListUpdates,
		LinkContainers, LinkCiscoAdvisory, LinkPANAdvisory:
	default:
		return ErrInvalidLink
	}
	return nil
}

// validatePorts checks listening ports and returns them without duplicates,
// sorted by number, then protocol, so the first MaxPortsPerHost are always the
// same ones. A duplicate (number, protocol) pair is dropped: it adds nothing,
// and a source that repeats entries must not push real ports out of the list.
func validatePorts(ps []Port) ([]Port, error) {
	type key struct {
		number   int
		protocol string
	}
	seen := make(map[key]bool, len(ps))
	out := make([]Port, 0, len(ps))
	for _, p := range ps {
		if p.Number < 1 || p.Number > 65535 {
			return nil, fmt.Errorf("port number: %w", ErrInvalidField)
		}
		if p.Protocol != "tcp" && p.Protocol != "udp" {
			return nil, fmt.Errorf("port protocol: %w", ErrInvalidField)
		}
		k := key{p.Number, p.Protocol}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Number != out[j].Number {
			return out[i].Number < out[j].Number
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out, nil
}
