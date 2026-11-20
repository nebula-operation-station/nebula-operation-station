// SPDX-License-Identifier: AGPL-3.0-or-later

// Sources of the ops projection over the stored findings (ADR 0016 D3, D4).
// opsVulnFindings is the finding source: it reads the vulnerability store and
// maps each finding to an opsfacts.Finding. opsVulnListeners is the listener
// source; it reports no ports (see its comment). The wiring into the
// projector is in ops.go and is not done here.
//
// Mapping rules:
//   - Every enum value leaves this file through a fixed switch table. A value
//     outside its table becomes the unknown value (fix outcome, fix link) or
//     the empty value, which opsfacts rejects and records as a skip. No text
//     of a finding (package name, version, vulnerability ID) is interpreted
//     beyond copying it into the field that the projection validates.
//   - Tier and KEV have the same origin as the open-findings count of the
//     digest (countFindings in leasewatch_wiring.go): the episode's peak tier,
//     and KEV when the episode was ever KEV-listed or the record carries a
//     KEV score.
//   - A failed read is an error of the source. Nothing is turned into an empty
//     list, because a partial list could hide findings.
//   - Fixed findings are left out here: they are closed, and ADR 0016 D3 lets
//     only open findings into a group.

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// opsImageSubjectHex is the number of digest hex digits that form the image
// subject ID. The ID must fit the subject-ID pattern (63 bytes at most with
// the "img-" prefix); 40 hex digits (160 bits) keep it unique per host.
const opsImageSubjectHex = 40

// errOpsFindingsTruncated: the store holds more findings than one read returns.
var errOpsFindingsTruncated = errors.New("more findings stored than one read returns")

// opsDigestRe is the platform digest form of an image subject.
var opsDigestRe = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// vulnFindingReader is the read the finding source needs from the store
// (*vulnstore.Store).
type vulnFindingReader interface {
	List(ctx context.Context, q vulnstore.ListQuery) ([]vulnstore.Finding, bool, error)
}

// fixDecider gives the "fix with" decision of a finding (*vulnfix.Resolver).
type fixDecider interface {
	Decide(ctx context.Context, f vulnstore.Finding) vulnfix.Result
}

// opsVulnFindings is the finding source of the projection (ADR 0016 D3). It
// holds no copy of the findings: each call reads the store again.
type opsVulnFindings struct {
	store vulnFindingReader
	fixes fixDecider
}

var _ opsfacts.FindingSource = opsVulnFindings{}

// newOpsVulnFindings returns the finding source over store and fixes. Both
// are required; a missing one fails closed as opsfacts.ErrNoSource.
func newOpsVulnFindings(store vulnFindingReader, fixes fixDecider) (opsVulnFindings, error) {
	if store == nil || fixes == nil {
		return opsVulnFindings{}, fmt.Errorf("ops finding source: %w", opsfacts.ErrNoSource)
	}
	return opsVulnFindings{store: store, fixes: fixes}, nil
}

// Findings returns every stored finding that is not fixed, with its fix
// decision. A failed read, a read that is truncated at MaxListFindings, or a
// finding whose stored scores do not compute, fails the whole list.
func (s opsVulnFindings) Findings(ctx context.Context) ([]opsfacts.Finding, error) {
	fs, more, err := s.store.List(ctx, vulnstore.ListQuery{Limit: vulnstore.MaxListFindings})
	if err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	if more {
		return nil, fmt.Errorf("read findings: %d or more: %w", vulnstore.MaxListFindings, errOpsFindingsTruncated)
	}
	out := make([]opsfacts.Finding, 0, len(fs))
	for _, f := range fs {
		if f.State == vulnstore.StateFixed {
			continue
		}
		of, err := opsFindingOf(f, s.fixes.Decide(ctx, f))
		if err != nil {
			return nil, fmt.Errorf("read findings: %w", err)
		}
		out = append(out, of)
	}
	return out, nil
}

// opsFindingOf maps one stored finding and its fix decision to the projection
// value. The score is the vu-prio-v1 score of the record's scores.
func opsFindingOf(f vulnstore.Finding, res vulnfix.Result) (opsfacts.Finding, error) {
	prio, err := vulnprio.Compute(vulnprio.Input{Scores: f.Record.Scores})
	if err != nil {
		return opsfacts.Finding{}, fmt.Errorf("finding score: %w", err)
	}
	out := opsfacts.Finding{
		HostID:    f.Subject.ID,
		VulnID:    f.Record.Vuln.ID,
		Package:   f.Record.Component.SourcePackage,
		Installed: f.Record.Component.SourceVersion,
		Tier:      opsTierOf(f.EpisodePeakTier),
		Score:     prio.Score,
		KEV:       f.EpisodeKEV() || f.Record.Scores.KEV != nil,
		State:     opsStateOf(f.State),
		Fix:       opsDecisionOf(res),
	}
	if f.Record.Fix.State == vulnfinding.FixFixed {
		out.Fixed = f.Record.Fix.Version
	}
	switch f.Subject.Kind {
	case vulnfinding.SubjectHost:
		out.Subject = opsfacts.SubjectOS
	case vulnfinding.SubjectImage:
		out.Subject = opsfacts.SubjectImage
		out.ImageSubject = opsImageSubjectOf(f.Subject.ImageDigest)
	default:
		// Device and unknown subjects keep the empty kind; opsfacts rejects
		// them as a skip (ADR 0016 D3: no fix notes for devices).
	}
	return out, nil
}

// opsImageSubjectOf derives the image subject ID from the platform digest:
// "img-" and the first opsImageSubjectHex hex digits. A digest of another
// form gives the empty ID, which opsfacts rejects as a skip.
func opsImageSubjectOf(digest string) string {
	m := opsDigestRe.FindStringSubmatch(digest)
	if m == nil {
		return ""
	}
	return "img-" + m[1][:opsImageSubjectHex]
}

// opsTierOf maps a stored tier to the projection tier. Unknown gives the
// empty tier, which opsfacts rejects as a skip.
func opsTierOf(t vulnstore.Tier) opsfacts.Tier {
	switch t {
	case vulnstore.TierLow:
		return opsfacts.TierLow
	case vulnstore.TierMedium:
		return opsfacts.TierMedium
	case vulnstore.TierHigh:
		return opsfacts.TierHigh
	case vulnstore.TierCritical:
		return opsfacts.TierCritical
	}
	return ""
}

// opsStateOf maps a stored state to the projection state. Fixed findings never
// reach this table (Findings leaves them out); any other value gives the empty
// state, which opsfacts rejects as a skip.
func opsStateOf(s vulnstore.State) opsfacts.FindingState {
	switch s {
	case vulnstore.StateOpen:
		return opsfacts.StateOpen
	case vulnstore.StateAcceptedRisk:
		return opsfacts.StateAcceptedRisk
	case vulnstore.StateFalsePositive:
		return opsfacts.StateFalsePositive
	}
	return ""
}

// opsDecisionOf maps a "fix with" result to the projection decision.
func opsDecisionOf(res vulnfix.Result) opsfacts.FixDecision {
	return opsfacts.FixDecision{Outcome: opsOutcomeOf(res.Status), Link: opsLinkOf(res.Action), Reboot: res.Reboot}
}

// opsOutcomeOf maps a decision status to a fix outcome; a status outside the
// table is opsfacts.OutcomeUnknown.
func opsOutcomeOf(s vulnfix.Status) opsfacts.FixOutcome {
	switch s {
	case vulnfix.StatusNone:
		return opsfacts.OutcomeNone
	case vulnfix.StatusVerified:
		return opsfacts.OutcomeVerified
	case vulnfix.StatusNotVerified:
		return opsfacts.OutcomeNotVerified
	case vulnfix.StatusBelowFixed:
		return opsfacts.OutcomeBelowFixed
	case vulnfix.StatusNoCandidate:
		return opsfacts.OutcomeNoCandidate
	case vulnfix.StatusNoFixYet:
		return opsfacts.OutcomeNoFixYet
	case vulnfix.StatusWontFix:
		return opsfacts.OutcomeWontFix
	case vulnfix.StatusImageCandidate:
		return opsfacts.OutcomeImageCandidate
	case vulnfix.StatusImageNoCandidate:
		return opsfacts.OutcomeImageNoCandidate
	case vulnfix.StatusDeviceNoPatch:
		return opsfacts.OutcomeDeviceNoPatch
	case vulnfix.StatusUnknown:
		return opsfacts.OutcomeUnknown
	}
	return opsfacts.OutcomeUnknown
}

// opsLinkOf maps a decision action to the link of the existing flow; an action
// outside the table is opsfacts.LinkNone.
func opsLinkOf(a vulnfix.Action) opsfacts.FixLink {
	switch a {
	case vulnfix.ActionInstallSecurity:
		return opsfacts.LinkInstallSecurity
	case vulnfix.ActionInstallAll:
		return opsfacts.LinkInstallAll
	case vulnfix.ActionListUpdates:
		return opsfacts.LinkListUpdates
	case vulnfix.ActionContainers:
		return opsfacts.LinkContainers
	case vulnfix.ActionCiscoAdvisory:
		return opsfacts.LinkCiscoAdvisory
	case vulnfix.ActionPANAdvisory:
		return opsfacts.LinkPANAdvisory
	}
	return opsfacts.LinkNone
}

// opsVulnListeners is the listener source of the projection (ADR 0016 D4,
// ADR 0009). The server stores no listening ports per host: server.db has no
// table for them (checked against the migrations in
// internal/serverdb/migrations), and the discovered_addresses ports are scan
// results of unmanaged addresses, not the host's own listeners. So it reports
// no ports. A host's exposure is then the inventory value, which is empty
// (unknown) until the inventory carries it, so exposure stays "unknown" and
// is never reported as "no listener".
type opsVulnListeners struct{}

var _ opsfacts.ListenerSource = opsVulnListeners{}

// Listeners returns no ports for hostID; see the type comment.
func (opsVulnListeners) Listeners(context.Context, string) ([]opsfacts.Port, error) {
	return nil, nil
}
