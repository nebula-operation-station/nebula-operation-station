// SPDX-License-Identifier: AGPL-3.0-or-later

// Sources of the ops projection over the stored findings (ADR 0016 D3, D4).
// opsVulnFindings is the finding source: it reads the vulnerability store and
// maps each finding to an opsfacts.Finding. opsVulnListeners is the listener
// source; it fails every read, because the server stores no ports (see its
// comment). The wiring into the projector is in ops.go and is not done here.
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

// errOpsUpdateListsUnread: the host update lists cannot be read, so the fix
// decision of a finding that needs them is not known. The read fails instead
// of giving an unknown decision, which would look like a decision.
var errOpsUpdateListsUnread = errors.New("host update lists cannot be read")

// errOpsPreviewUnreadable: a container preview of an image finding cannot be
// read. The resolver gives a failed read and a missing preview the same unknown
// decision (ReasonNoPreview), so the read fails instead.
var errOpsPreviewUnreadable = errors.New("container preview cannot be read")

// errOpsPreviewLimited: the open image findings cover more hosts than the
// resolver reads container previews of (vulnfix.MaxPreviewHosts); the hosts
// past the limit would read as "no preview", so the read fails instead.
var errOpsPreviewLimited = errors.New("more image hosts than container previews are read")

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
// holds no copy of the findings: each call reads the store again. It holds no
// fix decider either: a vulnfix.Resolver is a per-page object (it caches the
// update lists and container previews without a lock), so newFixes builds a
// fresh one for every Findings call, over a per-call preview guard.
type opsVulnFindings struct {
	store    vulnFindingReader
	previews vulnfix.PreviewSource
	newFixes func(vulnfix.PreviewSource) fixDecider
}

var _ opsfacts.FindingSource = opsVulnFindings{}

// newOpsVulnFindings returns the finding source over store, with the container
// previews of image findings and one fix decider per Findings call from
// newFixes (given the preview source it must read through). All three are
// required; a missing one fails closed as opsfacts.ErrNoSource.
func newOpsVulnFindings(store vulnFindingReader, previews vulnfix.PreviewSource,
	newFixes func(vulnfix.PreviewSource) fixDecider) (opsVulnFindings, error) {
	if store == nil || previews == nil || newFixes == nil {
		return opsVulnFindings{}, fmt.Errorf("ops finding source: %w", opsfacts.ErrNoSource)
	}
	return opsVulnFindings{store: store, previews: previews, newFixes: newFixes}, nil
}

// opsPreviewGuard is the container preview source of one Findings call. It
// passes every read to inner and keeps the first failed read. The resolver
// gives a failed read and a missing preview the same unknown decision, so
// Findings checks err after the decisions and fails the read.
type opsPreviewGuard struct {
	inner vulnfix.PreviewSource
	err   error
}

// Preview reads the newest preview of hostID through the guard; see opsPreviewGuard.
func (g *opsPreviewGuard) Preview(ctx context.Context, hostID string) (vulnfix.Preview, error) {
	p, err := g.inner.Preview(ctx, hostID)
	if err != nil && g.err == nil {
		g.err = fmt.Errorf("read container preview: %w: %w", errOpsPreviewUnreadable, err)
	}
	return p, err
}

// Findings returns every stored finding that is not fixed, with its fix
// decision. A failed read, a read that is truncated at MaxListFindings, a failed
// container preview read, more image hosts than the resolver reads previews of,
// or a finding whose stored scores do not compute, fails the whole list.
func (s opsVulnFindings) Findings(ctx context.Context) ([]opsfacts.Finding, error) {
	guard := &opsPreviewGuard{inner: s.previews}
	fixes := s.newFixes(guard)
	if fixes == nil {
		return nil, fmt.Errorf("read findings: fix decider: %w", opsfacts.ErrNoSource)
	}
	// The fixed history is skipped in the store, so only live findings count
	// toward the limit (a fixed history past MaxListFindings must not fail
	// every read).
	fs, more, err := s.store.List(ctx, vulnstore.ListQuery{ExcludeFixed: true, Limit: vulnstore.MaxListFindings})
	if err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	if more {
		return nil, fmt.Errorf("read findings: %d or more: %w", vulnstore.MaxListFindings, errOpsFindingsTruncated)
	}
	if n := opsPreviewHostsOf(fs); n > vulnfix.MaxPreviewHosts {
		return nil, fmt.Errorf("read findings: %d image hosts: %w", n, errOpsPreviewLimited)
	}
	out := make([]opsfacts.Finding, 0, len(fs))
	for _, f := range fs {
		if f.State == vulnstore.StateFixed {
			continue
		}
		res := fixes.Decide(ctx, f)
		if res.Status == vulnfix.StatusUnknown && res.Reason == vulnfix.ReasonListsUnread {
			return nil, fmt.Errorf("read findings: %w", errOpsUpdateListsUnread)
		}
		of, err := opsFindingOf(f, res)
		if err != nil {
			return nil, fmt.Errorf("read findings: %w", err)
		}
		out = append(out, of)
	}
	if guard.err != nil {
		return nil, fmt.Errorf("read findings: %w", guard.err)
	}
	return out, nil
}

// opsPreviewHostsOf counts the distinct hosts of the not fixed image findings.
// The decisions read one container preview per such host, so a count above
// vulnfix.MaxPreviewHosts means that some reads would be cut off.
func opsPreviewHostsOf(fs []vulnstore.Finding) int {
	hosts := map[string]bool{}
	for _, f := range fs {
		if f.State != vulnstore.StateFixed && f.Subject.Kind == vulnfinding.SubjectImage {
			hosts[f.Subject.ID] = true
		}
	}
	return len(hosts)
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
		// The version the decision used: the higher of the record's and the
		// episode's fixed version (vulnfix.Result.Fixed).
		out.Fixed = res.Fixed
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

// errOpsListenersUnavailable: the server holds no listening ports of a host.
var errOpsListenersUnavailable = errors.New("listening ports of the host are not stored")

// opsVulnListeners is the listener source of the projection (ADR 0016 D4,
// ADR 0009). The server stores no listening ports per host: server.db has no
// table for them (checked against the migrations in
// internal/serverdb/migrations), and the discovered_addresses ports are scan
// results of unmanaged addresses, not the host's own listeners. So every read
// fails with errOpsListenersUnavailable. It never returns an empty list: an
// empty list reads as "verified no listening ports", which the server cannot
// verify. The projection therefore fails for a host with a critical or high
// finding until a listener source exists; it does not show ports: [] instead.
type opsVulnListeners struct{}

var _ opsfacts.ListenerSource = opsVulnListeners{}

// Listeners always fails with errOpsListenersUnavailable; see the type comment.
func (opsVulnListeners) Listeners(context.Context, string) ([]opsfacts.Port, error) {
	return nil, errOpsListenersUnavailable
}
