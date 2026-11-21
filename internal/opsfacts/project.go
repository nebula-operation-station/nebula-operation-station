// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"context"
	"fmt"
	"sort"
	"strconv"
)

// FixStatus is the fix situation of one finding, as the agent may state it
// (ADR 0016 D4). It is a fixed enumeration; no text from a source passes it.
type FixStatus string

// Fix statuses.
const (
	FixVerified       FixStatus = "fix_verified"
	FixNotVerified    FixStatus = "update_not_verified"
	FixNoCandidate    FixStatus = "no_candidate"
	FixNoFixYet       FixStatus = "no_fix_yet"
	FixRebootRequired FixStatus = "reboot_required"
	FixUnknown        FixStatus = "unknown"
)

// LabHost is the host part of a class lab projection (ADR 0016 D4).
type LabHost struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Environment string `json:"environment"`
	Criticality string `json:"criticality"`
}

// LabFinding is one listed finding of a group. Every field is validated or
// cleaned; the vulnerability ID is only ever a strict-shape identifier.
type LabFinding struct {
	VulnID    string    `json:"vuln_id"`
	Package   string    `json:"package"`
	Installed string    `json:"installed"`
	Fixed     string    `json:"fixed,omitempty"`
	Tier      Tier      `json:"tier"`
	Score     int       `json:"score"`
	KEV       bool      `json:"kev"`
	Fix       FixStatus `json:"fix_status"`
}

// Candidate is one step candidate: an allowlisted action the operator could
// run on a host. Key is the opaque label the agent quotes back (c1, c2, ...).
// Label is the fixed NOS label of the action (Label, ADR 0016 D4); a
// candidate always has one.
type Candidate struct {
	Key    string `json:"key"`
	Action string `json:"action"`
	HostID string `json:"host_id"`
	Label  string `json:"label"`
}

// LabProjection is the projection of one group in class lab (ADR 0016 D4).
// It is the input of Digest and the only shape the agent receives for a
// group. The field set is fixed; nothing else is added to it.
type LabProjection struct {
	Group        string       `json:"group"`
	Host         LabHost      `json:"host"`
	Exposure     Exposure     `json:"exposure"`
	Ports        []Port       `json:"ports"`
	PortsOmitted int          `json:"ports_omitted"`
	Findings     []LabFinding `json:"findings"`
	Omitted      Counts       `json:"omitted"`
	Counts       Counts       `json:"counts"`
	Candidates   []Candidate  `json:"candidates"`
}

// Group is one eligible group with its projection and input digest.
type Group struct {
	// Key is "<host-id>/os" or "<host-id>/image:<image-subject>".
	Key        string
	Projection LabProjection
	// Digest is the SHA-256 of the canonical JSON of Projection.
	Digest string
}

// Projector builds the projections from its sources. It holds no state
// between calls; each call reads the sources again.
type Projector struct {
	src Sources
}

// New returns a Projector. Every source and the auditor are required.
func New(s Sources) (*Projector, error) {
	if s.Inventory == nil || s.Listeners == nil || s.Findings == nil || s.Catalog == nil || s.Audit == nil {
		return nil, ErrNoSource
	}
	return &Projector{src: s}, nil
}

// EligibleGroups returns every group with at least one open finding in tier
// critical or high, sorted by key. Callers compare each Digest with the
// digests of their stored notes to find the groups that are due.
func (p *Projector) EligibleGroups(ctx context.Context) ([]Group, error) {
	return p.build(ctx)
}

// Candidates returns the step candidates of group groupKey, but only while
// digest is the current digest of that group. It fails with ErrUnknownGroup
// when the group is not eligible and with ErrStaleDigest when the projection
// has changed since the digest was taken. A suggestion is checked against
// this list, so a candidate the agent invents or a stale one is refused.
func (p *Projector) Candidates(ctx context.Context, groupKey, digest string) ([]Candidate, error) {
	groups, err := p.build(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.Key != groupKey {
			continue
		}
		if g.Digest != digest {
			return nil, ErrStaleDigest
		}
		return append([]Candidate(nil), g.Projection.Candidates...), nil
	}
	return nil, ErrUnknownGroup
}

// audit records one skipped input. A failing auditor fails the projection.
func (p *Projector) audit(ctx context.Context, s Skip) error {
	if err := p.src.Audit.Skipped(ctx, s); err != nil {
		return fmt.Errorf("opsfacts: audit skip: %w", err)
	}
	return nil
}

// build reads the sources once and returns the eligible groups. A malformed
// host, finding or listener set is skipped and audited; only a failed read
// or a failed audit fails the build.
func (p *Projector) build(ctx context.Context) ([]Group, error) {
	byID, exposure, err := p.hostSet(ctx)
	if err != nil {
		return nil, err
	}

	findings, err := p.src.Findings.Findings(ctx)
	if err != nil {
		return nil, fmt.Errorf("opsfacts: read findings: %w", err)
	}
	open := map[string][]Finding{}
	for _, f := range findings {
		v, err := validateFinding(f)
		if err != nil {
			if err := p.audit(ctx, Skip{Scope: ScopeFinding, HostID: displayID(f.HostID), Rule: err.Error()}); err != nil {
				return nil, err
			}
			continue
		}
		if v.State != StateOpen {
			continue // accepted_risk and false_positive are left out (D3)
		}
		if _, known := byID[v.HostID]; !known {
			continue // not an inventory host: no group
		}
		key := groupKey(v)
		open[key] = append(open[key], v)
	}

	keys := make([]string, 0, len(open))
	for k := range open {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	type hostPorts struct {
		ports []Port
		rule  string // non-empty when the listener set is malformed
	}
	ports := map[string]hostPorts{}
	var out []Group
	for _, key := range keys {
		fs := open[key]
		if !hasCriticalOrHigh(fs) {
			continue
		}
		hostID := fs[0].HostID
		hp, read := ports[hostID]
		if !read {
			lp, err := p.src.Listeners.Listeners(ctx, hostID)
			if err != nil {
				return nil, fmt.Errorf("opsfacts: read listeners of host %q: %w", displayID(hostID), err)
			}
			validated, err := validatePorts(lp)
			hp = hostPorts{ports: validated}
			if err != nil {
				hp.rule = err.Error()
			}
			ports[hostID] = hp
		}
		if hp.rule != "" {
			if err := p.audit(ctx, Skip{Scope: ScopeListeners, HostID: displayID(hostID), Rule: hp.rule}); err != nil {
				return nil, err
			}
			continue // the group is left out; other groups are not affected
		}
		proj := p.project(key, byID[hostID], exposure[hostID], hp.ports, fs)
		digest, err := Digest(proj)
		if err != nil {
			return nil, fmt.Errorf("opsfacts: digest of group %q: %w", key, err)
		}
		out = append(out, Group{Key: key, Projection: proj, Digest: digest})
	}
	return out, nil
}

// hostSet reads and validates the inventory. It returns the lab part and the
// exposure of every valid host by ID. An invalid host is skipped and audited.
// Every copy of a duplicated ID is dropped and the duplicate is audited once:
// which host owns the ID is then unknown, so none of them may take findings.
func (p *Projector) hostSet(ctx context.Context) (map[string]LabHost, map[string]Exposure, error) {
	hosts, err := p.src.Inventory.Hosts(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("opsfacts: read inventory: %w", err)
	}
	valid := make([]Host, 0, len(hosts))
	count := map[string]int{}
	for _, h := range hosts {
		v, err := validateHost(h)
		if err != nil {
			if err := p.audit(ctx, Skip{Scope: ScopeHost, HostID: displayID(h.ID), Rule: err.Error()}); err != nil {
				return nil, nil, err
			}
			continue
		}
		valid = append(valid, v)
		count[v.ID]++
	}
	byID := make(map[string]LabHost, len(valid))
	exposure := make(map[string]Exposure, len(valid))
	reported := map[string]bool{}
	for _, v := range valid {
		if count[v.ID] > 1 {
			if !reported[v.ID] {
				reported[v.ID] = true
				if err := p.audit(ctx, Skip{Scope: ScopeHost, HostID: v.ID, Rule: ErrDuplicateHost.Error()}); err != nil {
					return nil, nil, err
				}
			}
			continue
		}
		byID[v.ID] = v.labHost()
		exposure[v.ID] = v.Exposure
	}
	return byID, exposure, nil
}

// External returns the external-class projection (ADR 0016 D5): the open
// findings of inventory hosts, counted per tier and KEV for the whole fleet.
// No host, package, version or vulnerability ID is read into the result. A
// malformed finding is skipped and audited, as in the lab projection.
func (p *Projector) External(ctx context.Context) (ExternalProjection, error) {
	byID, _, err := p.hostSet(ctx)
	if err != nil {
		return ExternalProjection{}, err
	}
	findings, err := p.src.Findings.Findings(ctx)
	if err != nil {
		return ExternalProjection{}, fmt.Errorf("opsfacts: read findings: %w", err)
	}
	var out ExternalProjection
	for _, f := range findings {
		v, err := validateFinding(f)
		if err != nil {
			if err := p.audit(ctx, Skip{Scope: ScopeFinding, HostID: displayID(f.HostID), Rule: err.Error()}); err != nil {
				return ExternalProjection{}, err
			}
			continue
		}
		if v.State != StateOpen {
			continue
		}
		if _, known := byID[v.HostID]; !known {
			continue
		}
		out.Fleet.add(v.Tier, v.KEV)
	}
	return out, nil
}

// project builds the lab projection of one group. Its findings are the open
// findings of the group, already validated.
func (p *Projector) project(key string, host LabHost, expo Exposure, ports []Port, fs []Finding) LabProjection {
	sortFindings(fs)
	var counts Counts
	for _, f := range fs {
		counts.add(f.Tier, f.KEV)
	}
	listed := fs
	var omitted Counts
	if len(fs) > MaxFindingsPerGroup {
		listed = fs[:MaxFindingsPerGroup]
		for _, f := range fs[MaxFindingsPerGroup:] {
			omitted.add(f.Tier, f.KEV)
		}
	}
	lf := make([]LabFinding, 0, len(listed))
	for _, f := range listed {
		lf = append(lf, LabFinding{
			VulnID:    f.VulnID,
			Package:   f.Package,
			Installed: f.Installed,
			Fixed:     f.Fixed,
			Tier:      f.Tier,
			Score:     f.Score,
			KEV:       f.KEV,
			Fix:       fixStatus(f.Fix),
		})
	}
	listedPorts := ports
	portsOmitted := 0
	if len(ports) > MaxPortsPerHost {
		listedPorts = ports[:MaxPortsPerHost]
		portsOmitted = len(ports) - MaxPortsPerHost
	}
	return LabProjection{
		Group:        key,
		Host:         host,
		Exposure:     expo,
		Ports:        append([]Port(nil), listedPorts...),
		PortsOmitted: portsOmitted,
		Findings:     lf,
		Omitted:      omitted,
		Counts:       counts,
		Candidates:   p.candidates(host.ID, groupSubject(fs), fs),
	}
}

// groupSubject returns the subject kind of a non-empty group. Every finding of
// a group has the same subject kind (the group key carries it).
func groupSubject(fs []Finding) SubjectKind {
	if len(fs) > 0 {
		return fs[0].Subject
	}
	return SubjectOS
}

// candidates returns the step candidates of a group: the allowlisted actions
// that the findings' "fix with" decisions offer, that the catalog contains,
// sorted by action ID and keyed c1, c2, ...
func (p *Projector) candidates(hostID string, subject SubjectKind, fs []Finding) []Candidate {
	want := map[string]bool{}
	for _, f := range fs {
		for _, a := range offeredActions(subject, f.Fix) {
			want[a] = true
		}
	}
	actions := make([]string, 0, len(want))
	for a := range want {
		if _, ok := Families(a); !ok || !p.src.Catalog.HasAction(a) {
			continue // not allowlisted, or not in the catalog: drops out
		}
		if _, ok := Label(a); !ok {
			continue // no fixed label: a candidate without one is refused
		}
		actions = append(actions, a)
	}
	sort.Strings(actions)
	if len(actions) > MaxCandidatesPerGroup {
		actions = actions[:MaxCandidatesPerGroup]
	}
	out := make([]Candidate, 0, len(actions))
	for i, a := range actions {
		label, _ := Label(a)
		out = append(out, Candidate{Key: "c" + strconv.Itoa(i+1), Action: a, HostID: hostID, Label: label})
	}
	return out
}

// offeredActions maps a "fix with" decision to the allowlisted actions it
// offers (ADR 0016 D4; the links are those of ADR 0011 D8). The OS install
// links offer their package action. The container link offers the container
// update flow of an image group, as batch actions. A kernel fix that is
// verified also offers the reboot, which takes it effect.
func offeredActions(subject SubjectKind, d FixDecision) []string {
	var out []string
	switch d.Link {
	case LinkInstallSecurity:
		out = append(out, "package.install_security")
	case LinkInstallAll:
		out = append(out, "package.install_all")
	case LinkContainers:
		if subject == SubjectImage {
			out = append(out, "docker.compose_update", "docker.update")
		}
	}
	if d.Reboot && d.Outcome == OutcomeVerified {
		out = append(out, "system.reboot")
	}
	return out
}

// fixStatus maps a "fix with" decision to the fix status the agent sees. An
// image candidate is a container update that is not a verified fix, so it
// reads as "update not verified", and an image without a candidate as "no
// candidate", the same as their OS counterparts (ADR 0016 D4).
func fixStatus(d FixDecision) FixStatus {
	switch d.Outcome {
	case OutcomeVerified:
		if d.Reboot {
			return FixRebootRequired
		}
		return FixVerified
	case OutcomeNotVerified, OutcomeBelowFixed, OutcomeImageCandidate:
		return FixNotVerified
	case OutcomeNoCandidate, OutcomeImageNoCandidate:
		return FixNoCandidate
	case OutcomeNoFixYet:
		return FixNoFixYet
	default:
		return FixUnknown
	}
}

// add counts one finding.
func (c *Counts) add(t Tier, kev bool) {
	switch t {
	case TierCritical:
		c.Critical++
	case TierHigh:
		c.High++
	case TierMedium:
		c.Medium++
	case TierLow:
		c.Low++
	}
	if kev {
		c.KEV++
	}
}

// sortFindings orders findings into a total order: score (highest first),
// then tier, then every field that the listed finding shows. Two findings
// equal in all of them are indistinguishable in the projection, so the
// digest does not depend on the order the source returned them in.
func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool { return findingLess(fs[i], fs[j]) })
}

// findingLess is the order of sortFindings.
func findingLess(a, b Finding) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	if a.Tier.rank() != b.Tier.rank() {
		return a.Tier.rank() > b.Tier.rank()
	}
	if a.VulnID != b.VulnID {
		return a.VulnID < b.VulnID
	}
	if a.Package != b.Package {
		return a.Package < b.Package
	}
	if a.Installed != b.Installed {
		return a.Installed < b.Installed
	}
	if a.Fixed != b.Fixed {
		return a.Fixed < b.Fixed
	}
	if a.KEV != b.KEV {
		return a.KEV
	}
	if a.Fix.Outcome != b.Fix.Outcome {
		return a.Fix.Outcome < b.Fix.Outcome
	}
	if a.Fix.Link != b.Fix.Link {
		return a.Fix.Link < b.Fix.Link
	}
	return !a.Fix.Reboot && b.Fix.Reboot
}

// hasCriticalOrHigh reports whether a group is eligible (D3).
func hasCriticalOrHigh(fs []Finding) bool {
	for _, f := range fs {
		if f.Tier == TierCritical || f.Tier == TierHigh {
			return true
		}
	}
	return false
}

// groupKey names the group a finding belongs to.
func groupKey(f Finding) string {
	if f.Subject == SubjectImage {
		return f.HostID + "/image:" + f.ImageSubject
	}
	return f.HostID + "/os"
}
