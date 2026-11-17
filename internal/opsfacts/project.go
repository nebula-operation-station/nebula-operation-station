// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
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
	VulnID    string        `json:"vuln_id"`
	Package   string        `json:"package"`
	Installed string        `json:"installed"`
	Fixed     string        `json:"fixed,omitempty"`
	Tier      vulnprio.Tier `json:"tier"`
	Score     int           `json:"score"`
	KEV       bool          `json:"kev"`
	Fix       FixStatus     `json:"fix_status"`
}

// Candidate is one step candidate: an allowlisted action the operator could
// run on a host. Key is the opaque label the agent quotes back (c1, c2, ...).
type Candidate struct {
	Key    string `json:"key"`
	Action string `json:"action"`
	HostID string `json:"host_id"`
}

// LabProjection is the projection of one group in class lab (ADR 0016 D4).
// It is the input of Digest and the only shape the agent receives for a
// group. The field set is fixed; nothing else is added to it.
type LabProjection struct {
	Group        string            `json:"group"`
	Host         LabHost           `json:"host"`
	Exposure     vulnprio.Exposure `json:"exposure"`
	Ports        []Port            `json:"ports"`
	PortsOmitted int               `json:"ports_omitted"`
	Findings     []LabFinding      `json:"findings"`
	Omitted      Counts            `json:"omitted"`
	Counts       Counts            `json:"counts"`
	Candidates   []Candidate       `json:"candidates"`
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

// New returns a Projector. Every source is required.
func New(s Sources) (*Projector, error) {
	if s.Inventory == nil || s.Listeners == nil || s.Findings == nil || s.Catalog == nil {
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

// build reads the sources once and returns the eligible groups.
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
			return nil, fmt.Errorf("opsfacts: finding of host %q: %w", f.HostID, err)
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

	var out []Group
	ports := map[string][]Port{}
	for _, key := range keys {
		fs := open[key]
		if !hasCriticalOrHigh(fs) {
			continue
		}
		hostID := fs[0].HostID
		if _, read := ports[hostID]; !read {
			lp, err := p.src.Listeners.Listeners(ctx, hostID)
			if err != nil {
				return nil, fmt.Errorf("opsfacts: read listeners of host %q: %w", hostID, err)
			}
			if ports[hostID], err = validatePorts(lp); err != nil {
				return nil, fmt.Errorf("opsfacts: listeners of host %q: %w", hostID, err)
			}
		}
		proj := p.project(key, byID[hostID], exposure[hostID], ports[hostID], fs)
		digest, err := Digest(proj)
		if err != nil {
			return nil, fmt.Errorf("opsfacts: digest of group %q: %w", key, err)
		}
		out = append(out, Group{Key: key, Projection: proj, Digest: digest})
	}
	return out, nil
}

// hostSet reads and validates the inventory. It returns the lab part and the
// exposure of every host by ID. A host that fails validation, or a duplicate
// ID, fails the whole read.
func (p *Projector) hostSet(ctx context.Context) (map[string]LabHost, map[string]vulnprio.Exposure, error) {
	hosts, err := p.src.Inventory.Hosts(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("opsfacts: read inventory: %w", err)
	}
	byID := make(map[string]LabHost, len(hosts))
	exposure := make(map[string]vulnprio.Exposure, len(hosts))
	for _, h := range hosts {
		v, err := validateHost(h)
		if err != nil {
			return nil, nil, fmt.Errorf("opsfacts: host %q: %w", h.ID, err)
		}
		if _, dup := byID[v.ID]; dup {
			return nil, nil, fmt.Errorf("opsfacts: host %q: %w", v.ID, ErrDuplicateHost)
		}
		byID[v.ID] = v.labHost()
		exposure[v.ID] = v.Exposure
	}
	return byID, exposure, nil
}

// External returns the external-class projection (ADR 0016 D5): the open
// findings of inventory hosts, counted per tier and KEV for the whole fleet.
// No host, package, version or vulnerability ID is read into the result.
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
			return ExternalProjection{}, fmt.Errorf("opsfacts: finding of host %q: %w", f.HostID, err)
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
func (p *Projector) project(key string, host LabHost, expo vulnprio.Exposure, ports []Port, fs []Finding) LabProjection {
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
		Candidates:   p.candidates(host.ID, fs),
	}
}

// candidates returns the step candidates of a group: the allowlisted actions
// that the findings' "fix with" decisions offer, that the catalog contains,
// sorted by action ID and keyed c1, c2, ...
func (p *Projector) candidates(hostID string, fs []Finding) []Candidate {
	want := map[string]bool{}
	for _, f := range fs {
		for _, a := range offeredActions(f.Fix) {
			want[a] = true
		}
	}
	actions := make([]string, 0, len(want))
	for a := range want {
		if _, ok := Families(a); !ok || !p.src.Catalog.HasAction(a) {
			continue // not allowlisted, or not in the catalog: drops out
		}
		actions = append(actions, a)
	}
	sort.Strings(actions)
	if len(actions) > MaxCandidatesPerGroup {
		actions = actions[:MaxCandidatesPerGroup]
	}
	out := make([]Candidate, 0, len(actions))
	for i, a := range actions {
		out = append(out, Candidate{Key: "c" + strconv.Itoa(i+1), Action: a, HostID: hostID})
	}
	return out
}

// offeredActions maps a "fix with" decision to the allowlisted actions it
// offers. vulnfix sets an install action only for a candidate that exists
// (verified or not verified), so a result without one offers no install. A
// kernel fix that is verified also offers the reboot, which takes it effect.
func offeredActions(r vulnfix.Result) []string {
	var out []string
	switch r.Action {
	case vulnfix.ActionInstallSecurity:
		out = append(out, "package.install_security")
	case vulnfix.ActionInstallAll:
		out = append(out, "package.install_all")
	}
	if r.Reboot && r.Status == vulnfix.StatusVerified {
		out = append(out, "system.reboot")
	}
	return out
}

// fixStatus maps a "fix with" decision to the fix status the agent sees.
func fixStatus(r vulnfix.Result) FixStatus {
	switch r.Status {
	case vulnfix.StatusVerified:
		if r.Reboot {
			return FixRebootRequired
		}
		return FixVerified
	case vulnfix.StatusNotVerified, vulnfix.StatusBelowFixed:
		return FixNotVerified
	case vulnfix.StatusNoCandidate:
		return FixNoCandidate
	case vulnfix.StatusNoFixYet:
		return FixNoFixYet
	default:
		return FixUnknown
	}
}

// add counts one finding.
func (c *Counts) add(t vulnprio.Tier, kev bool) {
	switch t {
	case vulnprio.TierCritical:
		c.Critical++
	case vulnprio.TierHigh:
		c.High++
	case vulnprio.TierMedium:
		c.Medium++
	case vulnprio.TierLow:
		c.Low++
	}
	if kev {
		c.KEV++
	}
}

// sortFindings orders findings by score (highest first), then tier, then
// the identifying fields, so the same input always lists the same findings.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Tier.Rank() != b.Tier.Rank() {
			return a.Tier.Rank() > b.Tier.Rank()
		}
		if a.VulnID != b.VulnID {
			return a.VulnID < b.VulnID
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Installed < b.Installed
	})
}

// hasCriticalOrHigh reports whether a group is eligible (D3).
func hasCriticalOrHigh(fs []Finding) bool {
	for _, f := range fs {
		if f.Tier == vulnprio.TierCritical || f.Tier == vulnprio.TierHigh {
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

// validateHost checks and cleans one inventory host.
func validateHost(h Host) (Host, error) {
	if !vulnfix.ValidSubjectID(h.ID) {
		return Host{}, fmt.Errorf("host id: %w", ErrInvalidField)
	}
	h.Label = cleanText(h.Label, MaxLabelBytes)
	h.Environment = cleanText(h.Environment, MaxEnvironmentBytes)
	switch h.Criticality {
	case inventory.CriticalityLow, inventory.CriticalityMedium,
		inventory.CriticalityHigh, inventory.CriticalityCritical:
	default:
		return Host{}, fmt.Errorf("criticality: %w", ErrInvalidField)
	}
	switch h.Exposure {
	case "":
		h.Exposure = vulnprio.ExposureUnknown
	case vulnprio.ExposureInternet, vulnprio.ExposureVPNEntry, vulnprio.ExposureUnknown,
		vulnprio.ExposureInternal, vulnprio.ExposureNoListener:
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
// shape rejects the finding; the caller fails closed.
func validateFinding(f Finding) (Finding, error) {
	if !vulnfix.ValidSubjectID(f.HostID) {
		return Finding{}, fmt.Errorf("host id: %w", ErrInvalidField)
	}
	switch f.Subject {
	case SubjectOS:
		if f.ImageSubject != "" {
			return Finding{}, fmt.Errorf("image subject on os finding: %w", ErrInvalidField)
		}
	case SubjectImage:
		if !vulnfix.ValidSubjectID(f.ImageSubject) {
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
	case vulnprio.TierCritical, vulnprio.TierHigh, vulnprio.TierMedium, vulnprio.TierLow:
	default:
		return Finding{}, ErrInvalidTier
	}
	if f.Score < 0 || f.Score > MaxScore {
		return Finding{}, fmt.Errorf("score: %w", ErrInvalidField)
	}
	if !vulnIDRe.MatchString(f.VulnID) {
		return Finding{}, fmt.Errorf("vulnerability id: %w", ErrInvalidField)
	}
	f.Package = cleanText(f.Package, MaxPackageBytes)
	if !packageRe.MatchString(f.Package) {
		return Finding{}, fmt.Errorf("package name: %w", ErrInvalidField)
	}
	if !versionRe.MatchString(f.Installed) {
		return Finding{}, fmt.Errorf("installed version: %w", ErrInvalidField)
	}
	if f.Fixed != "" && !versionRe.MatchString(f.Fixed) {
		return Finding{}, fmt.Errorf("fixed version: %w", ErrInvalidField)
	}
	return f, nil
}

// validatePorts checks listening ports and returns them sorted by number,
// then protocol, so the first MaxPortsPerHost are always the same ones.
func validatePorts(ps []Port) ([]Port, error) {
	out := make([]Port, 0, len(ps))
	for _, p := range ps {
		if p.Number < 1 || p.Number > 65535 {
			return nil, fmt.Errorf("port number %d: %w", p.Number, ErrInvalidField)
		}
		if p.Protocol != "tcp" && p.Protocol != "udp" {
			return nil, fmt.Errorf("port protocol: %w", ErrInvalidField)
		}
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
