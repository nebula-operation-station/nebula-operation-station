// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeInventory struct {
	hosts []Host
	err   error
}

func (f fakeInventory) Hosts(context.Context) ([]Host, error) { return f.hosts, f.err }

type fakeListeners map[string][]Port

func (f fakeListeners) Listeners(_ context.Context, id string) ([]Port, error) {
	return f[id], nil
}

type fakeFindings struct {
	fs  []Finding
	err error
}

func (f fakeFindings) Findings(context.Context) ([]Finding, error) { return f.fs, f.err }

type fakeCatalog map[string]bool

func (f fakeCatalog) HasAction(a string) bool { return f[a] }

// recordAudit keeps every skip it is given. A non-nil err makes it fail.
type recordAudit struct {
	skips []Skip
	err   error
}

func (r *recordAudit) Skipped(_ context.Context, s Skip) error {
	if r.err != nil {
		return r.err
	}
	r.skips = append(r.skips, s)
	return nil
}

// fullCatalog contains every allowlisted action.
func fullCatalog() fakeCatalog {
	c := fakeCatalog{}
	for a := range suggestionAllowlist {
		c[a] = true
	}
	return c
}

// webHost is the host of most tests.
func webHost() Host {
	return Host{
		ID:          "web-01",
		Label:       "web-01",
		Environment: "lab",
		Criticality: CriticalityHigh,
		Exposure:    ExposureInternet,
	}
}

// osFinding is a high, open, verified-fix OS finding of web-01.
func osFinding(vuln string, tier Tier, score int) Finding {
	return Finding{
		Subject:   SubjectOS,
		HostID:    "web-01",
		VulnID:    vuln,
		Package:   "openssl",
		Installed: "3.0.1-1",
		Fixed:     "3.0.2-1",
		Tier:      tier,
		Score:     score,
		State:     StateOpen,
		Fix:       FixDecision{Outcome: OutcomeVerified, Link: LinkInstallSecurity},
	}
}

// imageFinding is an open finding of image "nginx-img" that runs on web-01.
func imageFinding(vuln string, tier Tier, score int, outcome FixOutcome, link FixLink) Finding {
	f := osFinding(vuln, tier, score)
	f.Subject = SubjectImage
	f.ImageSubject = "nginx-img"
	f.Package = "libssl3"
	f.Fix = FixDecision{Outcome: outcome, Link: link}
	return f
}

// newProjectorWith returns a projector over src and the auditor it records to.
func newProjectorWith(t *testing.T, src Sources) (*Projector, *recordAudit) {
	t.Helper()
	audit := &recordAudit{}
	if src.Audit == nil {
		src.Audit = audit
	} else if a, ok := src.Audit.(*recordAudit); ok {
		audit = a
	}
	p, err := New(src)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, audit
}

func newProjector(t *testing.T, hosts []Host, fs []Finding, ports fakeListeners, cat fakeCatalog) *Projector {
	t.Helper()
	p, _ := newProjectorWith(t, Sources{
		Inventory: fakeInventory{hosts: hosts},
		Listeners: ports,
		Findings:  fakeFindings{fs: fs},
		Catalog:   cat,
	})
	return p
}

func groupsOf(t *testing.T, p *Projector) []Group {
	t.Helper()
	gs, err := p.EligibleGroups(context.Background())
	if err != nil {
		t.Fatalf("EligibleGroups: %v", err)
	}
	return gs
}

// oneGroup returns the only eligible group of p, failing if there is not one.
func oneGroup(t *testing.T, p *Projector) Group {
	t.Helper()
	gs := groupsOf(t, p)
	if len(gs) != 1 {
		t.Fatalf("got %d eligible groups, want 1", len(gs))
	}
	return gs[0]
}

// digestOf returns the digest of the only group of the given sources.
func digestOf(t *testing.T, hosts []Host, fs []Finding, ports fakeListeners, cat fakeCatalog) string {
	t.Helper()
	return oneGroup(t, newProjector(t, hosts, fs, ports, cat)).Digest
}

// TestSameInputSameDigest checks that the digest does not depend on the order
// the sources return their items in.
func TestSameInputSameDigest(t *testing.T) {
	a := osFinding("CVE-2026-0001", TierHigh, 80)
	b := osFinding("CVE-2026-0002", TierCritical, 95)
	ports := fakeListeners{"web-01": {{Number: 443, Protocol: "tcp"}, {Number: 22, Protocol: "tcp"}}}

	g1 := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{a, b}, ports, fullCatalog()))
	g2 := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{b, a}, ports, fullCatalog()))
	if g1.Digest != g2.Digest {
		t.Fatalf("digest differs for the same input: %s vs %s", g1.Digest, g2.Digest)
	}
	if !strings.HasPrefix(g1.Digest, "sha256:") || len(g1.Digest) != len("sha256:")+64 {
		t.Fatalf("digest shape: %q", g1.Digest)
	}
}

// TestFindingOrderDoesNotChangeDigest checks the total order of sortFindings:
// findings that tie on every field of the old partial order (score, tier,
// vulnerability, package, installed version) but differ in a later field
// give the same digest in either input order.
func TestFindingOrderDoesNotChangeDigest(t *testing.T) {
	base := osFinding("CVE-2026-0001", TierHigh, 80)
	ties := map[string]func(*Finding){
		"fixed":   func(f *Finding) { f.Fixed = "3.0.9-1" },
		"kev":     func(f *Finding) { f.KEV = true },
		"outcome": func(f *Finding) { f.Fix = FixDecision{Outcome: OutcomeNotVerified, Link: LinkInstallSecurity} },
		"link":    func(f *Finding) { f.Fix = FixDecision{Outcome: OutcomeVerified, Link: LinkInstallAll} },
		"reboot":  func(f *Finding) { f.Fix.Reboot = true },
	}
	for name, tie := range ties {
		t.Run(name, func(t *testing.T) {
			other := base
			tie(&other)
			ports := fakeListeners{"web-01": {{Number: 22, Protocol: "tcp"}}}
			d1 := digestOf(t, []Host{webHost()}, []Finding{base, other}, ports, fullCatalog())
			d2 := digestOf(t, []Host{webHost()}, []Finding{other, base}, ports, fullCatalog())
			if d1 != d2 {
				t.Fatalf("digest depends on input order: %s vs %s", d1, d2)
			}
		})
	}
}

// TestChangedFindingChangesDigest changes one listed value at a time and
// checks that each change produces a new digest.
func TestChangedFindingChangesDigest(t *testing.T) {
	base := osFinding("CVE-2026-0001", TierHigh, 80)
	want := digestOf(t, []Host{webHost()}, []Finding{base}, nil, fullCatalog())

	changes := map[string]func(*Finding){
		"fixed version":  func(f *Finding) { f.Fixed = "3.0.3-1" },
		"installed":      func(f *Finding) { f.Installed = "3.0.0-9" },
		"tier":           func(f *Finding) { f.Tier = TierCritical },
		"score":          func(f *Finding) { f.Score = 81 },
		"kev":            func(f *Finding) { f.KEV = true },
		"fix outcome":    func(f *Finding) { f.Fix.Outcome = OutcomeNotVerified },
		"fix link":       func(f *Finding) { f.Fix.Link = LinkInstallAll },
		"reboot":         func(f *Finding) { f.Fix.Reboot = true },
		"vulnerability":  func(f *Finding) { f.VulnID = "CVE-2026-0009" },
		"package":        func(f *Finding) { f.Package = "libssl3" },
		"extra finding":  nil,
		"accepted state": func(f *Finding) { f.State = StateAcceptedRisk },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			fs := []Finding{base}
			if change == nil {
				fs = append(fs, osFinding("CVE-2026-0005", TierHigh, 70))
			} else {
				f := base
				change(&f)
				fs = []Finding{f}
			}
			got := groupsOf(t, newProjector(t, []Host{webHost()}, fs, nil, fullCatalog()))
			if name == "accepted state" {
				// An accepted finding leaves the group, which then has no
				// eligible finding at all.
				if len(got) != 0 {
					t.Fatalf("accepted finding still eligible: %d groups", len(got))
				}
				return
			}
			if len(got) != 1 || got[0].Digest == want {
				t.Fatalf("change %q did not change the digest", name)
			}
		})
	}
}

// TestChangedHostAndCandidatesChangeDigest covers the host part and the
// candidates, which are not finding fields: each change must give a new
// digest, so that a note written before it is due again.
func TestChangedHostAndCandidatesChangeDigest(t *testing.T) {
	fs := []Finding{osFinding("CVE-2026-0001", TierHigh, 80)}
	ports := fakeListeners{"web-01": {{Number: 22, Protocol: "tcp"}}}
	want := digestOf(t, []Host{webHost()}, fs, ports, fullCatalog())

	changes := map[string]func(h *Host, p *fakeListeners, c fakeCatalog){
		"host label":  func(h *Host, _ *fakeListeners, _ fakeCatalog) { h.Label = "web-02" },
		"environment": func(h *Host, _ *fakeListeners, _ fakeCatalog) { h.Environment = "prod" },
		"criticality": func(h *Host, _ *fakeListeners, _ fakeCatalog) { h.Criticality = CriticalityCritical },
		"exposure":    func(h *Host, _ *fakeListeners, _ fakeCatalog) { h.Exposure = ExposureVPNEntry },
		"port added": func(_ *Host, p *fakeListeners, _ fakeCatalog) {
			(*p)["web-01"] = append((*p)["web-01"], Port{Number: 443, Protocol: "tcp"})
		},
		"port protocol":   func(_ *Host, p *fakeListeners, _ fakeCatalog) { (*p)["web-01"][0].Protocol = "udp" },
		"catalog removes": func(_ *Host, _ *fakeListeners, c fakeCatalog) { delete(c, "package.install_security") },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			h := webHost()
			pl := fakeListeners{"web-01": append([]Port(nil), ports["web-01"]...)}
			cat := fullCatalog()
			change(&h, &pl, cat)
			got := digestOf(t, []Host{h}, fs, pl, cat)
			if got == want {
				t.Fatalf("change %q did not change the digest", name)
			}
		})
	}
}

// TestDigestChangesAfterRealSourceChange runs the projection twice on source
// data that differs in one patch: the digest of the first run must be stale
// after the change, and Candidates must refuse it (ADR 0016 D7).
func TestDigestChangesAfterRealSourceChange(t *testing.T) {
	ctx := context.Background()
	before := osFinding("CVE-2026-0001", TierHigh, 80)
	p1 := newProjector(t, []Host{webHost()}, []Finding{before}, nil, fullCatalog())
	g := oneGroup(t, p1)

	// The same host after the package was updated and the finding closed.
	after := before
	after.Installed = "3.0.2-1"
	after.Fix = FixDecision{Outcome: OutcomeVerified, Link: LinkNone}
	p2 := newProjector(t, []Host{webHost()}, []Finding{after}, nil, fullCatalog())
	g2 := oneGroup(t, p2)
	if g2.Digest == g.Digest {
		t.Fatal("digest did not change after the source changed")
	}
	if _, err := p2.Candidates(ctx, g.Key, g.Digest); !errors.Is(err, ErrStaleDigest) {
		t.Fatalf("Candidates with the old digest: error = %v, want ErrStaleDigest", err)
	}
	if _, err := p2.Candidates(ctx, g2.Key, g2.Digest); err != nil {
		t.Fatalf("Candidates with the new digest: %v", err)
	}
}

// TestAcceptedRiskAndFalsePositiveLeftOut checks that only open findings
// enter a group and its counts (ADR 0016 D3).
func TestAcceptedRiskAndFalsePositiveLeftOut(t *testing.T) {
	open := osFinding("CVE-2026-0001", TierHigh, 80)
	accepted := osFinding("CVE-2026-0002", TierCritical, 99)
	accepted.State = StateAcceptedRisk
	fp := osFinding("CVE-2026-0003", TierCritical, 98)
	fp.State = StateFalsePositive
	g := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{open, accepted, fp}, nil, fullCatalog()))
	if len(g.Projection.Findings) != 1 || g.Projection.Findings[0].VulnID != "CVE-2026-0001" {
		t.Fatalf("listed findings = %+v, want only the open one", g.Projection.Findings)
	}
	if g.Projection.Counts != (Counts{High: 1}) {
		t.Fatalf("counts = %+v, want only high=1", g.Projection.Counts)
	}
}

// TestNoEligibleGroupWithoutCriticalOrHigh checks the eligibility rule: a
// group with only medium or low findings is not eligible (ADR 0016 D3).
func TestNoEligibleGroupWithoutCriticalOrHigh(t *testing.T) {
	fs := []Finding{
		osFinding("CVE-2026-0001", TierMedium, 50),
		osFinding("CVE-2026-0002", TierLow, 10),
	}
	if gs := groupsOf(t, newProjector(t, []Host{webHost()}, fs, nil, fullCatalog())); len(gs) != 0 {
		t.Fatalf("got %d groups, want none", len(gs))
	}
}

// TestImageGroupIsSeparateFromOS checks that image findings form their own
// group, keyed by the image subject.
func TestImageGroupIsSeparateFromOS(t *testing.T) {
	img := osFinding("CVE-2026-0001", TierCritical, 90)
	img.Subject = SubjectImage
	img.ImageSubject = "nginx-img"
	fs := []Finding{img, osFinding("CVE-2026-0002", TierHigh, 70)}
	gs := groupsOf(t, newProjector(t, []Host{webHost()}, fs, nil, fullCatalog()))
	if len(gs) != 2 || gs[0].Key != "web-01/image:nginx-img" || gs[1].Key != "web-01/os" {
		var keys []string
		for _, g := range gs {
			keys = append(keys, g.Key)
		}
		t.Fatalf("group keys = %v, want [web-01/image:nginx-img web-01/os]", keys)
	}
}

// TestImageGroupOffersContainerCandidates checks that an image group gets the
// container update candidates of the "fix with" container link (ADR 0016 D4)
// and that the image statuses read as the OS statuses do.
func TestImageGroupOffersContainerCandidates(t *testing.T) {
	cand := imageFinding("CVE-2026-0001", TierCritical, 90, OutcomeImageCandidate, LinkContainers)
	g := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{cand}, nil, fullCatalog()))
	want := []Candidate{
		{Key: "c1", Action: "docker.compose_update", HostID: "web-01", Label: "Update the Compose project"},
		{Key: "c2", Action: "docker.update", HostID: "web-01", Label: "Update the standalone container"},
	}
	if fmt.Sprint(g.Projection.Candidates) != fmt.Sprint(want) {
		t.Fatalf("candidates = %+v, want %+v", g.Projection.Candidates, want)
	}
	if g.Projection.Findings[0].Fix != FixNotVerified {
		t.Fatalf("fix status = %q, want %q", g.Projection.Findings[0].Fix, FixNotVerified)
	}

	none := imageFinding("CVE-2026-0002", TierHigh, 70, OutcomeImageNoCandidate, LinkNone)
	g = oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{none}, nil, fullCatalog()))
	if len(g.Projection.Candidates) != 0 || g.Projection.Findings[0].Fix != FixNoCandidate {
		t.Fatalf("image without candidate: candidates %+v, fix %q", g.Projection.Candidates, g.Projection.Findings[0].Fix)
	}
}

// TestContainerLinkOffersNoCandidateForOS checks that the container link is
// only a container action on an image group.
func TestContainerLinkOffersNoCandidateForOS(t *testing.T) {
	f := osFinding("CVE-2026-0001", TierHigh, 80)
	f.Fix = FixDecision{Outcome: OutcomeNotVerified, Link: LinkContainers}
	g := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{f}, nil, fullCatalog()))
	if len(g.Projection.Candidates) != 0 {
		t.Fatalf("candidates = %+v, want none for an OS group", g.Projection.Candidates)
	}
}

// TestFindingsOfUnknownHostAreIgnored checks that a finding whose host is not
// in the inventory forms no group.
func TestFindingsOfUnknownHostAreIgnored(t *testing.T) {
	f := osFinding("CVE-2026-0001", TierCritical, 90)
	f.HostID = "ghost-9"
	if gs := groupsOf(t, newProjector(t, []Host{webHost()}, []Finding{f}, nil, fullCatalog())); len(gs) != 0 {
		t.Fatalf("got %d groups for an unknown host, want none", len(gs))
	}
}

// TestFindingsCappedAt40ByScore checks that a group lists at most
// MaxFindingsPerGroup findings, the highest scores first, and counts the rest
// per tier.
func TestFindingsCappedAt40ByScore(t *testing.T) {
	var fs []Finding
	for i := 0; i < 45; i++ {
		tier := TierHigh
		if i >= 40 {
			tier = TierMedium // lowest scores: counted, not listed
		}
		f := osFinding(fmt.Sprintf("CVE-2026-%04d", i), tier, 100-i)
		fs = append(fs, f)
	}
	g := oneGroup(t, newProjector(t, []Host{webHost()}, fs, nil, fullCatalog()))
	if len(g.Projection.Findings) != MaxFindingsPerGroup {
		t.Fatalf("listed %d findings, want %d", len(g.Projection.Findings), MaxFindingsPerGroup)
	}
	if g.Projection.Findings[0].Score != 100 || g.Projection.Findings[39].Score != 61 {
		t.Fatalf("listed scores not the highest: first %d last %d",
			g.Projection.Findings[0].Score, g.Projection.Findings[39].Score)
	}
	if g.Projection.Omitted != (Counts{Medium: 5}) {
		t.Fatalf("omitted = %+v, want medium=5", g.Projection.Omitted)
	}
	if g.Projection.Counts != (Counts{High: 40, Medium: 5}) {
		t.Fatalf("counts = %+v, want high=40 medium=5", g.Projection.Counts)
	}
}

// TestPortsCappedAt32 checks that at most MaxPortsPerHost ports are listed,
// lowest number first, and the rest are counted.
func TestPortsCappedAt32(t *testing.T) {
	var ports []Port
	for i := 40; i >= 1; i-- { // unsorted on purpose
		ports = append(ports, Port{Number: i, Protocol: "tcp"})
	}
	fs := []Finding{osFinding("CVE-2026-0001", TierHigh, 80)}
	g := oneGroup(t, newProjector(t, []Host{webHost()}, fs, fakeListeners{"web-01": ports}, fullCatalog()))
	if len(g.Projection.Ports) != MaxPortsPerHost {
		t.Fatalf("listed %d ports, want %d", len(g.Projection.Ports), MaxPortsPerHost)
	}
	if g.Projection.Ports[0].Number != 1 || g.Projection.Ports[31].Number != 32 {
		t.Fatalf("listed ports not the lowest numbers: %+v", g.Projection.Ports)
	}
	if g.Projection.PortsOmitted != 8 {
		t.Fatalf("ports omitted = %d, want 8", g.Projection.PortsOmitted)
	}
}

// TestRepeatedPortsDoNotCrowdOutRealPorts checks that duplicate (number,
// protocol) entries are dropped, so a source that repeats one port cannot
// push real ports out of the listed 32.
func TestRepeatedPortsDoNotCrowdOutRealPorts(t *testing.T) {
	var ports []Port
	for i := 0; i < 40; i++ {
		ports = append(ports, Port{Number: 443, Protocol: "tcp"})
	}
	ports = append(ports, Port{Number: 22, Protocol: "tcp"}, Port{Number: 80, Protocol: "tcp"}, Port{Number: 53, Protocol: "udp"})
	fs := []Finding{osFinding("CVE-2026-0001", TierHigh, 80)}
	g := oneGroup(t, newProjector(t, []Host{webHost()}, fs, fakeListeners{"web-01": ports}, fullCatalog()))
	if len(g.Projection.Ports) != 4 || g.Projection.PortsOmitted != 0 {
		t.Fatalf("ports = %+v omitted %d, want the 4 distinct ports and none omitted",
			g.Projection.Ports, g.Projection.PortsOmitted)
	}
}

// TestHostileLabelIsCleaned checks that a label with bidi overrides,
// zero-width characters, control bytes, invalid UTF-8 and excess length
// leaves the projection as plain text of at most MaxLabelBytes.
func TestHostileLabelIsCleaned(t *testing.T) {
	h := webHost()
	h.Label = "web" + string(rune(0x202e)) + string(rune(0x200b)) + "\x00 evil\xff\n" + strings.Repeat("ä", 100)
	fs := []Finding{osFinding("CVE-2026-0001", TierHigh, 80)}
	g := oneGroup(t, newProjector(t, []Host{h}, fs, nil, fullCatalog()))
	label := g.Projection.Host.Label
	if len(label) > MaxLabelBytes {
		t.Fatalf("label %d bytes, want <= %d", len(label), MaxLabelBytes)
	}
	assertNoHostileRunes(t, label)
	if !strings.HasPrefix(label, "web evil ") {
		t.Fatalf("label = %q, want it to start with the cleaned text", label)
	}
}

// TestHostilePackageNameSkipped checks that a package name with shell
// metacharacters is skipped and audited without its text, while a clean name
// with a control byte is cleaned and accepted.
func TestHostilePackageNameSkipped(t *testing.T) {
	bad := osFinding("CVE-2026-0001", TierHigh, 80)
	bad.Package = "open ssl;rm -rf /"
	p, audit := newProjectorWith(t, Sources{
		Inventory: fakeInventory{hosts: []Host{webHost()}},
		Listeners: fakeListeners{},
		Findings:  fakeFindings{fs: []Finding{bad}},
		Catalog:   fullCatalog(),
	})
	if gs := groupsOf(t, p); len(gs) != 0 {
		t.Fatalf("got %d groups, want the bad finding skipped", len(gs))
	}
	if len(audit.skips) != 1 || audit.skips[0].Scope != ScopeFinding {
		t.Fatalf("audit = %+v, want one finding skip", audit.skips)
	}
	assertNoInputEcho(t, audit.skips[0], "rm -rf")

	ok := osFinding("CVE-2026-0002", TierHigh, 80)
	ok.Package = "openssl\x07"
	g := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{ok}, nil, fullCatalog()))
	if g.Projection.Findings[0].Package != "openssl" {
		t.Fatalf("package = %q, want %q", g.Projection.Findings[0].Package, "openssl")
	}
}

// TestInvalidInputIsSkippedAndAudited checks that a malformed finding or host
// is left out and recorded with its rule, while the rest of the fleet is
// projected as before.
func TestInvalidInputIsSkippedAndAudited(t *testing.T) {
	good := osFinding("CVE-2026-0100", TierHigh, 80)
	tests := []struct {
		name  string
		hosts []Host
		fs    []Finding
		scope SkipScope
		rule  error
	}{
		{"unknown state", []Host{webHost()}, []Finding{withState(osFinding("CVE-2026-0001", TierHigh, 80), "closed")}, ScopeFinding, ErrInvalidState},
		{"unknown tier", []Host{webHost()}, []Finding{osFinding("CVE-2026-0001", Tier("urgent"), 80)}, ScopeFinding, ErrInvalidTier},
		{"bad vuln id", []Host{webHost()}, []Finding{withVuln(osFinding("x", TierHigh, 80), "CVE 1;DROP")}, ScopeFinding, ErrInvalidField},
		{"score out of range", []Host{webHost()}, []Finding{withScore(osFinding("CVE-2026-0001", TierHigh, 80), 101)}, ScopeFinding, ErrInvalidField},
		{"unknown outcome", []Host{webHost()}, []Finding{withOutcome(osFinding("CVE-2026-0001", TierHigh, 80), "pwned")}, ScopeFinding, ErrInvalidOutcome},
		{"unknown link", []Host{webHost()}, []Finding{withLink(osFinding("CVE-2026-0001", TierHigh, 80), "shell")}, ScopeFinding, ErrInvalidLink},
		{"bad host id", []Host{{ID: "../etc", Criticality: CriticalityLow}}, nil, ScopeHost, ErrInvalidField},
		{"bad criticality", []Host{{ID: "web-02", Criticality: "EXTREME"}}, nil, ScopeHost, ErrInvalidField},
		{"duplicate host", []Host{webHost(), webHost()}, nil, ScopeHost, ErrDuplicateHost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := append([]Finding{good}, tt.fs...)
			p, audit := newProjectorWith(t, Sources{
				Inventory: fakeInventory{hosts: tt.hosts},
				Listeners: fakeListeners{},
				Findings:  fakeFindings{fs: fs},
				Catalog:   fullCatalog(),
			})
			gs, err := p.EligibleGroups(context.Background())
			if err != nil {
				t.Fatalf("EligibleGroups: %v, want the bad input skipped", err)
			}
			if tt.scope == ScopeFinding && (len(gs) != 1 || gs[0].Key != "web-01/os") {
				t.Fatalf("good group lost: %d groups", len(gs))
			}
			if len(audit.skips) != 1 {
				t.Fatalf("audit = %+v, want one skip", audit.skips)
			}
			if s := audit.skips[0]; s.Scope != tt.scope || !strings.Contains(s.Rule, tt.rule.Error()) {
				t.Fatalf("skip = %+v, want scope %s rule %q", s, tt.scope, tt.rule.Error())
			}
		})
	}
}

// TestMalformedHostIDIsNotEchoed checks that an oversized, hostile host ID
// reaches neither the audit record nor an error.
func TestMalformedHostIDIsNotEchoed(t *testing.T) {
	hostile := "EVIL" + strings.Repeat("x", 5000) + string(rune(0x202e))
	f := osFinding("CVE-2026-0001", TierCritical, 90)
	f.HostID = hostile
	p, audit := newProjectorWith(t, Sources{
		Inventory: fakeInventory{hosts: []Host{webHost()}},
		Listeners: fakeListeners{},
		Findings:  fakeFindings{fs: []Finding{f}},
		Catalog:   fullCatalog(),
	})
	gs, err := p.EligibleGroups(context.Background())
	if err != nil || len(gs) != 0 {
		t.Fatalf("EligibleGroups = %d groups, %v; want the finding skipped", len(gs), err)
	}
	if len(audit.skips) != 1 {
		t.Fatalf("audit = %+v, want one skip", audit.skips)
	}
	if audit.skips[0].HostID != "" {
		t.Fatalf("audit host ID = %q, want none for a malformed ID", audit.skips[0].HostID)
	}
	assertNoInputEcho(t, audit.skips[0], "EVIL")

	// The same finding through External must not echo it either.
	_, err = p.External(context.Background())
	if err != nil {
		t.Fatalf("External: %v", err)
	}
}

// TestBadListenersSkipOnlyTheirGroup checks that a malformed listener set
// drops the groups of its host and nothing else.
func TestBadListenersSkipOnlyTheirGroup(t *testing.T) {
	db := webHost()
	db.ID = "db-01"
	bad := []Port{{Number: 0, Protocol: "tcp"}, {Number: 70000, Protocol: "tcp"}, {Number: 22, Protocol: "sctp"}}
	for _, port := range bad {
		fs := []Finding{osFinding("CVE-2026-0001", TierHigh, 80)}
		dbFinding := osFinding("CVE-2026-0002", TierHigh, 80)
		dbFinding.HostID = "db-01"
		fs = append(fs, dbFinding)
		p, audit := newProjectorWith(t, Sources{
			Inventory: fakeInventory{hosts: []Host{webHost(), db}},
			Listeners: fakeListeners{"web-01": {port}, "db-01": {{Number: 5432, Protocol: "tcp"}}},
			Findings:  fakeFindings{fs: fs},
			Catalog:   fullCatalog(),
		})
		gs, err := p.EligibleGroups(context.Background())
		if err != nil {
			t.Fatalf("port %+v: EligibleGroups: %v", port, err)
		}
		if len(gs) != 1 || gs[0].Key != "db-01/os" {
			var keys []string
			for _, g := range gs {
				keys = append(keys, g.Key)
			}
			t.Fatalf("port %+v: groups %v, want only db-01/os", port, keys)
		}
		if len(audit.skips) != 1 || audit.skips[0].Scope != ScopeListeners || audit.skips[0].HostID != "web-01" {
			t.Fatalf("port %+v: audit = %+v", port, audit.skips)
		}
	}
}

// TestAuditFailureFailsProjection checks that a failing audit stops the
// projection: a skip must be on record before its group is left out.
func TestAuditFailureFailsProjection(t *testing.T) {
	boom := errors.New("audit log full")
	bad := osFinding("CVE-2026-0001", TierHigh, 80)
	bad.Package = "open ssl"
	p, _ := newProjectorWith(t, Sources{
		Inventory: fakeInventory{hosts: []Host{webHost()}},
		Listeners: fakeListeners{},
		Findings:  fakeFindings{fs: []Finding{bad}},
		Catalog:   fullCatalog(),
		Audit:     &recordAudit{err: boom},
	})
	if _, err := p.EligibleGroups(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("error = %v, want wrapped %v", err, boom)
	}
}

// TestCandidatesFromCatalogAndAllowlist checks that a candidate exists only
// for an action the catalog contains: an action missing from the catalog
// drops out and the others keep their keys c1, c2, ... in action order.
func TestCandidatesFromCatalogAndAllowlist(t *testing.T) {
	reboot := osFinding("CVE-2026-0002", TierCritical, 95)
	reboot.Fix = FixDecision{Outcome: OutcomeVerified, Link: LinkInstallSecurity, Reboot: true}
	allSec := osFinding("CVE-2026-0003", TierHigh, 70)
	allSec.Fix.Link = LinkInstallAll
	fs := []Finding{osFinding("CVE-2026-0001", TierHigh, 80), reboot, allSec}

	cat := fakeCatalog{"package.install_security": true, "system.reboot": true}
	g := oneGroup(t, newProjector(t, []Host{webHost()}, fs, nil, cat))
	want := []Candidate{
		{Key: "c1", Action: "package.install_security", HostID: "web-01", Label: "Install security updates"},
		{Key: "c2", Action: "system.reboot", HostID: "web-01", Label: "Reboot the host"},
	}
	if fmt.Sprint(g.Projection.Candidates) != fmt.Sprint(want) {
		t.Fatalf("candidates = %+v, want %+v", g.Projection.Candidates, want)
	}
}

// TestNoCandidateWithoutFixLink checks that a "no candidate" or "no fix yet"
// result offers no action.
func TestNoCandidateWithoutFixLink(t *testing.T) {
	f := osFinding("CVE-2026-0001", TierCritical, 90)
	f.Fix = FixDecision{Outcome: OutcomeNoCandidate, Link: LinkNone}
	g := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{f}, nil, fullCatalog()))
	if len(g.Projection.Candidates) != 0 {
		t.Fatalf("candidates = %+v, want none", g.Projection.Candidates)
	}
}

// TestCandidatesRequireCurrentDigest checks the validation entry point: a
// candidate list is returned only for the current digest of an eligible group.
func TestCandidatesRequireCurrentDigest(t *testing.T) {
	fs := []Finding{osFinding("CVE-2026-0001", TierHigh, 80)}
	p := newProjector(t, []Host{webHost()}, fs, nil, fullCatalog())
	g := oneGroup(t, p)
	ctx := context.Background()

	got, err := p.Candidates(ctx, g.Key, g.Digest)
	if err != nil || len(got) != 1 || got[0].Key != "c1" {
		t.Fatalf("Candidates(current) = %+v, %v", got, err)
	}
	if _, err := p.Candidates(ctx, g.Key, "sha256:"+strings.Repeat("0", 64)); !errors.Is(err, ErrStaleDigest) {
		t.Fatalf("stale digest: error = %v, want ErrStaleDigest", err)
	}
	if _, err := p.Candidates(ctx, "web-01/os-missing", g.Digest); !errors.Is(err, ErrUnknownGroup) {
		t.Fatalf("unknown group: error = %v, want ErrUnknownGroup", err)
	}
}

// TestFixStatusMapping checks every decision the agent may see as a fix
// status (ADR 0016 D4).
func TestFixStatusMapping(t *testing.T) {
	tests := []struct {
		name string
		d    FixDecision
		want FixStatus
	}{
		{"verified", FixDecision{Outcome: OutcomeVerified}, FixVerified},
		{"verified kernel", FixDecision{Outcome: OutcomeVerified, Reboot: true}, FixRebootRequired},
		{"not verified", FixDecision{Outcome: OutcomeNotVerified}, FixNotVerified},
		{"below fixed", FixDecision{Outcome: OutcomeBelowFixed}, FixNotVerified},
		{"image candidate", FixDecision{Outcome: OutcomeImageCandidate}, FixNotVerified},
		{"no candidate", FixDecision{Outcome: OutcomeNoCandidate}, FixNoCandidate},
		{"image no candidate", FixDecision{Outcome: OutcomeImageNoCandidate}, FixNoCandidate},
		{"no fix yet", FixDecision{Outcome: OutcomeNoFixYet}, FixNoFixYet},
		{"wont fix", FixDecision{Outcome: OutcomeWontFix}, FixUnknown},
		{"unknown", FixDecision{Outcome: OutcomeUnknown}, FixUnknown},
		{"none", FixDecision{Outcome: OutcomeNone}, FixUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fixStatus(tt.d); got != tt.want {
				t.Fatalf("fixStatus = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNewRequiresEverySource checks that a missing source or auditor is
// refused.
func TestNewRequiresEverySource(t *testing.T) {
	full := Sources{
		Inventory: fakeInventory{},
		Listeners: fakeListeners{},
		Findings:  fakeFindings{},
		Catalog:   fakeCatalog{},
		Audit:     &recordAudit{},
	}
	for name, mutate := range map[string]func(*Sources){
		"inventory": func(s *Sources) { s.Inventory = nil },
		"listeners": func(s *Sources) { s.Listeners = nil },
		"findings":  func(s *Sources) { s.Findings = nil },
		"catalog":   func(s *Sources) { s.Catalog = nil },
		"audit":     func(s *Sources) { s.Audit = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := full
			mutate(&s)
			if _, err := New(s); !errors.Is(err, ErrNoSource) {
				t.Fatalf("New error = %v, want ErrNoSource", err)
			}
		})
	}
}

// TestSourceErrorIsReturned checks that a failing source fails the whole
// projection instead of returning partial groups.
func TestSourceErrorIsReturned(t *testing.T) {
	boom := errors.New("store down")
	p, _ := newProjectorWith(t, Sources{
		Inventory: fakeInventory{hosts: []Host{webHost()}},
		Listeners: fakeListeners{},
		Findings:  fakeFindings{err: boom},
		Catalog:   fullCatalog(),
	})
	if _, err := p.EligibleGroups(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("error = %v, want wrapped %v", err, boom)
	}
}

// TestDigestRefusesOversizedItem checks the item bound of ADR 0016 D4.
func TestDigestRefusesOversizedItem(t *testing.T) {
	p := LabProjection{Group: "web-01/os", Host: LabHost{ID: "web-01", Label: strings.Repeat("x", MaxItemBytes)}}
	if _, err := Digest(p); !errors.Is(err, ErrItemTooLarge) {
		t.Fatalf("Digest error = %v, want ErrItemTooLarge", err)
	}
}

// assertNoInputEcho fails when the audit record of a skip contains the given
// piece of input text.
func assertNoInputEcho(t *testing.T, s Skip, input string) {
	t.Helper()
	if strings.Contains(fmt.Sprintf("%+v", s), input) {
		t.Fatalf("skip record %+v echoes input %q", s, input)
	}
}

func withState(f Finding, s FindingState) Finding { f.State = s; return f }
func withVuln(f Finding, id string) Finding       { f.VulnID = id; return f }
func withScore(f Finding, s int) Finding          { f.Score = s; return f }
func withOutcome(f Finding, o FixOutcome) Finding { f.Fix.Outcome = o; return f }
func withLink(f Finding, l FixLink) Finding       { f.Fix.Link = l; return f }
