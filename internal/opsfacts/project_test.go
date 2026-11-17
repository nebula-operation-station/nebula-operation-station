// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
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
		Criticality: inventory.CriticalityHigh,
		Exposure:    vulnprio.ExposureInternet,
	}
}

// osFinding is a high, open, verified-fix OS finding of web-01.
func osFinding(vuln string, tier vulnprio.Tier, score int) Finding {
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
		Fix: vulnfix.Result{
			Status: vulnfix.StatusVerified,
			Action: vulnfix.ActionInstallSecurity,
			HostID: "web-01",
			Fixed:  "3.0.2-1",
		},
	}
}

func newProjector(t *testing.T, hosts []Host, fs []Finding, ports fakeListeners, cat fakeCatalog) *Projector {
	t.Helper()
	p, err := New(Sources{
		Inventory: fakeInventory{hosts: hosts},
		Listeners: ports,
		Findings:  fakeFindings{fs: fs},
		Catalog:   cat,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

// TestSameInputSameDigest checks that the digest does not depend on the order
// the sources return their items in.
func TestSameInputSameDigest(t *testing.T) {
	a := osFinding("CVE-2026-0001", vulnprio.TierHigh, 80)
	b := osFinding("CVE-2026-0002", vulnprio.TierCritical, 95)
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

// TestChangedFindingChangesDigest changes one listed value at a time and
// checks that each change produces a new digest.
func TestChangedFindingChangesDigest(t *testing.T) {
	base := osFinding("CVE-2026-0001", vulnprio.TierHigh, 80)
	want := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{base}, nil, fullCatalog())).Digest

	changes := map[string]func(*Finding){
		"fixed version":  func(f *Finding) { f.Fixed = "3.0.3-1" },
		"installed":      func(f *Finding) { f.Installed = "3.0.0-9" },
		"tier":           func(f *Finding) { f.Tier = vulnprio.TierCritical },
		"score":          func(f *Finding) { f.Score = 81 },
		"kev":            func(f *Finding) { f.KEV = true },
		"fix status":     func(f *Finding) { f.Fix.Status = vulnfix.StatusNotVerified },
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
				fs = append(fs, osFinding("CVE-2026-0005", vulnprio.TierHigh, 70))
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

// TestAcceptedRiskAndFalsePositiveLeftOut checks that only open findings
// enter a group and its counts (ADR 0016 D3).
func TestAcceptedRiskAndFalsePositiveLeftOut(t *testing.T) {
	open := osFinding("CVE-2026-0001", vulnprio.TierHigh, 80)
	accepted := osFinding("CVE-2026-0002", vulnprio.TierCritical, 99)
	accepted.State = StateAcceptedRisk
	fp := osFinding("CVE-2026-0003", vulnprio.TierCritical, 98)
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
		osFinding("CVE-2026-0001", vulnprio.TierMedium, 50),
		osFinding("CVE-2026-0002", vulnprio.TierLow, 10),
	}
	if gs := groupsOf(t, newProjector(t, []Host{webHost()}, fs, nil, fullCatalog())); len(gs) != 0 {
		t.Fatalf("got %d groups, want none", len(gs))
	}
}

// TestImageGroupIsSeparateFromOS checks that image findings form their own
// group, keyed by the image subject.
func TestImageGroupIsSeparateFromOS(t *testing.T) {
	img := osFinding("CVE-2026-0001", vulnprio.TierCritical, 90)
	img.Subject = SubjectImage
	img.ImageSubject = "nginx-img"
	fs := []Finding{img, osFinding("CVE-2026-0002", vulnprio.TierHigh, 70)}
	gs := groupsOf(t, newProjector(t, []Host{webHost()}, fs, nil, fullCatalog()))
	if len(gs) != 2 || gs[0].Key != "web-01/image:nginx-img" || gs[1].Key != "web-01/os" {
		var keys []string
		for _, g := range gs {
			keys = append(keys, g.Key)
		}
		t.Fatalf("group keys = %v, want [web-01/image:nginx-img web-01/os]", keys)
	}
}

// TestFindingsOfUnknownHostAreIgnored checks that a finding whose host is not
// in the inventory forms no group.
func TestFindingsOfUnknownHostAreIgnored(t *testing.T) {
	f := osFinding("CVE-2026-0001", vulnprio.TierCritical, 90)
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
		tier := vulnprio.TierHigh
		if i >= 40 {
			tier = vulnprio.TierMedium // lowest scores: counted, not listed
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
	fs := []Finding{osFinding("CVE-2026-0001", vulnprio.TierHigh, 80)}
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

// TestHostileLabelIsCleaned checks that a label with bidi overrides,
// zero-width characters, control bytes, invalid UTF-8 and excess length
// leaves the projection as plain text of at most MaxLabelBytes.
func TestHostileLabelIsCleaned(t *testing.T) {
	h := webHost()
	h.Label = "web" + string(rune(0x202e)) + string(rune(0x200b)) + "\x00 evil\xff\n" + strings.Repeat("ä", 100)
	fs := []Finding{osFinding("CVE-2026-0001", vulnprio.TierHigh, 80)}
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

// TestHostilePackageNameRejected checks that a package name with shell
// metacharacters after cleaning is refused, and a clean name with a control
// byte is cleaned and accepted.
func TestHostilePackageNameRejected(t *testing.T) {
	bad := osFinding("CVE-2026-0001", vulnprio.TierHigh, 80)
	bad.Package = "open ssl;rm -rf /"
	if _, err := New(Sources{Inventory: fakeInventory{hosts: []Host{webHost()}}, Listeners: fakeListeners{},
		Findings: fakeFindings{fs: []Finding{bad}}, Catalog: fullCatalog()}); err != nil {
		t.Fatalf("New: %v", err)
	}
	p := newProjector(t, []Host{webHost()}, []Finding{bad}, nil, fullCatalog())
	if _, err := p.EligibleGroups(context.Background()); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("EligibleGroups error = %v, want ErrInvalidField", err)
	}

	ok := osFinding("CVE-2026-0002", vulnprio.TierHigh, 80)
	ok.Package = "openssl\x07"
	g := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{ok}, nil, fullCatalog()))
	if g.Projection.Findings[0].Package != "openssl" {
		t.Fatalf("package = %q, want %q", g.Projection.Findings[0].Package, "openssl")
	}
}

// TestInvalidInputFailsClosed checks that malformed input stops the whole
// projection with a sentinel error rather than projecting a partial set.
func TestInvalidInputFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		hosts []Host
		fs    []Finding
		want  error
	}{
		{"unknown state", []Host{webHost()}, []Finding{withState(osFinding("CVE-2026-0001", vulnprio.TierHigh, 80), "closed")}, ErrInvalidState},
		{"unknown tier", []Host{webHost()}, []Finding{osFinding("CVE-2026-0001", vulnprio.Tier("urgent"), 80)}, ErrInvalidTier},
		{"bad vuln id", []Host{webHost()}, []Finding{withVuln(osFinding("x", vulnprio.TierHigh, 80), "CVE 1;DROP")}, ErrInvalidField},
		{"score out of range", []Host{webHost()}, []Finding{withScore(osFinding("CVE-2026-0001", vulnprio.TierHigh, 80), 101)}, ErrInvalidField},
		{"duplicate host", []Host{webHost(), webHost()}, nil, ErrDuplicateHost},
		{"bad host id", []Host{{ID: "../etc", Criticality: inventory.CriticalityLow}}, nil, ErrInvalidField},
		{"bad criticality", []Host{{ID: "web-01", Criticality: "EXTREME"}}, nil, ErrInvalidField},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newProjector(t, tt.hosts, tt.fs, nil, fullCatalog())
			if _, err := p.EligibleGroups(context.Background()); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestBadPortFailsClosed checks that a port outside 1..65535 or with an
// unknown protocol fails the projection of its host.
func TestBadPortFailsClosed(t *testing.T) {
	fs := []Finding{osFinding("CVE-2026-0001", vulnprio.TierHigh, 80)}
	for _, port := range []Port{{Number: 0, Protocol: "tcp"}, {Number: 70000, Protocol: "tcp"}, {Number: 22, Protocol: "sctp"}} {
		p := newProjector(t, []Host{webHost()}, fs, fakeListeners{"web-01": {port}}, fullCatalog())
		if _, err := p.EligibleGroups(context.Background()); !errors.Is(err, ErrInvalidField) {
			t.Fatalf("port %+v: error = %v, want ErrInvalidField", port, err)
		}
	}
}

// TestCandidatesFromCatalogAndAllowlist checks that a candidate exists only
// for an action the catalog contains: an action missing from the catalog
// drops out and the others keep their keys c1, c2, ... in action order.
func TestCandidatesFromCatalogAndAllowlist(t *testing.T) {
	reboot := osFinding("CVE-2026-0002", vulnprio.TierCritical, 95)
	reboot.Fix = vulnfix.Result{Status: vulnfix.StatusVerified, Reboot: true, Action: vulnfix.ActionInstallSecurity, HostID: "web-01"}
	allSec := osFinding("CVE-2026-0003", vulnprio.TierHigh, 70)
	allSec.Fix.Action = vulnfix.ActionInstallAll
	fs := []Finding{osFinding("CVE-2026-0001", vulnprio.TierHigh, 80), reboot, allSec}

	cat := fakeCatalog{"package.install_security": true, "system.reboot": true}
	g := oneGroup(t, newProjector(t, []Host{webHost()}, fs, nil, cat))
	want := []Candidate{
		{Key: "c1", Action: "package.install_security", HostID: "web-01"},
		{Key: "c2", Action: "system.reboot", HostID: "web-01"},
	}
	if fmt.Sprint(g.Projection.Candidates) != fmt.Sprint(want) {
		t.Fatalf("candidates = %+v, want %+v", g.Projection.Candidates, want)
	}
}

// TestNoCandidateWithoutFixLink checks that a "no candidate" or "no fix yet"
// result offers no action.
func TestNoCandidateWithoutFixLink(t *testing.T) {
	f := osFinding("CVE-2026-0001", vulnprio.TierCritical, 90)
	f.Fix = vulnfix.Result{Status: vulnfix.StatusNoCandidate, HostID: "web-01"}
	g := oneGroup(t, newProjector(t, []Host{webHost()}, []Finding{f}, nil, fullCatalog()))
	if len(g.Projection.Candidates) != 0 {
		t.Fatalf("candidates = %+v, want none", g.Projection.Candidates)
	}
}

// TestCandidatesRequireCurrentDigest checks the validation entry point: a
// candidate list is returned only for the current digest of an eligible group.
func TestCandidatesRequireCurrentDigest(t *testing.T) {
	fs := []Finding{osFinding("CVE-2026-0001", vulnprio.TierHigh, 80)}
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
		r    vulnfix.Result
		want FixStatus
	}{
		{"verified", vulnfix.Result{Status: vulnfix.StatusVerified}, FixVerified},
		{"verified kernel", vulnfix.Result{Status: vulnfix.StatusVerified, Reboot: true}, FixRebootRequired},
		{"not verified", vulnfix.Result{Status: vulnfix.StatusNotVerified}, FixNotVerified},
		{"below fixed", vulnfix.Result{Status: vulnfix.StatusBelowFixed}, FixNotVerified},
		{"no candidate", vulnfix.Result{Status: vulnfix.StatusNoCandidate}, FixNoCandidate},
		{"no fix yet", vulnfix.Result{Status: vulnfix.StatusNoFixYet}, FixNoFixYet},
		{"wont fix", vulnfix.Result{Status: vulnfix.StatusWontFix}, FixUnknown},
		{"unknown", vulnfix.Result{Status: vulnfix.StatusUnknown}, FixUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fixStatus(tt.r); got != tt.want {
				t.Fatalf("fixStatus = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNewRequiresEverySource checks that a missing source is refused.
func TestNewRequiresEverySource(t *testing.T) {
	full := Sources{
		Inventory: fakeInventory{},
		Listeners: fakeListeners{},
		Findings:  fakeFindings{},
		Catalog:   fakeCatalog{},
	}
	for name, mutate := range map[string]func(*Sources){
		"inventory": func(s *Sources) { s.Inventory = nil },
		"listeners": func(s *Sources) { s.Listeners = nil },
		"findings":  func(s *Sources) { s.Findings = nil },
		"catalog":   func(s *Sources) { s.Catalog = nil },
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
	p, err := New(Sources{
		Inventory: fakeInventory{hosts: []Host{webHost()}},
		Listeners: fakeListeners{},
		Findings:  fakeFindings{err: boom},
		Catalog:   fullCatalog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

func withState(f Finding, s FindingState) Finding { f.State = s; return f }
func withVuln(f Finding, id string) Finding       { f.VulnID = id; return f }
func withScore(f Finding, s int) Finding          { f.Score = s; return f }
