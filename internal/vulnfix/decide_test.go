// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfix_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// hostFinding is an open host finding on source with the installed
// binaries and fixed version.
func hostFinding(eco, source, fixed string, bins ...string) vulnstore.Finding {
	f := vulnstore.Finding{
		Subject: vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "h1"},
		State:   vulnstore.StateOpen,
	}
	f.Record.Ecosystem = eco
	f.Record.Component.SourcePackage = source
	for _, b := range bins {
		f.Record.Component.Binaries = append(f.Record.Component.Binaries, vulnfinding.Binary{Name: b, Version: "0"})
	}
	f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: fixed}
	return f
}

func pkg(name, srcName, srcVersion string, security bool) vulnfix.Package {
	return vulnfix.Package{Name: name, SourceName: srcName, SourceVersion: srcVersion, Security: security}
}

// TestHostResultCandidateSourceVersion mirrors the candidate decisions of
// the "fix with" links: a fix is verified only by the candidate's SOURCE
// version (binNMU-aware), a binary-only candidate is not verified.
func TestHostResultCandidateSourceVersion(t *testing.T) {
	deb := func(fixed string, bins ...string) vulnstore.Finding {
		return hostFinding("debian:bookworm", "openssl", fixed, bins...)
	}
	tests := []struct {
		name     string
		f        vulnstore.Finding
		upd      *vulnfix.Updates
		status   vulnfix.Status
		reason   vulnfix.Reason
		action   vulnfix.Action
		reboot   bool
		fixed    string
		candVers string
	}{
		{
			name: "Debian backport: candidate source equals the fixed security version",
			f:    deb("3.0.11-1~deb12u2", "openssl", "libssl3"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("openssl", "openssl", "3.0.11-1~deb12u2", true),
				pkg("libssl3", "openssl", "3.0.11-1~deb12u2", true),
			}},
			status: vulnfix.StatusVerified, action: vulnfix.ActionInstallSecurity, fixed: "3.0.11-1~deb12u2", candVers: "3.0.11-1~deb12u2",
		},
		{
			name: "Ubuntu backport below the fixed upload",
			f:    hostFinding("ubuntu:24.04", "curl", "8.5.0-2ubuntu10.2", "curl"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("curl", "curl", "8.5.0-2ubuntu10.1", true),
			}},
			status: vulnfix.StatusBelowFixed, fixed: "8.5.0-2ubuntu10.2", candVers: "8.5.0-2ubuntu10.1",
		},
		{
			name: "Ubuntu backport at the fixed upload",
			f:    hostFinding("ubuntu:24.04", "curl", "8.5.0-2ubuntu10.2", "curl"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("curl", "curl", "8.5.0-2ubuntu10.2", true),
			}},
			status: vulnfix.StatusVerified, action: vulnfix.ActionInstallSecurity, fixed: "8.5.0-2ubuntu10.2", candVers: "8.5.0-2ubuntu10.2",
		},
		{
			name: "binNMU candidate: source version decides, fixed",
			f:    hostFinding("debian:bookworm", "foo", "1.2-3", "libfoo1"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("libfoo1:amd64", "foo", "1.2-3", false),
			}},
			status: vulnfix.StatusVerified, action: vulnfix.ActionInstallAll, fixed: "1.2-3", candVers: "1.2-3",
		},
		{
			name: "binNMU candidate: binary version reaches fixed but source does not",
			f:    hostFinding("debian:bookworm", "foo", "1.2-2+b1", "libfoo1"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("libfoo1", "foo", "1.2-2", false),
			}},
			status: vulnfix.StatusBelowFixed, fixed: "1.2-2+b1", candVers: "1.2-2",
		},
		{
			name: "binary-only candidate (no source data) is not a verified fix",
			f:    deb("3.0.11-1~deb12u2", "openssl"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("openssl", "", "", true),
			}},
			status: vulnfix.StatusNotVerified, action: vulnfix.ActionInstallSecurity,
		},
		{
			name: "binary of the source left without a candidate",
			f:    deb("3.0.11-1~deb12u2", "openssl", "libssl3"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("libssl3", "openssl", "3.0.11-1~deb12u2", true),
			}},
			status: vulnfix.StatusNotVerified, action: vulnfix.ActionInstallSecurity,
		},
		{
			name: "installed binaries unknown",
			f:    deb("3.0.11-1~deb12u2"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("openssl", "openssl", "3.0.11-1~deb12u2", true),
			}},
			status: vulnfix.StatusNotVerified, action: vulnfix.ActionInstallSecurity,
		},
		{
			name: "mixed archives propose all updates",
			f:    deb("3.0.11-1~deb12u2", "openssl", "libssl3"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("openssl", "openssl", "3.0.11-1~deb12u2", true),
				pkg("libssl3", "openssl", "3.0.11-1~deb12u2", false),
			}},
			status: vulnfix.StatusVerified, action: vulnfix.ActionInstallAll, fixed: "3.0.11-1~deb12u2", candVers: "3.0.11-1~deb12u2",
		},
		{
			name: "candidate of another source with the same binary name is ignored",
			f:    deb("3.0.11-1~deb12u2", "openssl"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("openssl", "evil", "9.9-1", true),
			}},
			status: vulnfix.StatusNoCandidate,
		},
		{
			name:   "no candidate",
			f:      deb("3.0.11-1~deb12u2", "openssl"),
			upd:    &vulnfix.Updates{Packages: []vulnfix.Package{pkg("bash", "bash", "5.2-1", false)}},
			status: vulnfix.StatusNoCandidate,
		},
		{
			name:   "no update list yet",
			f:      deb("3.0.11-1~deb12u2", "openssl"),
			status: vulnfix.StatusUnknown, reason: vulnfix.ReasonNoUpdateList, action: vulnfix.ActionListUpdates,
		},
		{
			name: "episode fixed version higher than the current one",
			f: func() vulnstore.Finding {
				f := deb("3.0.11-1~deb12u1", "openssl")
				f.EpisodeFixedVersion = "3.0.11-1~deb12u2"
				return f
			}(),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("openssl", "openssl", "3.0.11-1~deb12u1", true),
			}},
			status: vulnfix.StatusBelowFixed, fixed: "3.0.11-1~deb12u2", candVers: "3.0.11-1~deb12u1",
		},
		{
			name:   "fixed version not comparable",
			f:      deb("not a version!", "openssl"),
			upd:    &vulnfix.Updates{Packages: []vulnfix.Package{pkg("openssl", "openssl", "3.0.11-1~deb12u2", true)}},
			status: vulnfix.StatusUnknown, reason: vulnfix.ReasonFixedNotComparable,
		},
		{
			name: "no fix yet",
			f: func() vulnstore.Finding {
				f := deb("", "openssl")
				f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixNoFixYet}
				return f
			}(),
			upd:    &vulnfix.Updates{},
			status: vulnfix.StatusNoFixYet,
		},
		{
			name: "won't fix",
			f: func() vulnstore.Finding {
				f := deb("", "openssl")
				f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixWontFix}
				return f
			}(),
			upd:    &vulnfix.Updates{},
			status: vulnfix.StatusWontFix,
		},
		{
			name:   "kernel: unsigned image of the source at the fixed version",
			f:      hostFinding("debian:bookworm", "linux", "6.1.115-1"),
			upd:    &vulnfix.Updates{Packages: []vulnfix.Package{pkg("linux-image-6.1.0-28-cloud-amd64", "linux", "6.1.115-1", true)}},
			status: vulnfix.StatusVerified, action: vulnfix.ActionInstallSecurity, reboot: true, fixed: "6.1.115-1", candVers: "6.1.115-1",
		},
		{
			name: "kernel: signed image is never a version basis",
			f:    hostFinding("debian:bookworm", "linux", "6.1.115-1"),
			upd: &vulnfix.Updates{Packages: []vulnfix.Package{
				pkg("linux-image-6.1.0-28-amd64", "linux-signed-amd64", "6.1.115+1", true),
				pkg("linux-headers-6.1.0-28-common", "linux", "6.1.115-1", true),
			}},
			status: vulnfix.StatusNotVerified, action: vulnfix.ActionInstallSecurity, reboot: true,
		},
		{
			name:   "kernel: image below the fixed version",
			f:      hostFinding("ubuntu:24.04", "linux", "6.8.0-48.48"),
			upd:    &vulnfix.Updates{Packages: []vulnfix.Package{pkg("linux-image-6.8.0-47-generic", "linux", "6.8.0-47.47", false)}},
			status: vulnfix.StatusBelowFixed, reboot: true, fixed: "6.8.0-48.48", candVers: "6.8.0-47.47",
		},
		{
			name:   "unsupported ecosystem",
			f:      hostFinding("alpine:3.20", "openssl", "3.3.2-r0", "openssl"),
			upd:    &vulnfix.Updates{},
			status: vulnfix.StatusUnknown, reason: vulnfix.ReasonUnsupportedEcosystem,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := vulnfix.HostResult(tc.f, tc.upd)
			if r.Status != tc.status || r.Reason != tc.reason || r.Action != tc.action || r.Reboot != tc.reboot {
				t.Fatalf("got %+v, want status %v reason %v action %v reboot %v", r, tc.status, tc.reason, tc.action, tc.reboot)
			}
			if tc.fixed != "" && r.Fixed != tc.fixed {
				t.Errorf("fixed %q, want %q", r.Fixed, tc.fixed)
			}
			if tc.candVers != "" && r.Candidate != tc.candVers {
				t.Errorf("candidate %q, want %q", r.Candidate, tc.candVers)
			}
		})
	}
}

func TestHostResultRejectsHostileSubjectID(t *testing.T) {
	f := hostFinding("debian:bookworm", "openssl", "3.0.11-1~deb12u2", "openssl")
	f.Subject.ID = "h1&action=package.install_all"
	if r := vulnfix.HostResult(f, &vulnfix.Updates{}); r != (vulnfix.Result{}) {
		t.Fatalf("hostile subject id produced %+v", r)
	}
}

func imageFinding(digest string) vulnstore.Finding {
	f := vulnstore.Finding{
		Subject: vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: "h1", ImageDigest: digest},
		State:   vulnstore.StateOpen,
	}
	f.Record.Ecosystem = "debian:bookworm"
	f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "1.0-2"}
	return f
}

// TestImageResultNeverVerifies mirrors the container update decisions:
// a candidate is never a verified fix, and an unknown preview links to the
// container page.
func TestImageResultNeverVerifies(t *testing.T) {
	running := "sha256:" + strings.Repeat("a", 64)
	newer := "sha256:" + strings.Repeat("b", 64)
	other := "sha256:" + strings.Repeat("c", 64)
	candidate := vulnfix.Preview{ID: "run1", OK: true, Units: []vulnfix.Unit{{Images: []vulnfix.Image{{
		OldDigests: []string{running}, Resolved: []vulnfix.Resolution{{PlatformDigest: newer}},
	}}}}}
	tests := []struct {
		name   string
		p      vulnfix.Preview
		ok     bool
		status vulnfix.Status
		action vulnfix.Action
	}{
		{"candidate", candidate, true, vulnfix.StatusImageCandidate, vulnfix.ActionContainers},
		{"current tag resolves to the running digest", vulnfix.Preview{ID: "run1", OK: true, Units: []vulnfix.Unit{{Images: []vulnfix.Image{{
			OldDigests: []string{running}, Resolved: []vulnfix.Resolution{{PlatformDigest: running}},
		}}}}}, true, vulnfix.StatusImageNoCandidate, vulnfix.ActionNone},
		{"other image only", vulnfix.Preview{ID: "run1", OK: true, Units: []vulnfix.Unit{{Images: []vulnfix.Image{{
			OldDigests: []string{newer}, Resolved: []vulnfix.Resolution{{PlatformDigest: other}},
		}}}}}, true, vulnfix.StatusImageNoCandidate, vulnfix.ActionNone},
		{"unavailable unit", vulnfix.Preview{ID: "run1", OK: true, Units: []vulnfix.Unit{{Failed: true, Images: []vulnfix.Image{{
			OldDigests: []string{running}, Resolved: []vulnfix.Resolution{{PlatformDigest: newer}},
		}}}}}, true, vulnfix.StatusImageNoCandidate, vulnfix.ActionNone},
		{"stale preview", vulnfix.Preview{ID: "run1", OK: true, Stale: true, Units: candidate.Units}, true, vulnfix.StatusUnknown, vulnfix.ActionContainers},
		{"no preview", vulnfix.Preview{}, true, vulnfix.StatusUnknown, vulnfix.ActionContainers},
		{"preview not ok", vulnfix.Preview{ID: "run1", Units: candidate.Units}, true, vulnfix.StatusUnknown, vulnfix.ActionContainers},
		{"preview unreadable", vulnfix.Preview{}, false, vulnfix.StatusUnknown, vulnfix.ActionContainers},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := vulnfix.ImageResult(imageFinding(running), tc.p, tc.ok)
			if r.Status != tc.status || r.Action != tc.action || r.Reboot {
				t.Fatalf("got %+v, want status %v action %v", r, tc.status, tc.action)
			}
			if tc.status == vulnfix.StatusUnknown && r.Reason != vulnfix.ReasonNoPreview {
				t.Fatalf("reason %v, want no preview", r.Reason)
			}
		})
	}
}

func TestDeviceResultAdvisoryIDs(t *testing.T) {
	dev := func(eco, id string, aliases ...string) vulnstore.Finding {
		f := vulnstore.Finding{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: "fw1"}, State: vulnstore.StateOpen}
		f.Record.Ecosystem = eco
		f.Record.Vuln = vulnfinding.Vuln{ID: id, Aliases: aliases}
		f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "17.9.4a"}
		return f
	}
	tests := []struct {
		name     string
		f        vulnstore.Finding
		action   vulnfix.Action
		advisory string
	}{
		{"cisco alias", dev("vendor:cisco:iosxe", "CVE-2023-20198", "cisco-sa-iosxe-webui-privesc-j22SaA4z"),
			vulnfix.ActionCiscoAdvisory, "cisco-sa-iosxe-webui-privesc-j22SaA4z"},
		{"palo alto advisory", dev("vendor:paloalto:panos", "CVE-2024-3400", "PAN-SA-2024-0001"), vulnfix.ActionPANAdvisory, "PAN-SA-2024-0001"},
		{"palo alto CVE", dev("vendor:paloalto:panos", "CVE-2024-3400"), vulnfix.ActionPANAdvisory, "CVE-2024-3400"},
		{"cisco CVE only", dev("vendor:cisco:iosxe", "CVE-2023-20198"), vulnfix.ActionNone, ""},
		{"hostile id", dev("vendor:cisco:iosxe", "cisco-sa-x/../../evil"), vulnfix.ActionNone, ""},
		{"cisco id on palo alto", dev("vendor:paloalto:panos", "cisco-sa-abc"), vulnfix.ActionNone, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := vulnfix.DeviceResult(tc.f)
			if tc.action == vulnfix.ActionNone {
				if r.Status != vulnfix.StatusUnknown || r.Reason != vulnfix.ReasonNoAdvisoryLink || r.Action != vulnfix.ActionNone || r.Advisory != "" {
					t.Fatalf("got %+v, want no advisory link", r)
				}
				return
			}
			if r.Status != vulnfix.StatusDeviceNoPatch || r.Action != tc.action || r.Advisory != tc.advisory {
				t.Fatalf("got %+v, want advisory %q via %v", r, tc.advisory, tc.action)
			}
		})
	}
}

// fakeUpdates serves a fixed host→candidates map and counts reads.
type fakeUpdates struct {
	calls int
	lists map[string]vulnfix.Updates
	err   error
}

func (f *fakeUpdates) Lists(context.Context) (map[string]vulnfix.Updates, error) {
	f.calls++
	return f.lists, f.err
}

// fakePreviews serves previews and counts reads.
type fakePreviews struct{ calls int }

func (f *fakePreviews) Preview(context.Context, string) (vulnfix.Preview, error) {
	f.calls++
	return vulnfix.Preview{}, nil
}

func TestResolverReadsOnceAndOnlyDecidesOpenFindings(t *testing.T) {
	src := &fakeUpdates{lists: map[string]vulnfix.Updates{"h1": {}}}
	r := vulnfix.NewResolver(src, nil)
	f := hostFinding("debian:bookworm", "openssl", "3.0.11-1~deb12u2", "openssl")
	for range 3 {
		if res := r.Decide(context.Background(), f); res.Status != vulnfix.StatusNoCandidate {
			t.Fatalf("got %+v", res)
		}
	}
	if src.calls != 1 {
		t.Fatalf("results read %d times", src.calls)
	}
	other := f
	other.Subject.ID = "h2"
	if res := r.Decide(context.Background(), other); res.Status != vulnfix.StatusUnknown || res.Reason != vulnfix.ReasonNoUpdateList {
		t.Fatalf("host without a result: %+v", res)
	}
	closed := f
	closed.State = vulnstore.StateFixed
	if res := r.Decide(context.Background(), closed); res != (vulnfix.Result{}) {
		t.Fatalf("fixed finding got %+v", res)
	}
}

func TestResolverUnreadableOrOffResultsNeverClaimAFix(t *testing.T) {
	f := hostFinding("debian:bookworm", "openssl", "3.0.11-1~deb12u2", "openssl")
	failing := vulnfix.NewResolver(&fakeUpdates{err: errors.New("db down")}, nil)
	if res := failing.Decide(context.Background(), f); res.Status != vulnfix.StatusUnknown || res.Reason != vulnfix.ReasonListsUnread || res.Action != vulnfix.ActionNone {
		t.Fatalf("unreadable: %+v", res)
	}
	off := vulnfix.NewResolver(nil, nil)
	if res := off.Decide(context.Background(), f); res.Status != vulnfix.StatusUnknown || res.Reason != vulnfix.ReasonOpsOff || res.Action != vulnfix.ActionNone {
		t.Fatalf("operations off: %+v", res)
	}
}

func TestResolverBoundsPreviewReads(t *testing.T) {
	src := &fakePreviews{}
	r := vulnfix.NewResolver(nil, src)
	digest := "sha256:" + strings.Repeat("a", 64)
	for i := range vulnfix.MaxPreviewHosts + 5 {
		f := imageFinding(digest)
		f.Subject.ID = "h" + strings.Repeat("x", i)
		r.Decide(context.Background(), f)
		r.Decide(context.Background(), f)
	}
	if src.calls != vulnfix.MaxPreviewHosts {
		t.Fatalf("preview read %d times, want %d", src.calls, vulnfix.MaxPreviewHosts)
	}
}
