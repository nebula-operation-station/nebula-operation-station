// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
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

func cand(name, to, srcName, srcVersion string, security bool) osdebian.Package {
	return osdebian.Package{Name: name, To: to, SourceName: srcName, SourceVersion: srcVersion, Security: security}
}

func TestHostFixWithCandidateSourceVersion(t *testing.T) {
	const (
		urlSec  = "/operations/new?action=package.install_security&host=h1"
		urlAll  = "/operations/new?action=package.install_all&host=h1"
		urlList = "/operations/new?action=package.list_updates&host=h1"
	)
	deb := func(fixed string, bins ...string) vulnstore.Finding {
		return hostFinding("debian:bookworm", "openssl", fixed, bins...)
	}
	tests := []struct {
		name     string
		f        vulnstore.Finding
		upd      *osdebian.Updates
		text     string
		url      string
		verified bool
		reboot   bool
	}{
		{
			name: "Debian backport: candidate source equals the fixed security version",
			f:    deb("3.0.11-1~deb12u2", "openssl", "libssl3"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("openssl", "3.0.11-1~deb12u2", "openssl", "3.0.11-1~deb12u2", true),
				cand("libssl3:amd64", "3.0.11-1~deb12u2", "openssl", "3.0.11-1~deb12u2", true),
			}},
			text: fixTextVerified, url: urlSec, verified: true,
		},
		{
			name: "Ubuntu backport below the fixed upload",
			f:    hostFinding("ubuntu:24.04", "curl", "8.5.0-2ubuntu10.2", "curl"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("curl", "8.5.0-2ubuntu10.1", "curl", "8.5.0-2ubuntu10.1", true),
			}},
			text: fixTextBelowFixed,
		},
		{
			name: "Ubuntu backport at the fixed upload",
			f:    hostFinding("ubuntu:24.04", "curl", "8.5.0-2ubuntu10.2", "curl"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("curl", "8.5.0-2ubuntu10.2", "curl", "8.5.0-2ubuntu10.2", true),
			}},
			text: fixTextVerified, url: urlSec, verified: true,
		},
		{
			name: "binNMU candidate: source version decides, fixed",
			f:    hostFinding("debian:bookworm", "foo", "1.2-3", "libfoo1"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("libfoo1", "1.2-3+b1", "foo", "1.2-3", false),
			}},
			text: fixTextVerified, url: urlAll, verified: true,
		},
		{
			name: "binNMU candidate: binary version reaches fixed but source does not",
			f:    hostFinding("debian:bookworm", "foo", "1.2-2+b1", "libfoo1"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("libfoo1", "1.2-2+b2", "foo", "1.2-2", false),
			}},
			text: fixTextBelowFixed,
		},
		{
			name: "binary-only candidate (no Source data) is not a verified fix",
			f:    deb("3.0.11-1~deb12u2", "openssl"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("openssl", "3.0.11-1~deb12u3", "", "", true),
			}},
			text: fixTextNotVerified, url: urlSec,
		},
		{
			name: "binary of the source left without a candidate",
			f:    deb("3.0.11-1~deb12u2", "openssl", "libssl3"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("libssl3", "3.0.11-1~deb12u2", "openssl", "3.0.11-1~deb12u2", true),
			}},
			text: fixTextNotVerified, url: urlSec,
		},
		{
			name: "installed binaries unknown",
			f:    deb("3.0.11-1~deb12u2"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("openssl", "3.0.11-1~deb12u2", "openssl", "3.0.11-1~deb12u2", true),
			}},
			text: fixTextNotVerified, url: urlSec,
		},
		{
			name: "mixed archives propose all updates",
			f:    deb("3.0.11-1~deb12u2", "openssl", "libssl3"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("openssl", "3.0.11-1~deb12u2", "openssl", "3.0.11-1~deb12u2", true),
				cand("libssl3", "3.0.11-1~deb12u2", "openssl", "3.0.11-1~deb12u2", false),
			}},
			text: fixTextVerified, url: urlAll, verified: true,
		},
		{
			name: "candidate of another source with the same binary name is ignored",
			f:    deb("3.0.11-1~deb12u2", "openssl"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("openssl", "9.9-1", "evil", "9.9-1", true),
			}},
			text: fixTextNoCandidate,
		},
		{
			name: "no candidate",
			f:    deb("3.0.11-1~deb12u2", "openssl"),
			upd:  &osdebian.Updates{Packages: []osdebian.Package{cand("bash", "5.2-1", "bash", "5.2-1", false)}},
			text: fixTextNoCandidate,
		},
		{
			name: "no update list yet",
			f:    deb("3.0.11-1~deb12u2", "openssl"),
			text: fixTextNoList, url: urlList,
		},
		{
			name: "episode fixed version higher than the current one",
			f: func() vulnstore.Finding {
				f := deb("3.0.11-1~deb12u1", "openssl")
				f.EpisodeFixedVersion = "3.0.11-1~deb12u2"
				return f
			}(),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("openssl", "3.0.11-1~deb12u1", "openssl", "3.0.11-1~deb12u1", true),
			}},
			text: fixTextBelowFixed,
		},
		{
			name: "fixed version not comparable",
			f:    deb("not a version!", "openssl"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("openssl", "3.0.11-1~deb12u2", "openssl", "3.0.11-1~deb12u2", true),
			}},
			text: fixTextNoFixed,
		},
		{
			name: "no fix yet",
			f: func() vulnstore.Finding {
				f := deb("", "openssl")
				f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixNoFixYet}
				return f
			}(),
			upd:  &osdebian.Updates{},
			text: fixTextNoFixYet,
		},
		{
			name: "won't fix",
			f: func() vulnstore.Finding {
				f := deb("", "openssl")
				f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixWontFix}
				return f
			}(),
			upd:  &osdebian.Updates{},
			text: fixTextWontFix,
		},
		{
			name: "kernel: unsigned image of the source at the fixed version",
			f:    hostFinding("debian:bookworm", "linux", "6.1.115-1"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("linux-image-6.1.0-28-cloud-amd64", "6.1.115-1", "linux", "6.1.115-1", true),
			}},
			text: fixTextVerified, url: urlSec, verified: true, reboot: true,
		},
		{
			name: "kernel: signed image is never a version basis",
			f:    hostFinding("debian:bookworm", "linux", "6.1.115-1"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("linux-image-6.1.0-28-amd64", "6.1.115+1", "linux-signed-amd64", "6.1.115+1", true),
				cand("linux-headers-6.1.0-28-common", "6.1.115-1", "linux", "6.1.115-1", true),
			}},
			text: fixTextNotVerified, url: urlSec, reboot: true,
		},
		{
			name: "kernel: image below the fixed version",
			f:    hostFinding("ubuntu:24.04", "linux", "6.8.0-48.48"),
			upd: &osdebian.Updates{Packages: []osdebian.Package{
				cand("linux-image-6.8.0-47-generic", "6.8.0-47.47", "linux", "6.8.0-47.47", false),
			}},
			text: fixTextBelowFixed, reboot: true,
		},
		{
			name: "unsupported ecosystem",
			f:    hostFinding("alpine:3.20", "openssl", "3.3.2-r0", "openssl"),
			upd:  &osdebian.Updates{},
			text: fixTextUnsupported,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := hostFixWith(tc.f, tc.upd)
			if v.Text != tc.text || v.URL != tc.url || v.Verified != tc.verified {
				t.Fatalf("got text %q url %q verified %v, want %q %q %v", v.Text, v.URL, v.Verified, tc.text, tc.url, tc.verified)
			}
			hasReboot := len(v.Notes) == 1 && v.Notes[0] == fixTextReboot
			if hasReboot != tc.reboot {
				t.Fatalf("reboot note %v, want %v", v.Notes, tc.reboot)
			}
		})
	}
}

func TestHostFixWithRejectsHostileSubjectID(t *testing.T) {
	f := hostFinding("debian:bookworm", "openssl", "3.0.11-1~deb12u2", "openssl")
	f.Subject.ID = "h1&action=package.install_all"
	if v := hostFixWith(f, &osdebian.Updates{}); v.Text != "" || v.URL != "" {
		t.Fatalf("hostile subject id produced %+v", v)
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

func TestImageFixWith(t *testing.T) {
	running := "sha256:" + strings.Repeat("a", 64)
	newer := "sha256:" + strings.Repeat("b", 64)
	unit := func(resolved ...string) []dockerhost.PreviewUnit {
		im := dockerhost.PreviewImage{OldDigests: []string{running}}
		for _, d := range resolved {
			im.Resolved = append(im.Resolved, dockerhost.PreviewResolution{Tag: "x", PlatformDigest: d})
		}
		return []dockerhost.PreviewUnit{{Form: "compose", Images: []dockerhost.PreviewImage{im}}}
	}
	ok := func(units []dockerhost.PreviewUnit) executions.ContainerPreview {
		return executions.ContainerPreview{ID: "run1", Status: dockerhost.PreviewOK, Units: units}
	}
	const link = "/inventory/containers?host=h1"
	tests := []struct {
		name string
		p    executions.ContainerPreview
		ok   bool
		text string
		url  string
	}{
		{"candidate", ok(unit(newer)), true, fixTextImageCand, link},
		{"current tag resolves to the running digest", ok(unit(running)), true, fixTextImageNone, ""},
		{"other image only", ok([]dockerhost.PreviewUnit{{Images: []dockerhost.PreviewImage{{OldDigests: []string{newer}, Resolved: []dockerhost.PreviewResolution{{PlatformDigest: "sha256:" + strings.Repeat("c", 64)}}}}}}), true, fixTextImageNone, ""},
		{"unavailable unit", func() executions.ContainerPreview {
			p := ok(unit(newer))
			p.Units[0].Reason = "unsupported"
			return p
		}(), true, fixTextImageNone, ""},
		{"stale preview", func() executions.ContainerPreview { p := ok(unit(newer)); p.Stale = "too old"; return p }(), true, fixTextImageUnknown, link},
		{"no preview", executions.ContainerPreview{}, true, fixTextImageUnknown, link},
		{"preview unreadable", executions.ContainerPreview{}, false, fixTextImageUnknown, link},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := imageFixWith(imageFinding(running), tc.p, tc.ok)
			if v.Text != tc.text || v.URL != tc.url || v.Verified {
				t.Fatalf("got %+v, want %q %q (never verified)", v, tc.text, tc.url)
			}
		})
	}
}

func TestDeviceFixWithAdvisoryLinks(t *testing.T) {
	dev := func(eco, id string, aliases ...string) vulnstore.Finding {
		f := vulnstore.Finding{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: "fw1"}, State: vulnstore.StateOpen}
		f.Record.Ecosystem = eco
		f.Record.Vuln = vulnfinding.Vuln{ID: id, Aliases: aliases}
		f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "17.9.4a"}
		return f
	}
	tests := []struct {
		name string
		f    vulnstore.Finding
		url  string
	}{
		{"cisco alias", dev("vendor:cisco:iosxe", "CVE-2023-20198", "cisco-sa-iosxe-webui-privesc-j22SaA4z"),
			ciscoAdvisoryBase + "cisco-sa-iosxe-webui-privesc-j22SaA4z"},
		{"palo alto advisory", dev("vendor:paloalto:panos", "CVE-2024-3400", "PAN-SA-2024-0001"), panAdvisoryBase + "PAN-SA-2024-0001"},
		{"palo alto CVE", dev("vendor:paloalto:panos", "CVE-2024-3400"), panAdvisoryBase + "CVE-2024-3400"},
		{"cisco CVE only", dev("vendor:cisco:iosxe", "CVE-2023-20198"), ""},
		{"hostile id", dev("vendor:cisco:iosxe", "cisco-sa-x/../../evil"), ""},
		{"cisco id on palo alto", dev("vendor:paloalto:panos", "cisco-sa-abc"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := deviceFixWith(tc.f)
			if v.URL != tc.url || v.External != (tc.url != "") || v.Verified {
				t.Fatalf("got %+v, want url %q", v, tc.url)
			}
		})
	}
}

func TestFixResolverReadsOnceAndOnlyOpensFlows(t *testing.T) {
	calls := 0
	upd := []byte(`{"format":"apt-simulate-v1","mode":"upgrade","simulate":"","reboot_required":false,"reboot_pkgs":"","lists_mtime":0,"proxmox":false}`)
	r := &vulnFixResolver{lastResults: func(_ context.Context, action string) (map[string]executions.LastResultRow, error) {
		calls++
		if action != "package.list_updates" {
			t.Errorf("read %q", action)
		}
		return map[string]executions.LastResultRow{"h1": {Result: upd}}, nil
	}}
	f := hostFinding("debian:bookworm", "openssl", "3.0.11-1~deb12u2", "openssl")
	for range 3 {
		v := r.fixWith(context.Background(), f)
		if v == nil || v.Text != fixTextNoCandidate {
			t.Fatalf("got %+v", v)
		}
	}
	if calls != 1 {
		t.Fatalf("results read %d times", calls)
	}
	other := f
	other.Subject.ID = "h2"
	if v := r.fixWith(context.Background(), other); v == nil || v.Text != fixTextNoList ||
		!strings.HasPrefix(v.URL, "/operations/new?") {
		t.Fatalf("host without a result: %+v", v)
	}
	closed := f
	closed.State = vulnstore.StateFixed
	if v := r.fixWith(context.Background(), closed); v != nil {
		t.Fatalf("fixed finding got %+v", v)
	}
}

func TestFixResolverUnreadableResultsNeverClaimAFix(t *testing.T) {
	r := &vulnFixResolver{lastResults: func(context.Context, string) (map[string]executions.LastResultRow, error) {
		return nil, errors.New("db down")
	}}
	v := r.fixWith(context.Background(), hostFinding("debian:bookworm", "openssl", "3.0.11-1~deb12u2", "openssl"))
	if v == nil || v.Verified || v.URL != "" || v.Text != fixTextListsUnread {
		t.Fatalf("got %+v", v)
	}
	if v := (&vulnFixResolver{}).fixWith(context.Background(), hostFinding("debian:bookworm", "openssl", "1-1", "openssl")); v == nil || v.Verified ||
		v.URL != "" || v.Text != fixTextOpsOff {
		t.Fatalf("operations off: %+v", v)
	}
}

func TestFixResolverBoundsPreviewReads(t *testing.T) {
	calls := 0
	r := &vulnFixResolver{preview: func(context.Context, string) (executions.ContainerPreview, error) {
		calls++
		return executions.ContainerPreview{}, nil
	}}
	digest := "sha256:" + strings.Repeat("a", 64)
	for i := range maxFixPreviewHosts + 5 {
		f := imageFinding(digest)
		f.Subject.ID = "h" + strings.Repeat("x", i)
		r.fixWith(context.Background(), f)
		r.fixWith(context.Background(), f)
	}
	if calls != maxFixPreviewHosts {
		t.Fatalf("preview read %d times, want %d", calls, maxFixPreviewHosts)
	}
}
