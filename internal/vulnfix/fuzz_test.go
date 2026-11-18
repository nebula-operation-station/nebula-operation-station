// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfix_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// fuzzStatuses, fuzzReasons and fuzzActions list every state the package
// defines. A decision must always be one of them.
var (
	fuzzStatuses = []vulnfix.Status{
		vulnfix.StatusNone, vulnfix.StatusVerified, vulnfix.StatusNotVerified,
		vulnfix.StatusBelowFixed, vulnfix.StatusNoCandidate, vulnfix.StatusNoFixYet,
		vulnfix.StatusWontFix, vulnfix.StatusUnknown, vulnfix.StatusImageCandidate,
		vulnfix.StatusImageNoCandidate, vulnfix.StatusDeviceNoPatch,
	}
	fuzzReasons = []vulnfix.Reason{
		vulnfix.ReasonNone, vulnfix.ReasonNoUpdateList, vulnfix.ReasonListsUnread,
		vulnfix.ReasonOpsOff, vulnfix.ReasonFixedNotComparable,
		vulnfix.ReasonUnsupportedEcosystem, vulnfix.ReasonNoPreview,
		vulnfix.ReasonNoAdvisoryLink,
	}
	fuzzActions = []vulnfix.Action{
		vulnfix.ActionNone, vulnfix.ActionInstallSecurity, vulnfix.ActionInstallAll,
		vulnfix.ActionListUpdates, vulnfix.ActionContainers, vulnfix.ActionCiscoAdvisory,
		vulnfix.ActionPANAdvisory,
	}
)

// fuzzFixState maps a fuzz byte to a fix state; the last value is not a
// known state at all.
func fuzzFixState(s uint8) vulnfinding.FixState {
	switch s % 5 {
	case 0:
		return vulnfinding.FixFixed
	case 1:
		return vulnfinding.FixNoFixYet
	case 2:
		return vulnfinding.FixWontFix
	case 3:
		return vulnfinding.FixNotAffected
	default:
		return vulnfinding.FixState("bogus")
	}
}

// fuzzPackages parses update candidates from lines of "name|source|version|security".
// Missing fields are empty; security is set only by "1".
func fuzzPackages(s string) []vulnfix.Package {
	var out []vulnfix.Package
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		for len(parts) < 4 {
			parts = append(parts, "")
		}
		out = append(out, vulnfix.Package{
			Name:          parts[0],
			SourceName:    parts[1],
			SourceVersion: parts[2],
			Security:      parts[3] == "1",
		})
	}
	return out
}

// fuzzHostFinding builds an open host finding from fuzz inputs. bins is a
// comma-separated list of installed binary names.
func fuzzHostFinding(eco, source, fixed, episode, hostID string, state vulnfinding.FixState, bins string) vulnstore.Finding {
	var fd vulnstore.Finding
	fd.Subject = vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: hostID}
	fd.State = vulnstore.StateOpen
	fd.Record.Ecosystem = eco
	fd.Record.Component.SourcePackage = source
	for _, b := range strings.Split(bins, ",") {
		if b != "" {
			fd.Record.Component.Binaries = append(fd.Record.Component.Binaries, vulnfinding.Binary{Name: b, Version: "0"})
		}
	}
	fd.Record.Fix = vulnfinding.Fix{State: state, Version: fixed}
	fd.EpisodeFixedVersion = episode
	return fd
}

// FuzzHostResult fuzzes the "fix with" decision of a host package finding
// against an untrusted update list. The oracle: no panic; the status, reason
// and action are defined; no verified fix without a candidate of the list
// that reaches the fixed version; the candidate's source version is compared
// with vulnver, never trusted as text.
func FuzzHostResult(f *testing.F) {
	type seed struct {
		eco, source, fixed, episode, hostID string
		state                               uint8
		bins, pkgs                          string
		hasList                             bool
	}
	seeds := []seed{
		// decide_test.go: candidate source version decisions.
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h1", 0, "openssl,libssl3",
			"openssl|openssl|3.0.11-1~deb12u2|1\nlibssl3|openssl|3.0.11-1~deb12u2|1", true},
		{"ubuntu:24.04", "curl", "8.5.0-2ubuntu10.2", "", "h1", 0, "curl", "curl|curl|8.5.0-2ubuntu10.1|1", true},
		{"ubuntu:24.04", "curl", "8.5.0-2ubuntu10.2", "", "h1", 0, "curl", "curl|curl|8.5.0-2ubuntu10.2|1", true},
		{"debian:bookworm", "foo", "1.2-3", "", "h1", 0, "libfoo1", "libfoo1:amd64|foo|1.2-3|0", true},
		{"debian:bookworm", "foo", "1.2-2+b1", "", "h1", 0, "libfoo1", "libfoo1|foo|1.2-2|0", true},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h1", 0, "openssl", "openssl||||1", true},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h1", 0, "openssl,libssl3", "libssl3|openssl|3.0.11-1~deb12u2|1", true},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h1", 0, "", "openssl|openssl|3.0.11-1~deb12u2|1", true},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h1", 0, "openssl,libssl3",
			"openssl|openssl|3.0.11-1~deb12u2|1\nlibssl3|openssl|3.0.11-1~deb12u2|0", true},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h1", 0, "openssl", "openssl|evil|9.9-1|1", true},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h1", 0, "openssl", "bash|bash|5.2-1|0", true},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h1", 0, "openssl", "", false},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u1", "3.0.11-1~deb12u2", "h1", 0, "openssl",
			"openssl|openssl|3.0.11-1~deb12u1|1", true},
		{"debian:bookworm", "openssl", "not a version!", "", "h1", 0, "openssl",
			"openssl|openssl|3.0.11-1~deb12u2|1", true},
		{"debian:bookworm", "openssl", "", "", "h1", 1, "openssl", "", true},
		{"debian:bookworm", "openssl", "", "", "h1", 2, "openssl", "", true},
		{"debian:bookworm", "linux", "6.1.115-1", "", "h1", 0, "",
			"linux-image-6.1.0-28-cloud-amd64|linux|6.1.115-1|1", true},
		{"debian:bookworm", "linux", "6.1.115-1", "", "h1", 0, "",
			"linux-image-6.1.0-28-amd64|linux-signed-amd64|6.1.115+1|1\nlinux-headers-6.1.0-28-common|linux|6.1.115-1|1", true},
		{"ubuntu:24.04", "linux", "6.8.0-48.48", "", "h1", 0, "",
			"linux-image-6.8.0-47-generic|linux|6.8.0-47.47|0", true},
		{"alpine:3.20", "openssl", "3.3.2-r0", "", "h1", 0, "openssl", "", true},
		// boundary_test.go and decide_test.go: hostile subject IDs.
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "../etc", 0, "openssl",
			"openssl|openssl|3.0.11-1~deb12u2|1", true},
		{"debian:bookworm", "openssl", "3.0.11-1~deb12u2", "", "h\x00", 0, "openssl",
			"openssl|openssl|3.0.11-1~deb12u2|1", true},
	}
	for _, s := range seeds {
		f.Add(s.eco, s.source, s.fixed, s.episode, s.hostID, s.state, s.bins, s.pkgs, s.hasList)
	}

	f.Fuzz(func(t *testing.T, eco, source, fixed, episode, hostID string, state uint8, bins, pkgs string, hasList bool) {
		fs := fuzzFixState(state)
		fd := fuzzHostFinding(eco, source, fixed, episode, hostID, fs, bins)
		var upd *vulnfix.Updates
		var list []vulnfix.Package
		if hasList {
			list = fuzzPackages(pkgs)
			upd = &vulnfix.Updates{Packages: list}
		}

		r := vulnfix.HostResult(fd, upd)

		if !slices.Contains(fuzzStatuses, r.Status) {
			t.Fatalf("undefined status %d", r.Status)
		}
		if !slices.Contains(fuzzReasons, r.Reason) {
			t.Fatalf("undefined reason %d", r.Reason)
		}
		if !slices.Contains(fuzzActions, r.Action) {
			t.Fatalf("undefined action %d", r.Action)
		}
		if r.HostID != "" && (r.HostID != hostID || !vulnfix.ValidSubjectID(r.HostID)) {
			t.Fatalf("result host ID %q is not the validated subject %q", r.HostID, hostID)
		}
		if !vulnfix.ValidSubjectID(hostID) && fs == vulnfinding.FixFixed && r.Status != vulnfix.StatusNone {
			t.Fatalf("invalid subject ID %q got status %d, want none", hostID, r.Status)
		}

		candidateDecision := r.Status == vulnfix.StatusVerified ||
			r.Status == vulnfix.StatusNotVerified ||
			r.Status == vulnfix.StatusBelowFixed ||
			r.Status == vulnfix.StatusNoCandidate
		if candidateDecision && fs != vulnfinding.FixFixed {
			t.Fatalf("status %d from fix state %q; candidates only decide a fixed finding", r.Status, fs)
		}
		if candidateDecision && upd == nil {
			t.Fatalf("status %d without an update list", r.Status)
		}
		if (r.Status == vulnfix.StatusVerified || r.Status == vulnfix.StatusNotVerified ||
			r.Status == vulnfix.StatusBelowFixed) && len(list) == 0 {
			t.Fatalf("status %d without candidates", r.Status)
		}
		if r.Status != vulnfix.StatusVerified && r.Status != vulnfix.StatusBelowFixed {
			return
		}

		// Verified and below-fixed results name a candidate of the list.
		if r.Candidate == "" {
			t.Fatalf("status %d names no candidate version", r.Status)
		}
		if r.Fixed == "" {
			t.Fatalf("status %d names no fixed version", r.Status)
		}
		if !slices.ContainsFunc(list, func(p vulnfix.Package) bool { return p.SourceVersion == r.Candidate }) {
			t.Fatalf("candidate %q is not a source version of the list", r.Candidate)
		}
		cmp, err := vulnver.CompareDpkg(r.Candidate, r.Fixed)
		if err != nil {
			t.Fatalf("candidate %q vs fixed %q: %v", r.Candidate, r.Fixed, err)
		}
		if r.Status == vulnfix.StatusVerified && cmp < 0 {
			t.Fatalf("verified fix names candidate %q below fixed %q", r.Candidate, r.Fixed)
		}
		if r.Status == vulnfix.StatusBelowFixed && cmp >= 0 {
			t.Fatalf("below-fixed result names candidate %q at or after fixed %q", r.Candidate, r.Fixed)
		}
		if r.Status == vulnfix.StatusVerified && !vulnver.IsKernelSource(source) {
			checkEveryCandidateReachesFix(t, source, bins, list, r.Fixed)
		}
	})
}

// checkEveryCandidateReachesFix asserts the non-kernel basis rule of a
// verified fix: every candidate of the source has a known source version at
// or after fixed, and no installed binary is matched by an unknown-source
// candidate.
func checkEveryCandidateReachesFix(t *testing.T, source, bins string, list []vulnfix.Package, fixed string) {
	t.Helper()
	installed := map[string]bool{}
	for _, b := range strings.Split(bins, ",") {
		if b != "" {
			installed[b] = true
		}
	}
	for _, p := range list {
		name, _, _ := strings.Cut(p.Name, ":")
		if p.SourceName == "" && installed[name] {
			t.Fatalf("verified fix while installed binary %q has a candidate of unknown source", name)
		}
		if p.SourceName != source {
			continue
		}
		c, err := vulnver.CompareDpkg(p.SourceVersion, fixed)
		if err != nil || c < 0 {
			t.Fatalf("verified fix while candidate %s has source version %q below fixed %q (err %v)", p.Name, p.SourceVersion, fixed, err)
		}
	}
}

// FuzzValidIDs fuzzes the link validators. An accepted subject ID is ASCII,
// 1 to 63 bytes of [a-z0-9._-] starting with an alphanumeric; an accepted
// digest is "sha256:" plus 64 lowercase hex digits. Control characters,
// spaces, slashes and non-ASCII bytes are never accepted.
func FuzzValidIDs(f *testing.F) {
	for _, s := range []string{
		"h1", "a", "host-01.lan", "", "-x", "a b", "a/b", "a\n", "é", "h\x00",
		"sha256:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 64) + "\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if vulnfix.ValidSubjectID(s) {
			if len(s) < 1 || len(s) > 63 {
				t.Fatalf("accepted subject ID of length %d", len(s))
			}
			for i := 0; i < len(s); i++ {
				c := s[i]
				ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
				if !ok {
					t.Fatalf("accepted subject ID %q with byte 0x%02x at %d", s, c, i)
				}
			}
		}
		if vulnfix.ValidDigest(s) {
			const prefix = "sha256:"
			if len(s) != len(prefix)+64 || !strings.HasPrefix(s, prefix) {
				t.Fatalf("accepted digest %q of wrong shape", s)
			}
			for i := len(prefix); i < len(s); i++ {
				c := s[i]
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Fatalf("accepted digest %q with byte 0x%02x at %d", s, c, i)
				}
			}
		}
	})
}
