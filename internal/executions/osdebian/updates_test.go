// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func doc(t *testing.T, sim, rebootPkgs string, reboot bool) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"format": "apt-simulate-v1", "mode": "upgrade",
		"simulate": base64.StdEncoding.EncodeToString([]byte(sim)), "reboot_required": reboot,
		"reboot_pkgs": base64.StdEncoding.EncodeToString([]byte(rebootPkgs)), "lists_mtime": 1791960000, "proxmox": false})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseUpdates(t *testing.T) {
	sim := strings.Join([]string{
		"Inst openssl [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])",
		"Inst ure [4:24.2.7-0ubuntu0.24.04.6] (4:24.2.7-0ubuntu0.24.04.7 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64]) []",
		"Inst docker-ce [5:29.8.2-1~ubuntu.24.04~noble] (5:29.9.0-1~ubuntu.24.04~noble Docker CE:noble [amd64])",
		"Inst linux-image-6.1.0-27-amd64 (6.1.115-1 Debian:12.8/stable [amd64])",
		"Inst openssl [x] (y Debian:12/stable [amd64])",
		"Inst <script> [1] (2 x [amd64])",
		"Conf openssl (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])",
		"garbage",
	}, "\n")
	u, err := ParseUpdates(doc(t, sim, "linux-image-6.1.0-27-amd64\n<b>bad</b>\n", true))
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Packages) != 4 || u.Security != 2 || u.Kernel != 1 || !u.RebootRequired || u.ListsUpdated.Unix() != 1791960000 {
		t.Fatalf("%+v", u)
	}
	p := u.Packages[1]
	if p.Name != "ure" || p.From != "4:24.2.7-0ubuntu0.24.04.6" || len(p.Archives) != 2 || !p.Security {
		t.Fatalf("%+v", p)
	}
	if u.Packages[3].From != "" || !u.Packages[3].Kernel {
		t.Fatalf("new kernel package: %+v", u.Packages[3])
	}
	if len(u.RebootPackages) != 1 {
		t.Fatalf("reboot pkgs %v", u.RebootPackages)
	}
}

func TestParseUpdatesRejectsOtherDocuments(t *testing.T) {
	for _, in := range []string{`{}`, `not json`, `{"format":"apt-simulate-v1","simulate":"%%%"}`,
		`{"format":"apt-simulate-v1","simulate":"` + base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe}) + `"}`} {
		if _, err := ParseUpdates([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	long := "Inst a (1 " + strings.Repeat("x", 3000) + " [amd64])"
	if u, err := ParseUpdates(doc(t, long, "", false)); err == nil && len(u.Packages) != 0 {
		t.Error("over-long line parsed")
	}
}

// docWithCandidates adds the optional "candidates" field (apt-cache show
// Package/Version/Source lines of the candidate versions).
func docWithCandidates(t *testing.T, sim, candidates string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(doc(t, sim, "", false), &m); err != nil {
		t.Fatal(err)
	}
	m["candidates"] = base64.StdEncoding.EncodeToString([]byte(candidates))
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCandidateSourceVersion(t *testing.T) {
	sim := strings.Join([]string{
		"Inst openssl [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])",
		"Inst libssl3:i386 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [i386])",
		"Inst libfoo1 [1.2-3] (1.2-3+b1 Debian:12/stable [amd64])",
		"Inst bar [1.0-1] (1.0-2 Debian:12/stable [amd64])",
		"Inst baz [1.0-1] (1.0-2 Debian:12/stable [amd64])",
		"Inst qux [1.0-1] (1.0-2 Debian:12/stable [amd64])",
		"Inst evil [1.0-1] (1.0-2 Debian:12/stable [amd64])",
		"Inst nostanza [1.0-1] (1.0-2 Debian:12/stable [amd64])",
	}, "\n")
	cands := strings.Join([]string{
		// Source without version: the source version is the binary version.
		"Package: openssl", "Version: 3.0.11-1~deb12u2", "Source: openssl", "",
		"Package: libssl3", "Version: 3.0.11-1~deb12u2", "Source: openssl", "",
		// binNMU: the binary version carries +b1, Source names the real one.
		"Package: libfoo1", "Version: 1.2-3+b1", "Source: foo (1.2-3)", "",
		// No Source field: source name and version equal the binary's.
		"Package: bar", "Version: 1.0-2", "",
		// A stanza for another version is not the candidate.
		"Package: baz", "Version: 9.9-9", "Source: baz", "",
		// Two stanzas of the candidate disagreeing: unknown.
		"Package: qux", "Version: 1.0-2", "Source: qux (1.0-2)", "",
		"Package: qux", "Version: 1.0-2", "Source: other (1.0-2)", "",
		// Malformed source version: unknown.
		"Package: evil", "Version: 1.0-2", "Source: evil (<script>)", "",
	}, "\n")
	u, err := ParseUpdates(docWithCandidates(t, sim, cands))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"openssl":      {"openssl", "3.0.11-1~deb12u2"},
		"libssl3:i386": {"openssl", "3.0.11-1~deb12u2"},
		"libfoo1":      {"foo", "1.2-3"},
		"bar":          {"bar", "1.0-2"},
		"baz":          {"", ""},
		"qux":          {"", ""},
		"evil":         {"", ""},
		"nostanza":     {"", ""},
	}
	if len(u.Packages) != len(want) {
		t.Fatalf("got %d packages", len(u.Packages))
	}
	for _, p := range u.Packages {
		w := want[p.Name]
		if p.SourceName != w[0] || p.SourceVersion != w[1] {
			t.Errorf("%s: source %q %q, want %q %q", p.Name, p.SourceName, p.SourceVersion, w[0], w[1])
		}
	}
}

func TestCandidateSourceMissingOrBrokenStaysUnknown(t *testing.T) {
	sim := "Inst openssl [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])"
	tests := map[string][]byte{
		"no field (older script)": doc(t, sim, "", false),
		"not base64": func() []byte {
			b := docWithCandidates(t, sim, "")
			return []byte(strings.Replace(string(b), `"candidates":""`, `"candidates":"%%%"`, 1))
		}(),
		"invalid utf-8":  docWithCandidates(t, sim, "Package: openssl\nVersion: 3.0.11-1~deb12u2\nSource: openssl \xff\n"),
		"over-long line": docWithCandidates(t, sim, "Package: openssl\nVersion: 3.0.11-1~deb12u2\nSource: "+strings.Repeat("a", 3000)+"\n"),
		"bad name":       docWithCandidates(t, sim, "Package: openssl\nVersion: 3.0.11-1~deb12u2\nSource: Open_SSL (3.0.11-1~deb12u2)\n"),
		"field order":    docWithCandidates(t, sim, "Version: 3.0.11-1~deb12u2\nSource: openssl\n"),
		"duplicate field": docWithCandidates(t, sim,
			"Package: openssl\nVersion: 3.0.11-1~deb12u2\nSource: openssl (1.0-1)\nSource: openssl (9.0-1)\n"),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			u, err := ParseUpdates(in)
			if err != nil {
				t.Fatalf("update list rejected: %v", err)
			}
			if len(u.Packages) != 1 {
				t.Fatalf("packages %+v", u.Packages)
			}
			if p := u.Packages[0]; p.SourceName != "" || p.SourceVersion != "" {
				t.Fatalf("source known from bad input: %+v", p)
			}
		})
	}
}

func TestCandidateStanzaLimit(t *testing.T) {
	sim := "Inst openssl [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])"
	var b strings.Builder
	for i := 0; i <= MaxCandidateStanzas; i++ {
		b.WriteString("Package: x\nVersion: 1\n\n")
	}
	b.WriteString("Package: openssl\nVersion: 3.0.11-1~deb12u2\nSource: openssl\n")
	u, err := ParseUpdates(docWithCandidates(t, sim, b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if p := u.Packages[0]; p.SourceVersion != "" {
		t.Fatalf("source read past the stanza limit: %+v", p)
	}
}

func TestParseInstall(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	in := `{"format":"apt-install-v1","phase":"done","mode":"install_security","apt_exit":0,"packages":"` + enc("openssl\nlibssl3\n<x>\n") +
		`","dpkg_audit_clean":true,"reboot_required":true,"new_failed_units":"` + enc("nginx.service\nevil\u202eunit\n") + `","docker":"","proxmox":false}`
	i, err := ParseInstall([]byte(in))
	if err != nil || len(i.Packages) != 2 || !i.RebootRequired || len(i.NewFailedUnits) != 1 || !i.Warning() {
		t.Fatalf("%+v %v", i, err)
	}
	p, err := ParseInstall([]byte(`{"format":"apt-install-v1","phase":"precheck","reason":"less than 500 MB free on /var"}`))
	if err != nil || p.Phase != "precheck" || p.Reason != "less than 500 MB free on /var" || p.Warning() {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ParseInstall([]byte(`{"format":"apt-install-v1","phase":"other"}`)); err == nil {
		t.Fatal("unknown phase accepted")
	}
}

func TestParseSystemd(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	units, err := ParseUnits([]byte(`{"format":"systemd-units-v1","units":"` + enc("cron.service loaded active running Regular background program processing daemon\n-bad x y z\nnginx.service loaded failed failed A high performance web server\n") + `"}`))
	if err != nil || len(units) != 2 || units[1].Active != "failed" || units[0].Description == "" {
		t.Fatalf("%+v %v", units, err)
	}
	st, err := ParseServiceStatus([]byte(`{"format":"systemd-status-v1","phase":"done","verb":"restart","exit":0,"show":"` +
		enc("Id=nginx.service\nActiveState=active\nExecStart=/bin/evil\n") + `","journal":"` + enc("line 1\nline 2\n") + `"}`))
	if err != nil || len(st.Props) != 2 || len(st.Journal) != 2 || st.Verb != "restart" {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := ParseServiceStatus([]byte(`{"format":"systemd-status-v1","phase":"other"}`)); err == nil {
		t.Fatal("bad phase accepted")
	}
}
