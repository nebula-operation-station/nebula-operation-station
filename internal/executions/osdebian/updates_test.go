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
