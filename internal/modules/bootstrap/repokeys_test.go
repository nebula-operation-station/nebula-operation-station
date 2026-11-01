// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoKeyPins is the full primary-key fingerprint each vendor install
// script must pin, and the key URL it must download. The values come from
// the vendors' documentation (cited in the scripts); a script that installs
// a vendor apt signing key without checking this fingerprint is a
// supply-chain break, so its absence fails the build.
var repoKeyPins = map[string]struct {
	fingerprint string
	keyURL      string
}{
	"docker":   {fingerprint: "9DC858229FC7DD38854AE2D88D81803C0EBFCD88", keyURL: "https://download.docker.com/linux/$distro/gpg"},
	"netbird":  {fingerprint: "EFE37DF047DF7CCDF1FC54FA83F79AD029778355", keyURL: "https://pkgs.netbird.io/debian/public.key"},
	"telegraf": {fingerprint: "24C975CBA61A024EE1B631787C3D57159FC2F927", keyURL: "https://repos.influxdata.com/influxdata-archive.key"},
}

// TestBootstrapTreeRepoKeysPinned checks the real tree: each vendor install
// script pins the vendor's full key fingerprint, downloads the key from the
// documented URL, verifies it with gpg --show-keys --with-colons, and writes
// the key only under $NEBULA_RUN_DIR (failing when that is unset).
func TestBootstrapTreeRepoKeysPinned(t *testing.T) {
	ms, err := Load(treeRoot)
	if err != nil {
		t.Fatalf("Load(%s): %v", treeRoot, err)
	}
	for _, m := range ms {
		pin, ok := repoKeyPins[m.Name]
		if !ok {
			continue
		}
		body, ok := m.Scripts["actions/install.sh"]
		if !ok {
			t.Fatalf("%s: no install.sh", m.Name)
		}
		s := string(body)
		if !strings.Contains(s, pin.fingerprint) {
			t.Errorf("%s: install.sh does not pin the vendor key fingerprint %s", m.Name, pin.fingerprint)
		}
		if !strings.Contains(s, "gpg --show-keys --with-colons") {
			t.Errorf("%s: install.sh does not verify the key with gpg --show-keys --with-colons", m.Name)
		}
		if !strings.Contains(s, pin.keyURL) {
			t.Errorf("%s: install.sh does not download the key from %s", m.Name, pin.keyURL)
		}
		// The key must be written only under $NEBULA_RUN_DIR: no /tmp or
		// TMPDIR fallback, and the run must fail when it is unset.
		if strings.Contains(s, "NEBULA_RUN_DIR:-/tmp") || strings.Contains(s, "NEBULA_RUN_DIR:-${TMPDIR") {
			t.Errorf("%s: install.sh writes the key outside $NEBULA_RUN_DIR", m.Name)
		}
		if !strings.Contains(s, `[ -n "${NEBULA_RUN_DIR:-}" ]`) {
			t.Errorf("%s: install.sh does not fail when NEBULA_RUN_DIR is unset", m.Name)
		}
	}
}

// extractFunction returns the text of the shell function named name from
// body: from the line "name() {" to the next line that is exactly "}".
func extractFunction(body, name string) (string, bool) {
	var b strings.Builder
	in := false
	for _, l := range strings.Split(body, "\n") {
		if !in {
			if strings.HasPrefix(l, name+"() {") {
				in = true
			} else {
				continue
			}
		}
		b.WriteString(l + "\n")
		if l == "}" {
			return b.String(), true
		}
	}
	return "", false
}

// runRepoKeyCheck builds a harness that defines fail() and the module's real
// nebula_check_repo_key, then calls it with a stub gpg that reports keyFpr as
// the downloaded key's fingerprint and pinned as the expected value. It
// returns the harness exit code and output.
func runRepoKeyCheck(t *testing.T, m Module, keyFpr, pinned string) (int, string) {
	t.Helper()
	body := string(m.Scripts["actions/install.sh"])
	fn, ok := extractFunction(body, "nebula_check_repo_key")
	if !ok {
		t.Fatalf("%s: install.sh has no nebula_check_repo_key function", m.Name)
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "gpg")
	var stubBody string
	if keyFpr == "" {
		// No readable key: gpg fails and prints nothing.
		stubBody = "#!/bin/sh\nexit 1\n"
	} else {
		// One pub/fpr record pair per comma-separated fingerprint.
		var recs strings.Builder
		for _, f := range strings.Split(keyFpr, ",") {
			recs.WriteString("pub:u:4096:1:0000000000000000:1700000000:::u:::c\\nfpr:::::::::" + f + ":\\n")
		}
		stubBody = "#!/bin/sh\nprintf '" + recs.String() + "'\n"
	}
	if err := os.WriteFile(stub, []byte(stubBody), 0o755); err != nil {
		t.Fatal(err)
	}
	harness := "#!/bin/sh\nset -eu\nfail() {\n  printf 'ERROR: %s\\n' \"$*\" >&2\n  exit 1\n}\n" + fn +
		"\nnebula_check_repo_key /dev/null " + pinned + "\n"
	hp := filepath.Join(dir, "harness.sh")
	if err := os.WriteFile(hp, []byte(harness), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(hp)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	}
	t.Fatalf("run harness: %v", err)
	return -1, string(out)
}

// TestRepoKeyCheckRejectsWrongFingerprint runs each vendor's real
// nebula_check_repo_key (extracted from the installed script) against a stub
// gpg: a key whose fingerprint differs from the pinned one, and a key with no
// readable fingerprint, are rejected; the vendor's own key is accepted.
func TestRepoKeyCheckRejectsWrongFingerprint(t *testing.T) {
	ms, err := Load(treeRoot)
	if err != nil {
		t.Fatalf("Load(%s): %v", treeRoot, err)
	}
	byName := map[string]Module{}
	for _, m := range ms {
		byName[m.Name] = m
	}
	wrong := strings.Repeat("0", 40)
	for _, name := range []string{"docker", "netbird", "telegraf"} {
		m, ok := byName[name]
		if !ok {
			t.Fatalf("module %s not loaded", name)
		}
		pin := repoKeyPins[name].fingerprint
		if rc, out := runRepoKeyCheck(t, m, wrong, pin); rc == 0 {
			t.Errorf("%s: a key with the wrong fingerprint was accepted (rc 0, %q)", name, out)
		}
		if rc, out := runRepoKeyCheck(t, m, "", pin); rc == 0 {
			t.Errorf("%s: a key with no readable fingerprint was accepted (rc 0, %q)", name, out)
		}
		// apt trusts every key in the signed-by file: a second key behind
		// the genuine one must not pass.
		if rc, out := runRepoKeyCheck(t, m, pin+","+wrong, pin); rc == 0 {
			t.Errorf("%s: a key file with an extra key was accepted (rc 0, %q)", name, out)
		}
		if rc, out := runRepoKeyCheck(t, m, pin, pin); rc != 0 {
			t.Errorf("%s: the vendor key was rejected (rc %d, %q)", name, rc, out)
		}
	}
}
