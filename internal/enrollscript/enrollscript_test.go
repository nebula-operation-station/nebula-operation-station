// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollscript

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// goldenKey is the fixed ed25519 key (seed 0x01..0x20) the golden scripts
// were generated with (cmd/nebula/enroll_test.go).
func goldenKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	k, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// goldenCases are the option sets of the golden scripts in testdata. The
// files were generated with the CLI code before the extraction; the same
// names with CLI arguments are in cmd/nebula/enroll_test.go.
func goldenCases(t *testing.T) []struct {
	name string
	o    Options
} {
	k := goldenKey(t)
	return []struct {
		name string
		o    Options
	}{
		{"default", Options{From: []string{"192.168.0.10", "10.8.0.0/24"}, User: "nebula", KeyRef: "nebula-default", Key: k, Sudo: true}},
		{"no-sudo-user-ops", Options{From: []string{"10.0.0.1"}, User: "ops", KeyRef: "nebula-default", Key: k}},
		{"ipv6-custom-key", Options{From: []string{"2001:db8::10", "fd00:1:2::/64"}, User: "nebula", KeyRef: "lab_key-2", Key: k, Sudo: true}},
		{"mixed-many", Options{From: []string{"10.0.0.1", "10.0.0.2/32", "172.16.0.0/12", "::1", "fe80::/10", "192.0.2.255"}, User: "_svc-nos_1", KeyRef: "nebula-default", Key: k, Sudo: true}},
		{"max-lengths-no-sudo", Options{From: []string{"203.0.113.7"}, User: "a" + strings.Repeat("b", 31), KeyRef: "k" + strings.Repeat("0", 63), Key: k}},
	}
}

func TestRenderMatchesGolden(t *testing.T) {
	for _, tc := range goldenCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Render(tc.o)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", tc.name+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("script differs from testdata/%s.golden:\n%s", tc.name, got)
			}
		})
	}
}

// TestRenderedScriptsParse: every rendered variant passes `bash -n` and
// `dash -n`.
func TestRenderedScriptsParse(t *testing.T) {
	dir := t.TempDir()
	for _, shell := range []string{"bash", "dash"} {
		t.Run(shell, func(t *testing.T) {
			bin, err := exec.LookPath(shell)
			if err != nil {
				t.Skipf("%s not installed", shell)
			}
			for _, tc := range goldenCases(t) {
				for _, sudo := range []bool{true, false} {
					o := tc.o
					o.Sudo = sudo
					s, err := Render(o)
					if err != nil {
						t.Fatal(err)
					}
					p := filepath.Join(dir, fmt.Sprintf("%s-%s-sudo%v.sh", shell, tc.name, sudo))
					if err := os.WriteFile(p, s, 0o600); err != nil {
						t.Fatal(err)
					}
					if out, err := exec.Command(bin, "-n", p).CombinedOutput(); err != nil {
						t.Errorf("%s -n %s (sudo=%v): %v %s", shell, tc.name, sudo, err, out)
					}
				}
			}
		})
	}
}

// TestRenderSizeLimit: a script up to MaxScriptBytes is rendered, a larger
// one is refused with ErrTooLarge.
func TestRenderSizeLimit(t *testing.T) {
	o := Options{User: "nebula", KeyRef: "nebula-default", Key: goldenKey(t), Sudo: true}
	n := 0
	for len(render(o)) <= MaxScriptBytes {
		n++
		o.From = append(o.From, fmt.Sprintf("2001:db8:%x::/64", n))
	}
	if len(o.From) < 2 {
		t.Fatal("limit reached without addresses")
	}
	s, err := Render(o)
	if !errors.Is(err, ErrTooLarge) || s != nil {
		t.Fatalf("Render over the limit (%d bytes) = %d bytes, %v; want ErrTooLarge", len(render(o)), len(s), err)
	}
	o.From = o.From[:len(o.From)-1]
	s, err = Render(o)
	if err != nil || len(s) > MaxScriptBytes {
		t.Fatalf("Render under the limit = %d bytes, %v", len(s), err)
	}
}

// TestRenderRejectsUnsafeInput: values that are not a valid user name, key
// reference or IP/CIDR never reach a script.
func TestRenderRejectsUnsafeInput(t *testing.T) {
	k := goldenKey(t)
	valid := Options{From: []string{"10.0.0.1"}, User: "nebula", KeyRef: "nebula-default", Key: k, Sudo: true}
	if _, err := Render(valid); err != nil {
		t.Fatalf("valid options refused: %v", err)
	}
	cases := map[string]func(o *Options){
		"user root":             func(o *Options) { o.User = "root" },
		"user empty":            func(o *Options) { o.User = "" },
		"user quote":            func(o *Options) { o.User = "a'b" },
		"user double quote":     func(o *Options) { o.User = `a"b` },
		"user dollar":           func(o *Options) { o.User = "a$(id)" },
		"user backtick":         func(o *Options) { o.User = "a`id`" },
		"user semicolon":        func(o *Options) { o.User = "a;id" },
		"user newline":          func(o *Options) { o.User = "a\nid" },
		"user trailing newline": func(o *Options) { o.User = "nebula\n" },
		"user space":            func(o *Options) { o.User = "a b" },
		"user at":               func(o *Options) { o.User = "a@b" },
		"user upper case":       func(o *Options) { o.User = "Nebula" },
		"user leading digit":    func(o *Options) { o.User = "1nebula" },
		"user leading hyphen":   func(o *Options) { o.User = "-nebula" },
		"user too long":         func(o *Options) { o.User = "a" + strings.Repeat("b", 32) },
		"user non-ASCII":        func(o *Options) { o.User = "nébula" },
		"user glob":             func(o *Options) { o.User = "neb*" },
		"ref empty":             func(o *Options) { o.KeyRef = "" },
		"ref traversal":         func(o *Options) { o.KeyRef = "../x" },
		"ref quote":             func(o *Options) { o.KeyRef = "a'b" },
		"ref space":             func(o *Options) { o.KeyRef = "a b" },
		"ref newline":           func(o *Options) { o.KeyRef = "a\nb" },
		"ref dollar":            func(o *Options) { o.KeyRef = "a$(id)" },
		"ref leading hyphen":    func(o *Options) { o.KeyRef = "-a" },
		"ref leading _":         func(o *Options) { o.KeyRef = "_a" },
		"ref upper case":        func(o *Options) { o.KeyRef = "Nebula" },
		"ref too long":          func(o *Options) { o.KeyRef = "k" + strings.Repeat("0", 64) },
		"from none":             func(o *Options) { o.From = nil },
		"from empty entry":      func(o *Options) { o.From = []string{"10.0.0.1", ""} },
		"from host name":        func(o *Options) { o.From = []string{"nebula.lan"} },
		"from quote":            func(o *Options) { o.From = []string{`10.0.0.1"`} },
		"from single quote":     func(o *Options) { o.From = []string{"10.0.0.1'"} },
		"from command":          func(o *Options) { o.From = []string{"$(id)"} },
		"from space":            func(o *Options) { o.From = []string{" 10.0.0.1"} },
		"from two in one":       func(o *Options) { o.From = []string{"10.0.0.1 10.0.0.2"} },
		"from comma in one":     func(o *Options) { o.From = []string{"10.0.0.1,10.0.0.2"} },
		"from newline":          func(o *Options) { o.From = []string{"10.0.0.1\n"} },
		"from bad prefix":       func(o *Options) { o.From = []string{"10.0.0.0/33"} },
		"from prefix suffix":    func(o *Options) { o.From = []string{"10.0.0.0/24;id"} },
		"from zone":             func(o *Options) { o.From = []string{"fe80::1%eth0"} },
		"from with port":        func(o *Options) { o.From = []string{"10.0.0.1:22"} },
		"from wildcard":         func(o *Options) { o.From = []string{"*"} },
		"no key":                func(o *Options) { o.Key = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := valid
			o.From = append([]string(nil), valid.From...)
			mutate(&o)
			s, err := Render(o)
			if !errors.Is(err, ErrInvalidOptions) || s != nil {
				t.Fatalf("Render = %q, %v; want ErrInvalidOptions", s, err)
			}
		})
	}
}

// TestRenderKeyIsReencoded: only the key's type and data reach the script,
// and the fingerprint comment matches the key.
func TestRenderKeyIsReencoded(t *testing.T) {
	k := goldenKey(t)
	s, err := Render(Options{From: []string{"10.0.0.1"}, User: "nebula", KeyRef: "nebula-default", Key: k})
	if err != nil {
		t.Fatal(err)
	}
	want := "key_line='from=\"10.0.0.1\",no-agent-forwarding,no-port-forwarding,no-X11-forwarding " +
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " nebula-nebula-default'\n"
	if !strings.Contains(string(s), want) {
		t.Fatalf("key line %q missing:\n%s", want, s)
	}
	if !strings.Contains(string(s), "Key: "+ssh.FingerprintSHA256(k)+"\n") {
		t.Fatal("fingerprint missing")
	}
}
