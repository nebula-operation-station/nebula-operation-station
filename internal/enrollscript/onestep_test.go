// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollscript

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
)

// pairingVectors mirrors internal/pairing/testdata/vectors.json, the test
// vectors shared by EN-03 (Go) and EN-04 (script).
type pairingVectors struct {
	Comment string `json:"comment"`
	Domain  string `json:"domain"`
	Vectors []struct {
		SaltHex       string `json:"salt_hex"`
		KeyBlobBase64 string `json:"key_blob_base64"`
		HiHex         string `json:"hi_hex"`
		LoHex         string `json:"lo_hex"`
		CheckValue    int    `json:"check_value"`
		Code          string `json:"code"`
	} `json:"vectors"`
}

func loadPairingVectors(t *testing.T) pairingVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "pairing", "testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf pairingVectors
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vf); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return vf
}

// testSalt is a fixed offer salt for tests that do not use the vectors.
func testSalt() []byte {
	s := make([]byte, pairing.SaltSize)
	for i := range s {
		s[i] = byte(0xa0 + i)
	}
	return s
}

func validOneStep(t *testing.T) OneStepOptions {
	return OneStepOptions{
		Options: Options{From: []string{"192.168.0.10", "10.8.0.0/24"}, User: "nebula", KeyRef: "nebula-default", Key: goldenKey(t), Sudo: true},
		Salt:    testSalt(),
	}
}

// testShells are the shells the script pieces run in; a missing one is
// skipped in its subtest.
var testShells = []string{"dash", "bash"}

// runShell runs script with shell in an empty temp directory, with a
// minimal environment (no proxy variables, nothing network related) and a
// timeout. It returns stdout, stderr and the exit error.
func runShell(t *testing.T, shell, script string, path string, args ...string) (string, string, error) {
	t.Helper()
	bin, err := exec.LookPath(shell)
	if err != nil {
		t.Skipf("%s not installed", shell)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "piece.sh")
	if err := os.WriteFile(p, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if path == "" {
		path = "/usr/bin:/bin"
	}
	cmd := exec.Command(bin, append([]string{p}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + path, "LC_ALL=C", "HOME=" + dir}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("%s timed out", shell)
	}
	return stdout.String(), stderr.String(), err
}

// TestOneStepPairingCodeMatchesGo: the rendered pairing piece computes, in
// dash and in bash, exactly the code of the Go implementation for every
// shared EN-03 vector.
func TestOneStepPairingCodeMatchesGo(t *testing.T) {
	vf := loadPairingVectors(t)
	if vf.Domain != "nos-enroll-pair-v1" {
		t.Fatalf("vector domain %q", vf.Domain)
	}
	var script strings.Builder
	script.WriteString("set -eu\n")
	var want strings.Builder
	for i, v := range vf.Vectors {
		salt, err := hex.DecodeString(v.SaltHex)
		if err != nil {
			t.Fatalf("vector %d salt: %v", i, err)
		}
		blob, err := base64.StdEncoding.DecodeString(v.KeyBlobBase64)
		if err != nil {
			t.Fatalf("vector %d blob: %v", i, err)
		}
		c, err := pairing.Compute(salt, blob)
		if err != nil {
			t.Fatalf("vector %d: Compute: %v", i, err)
		}
		if c.String() != v.Code {
			t.Fatalf("vector %d: Go code %s, vector %s", i, c, v.Code)
		}
		fmt.Fprintf(&want, "%s\n", c)
		// Each vector gets its own rendered piece (the salt is part of it).
		script.WriteString(pairingFuncs(salt, []string{"10.0.0.1"}))
		fmt.Fprintf(&script, "nos_pair_code '%s'\n", v.KeyBlobBase64)
	}
	for _, shell := range testShells {
		t.Run(shell, func(t *testing.T) {
			out, errOut, err := runShell(t, shell, script.String(), "")
			if err != nil {
				t.Fatalf("%s: %v\n%s", shell, err, errOut)
			}
			if out != want.String() {
				t.Fatalf("%s codes differ from Go:\n got %q\nwant %q", shell, out, want.String())
			}
		})
	}
}

// TestOneStepPairingCodeRejectsBadBlob: a key that is not an ed25519 blob
// in SSH wire format gives no code.
func TestOneStepPairingCodeRejectsBadBlob(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(goldenKey(t).Marshal())
	ecdsa := "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg="
	raw := goldenKey(t).Marshal()
	cases := map[string]string{
		"empty":            "",
		"ecdsa":            ecdsa,
		"truncated":        good[:len(good)-8],
		"extra byte":       base64.StdEncoding.EncodeToString(append(append([]byte(nil), raw...), 0)),
		"wrong key len":    base64.StdEncoding.EncodeToString(append(append([]byte(nil), raw[:15]...), append([]byte{0, 0, 0, 0x21}, raw[19:]...)...)),
		"not base64":       "AAAAC3NzaC1lZDI1NTE5AAAAI$(id)",
		"space":            good[:20] + " " + good[21:],
		"double pad":       good[:len(good)-2] + "==",
		"pad in middle":    good[:30] + "=" + good[31:],
		"quote":            good[:20] + "'" + good[21:],
		"key type renamed": base64.StdEncoding.EncodeToString(append(append([]byte{0, 0, 0, 11}, "ssh-ed25518"...), raw[15:]...)),
	}
	if _, err := pairing.Compute(testSalt(), raw); err != nil {
		t.Fatal(err)
	}
	for _, shell := range testShells {
		t.Run(shell, func(t *testing.T) {
			var script strings.Builder
			script.WriteString(pairingFuncs(testSalt(), []string{"10.0.0.1"}))
			script.WriteString("if nos_pair_code \"$1\"; then echo ACCEPTED; else echo REFUSED; fi\n")
			out, errOut, err := runShell(t, shell, script.String(), "", good)
			if err != nil || !regexp.MustCompile(`^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}-[0-9A-Z]{4}[0-9A-Z*~$=]\nACCEPTED\n$`).MatchString(out) {
				t.Fatalf("good key: %q %v %s", out, err, errOut)
			}
			for name, k := range cases {
				out, errOut, err := runShell(t, shell, script.String(), "", k)
				if err != nil || out != "REFUSED\n" {
					t.Errorf("%s: %q %v %s", name, out, err, errOut)
				}
			}
		})
	}
}

// stubSSHD writes an executable sshd stub that prints the given sshd -T
// output, or fails when fail is set.
func stubSSHD(t *testing.T, dir, output string, fail bool) string {
	t.Helper()
	p := filepath.Join(dir, "sshd")
	body := "#!/bin/sh\n[ \"$1\" = -T ] || exit 2\ncat <<'EOF'\n" + output + "EOF\n"
	if fail {
		body = "#!/bin/sh\necho 'sshd: config broken' >&2\nexit 255\n"
	}
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestOneStepHostKeyDiscovery: the code is shown for the ed25519 key sshd
// serves (or the fallback file when sshd -T is unavailable); a host without
// an ed25519 key gets a clear message and no code.
func TestOneStepHostKeyDiscovery(t *testing.T) {
	k := goldenKey(t)
	edLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(k.Marshal()) + " root@host\n"
	ecLine := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg= root@host\n"
	code, err := pairing.Compute(testSalt(), k.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	codeRe := regexp.MustCompile(`[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-`)
	type tc struct {
		name     string
		setup    func(t *testing.T, dir string) (sshd, fallback string)
		wantCode bool
	}
	write := func(t *testing.T, p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []tc{
		{"sshd serves ed25519", func(t *testing.T, d string) (string, string) {
			write(t, filepath.Join(d, "ec.pub"), ecLine)
			write(t, filepath.Join(d, "ed.pub"), edLine)
			return stubSSHD(t, d, "port 22\nhostkey "+filepath.Join(d, "ec")+"\nhostkey "+filepath.Join(d, "ed")+"\n", false), filepath.Join(d, "missing.pub")
		}, true},
		{"sshd serves ed25519, no trailing newline in pub", func(t *testing.T, d string) (string, string) {
			write(t, filepath.Join(d, "ed.pub"), strings.TrimSuffix(edLine, "\n"))
			return stubSSHD(t, d, "hostkey "+filepath.Join(d, "ed")+"\n", false), filepath.Join(d, "missing.pub")
		}, true},
		{"sshd serves only ecdsa, fallback present", func(t *testing.T, d string) (string, string) {
			write(t, filepath.Join(d, "ec.pub"), ecLine)
			write(t, filepath.Join(d, "fallback.pub"), edLine)
			return stubSSHD(t, d, "hostkey "+filepath.Join(d, "ec")+"\n", false), filepath.Join(d, "fallback.pub")
		}, false},
		{"sshd hostkey without pub file", func(t *testing.T, d string) (string, string) {
			return stubSSHD(t, d, "hostkey "+filepath.Join(d, "ed")+"\n", false), filepath.Join(d, "missing.pub")
		}, false},
		{"pub file named ed25519 but other type", func(t *testing.T, d string) (string, string) {
			write(t, filepath.Join(d, "ssh_host_ed25519_key.pub"), ecLine)
			return stubSSHD(t, d, "hostkey "+filepath.Join(d, "ssh_host_ed25519_key")+"\n", false), filepath.Join(d, "missing.pub")
		}, false},
		{"no sshd, fallback ed25519", func(t *testing.T, d string) (string, string) {
			write(t, filepath.Join(d, "fallback.pub"), edLine)
			return filepath.Join(d, "nosshd"), filepath.Join(d, "fallback.pub")
		}, true},
		{"sshd -T fails, fallback ed25519", func(t *testing.T, d string) (string, string) {
			write(t, filepath.Join(d, "fallback.pub"), edLine)
			return stubSSHD(t, d, "", true), filepath.Join(d, "fallback.pub")
		}, true},
		{"no sshd, fallback ecdsa", func(t *testing.T, d string) (string, string) {
			write(t, filepath.Join(d, "fallback.pub"), ecLine)
			return filepath.Join(d, "nosshd"), filepath.Join(d, "fallback.pub")
		}, false},
		{"no sshd, no fallback", func(t *testing.T, d string) (string, string) {
			return filepath.Join(d, "nosshd"), filepath.Join(d, "missing.pub")
		}, false},
		{"no sshd, fallback garbage", func(t *testing.T, d string) (string, string) {
			write(t, filepath.Join(d, "fallback.pub"), "ssh-ed25519 $(touch pwned) x\n")
			return filepath.Join(d, "nosshd"), filepath.Join(d, "fallback.pub")
		}, false},
	}
	for _, shell := range testShells {
		t.Run(shell, func(t *testing.T) {
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					d := t.TempDir()
					sshd, fallback := c.setup(t, d)
					script := "set -eu\n" + pairingFuncs(testSalt(), []string{"10.0.0.1"}) + "nos_pair_show \"$1\" \"$2\"\n"
					out, errOut, err := runShell(t, shell, script, "", sshd, fallback)
					if _, statErr := os.Stat(filepath.Join(d, "pwned")); statErr == nil {
						t.Fatal("key file content was executed")
					}
					if c.wantCode {
						if err != nil {
							t.Fatalf("exit %v, stderr %s", err, errOut)
						}
						if !strings.Contains(out, "    "+code.String()+"\n") {
							t.Fatalf("code %s missing in:\n%s", code, out)
						}
						return
					}
					if err == nil {
						t.Fatalf("exit 0 without ed25519 key; stdout %q", out)
					}
					if codeRe.MatchString(out + errOut) {
						t.Fatalf("a code was printed without ed25519 key:\n%s%s", out, errOut)
					}
					if !strings.Contains(errOut, "no ed25519 SSH host key") || !strings.Contains(errOut, "classic") {
						t.Fatalf("no clear message: %q", errOut)
					}
				})
			}
		})
	}
}

// TestOneStepAddressList: the address list shows the host's global
// addresses from `ip -o addr show scope global`, and works without ip.
func TestOneStepAddressList(t *testing.T) {
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk not installed")
	}
	for _, shell := range testShells {
		t.Run(shell, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.Symlink(awk, filepath.Join(bin, "awk")); err != nil {
				t.Fatal(err)
			}
			script := "set -eu\n" + pairingFuncs(testSalt(), []string{"192.168.0.10", "10.8.0.0/24"}) + "nos_pair_addrs\n"
			out, errOut, err := runShell(t, shell, script, bin)
			if err != nil || !strings.Contains(out, "(ip not found)") {
				t.Fatalf("without ip: %q %v %s", out, err, errOut)
			}
			ip := "#!/bin/sh\n[ \"$*\" = '-o addr show scope global' ] || exit 2\n" +
				"echo '2: eth0    inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0\\       valid_lft forever preferred_lft forever'\n" +
				"echo '2: eth0    inet6 2001:db8::5/64 scope global \\       valid_lft forever preferred_lft forever'\n"
			if err := os.WriteFile(filepath.Join(bin, "ip"), []byte(ip), 0o700); err != nil {
				t.Fatal(err)
			}
			out, errOut, err = runShell(t, shell, script, bin+":/usr/bin:/bin")
			if err != nil {
				t.Fatalf("with ip: %v %s", err, errOut)
			}
			for _, want := range []string{"eth0  192.0.2.5\n", "eth0  2001:db8::5\n", "Nebula connects from: 192.168.0.10 10.8.0.0/24\n"} {
				if !strings.Contains(out, want) {
					t.Errorf("%q missing:\n%s", want, out)
				}
			}
		})
	}
}

// TestOneStepCheck64: the 64-bit arithmetic check passes in dash and bash
// and the full one-step script runs it before anything else.
func TestOneStepCheck64(t *testing.T) {
	for _, shell := range testShells {
		t.Run(shell, func(t *testing.T) {
			out, errOut, err := runShell(t, shell, check64+"echo OK\n", "")
			if err != nil || out != "OK\n" {
				t.Fatalf("%q %v %s", out, err, errOut)
			}
		})
	}
	s, err := RenderOneStep(validOneStep(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(s), "#!/bin/sh\n# Nebula Operation Station: enroll this host (spec 08).\n# Review, then run as root on the host. Key: ") {
		t.Fatalf("header changed:\n%s", s)
	}
	i := strings.Index(string(s), "set -eu\n")
	if i < 0 || !strings.HasPrefix(string(s)[i+len("set -eu\n"):], "\n"+check64) {
		t.Fatalf("64-bit check does not follow set -eu:\n%s", s)
	}
}

// TestOneStepExtendsClassic: the one-step script is the classic script for
// the same options plus the check at the start and the pairing part at the
// end.
func TestOneStepExtendsClassic(t *testing.T) {
	o := validOneStep(t)
	classic, err := Render(o.Options)
	if err != nil {
		t.Fatal(err)
	}
	s, err := RenderOneStep(o)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Replace(string(s), "\n"+check64, "", 1)
	tail := pairingFuncs(o.Salt, o.From) + pairingMain
	if !strings.HasSuffix(got, "\n"+tail) {
		t.Fatalf("pairing part missing at the end:\n%s", s)
	}
	if strings.TrimSuffix(got, "\n"+tail) != string(classic) {
		t.Fatalf("classic part differs:\n%s", s)
	}
}

// TestOneStepNoWideArithmetic: the script never forms a 120-bit number,
// never uses basenc, and reads only 15-digit hex halves with $((0x…)).
func TestOneStepNoWideArithmetic(t *testing.T) {
	s, err := RenderOneStep(validOneStep(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(s), "basenc") {
		t.Fatal("script uses basenc")
	}
	if strings.Contains(string(s), "0x$pair_hex") {
		t.Fatal("script reads the 120-bit value as one number")
	}
	for _, want := range []string{
		"cut -c1-30", "cut -c1-15)", "cut -c16-30)",
		"pair_hi=$((0x$pair_h))", "pair_lo=$((0x$pair_h))",
		"pair_c=$(( ((pair_hi % 37) * 10 + pair_lo % 37) % 37 ))",
		"tr 0123456789ABCDEFGHIJKLMNOPQRSTUV 0123456789ABCDEFGHJKMNPQRSTVWXYZ",
		"'0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U'",
	} {
		if !strings.Contains(string(s), want) {
			t.Errorf("%q missing", want)
		}
	}
}

// oneStepVariants are the option sets the syntax checks run on.
func oneStepVariants(t *testing.T) map[string]OneStepOptions {
	m := map[string]OneStepOptions{}
	for _, tc := range goldenCases(t) {
		for _, sudo := range []bool{true, false} {
			o := tc.o
			o.Sudo = sudo
			m[fmt.Sprintf("%s-sudo%v", tc.name, sudo)] = OneStepOptions{Options: o, Salt: testSalt()}
		}
	}
	allFF := make([]byte, pairing.SaltSize)
	for i := range allFF {
		allFF[i] = 0xff
	}
	o := validOneStep(t)
	o.Salt = allFF
	m["salt-ff"] = o
	for _, sudo := range []bool{true, false} {
		for name, nb := range map[string]NetBirdOptions{
			"netbird-mixed": validNetBird(),
			"netbird-env":   {ManagementURL: "https://[fd00::1]:33073/api", SetupKey: testSetupKey, Clients: []NetBirdClient{{Version: "0.31.0", KeyPassing: KeyPassingEnv}}},
			"netbird-file":  {ManagementURL: "https://10.0.0.1", SetupKey: testSetupKey, Clients: []NetBirdClient{{Version: "0.30.2", KeyPassing: KeyPassingFile}, {Version: "0.30.3", KeyPassing: KeyPassingFile}}},
			"netbird-show":  {ManagementURL: "https://nb.lan", SetupKey: SetupKeyPlaceholder, Clients: []NetBirdClient{{Version: "0.30.2", KeyPassing: KeyPassingFile}}},
		} {
			o := validOneStep(t)
			o.Sudo = sudo
			o.NetBird = &nb
			m[fmt.Sprintf("%s-sudo%v", name, sudo)] = o
		}
	}
	return m
}

// TestOneStepScriptsCheck: every one-step variant passes bash -n, dash -n
// and shellcheck (each skipped when not installed).
func TestOneStepScriptsCheck(t *testing.T) {
	dir := t.TempDir()
	var files []string
	for name, o := range oneStepVariants(t) {
		s, err := RenderOneStep(o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p := filepath.Join(dir, name+".sh")
		if err := os.WriteFile(p, s, 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	checks := []struct {
		bin  string
		args []string
	}{
		{"bash", []string{"-n"}},
		{"dash", []string{"-n"}},
		{"shellcheck", []string{"-s", "sh", "-S", "style"}},
	}
	for _, c := range checks {
		t.Run(c.bin, func(t *testing.T) {
			bin, err := exec.LookPath(c.bin)
			if err != nil {
				t.Skipf("%s not installed", c.bin)
			}
			for _, f := range files {
				out, err := exec.Command(bin, append(append([]string(nil), c.args...), f)...).CombinedOutput()
				if err != nil {
					t.Errorf("%s %s: %v\n%s", c.bin, filepath.Base(f), err, out)
				}
			}
		})
	}
}

// TestOneStepSizeLimit: the one-step script obeys MaxScriptBytes.
func TestOneStepSizeLimit(t *testing.T) {
	o := validOneStep(t)
	o.From = nil
	n := 0
	for {
		o.From = append(o.From, fmt.Sprintf("2001:db8:%x::/64", n))
		n++
		if len(renderOneStep(o)) > MaxScriptBytes {
			break
		}
	}
	s, err := RenderOneStep(o)
	if !errors.Is(err, ErrTooLarge) || s != nil {
		t.Fatalf("over the limit: %d bytes, %v", len(s), err)
	}
	o.From = o.From[:len(o.From)-1]
	s, err = RenderOneStep(o)
	if err != nil || len(s) > MaxScriptBytes {
		t.Fatalf("under the limit: %d bytes, %v", len(s), err)
	}
}

// TestOneStepRejectsUnsafeInput: user names, addresses and salts that fail
// validation never reach a one-step script.
func TestOneStepRejectsUnsafeInput(t *testing.T) {
	valid := validOneStep(t)
	if _, err := RenderOneStep(valid); err != nil {
		t.Fatalf("valid options refused: %v", err)
	}
	cases := map[string]func(o *OneStepOptions){
		"user root":         func(o *OneStepOptions) { o.User = "root" },
		"user quote":        func(o *OneStepOptions) { o.User = "a'b" },
		"user dollar":       func(o *OneStepOptions) { o.User = "a$(id)" },
		"user backtick":     func(o *OneStepOptions) { o.User = "a`id`" },
		"user newline":      func(o *OneStepOptions) { o.User = "a\nid" },
		"user semicolon":    func(o *OneStepOptions) { o.User = "a;id" },
		"user space":        func(o *OneStepOptions) { o.User = "a b" },
		"ref quote":         func(o *OneStepOptions) { o.KeyRef = "a'b" },
		"from none":         func(o *OneStepOptions) { o.From = nil },
		"from host name":    func(o *OneStepOptions) { o.From = []string{"nebula.lan"} },
		"from quote":        func(o *OneStepOptions) { o.From = []string{"10.0.0.1'"} },
		"from double quote": func(o *OneStepOptions) { o.From = []string{`10.0.0.1"`} },
		"from command":      func(o *OneStepOptions) { o.From = []string{"$(id)"} },
		"from backtick":     func(o *OneStepOptions) { o.From = []string{"`id`"} },
		"from space":        func(o *OneStepOptions) { o.From = []string{"10.0.0.1 10.0.0.2"} },
		"from newline":      func(o *OneStepOptions) { o.From = []string{"10.0.0.1\nid"} },
		"from semicolon":    func(o *OneStepOptions) { o.From = []string{"10.0.0.0/24;id"} },
		"from zone":         func(o *OneStepOptions) { o.From = []string{"fe80::1%eth0"} },
		"from wildcard":     func(o *OneStepOptions) { o.From = []string{"*"} },
		"no key":            func(o *OneStepOptions) { o.Key = nil },
		"salt nil":          func(o *OneStepOptions) { o.Salt = nil },
		"salt short":        func(o *OneStepOptions) { o.Salt = make([]byte, pairing.SaltSize-1) },
		"salt long":         func(o *OneStepOptions) { o.Salt = make([]byte, pairing.SaltSize+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := valid
			o.From = append([]string(nil), valid.From...)
			mutate(&o)
			s, err := RenderOneStep(o)
			if !errors.Is(err, ErrInvalidOptions) || s != nil {
				t.Fatalf("RenderOneStep = %q, %v; want ErrInvalidOptions", s, err)
			}
		})
	}
}

// TestOneStepSaltIsEmbedded: the salt reaches the script only as its
// base64 encoding inside one single-quoted literal, and the pairing part
// uses exactly that salt (the code changes with it).
func TestOneStepSaltIsEmbedded(t *testing.T) {
	o := validOneStep(t)
	s, err := RenderOneStep(o)
	if err != nil {
		t.Fatal(err)
	}
	want := "pair_salt='" + base64.StdEncoding.EncodeToString(o.Salt) + "'\n"
	if strings.Count(string(s), "pair_salt='") != 1 || !strings.Contains(string(s), want) {
		t.Fatalf("salt line %q missing or repeated", want)
	}
}
