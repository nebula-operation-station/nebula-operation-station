// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollscript

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testOfferID = "Q2hlY2tPZmZlcklELW5vdC1pbi1hcmd2LXRlc3Q"

func validCommand() CommandOptions {
	return CommandOptions{
		Origin:       "https://nos.example.lan",
		OfferID:      testOfferID,
		ScriptSHA256: strings.Repeat("ab", 32),
		Downloader:   DownloaderCurl,
	}
}

// commandVariants are the four shapes of the UI command.
func commandVariants() map[string]CommandOptions {
	m := map[string]CommandOptions{}
	for _, d := range []Downloader{DownloaderCurl, DownloaderWget} {
		for _, root := range []bool{false, true} {
			c := validCommand()
			c.Downloader, c.Root = d, root
			name := "curl"
			if d == DownloaderWget {
				name = "wget"
			}
			if root {
				name += "-root"
			} else {
				name += "-sudo"
			}
			m[name] = c
		}
	}
	return m
}

// Stub download clients and sudo. Each logs its argv to $STUB_LOG and
// whatever it reads on standard input to $STUB_STDIN; curl and wget then
// copy $STUB_PAYLOAD to the output file (or fail when $STUB_FAIL=1).
const (
	stubCurl = `#!/bin/sh
printf 'curl argv:' >> "$STUB_LOG"; for a in "$@"; do printf ' [%s]' "$a" >> "$STUB_LOG"; done; printf '\n' >> "$STUB_LOG"
cfg=$(cat)
printf '%s\n' "$cfg" >> "$STUB_STDIN"
[ "$STUB_FAIL" = 1 ] && exit 22
out=$(printf '%s\n' "$cfg" | sed -n 's/^output = "\(.*\)"$/\1/p')
cp "$STUB_PAYLOAD" "$out"
`
	stubWget = `#!/bin/sh
printf 'wget argv:' >> "$STUB_LOG"; for a in "$@"; do printf ' [%s]' "$a" >> "$STUB_LOG"; done; printf '\n' >> "$STUB_LOG"
out='' prev=''
for a in "$@"; do [ "$prev" = -O ] && out=$a; prev=$a; done
cat >> "$STUB_STDIN"
: > "$out"
[ "$STUB_FAIL" = 1 ] && exit 8
cp "$STUB_PAYLOAD" "$out"
`
	stubSudo = `#!/bin/sh
printf 'sudo argv:' >> "$STUB_LOG"; for a in "$@"; do printf ' [%s]' "$a" >> "$STUB_LOG"; done; printf '\n' >> "$STUB_LOG"
exec "$@"
`
	// stubPayload stands in for the downloaded script.
	stubPayload = `echo "ran in $(pwd)" >> "$STUB_LOG"
echo "dir mode: $(stat -c %a .)" >> "$STUB_LOG"
echo "file mode: $(stat -c %a nos-enroll.sh)" >> "$STUB_LOG"
`
)

type cmdResult struct {
	shm, log, stdin, stderr string
	code                    int
}

// runCommand runs the rendered command c with shell -c and stub clients,
// the /dev/shm candidate replaced by a test directory. wrongHash replaces
// the hash with one that does not match the payload; fail makes the
// download client fail.
func runCommand(t *testing.T, shell string, c CommandOptions, wrongHash, fail bool) cmdResult {
	t.Helper()
	bin, err := exec.LookPath(shell)
	if err != nil {
		t.Skipf("%s not installed", shell)
	}
	root := t.TempDir()
	res := cmdResult{shm: filepath.Join(root, "shm")}
	stubs := filepath.Join(root, "bin")
	work := filepath.Join(root, "work")
	for _, d := range []string{stubs, work, res.shm, filepath.Join(root, "tmp")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"curl": stubCurl, "wget": stubWget, "sudo": stubSudo} {
		if err := os.WriteFile(filepath.Join(stubs, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	payload := filepath.Join(root, "payload.sh")
	if err := os.WriteFile(payload, []byte(stubPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(stubPayload))
	c.ScriptSHA256 = hex.EncodeToString(sum[:])
	if wrongHash {
		c.ScriptSHA256 = strings.Repeat("0", 64)
	}
	cmdText, err := RenderCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(cmdText, tmpRootShm) != 1 {
		t.Fatalf("command must name %s exactly once", tmpRootShm)
	}
	cmdText = strings.Replace(cmdText, tmpRootShm, res.shm, 1)
	logPath, stdinPath := filepath.Join(root, "argv.log"), filepath.Join(root, "stdin.log")
	failFlag := "0"
	if fail {
		failFlag = "1"
	}
	cmd := exec.Command(bin, "-c", cmdText)
	cmd.Dir = work
	cmd.Env = []string{
		"PATH=" + stubs + ":/usr/bin:/bin", "LC_ALL=C", "HOME=" + work, "TMPDIR=" + filepath.Join(root, "tmp"),
		"STUB_LOG=" + logPath, "STUB_STDIN=" + stdinPath, "STUB_PAYLOAD=" + payload, "STUB_FAIL=" + failFlag,
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("%s timed out", shell)
	}
	res.code = cmd.ProcessState.ExitCode()
	res.stderr = stderr.String()
	if b, err := os.ReadFile(logPath); err == nil {
		res.log = string(b)
	}
	if b, err := os.ReadFile(stdinPath); err == nil {
		res.stdin = string(b)
	}
	ents, err := os.ReadDir(res.shm)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Errorf("left behind: %s", e.Name())
	}
	for _, d := range []string{filepath.Join(root, "tmp"), work} {
		if ents, _ := os.ReadDir(d); len(ents) != 0 {
			t.Errorf("unexpected files in %s", d)
		}
	}
	return res
}

// TestCommandOfferIDOnlyOnStdin: with curl and wget, with sudo and as root,
// the command downloads into a 0700 directory with a 0600 file, runs the
// script after the hash check, removes the directory, and the offer ID is
// in no recorded argv but reaches the client on standard input.
func TestCommandOfferIDOnlyOnStdin(t *testing.T) {
	for _, shell := range testShells {
		for name, c := range commandVariants() {
			t.Run(shell+"/"+name, func(t *testing.T) {
				res := runCommand(t, shell, c, false, false)
				if res.code != 0 {
					t.Fatalf("exit %d, stderr %s, log %s", res.code, res.stderr, res.log)
				}
				for _, want := range []string{"ran in " + res.shm + "/nos-enroll.", "dir mode: 700\n", "file mode: 600\n"} {
					if !strings.Contains(res.log, want) {
						t.Errorf("log lacks %q:\n%s", want, res.log)
					}
				}
				client := "curl argv: [--proto] [=https] [--tlsv1.2] [-fsS] [-K] [-]\n"
				wantStdin := "url = \"https://nos.example.lan/enroll/" + testOfferID + "\"\noutput = \"nos-enroll.sh\"\n"
				if c.Downloader == DownloaderWget {
					client = "wget argv: [--https-only] [-i] [-] [-O] [nos-enroll.sh]\n"
					wantStdin = "https://nos.example.lan/enroll/" + testOfferID + "\n"
				}
				if !strings.Contains(res.log, client) {
					t.Errorf("client argv not as expected:\n%s", res.log)
				}
				if strings.Contains(res.log, testOfferID) {
					t.Errorf("offer ID in an argv:\n%s", res.log)
				}
				if res.stdin != wantStdin {
					t.Errorf("client stdin = %q, want %q", res.stdin, wantStdin)
				}
				hasSudo := strings.Contains(res.log, "sudo argv: [sh] [nos-enroll.sh]\n")
				if hasSudo == c.Root {
					t.Errorf("sudo used = %v for root variant %v:\n%s", hasSudo, c.Root, res.log)
				}
			})
		}
	}
}

// TestCommandWrongHashLeavesNothing: a hash mismatch or a failed download
// runs nothing, leaves no file and exits non-zero.
func TestCommandWrongHashLeavesNothing(t *testing.T) {
	for _, shell := range testShells {
		for name, c := range commandVariants() {
			for _, mode := range []string{"wrong hash", "download fails"} {
				t.Run(shell+"/"+name+"/"+mode, func(t *testing.T) {
					res := runCommand(t, shell, c, mode == "wrong hash", mode == "download fails")
					if res.code == 0 {
						t.Fatal("exit 0")
					}
					if strings.Contains(res.log, "ran in") || strings.Contains(res.log, "sudo argv") {
						t.Errorf("script ran:\n%s", res.log)
					}
				})
			}
		}
	}
}

// TestCommandShape: the offer ID occurs once, as the single-quoted argument
// of the printf builtin; there is no pipe into a shell and no -k.
func TestCommandShape(t *testing.T) {
	for name, c := range commandVariants() {
		s, err := RenderCommand(c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Count(s, testOfferID) != 1 || !strings.Contains(s, "printf '") || !strings.Contains(s, "\\\n    '"+testOfferID+"' |\n") {
			t.Errorf("%s: offer ID not only the printf argument:\n%s", name, s)
		}
		for _, bad := range []string{"| sh ", "| sh\n", "|sh ", "| bash", "| sudo", " -k", "--insecure", "--no-check-certificate", "http://"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
}

// TestCommandScriptsCheck: every command variant passes bash -n, dash -n
// and shellcheck (each skipped when not installed).
func TestCommandScriptsCheck(t *testing.T) {
	dir := t.TempDir()
	var files []string
	for name, c := range commandVariants() {
		s, err := RenderCommand(c)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name+".sh")
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+s), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	for _, c := range []struct {
		bin  string
		args []string
	}{
		{"bash", []string{"-n"}},
		{"dash", []string{"-n"}},
		{"shellcheck", []string{"-s", "sh", "-S", "style"}},
	} {
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

// TestCommandRejectsUnsafeInput: origins, offer IDs, hashes and clients
// that fail validation never reach a command, and the offer ID is never in
// the error.
func TestCommandRejectsUnsafeInput(t *testing.T) {
	if _, err := RenderCommand(validCommand()); err != nil {
		t.Fatalf("valid options refused: %v", err)
	}
	cases := map[string]func(c *CommandOptions){
		"origin http":         func(c *CommandOptions) { c.Origin = "http://nos.example.lan" },
		"origin path":         func(c *CommandOptions) { c.Origin = "https://nos.example.lan/x" },
		"origin slash":        func(c *CommandOptions) { c.Origin = "https://nos.example.lan/" },
		"origin quote":        func(c *CommandOptions) { c.Origin = "https://nos'.lan" },
		"origin double quote": func(c *CommandOptions) { c.Origin = `https://nos".lan` },
		"origin percent":      func(c *CommandOptions) { c.Origin = "https://nos.lan%s" },
		"origin backslash":    func(c *CommandOptions) { c.Origin = `https://nos.lan\n` },
		"origin newline":      func(c *CommandOptions) { c.Origin = "https://nos.lan\nid" },
		"origin command":      func(c *CommandOptions) { c.Origin = "https://$(id).lan" },
		"origin userinfo":     func(c *CommandOptions) { c.Origin = "https://u@nos.lan" },
		"origin query":        func(c *CommandOptions) { c.Origin = "https://nos.lan?x" },
		"origin empty":        func(c *CommandOptions) { c.Origin = "" },
		"id short":            func(c *CommandOptions) { c.OfferID = testOfferID[:OfferIDMinLen-1] },
		"id long":             func(c *CommandOptions) { c.OfferID = strings.Repeat("a", OfferIDMaxLen+1) },
		"id quote":            func(c *CommandOptions) { c.OfferID = testOfferID + "'" },
		"id percent":          func(c *CommandOptions) { c.OfferID = testOfferID + "%s" },
		"id double quote":     func(c *CommandOptions) { c.OfferID = testOfferID + `"` },
		"id newline":          func(c *CommandOptions) { c.OfferID = testOfferID + "\nid" },
		"id slash":            func(c *CommandOptions) { c.OfferID = testOfferID + "/x" },
		"id base64 plus":      func(c *CommandOptions) { c.OfferID = testOfferID + "+" },
		"id space":            func(c *CommandOptions) { c.OfferID = testOfferID + " x" },
		"hash upper":          func(c *CommandOptions) { c.ScriptSHA256 = strings.Repeat("AB", 32) },
		"hash short":          func(c *CommandOptions) { c.ScriptSHA256 = strings.Repeat("a", 63) },
		"hash quote":          func(c *CommandOptions) { c.ScriptSHA256 = strings.Repeat("a", 63) + "'" },
		"hash two files":      func(c *CommandOptions) { c.ScriptSHA256 = strings.Repeat("a", 64) + "  x\n" + strings.Repeat("a", 64) },
		"client none":         func(c *CommandOptions) { c.Downloader = 0 },
		"client unknown":      func(c *CommandOptions) { c.Downloader = 3 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validCommand()
			mutate(&c)
			s, err := RenderCommand(c)
			if !errors.Is(err, ErrInvalidOptions) || s != "" {
				t.Fatalf("RenderCommand = %q, %v; want ErrInvalidOptions", s, err)
			}
			if strings.Contains(err.Error(), testOfferID) {
				t.Fatalf("error contains the offer ID: %v", err)
			}
		})
	}
}

// TestCommandOriginForms: accepted origins render into the URL unchanged.
func TestCommandOriginForms(t *testing.T) {
	for _, o := range []string{"https://nos.example.lan", "https://nos.example.lan:8443", "https://10.0.0.5", "https://[fd00::5]:443"} {
		c := validCommand()
		c.Origin = o
		s, err := RenderCommand(c)
		if err != nil {
			t.Fatalf("%s: %v", o, err)
		}
		if !strings.Contains(s, fmt.Sprintf(`url = "%s/enroll/%%s"`, o)) {
			t.Errorf("%s not in command:\n%s", o, s)
		}
	}
}
