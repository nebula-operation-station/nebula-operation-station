// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollscript

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// testSetupKey is a syntactically valid, made-up setup key.
const testSetupKey = "0A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D"

func validNetBird() NetBirdOptions {
	return NetBirdOptions{
		ManagementURL: "https://netbird.example.lan:33073",
		SetupKey:      testSetupKey,
		Clients: []NetBirdClient{
			{Version: "0.30.2", KeyPassing: KeyPassingFile},
			{Version: "0.31.0", KeyPassing: KeyPassingEnv},
		},
	}
}

// stubNetBird is a NetBird client stand-in. It logs its argv, umask, how
// the key arrived (only "match"/"mismatch", never the key) and the modes of
// the key file and its directory to $NB_STUB_LOG; `up` then succeeds,
// fails or hangs (after writing "started" to fd 3) per $NB_STUB_UP.
const stubNetBird = `#!/bin/sh
log=$NB_STUB_LOG
case $1 in
  version) printf '%s\n' "$NB_STUB_VERSION"; exit 0 ;;
  status) printf 'Daemon status: Connected\nNetBird IP: 100.64.0.7/16\n'; exit 0 ;;
  up) ;;
  *) exit 2 ;;
esac
printf 'argv:' >> "$log"
for a in "$@"; do printf ' [%s]' "$a" >> "$log"; done
printf '\n' >> "$log"
printf 'umask: %s\n' "$(umask)" >> "$log"
if [ "${NB_SETUP_KEY+set}" = set ]; then
  if [ "$NB_SETUP_KEY" = "$NB_STUB_EXPECT" ]; then echo "env: match" >> "$log"; else echo "env: mismatch" >> "$log"; fi
fi
f='' prev=''
for a in "$@"; do
  [ "$prev" = --setup-key-file ] && f=$a
  prev=$a
done
if [ -n "$f" ]; then
  echo "keyfile: $f" >> "$log"
  echo "keyfile mode: $(stat -c %a "$f")" >> "$log"
  echo "keydir mode: $(stat -c %a "$(dirname "$f")")" >> "$log"
  if [ "$(cat "$f")" = "$NB_STUB_EXPECT" ]; then echo "keyfile: match" >> "$log"; else echo "keyfile: mismatch" >> "$log"; fi
fi
case $NB_STUB_UP in
  ok) exit 0 ;;
  hang) echo started >&3; exec sleep 30 ;;
  *) exit 1 ;;
esac
`

// nbRun describes one run of the NetBird part of the script.
type nbRun struct {
	opts      NetBirdOptions
	version   string // printed by `netbird version`
	up        string // ok, fail or hang
	noClient  bool   // no netbird in PATH
	shm, xdg  bool   // whether the /dev/shm stand-in and $XDG_RUNTIME_DIR exist
	mid, tail string // script text between early part and join, and after the join
	term      bool   // send TERM once the client has started
}

// nbResult is what a run left behind.
type nbResult struct {
	root, script     string
	shm, xdg, tmp    string
	log, out, stderr string
	code             int
}

// runNetBirdPart runs the early NetBird part, r.mid, the join and r.tail
// with shell in a fresh directory tree, with the /dev/shm candidate
// replaced by a directory of that tree.
func runNetBirdPart(t *testing.T, shell string, r nbRun) nbResult {
	t.Helper()
	bin, err := exec.LookPath(shell)
	if err != nil {
		t.Skipf("%s not installed", shell)
	}
	root := t.TempDir()
	res := nbResult{
		root: root,
		shm:  filepath.Join(root, "shm"),
		xdg:  filepath.Join(root, "xdg"),
		tmp:  filepath.Join(root, "tmp"),
	}
	stubs := filepath.Join(root, "bin")
	work := filepath.Join(root, "work")
	for _, d := range []string{stubs, work, res.tmp} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if r.shm {
		if err := os.Mkdir(res.shm, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if r.xdg {
		if err := os.Mkdir(res.xdg, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if !r.noClient {
		if err := os.WriteFile(filepath.Join(stubs, "netbird"), []byte(stubNetBird), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	join := netbirdJoin
	if strings.Count(join, tmpRootShm) != 1 {
		t.Fatalf("join must name %s exactly once", tmpRootShm)
	}
	join = strings.Replace(join, tmpRootShm, res.shm, 1)
	script := "#!/bin/sh\nset -eu\n" + netbirdEarly(r.opts) + r.mid + join + r.tail
	res.script = filepath.Join(work, "nos-enroll.sh")
	if err := os.WriteFile(res.script, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "stub.log")
	env := []string{
		"PATH=" + stubs + ":/usr/bin:/bin", "LC_ALL=C", "HOME=" + work, "TMPDIR=" + res.tmp,
		"NB_STUB_LOG=" + logPath, "NB_STUB_VERSION=" + r.version, "NB_STUB_UP=" + r.up,
		"NB_STUB_EXPECT=" + r.opts.SetupKey,
	}
	if r.xdg {
		env = append(env, "XDG_RUNTIME_DIR="+res.xdg)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	cmd := exec.Command(bin, "nos-enroll.sh")
	cmd.Dir = work
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{pw}
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if r.term {
		started := make(chan bool, 1)
		go func() {
			line, _ := bufio.NewReader(pr).ReadString('\n')
			started <- line == "started\n"
		}()
		select {
		case ok := <-started:
			if !ok {
				t.Fatal("stub client did not start")
			}
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("stub client did not start in time")
		}
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err = <-done:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("%s timed out; stderr %s", shell, stderr.String())
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("the NetBird client outlived the script (output pipe still open)")
	}
	res.code = cmd.ProcessState.ExitCode()
	res.out, res.stderr = stdout.String(), stderr.String()
	if b, err := os.ReadFile(logPath); err == nil {
		res.log = string(b)
	}
	return res
}

// assertNoResidue: no temporary directory is left in any candidate root
// and the setup key is in no file under the run's tree (stub log included).
func assertNoResidue(t *testing.T, res nbResult, key string) {
	t.Helper()
	for _, d := range []string{res.shm, res.xdg, res.tmp} {
		ents, err := os.ReadDir(d)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		for _, e := range ents {
			t.Errorf("left behind: %s", filepath.Join(d, e.Name()))
		}
	}
	err := filepath.WalkDir(res.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(key)) {
			t.Errorf("setup key remains in %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func scriptGone(t *testing.T, res nbResult) bool {
	t.Helper()
	_, err := os.Stat(res.script)
	return errors.Is(err, fs.ErrNotExist)
}

// TestNetBirdJoinKeyFile: in file mode the key reaches the client only in a
// 0600 file in a 0700 directory under the first available root (/dev/shm,
// then $XDG_RUNTIME_DIR, then $TMPDIR), never in argv, under umask 077; the
// directory and the script are gone afterwards.
func TestNetBirdJoinKeyFile(t *testing.T) {
	cases := []struct {
		name     string
		shm, xdg bool
		want     func(nbResult) string
	}{
		{"shm", true, true, func(r nbResult) string { return r.shm }},
		{"xdg", false, true, func(r nbResult) string { return r.xdg }},
		{"fallback", false, false, func(r nbResult) string { return r.tmp }},
	}
	for _, shell := range testShells {
		for _, c := range cases {
			t.Run(shell+"/"+c.name, func(t *testing.T) {
				res := runNetBirdPart(t, shell, nbRun{opts: validNetBird(), version: "0.30.2", up: "ok", shm: c.shm, xdg: c.xdg})
				if res.code != 0 {
					t.Fatalf("exit %d, stderr %s", res.code, res.stderr)
				}
				for _, want := range []string{
					"keyfile: " + c.want(res) + "/nos-netbird.",
					"keyfile mode: 600\n", "keydir mode: 700\n", "keyfile: match\n", "umask: 0077\n",
					"argv: [up] [--management-url] [https://netbird.example.lan:33073] [--setup-key-file] [" + c.want(res) + "/nos-netbird.",
				} {
					if !strings.Contains(res.log, want) {
						t.Errorf("stub log lacks %q:\n%s", want, res.log)
					}
				}
				if strings.Contains(res.log, "env:") {
					t.Errorf("key also passed by environment:\n%s", res.log)
				}
				if !strings.Contains(res.out, "NetBird address: 100.64.0.7\n") {
					t.Errorf("no NetBird address in output: %s", res.out)
				}
				if !scriptGone(t, res) {
					t.Error("script with setup key not deleted")
				}
				assertNoResidue(t, res, testSetupKey)
			})
		}
	}
}

// TestNetBirdJoinKeyEnv: in env mode the key reaches the client only in
// NB_SETUP_KEY, no key file is written and argv has no key.
func TestNetBirdJoinKeyEnv(t *testing.T) {
	for _, shell := range testShells {
		t.Run(shell, func(t *testing.T) {
			res := runNetBirdPart(t, shell, nbRun{opts: validNetBird(), version: "0.31.0", up: "ok", shm: true})
			if res.code != 0 {
				t.Fatalf("exit %d, stderr %s", res.code, res.stderr)
			}
			if !strings.Contains(res.log, "env: match\n") || strings.Contains(res.log, "keyfile") {
				t.Errorf("key not passed by environment only:\n%s", res.log)
			}
			if !strings.Contains(res.log, "argv: [up] [--management-url] [https://netbird.example.lan:33073]\n") {
				t.Errorf("unexpected argv:\n%s", res.log)
			}
			if !scriptGone(t, res) {
				t.Error("script with setup key not deleted")
			}
			assertNoResidue(t, res, testSetupKey)
		})
	}
}

// TestNetBirdCleanupOnFailure: when the client fails, hangs and gets TERM,
// a step after the join fails, or an earlier step fails, the script exits
// non-zero and leaves neither its temporary directory, the key file, the
// key in any file, nor itself.
func TestNetBirdCleanupOnFailure(t *testing.T) {
	cases := []struct {
		name     string
		r        nbRun
		wantCode int
		upCalled bool
	}{
		{"client fails", nbRun{version: "0.30.2", up: "fail"}, 1, true},
		{"client fails env", nbRun{version: "0.31.0", up: "fail"}, 1, true},
		{"client hangs TERM", nbRun{version: "0.30.2", up: "hang", term: true}, 143, true},
		{"client hangs TERM env", nbRun{version: "0.31.0", up: "hang", term: true}, 143, true},
		{"step after join fails", nbRun{version: "0.30.2", up: "ok", tail: "false\n"}, 1, true},
		{"step before join fails", nbRun{version: "0.30.2", up: "ok", mid: "false\n"}, 1, false},
		{"unsupported client version", nbRun{version: "0.29.9", up: "ok"}, 1, false},
		{"client version with suffix", nbRun{version: "0.30.2-dev", up: "ok"}, 1, false},
		{"no client", nbRun{version: "0.30.2", up: "ok", noClient: true}, 1, false},
	}
	for _, shell := range testShells {
		for _, c := range cases {
			t.Run(shell+"/"+c.name, func(t *testing.T) {
				r := c.r
				r.opts = validNetBird()
				r.shm = true
				res := runNetBirdPart(t, shell, r)
				if res.code != c.wantCode {
					t.Fatalf("exit %d, want %d; stderr %s", res.code, c.wantCode, res.stderr)
				}
				if got := strings.Contains(res.log, "argv: [up]"); got != c.upCalled {
					t.Errorf("netbird up called = %v, want %v:\n%s", got, c.upCalled, res.log)
				}
				if !scriptGone(t, res) {
					t.Error("script with setup key not deleted")
				}
				assertNoResidue(t, res, testSetupKey)
			})
		}
	}
}

// TestNetBirdPlaceholderRefusesJoin: the "Show script" render stops before
// any change, never calls the client and does not delete itself (it holds
// no key).
func TestNetBirdPlaceholderRefusesJoin(t *testing.T) {
	for _, shell := range testShells {
		t.Run(shell, func(t *testing.T) {
			o := validNetBird()
			o.SetupKey = SetupKeyPlaceholder
			res := runNetBirdPart(t, shell, nbRun{opts: o, version: "0.30.2", up: "ok", shm: true})
			if res.code != 1 || !strings.Contains(res.stderr, "review copy") {
				t.Fatalf("exit %d, stderr %s", res.code, res.stderr)
			}
			if res.log != "" {
				t.Errorf("client called:\n%s", res.log)
			}
			if scriptGone(t, res) {
				t.Error("review copy deleted itself")
			}
		})
	}
}

// TestNetBirdPlaceholderOnlyDiffers: the review render differs from the
// download in the setup-key line only.
func TestNetBirdPlaceholderOnlyDiffers(t *testing.T) {
	o := validOneStep(t)
	nb := validNetBird()
	o.NetBird = &nb
	real, err := RenderOneStep(o)
	if err != nil {
		t.Fatal(err)
	}
	nb2 := nb
	nb2.SetupKey = SetupKeyPlaceholder
	o.NetBird = &nb2
	show, err := RenderOneStep(o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(real), testSetupKey) != 1 {
		t.Fatal("setup key must appear exactly once")
	}
	want := strings.Replace(string(real), "nb_key='"+testSetupKey+"'", "nb_key='"+SetupKeyPlaceholder+"'", 1)
	if string(show) != want {
		t.Fatal("review render differs from the download in more than the key line")
	}
}

// TestNetBirdScriptOrder: the NetBird preflight comes before the first
// change to the host and the join before the pairing code; without NetBird
// none of it is in the script.
func TestNetBirdScriptOrder(t *testing.T) {
	o := validOneStep(t)
	plain, err := RenderOneStep(o)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("nb_key")) || bytes.Contains(plain, []byte("netbird")) {
		t.Fatal("NetBird text in a script without NetBird")
	}
	nb := validNetBird()
	o.NetBird = &nb
	b, err := RenderOneStep(o)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	order := []string{"set -eu\n", "umask 077\n", "trap nos_nb_cleanup EXIT\n", "nb_mode=''", "groupadd", "# NetBird join", "nos_pair_addrs\n"}
	last := -1
	for _, m := range order {
		i := strings.Index(s, m)
		if i <= last {
			t.Fatalf("%q at %d, not after %d", m, i, last)
		}
		last = i
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "$nb_key") && !strings.Contains(line, "NB_SETUP_KEY=$nb_key ") &&
			!strings.Contains(line, `printf '%s\n' "$nb_key" > "$nb_dir/setup-key"`) &&
			!strings.HasPrefix(strings.TrimSpace(line), `if [ "$nb_key"`) {
			t.Errorf("setup key used outside env/key file/comparison: %q", line)
		}
	}
}

// TestNetBirdRejectsUnsafeInput: management URLs, setup keys and client
// tables that fail the spec 03 formats never reach a script, and the setup
// key never appears in the error.
func TestNetBirdRejectsUnsafeInput(t *testing.T) {
	cases := map[string]func(n *NetBirdOptions){
		"url http":           func(n *NetBirdOptions) { n.ManagementURL = "http://netbird.example.lan" },
		"url empty":          func(n *NetBirdOptions) { n.ManagementURL = "" },
		"url quote":          func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/'x" },
		"url double quote":   func(n *NetBirdOptions) { n.ManagementURL = `https://a.lan/"x` },
		"url dollar":         func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/$(id)" },
		"url backtick":       func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/`id`" },
		"url backslash":      func(n *NetBirdOptions) { n.ManagementURL = `https://a.lan/\x` },
		"url space":          func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/ x" },
		"url newline":        func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/\nid" },
		"url semicolon":      func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/;id" },
		"url userinfo":       func(n *NetBirdOptions) { n.ManagementURL = "https://u:p@a.lan" },
		"url query":          func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/?x=1" },
		"url fragment":       func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/#x" },
		"url percent":        func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan/%41" },
		"url port 0":         func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan:0" },
		"url port big":       func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan:65536" },
		"url port lead zero": func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan:0443" },
		"url port empty":     func(n *NetBirdOptions) { n.ManagementURL = "https://a.lan:" },
		"url zone":           func(n *NetBirdOptions) { n.ManagementURL = "https://[fe80::1%25eth0]" },
		"url v6 unbracketed": func(n *NetBirdOptions) { n.ManagementURL = "https://fe80::1" },
		"url v4 bracketed":   func(n *NetBirdOptions) { n.ManagementURL = "https://[10.0.0.1]" },
		"url bad label":      func(n *NetBirdOptions) { n.ManagementURL = "https://-a.lan" },
		"url empty label":    func(n *NetBirdOptions) { n.ManagementURL = "https://a..lan" },
		"url underscore":     func(n *NetBirdOptions) { n.ManagementURL = "https://a_b.lan" },
		"url too long": func(n *NetBirdOptions) {
			n.ManagementURL = "https://a.lan/" + strings.Repeat("x", NetBirdMgmtURLMaxLen)
		},
		"url non-ascii":       func(n *NetBirdOptions) { n.ManagementURL = "https://bücher.lan" },
		"url upper scheme":    func(n *NetBirdOptions) { n.ManagementURL = "HTTPS://a.lan" },
		"key lowercase":       func(n *NetBirdOptions) { n.SetupKey = strings.ToLower(testSetupKey) },
		"key quote":           func(n *NetBirdOptions) { n.SetupKey = "0A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5'" },
		"key newline":         func(n *NetBirdOptions) { n.SetupKey = testSetupKey + "\n" },
		"key space":           func(n *NetBirdOptions) { n.SetupKey = " " + testSetupKey },
		"key empty":           func(n *NetBirdOptions) { n.SetupKey = "" },
		"key no dashes":       func(n *NetBirdOptions) { n.SetupKey = strings.ReplaceAll(testSetupKey, "-", "") },
		"key command":         func(n *NetBirdOptions) { n.SetupKey = "$(id)" },
		"no clients":          func(n *NetBirdOptions) { n.Clients = nil },
		"too many clients":    func(n *NetBirdOptions) { n.Clients = make([]NetBirdClient, NetBirdClientVersionsMax+1) },
		"version v prefix":    func(n *NetBirdOptions) { n.Clients[0].Version = "v0.30.2" },
		"version quote":       func(n *NetBirdOptions) { n.Clients[0].Version = "0.30.2'" },
		"version glob":        func(n *NetBirdOptions) { n.Clients[0].Version = "*" },
		"version suffix":      func(n *NetBirdOptions) { n.Clients[0].Version = "0.30.2-rc1" },
		"version long part":   func(n *NetBirdOptions) { n.Clients[0].Version = "0.300000.2" },
		"version two parts":   func(n *NetBirdOptions) { n.Clients[0].Version = "0.30" },
		"version duplicate":   func(n *NetBirdOptions) { n.Clients[1].Version = n.Clients[0].Version },
		"mode zero":           func(n *NetBirdOptions) { n.Clients[0].KeyPassing = 0 },
		"mode unknown":        func(n *NetBirdOptions) { n.Clients[0].KeyPassing = 3 },
		"version pipe inject": func(n *NetBirdOptions) { n.Clients[0].Version = "0.30.2|*" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := validOneStep(t)
			nb := validNetBird()
			nb.Clients = append([]NetBirdClient(nil), nb.Clients...)
			mutate(&nb)
			o.NetBird = &nb
			s, err := RenderOneStep(o)
			if !errors.Is(err, ErrInvalidOptions) || s != nil {
				t.Fatalf("RenderOneStep = %q, %v; want ErrInvalidOptions", s, err)
			}
			if nb.SetupKey != "" && strings.Contains(err.Error(), nb.SetupKey) {
				t.Fatalf("error contains the setup key: %v", err)
			}
		})
	}
}

// TestNetBirdAcceptsValidURLs: the accepted management URL forms.
func TestNetBirdAcceptsValidURLs(t *testing.T) {
	for _, u := range []string{
		"https://netbird.example.lan",
		"https://api.netbird.io:443",
		"https://10.0.0.1:33073",
		"https://[fd00::1]:33073",
		"https://netbird.example.lan/api/v1",
		"https://nb.lan/a-b_c.d~e/",
	} {
		if !ValidManagementURL(u) {
			t.Errorf("%s refused", u)
		}
	}
}
