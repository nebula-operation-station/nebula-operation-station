// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// homePatterns are the roots summary entries of the home SSH files.
func homePatterns(base string) []string {
	var out []string
	for _, rel := range homeFiles {
		out = append(out, base+"/"+rel)
	}
	return out
}

// TestScriptUnlookedHomesAreUnreadableNotMissing: when the places a home
// pattern could match were not looked at (a symlinked or unlistable /home,
// only symlinked or newline-named homes, a symlinked /root or a symlinked
// .ssh directory), the pattern is "error" (unknown), never "missing", and
// the run is partial.
func TestScriptUnlookedHomesAreUnreadableNotMissing(t *testing.T) {
	removeHomes := func(t *testing.T, root string) {
		t.Helper()
		for _, h := range []string{"home/alice", "home/bob"} {
			if err := os.RemoveAll(filepath.Join(root, h)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, c := range []struct {
		name     string
		rootOnly bool // needs an unprivileged user
		setup    func(t *testing.T, root string)
		want     map[string]RootState
	}{
		{"symlinked /home", false, func(t *testing.T, root string) {
			moveAndLink(t, root, "home", "/elsewhere/home")
		}, statesFor(homePatterns("/home/*"), RootSkipped)},
		{"unlistable /home", true, func(t *testing.T, root string) {
			lock(t, filepath.Join(root, "home"))
		}, statesFor(homePatterns("/home/*"), RootSkipped)},
		{"only symlinked homes", false, func(t *testing.T, root string) {
			removeHomes(t, root)
			relLink(t, root, "/elsewhere", "/home/carol")
		}, statesFor(homePatterns("/home/*"), RootSkipped)},
		{"only a newline-named home", false, func(t *testing.T, root string) {
			removeHomes(t, root)
			p := filepath.Join(root, "home", "ev\nil", ".ssh")
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "authorized_keys"), []byte("k\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, statesFor(homePatterns("/home/*"), RootSkipped)},
		{"symlinked /root", false, func(t *testing.T, root string) {
			moveAndLink(t, root, "root", "/elsewhere/root")
		}, statesFor(homePatterns("/root"), RootSkipped)},
		{"symlinked /root/.ssh", false, func(t *testing.T, root string) {
			moveAndLink(t, root, "root/.ssh", "/elsewhere/root-ssh")
		}, map[string]RootState{
			"/root/.ssh/authorized_keys*": RootSkipped, "/root/.ssh/known_hosts": RootSkipped,
			"/root/.ssh/known_hosts2": RootSkipped, "/root/.shosts": RootAbsent, "/root/.k5login": RootAbsent,
		}},
		{"symlinked .ssh of the only home", false, func(t *testing.T, root string) {
			if err := os.RemoveAll(filepath.Join(root, "home/bob")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, "home/alice/.k5login")); err != nil {
				t.Fatal(err)
			}
			moveAndLink(t, root, "home/alice/.ssh", "/elsewhere/alice-ssh")
		}, map[string]RootState{
			"/home/*/.ssh/authorized_keys*": RootSkipped, "/home/*/.ssh/known_hosts": RootSkipped,
			"/home/*/.ssh/known_hosts2": RootSkipped, "/home/*/.k5login": RootAbsent,
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.rootOnly && os.Geteuid() == 0 {
				t.Skip("root lists a mode 000 directory; the case needs an unprivileged user")
			}
			root := buildTree(t, treeOpts{})
			c.setup(t, root)
			res := runAndParse(t, "/bin/sh", root, ModeFull)
			states := rootStates(res)
			for p, s := range c.want {
				if states[p] != s {
					t.Errorf("root %s: state %v, want %v", p, states[p], s)
				}
			}
			if res.Complete() || !slices.Contains(res.Partial, ReasonUnreadable) || res.Host.Unreadable == 0 {
				t.Errorf("partial %v, host %+v", res.Partial, res.Host)
			}
		})
	}
}

// TestScriptHomeHashBoundToInode: a home SSH hash comes with the
// device:inode:ctime it was read from and a cutoff second (the hash start
// less the timestamp granularity), and the record keeps it only if the
// meta pass saw the same file in the same state and its ctime and mtime
// lie before the cutoff. A file swapped (another inode) or changed in
// place (another ctime) between the passes, or one whose timestamps are
// too close to the hash start to prove the content unchanged (a write in
// the same timestamp tick keeps the ctime), has no hash and makes the run
// truncated, not unreadable; the old content's hash never stands for it.
func TestScriptHomeHashBoundToInode(t *testing.T) {
	const p = "/home/alice/.ssh/authorized_keys"
	h := strings.Repeat("a", 64)
	metaT := func(ino, mtime, ctime string) string {
		return "M1 f 1 600 1000 1000 " + ino + " " + mtime + " " + ctime + " 2049\x00" + p + "\x00\x00"
	}
	meta := func(ino, ctime string) string { return metaT(ino, "1700000000.5", ctime) }
	hash := func(hrec string) string { return hrec + "\x00" + h + "  " + p + "\x00" }
	head := "B1700000000\x00Rscanned /home/*/.ssh/authorized_keys*\x00"
	for _, c := range []struct {
		name   string
		stream string
		hashed bool
	}{
		{"same file", hash("H2049:7:1700000000.5 1700000001") + meta("7", "1700000000.5"), true},
		{"swapped between the passes", hash("H2049:7:1700000000.5 1700000001") + meta("8", "1700000000.5"), false},
		{"changed in place between the passes", hash("H2049:7:1700000000.5 1700000001") + meta("7", "1700000001.25"), false},
		{"other device", hash("H2050:7:1700000000.5 1700000001") + meta("7", "1700000000.5"), false},
		{"malformed id", hash("H2049:7:x 1700000001") + meta("7", "1700000000.5"), false},
		{"racy ctime", hash("H2049:7:1700000000.5 1700000000") + meta("7", "1700000000.5"), false},
		{"ctime after the cutoff", hash("H2049:7:1700000005 1700000001") + meta("7", "1700000005"), false},
		{"racy mtime", hash("H2049:7:1700000000.5 1700000001") + metaT("7", "1700000001", "1700000000.5"), false},
		{"mtime in the future", hash("H2049:7:1700000000.5 1700000001") + metaT("7", "1900000000", "1700000000.5"), false},
		{"no cutoff", hash("H2049:7:1700000000.5") + meta("7", "1700000000.5"), false},
		{"malformed cutoff", hash("H2049:7:1700000000.5 17x") + meta("7", "1700000000.5"), false},
		{"fractional cutoff", hash("H2049:7:1700000000.5 1700000001.5") + meta("7", "1700000000.5"), false},
		{"extra field", hash("H2049:7:1700000000.5 1700000001 1") + meta("7", "1700000000.5"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := runAwk(t, head+c.stream+"E1700000001\x00")
			r := findRecord(t, res, p)
			if c.hashed {
				if r.Hash != sealHash(scriptTestKey, []byte(p), mustHex(t, h)) || slices.Contains(res.Partial, ReasonHostTruncated) || res.Host.Unreadable != 0 {
					t.Errorf("hash %+v, partial %v, host %+v", r.Hash, res.Partial, res.Host)
				}
				return
			}
			if r.Hash.Kind != HashNone {
				t.Errorf("hash %+v kept for another file", r.Hash)
			}
			if !slices.Contains(res.Partial, ReasonHostTruncated) || res.Host.Unreadable != 0 {
				t.Errorf("partial %v, host %+v", res.Partial, res.Host)
			}
		})
	}
}

// TestScriptHomeRacyHashIsUnknown: with the production timestamp margin, a
// home SSH file written within the margin before the hash start keeps no
// hash (its ctime cannot prove that the content did not change after the
// read): the run is truncated, not unreadable, and other files are still
// hashed. Once the margin has passed, the same files are hashed.
func TestScriptHomeRacyHashIsUnknown(t *testing.T) {
	root := buildTree(t, treeOpts{})
	homes := []string{"/root/.ssh/authorized_keys", "/home/alice/.ssh/authorized_keys", "/home/alice/.k5login"}
	// An empty setting selects the production margin.
	res := runWith(t, root, ModeFull, os.Getenv("PATH"), "NEBULA_FIM_TEST_RACY_SECONDS=")
	for _, p := range homes {
		if r := findRecord(t, res, p); r.Hash.Kind != HashNone {
			t.Errorf("%s written just before the scan carries a hash", p)
		}
	}
	if r := findRecord(t, res, "/etc/hostname"); r.Hash.Kind == HashNone {
		t.Error("/etc/hostname not hashed")
	}
	if !slices.Contains(res.Partial, ReasonHostTruncated) || res.Host.Unreadable != 0 {
		t.Errorf("partial %v, host %+v", res.Partial, res.Host)
	}

	time.Sleep(3100 * time.Millisecond)
	res = runWith(t, root, ModeFull, os.Getenv("PATH"), "NEBULA_FIM_TEST_RACY_SECONDS=")
	want, sums := expectedRecords(t, root)
	compareRecords(t, res, want, sums, nil)
	if !res.Complete() {
		t.Errorf("partial %v, host %+v", res.Partial, res.Host)
	}
}

// TestScriptRacyMarginSettingValidated: the test margin setting accepts an
// optional minus sign and digits only.
func TestScriptRacyMarginSettingValidated(t *testing.T) {
	root := buildTree(t, treeOpts{})
	for _, v := range []string{"-", "x", "1-", "--1", "1 2", "-1x"} {
		_, _, err := runScriptPath(t, "/bin/sh", root, scanParams(t, ModeFull), os.Getenv("PATH"), "NEBULA_FIM_TEST_RACY_SECONDS="+v)
		if err == nil {
			t.Errorf("setting %q accepted", v)
		}
	}
}

// TestScriptHomeSwapBetweenPassesNeverMisattributes: while the scan runs, a
// user keeps replacing ~/.ssh/authorized_keys by one of two files with
// different contents (two inodes). A hash reported for it is always the
// hash of the inode the record names, never the other file's.
func TestScriptHomeSwapBetweenPassesNeverMisattributes(t *testing.T) {
	root := buildTree(t, treeOpts{})
	j := func(p string) string { return filepath.Join(root, p) }
	name := j("home/alice/.ssh/authorized_keys")
	sums := map[uint64][sha256.Size]byte{}
	var parked []string
	for i, content := range []string{"ssh-ed25519 AAAA old\n", "ssh-ed25519 AAAA new attacker\n"} {
		p := j("home/alice/.ssh/park" + strconv.Itoa(i))
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		sums[st.Ino] = sha256.Sum256([]byte(content))
		parked = append(parked, p)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			p := parked[i%2]
			if err := os.Rename(p, name); err != nil {
				t.Error(err)
				return
			}
			// Mostly quick swaps; every third file stays long enough for
			// a whole run to see it unchanged (and keep its hash).
			hold := time.Duration(rand.IntN(3000)) * time.Microsecond
			if i%3 == 0 {
				hold = time.Duration(300+rand.IntN(700)) * time.Millisecond
			}
			time.Sleep(hold)
			if err := os.Rename(name, p); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()
	// At least 10 runs, and runs until one record kept a hash: a scan
	// that never hashes home files must not pass.
	hashed := 0
	for run := 0; run < 10 || (hashed == 0 && run < 40); run++ {
		res := runWith(t, root, ModeFull, os.Getenv("PATH"))
		for _, r := range res.Records {
			if string(r.Path) != "/home/alice/.ssh/authorized_keys" || r.Hash.Kind == HashNone {
				continue
			}
			hashed++
			sum, ok := sums[r.Inode]
			if !ok || r.Hash != sealHash(scriptTestKey, r.Path, sum) {
				t.Errorf("record of inode %d carries a hash that is not its content's", r.Inode)
			}
		}
	}
	if hashed == 0 {
		t.Error("no run kept a hash for the swapped file")
	}
	t.Logf("%d hashed records", hashed)
}

// scriptVar returns the single-quoted value of the top-level shell
// variable name in the script.
func scriptVar(t *testing.T, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?ms)^` + name + `='([^']*)'$`).FindStringSubmatch(string(Script))
	if m == nil {
		t.Fatalf("%s not found in the script", name)
	}
	return m[1]
}

// fileID is the device:inode:ctime find prints for p (%D:%i:%C@).
func fileID(t *testing.T, p string) string {
	t.Helper()
	out, err := exec.Command("find", "-P", p, "-maxdepth", "0", "-printf", "%D:%i:%C@").Output()
	if err != nil || len(out) == 0 {
		t.Fatalf("find %s: %v", p, err)
	}
	return string(out)
}

// TestScriptHashFDNeverBlocksOrFollows: the home hash helper opens and
// hashes the file in a holder process (as the owner of the directory when
// the scan runs as root) and returns a hash only for a regular file whose
// device:inode:ctime is the one find saw, before and after the read. A FIFO
// (directly or behind a symlink) swapped in does not stall it past the open
// bound, which needs no timeout tool, and a symlink or another file swapped
// in yields no hash. The root side never opens the file: it has no path
// into /proc and no input redirection of its own.
func TestScriptHashFDNeverBlocksOrFollows(t *testing.T) {
	hashFD, hold := scriptVar(t, "HASH_FD"), scriptVar(t, "HOLD")
	if strings.Contains(hashFD, "/proc") || strings.Contains(hashFD, "3<") || strings.Contains(hashFD, "sha256sum") {
		t.Errorf("the root side of the home hash opens or reads the file itself:\n%s", hashFD)
	}
	const content = "ssh-ed25519 AAAA alice\n"
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, dir string) (id string) // returns the id find saw
		want  string                                     // plain hex, "" for no hash
	}{
		{"regular file", func(t *testing.T, dir string) string {
			return fileID(t, filepath.Join(dir, "authorized_keys"))
		}, hex.EncodeToString(sha(content))},
		{"fifo swapped in", func(t *testing.T, dir string) string {
			id := fileID(t, filepath.Join(dir, "authorized_keys"))
			swapIn(t, dir, func(p string) error { return syscall.Mkfifo(p, 0o600) })
			return id
		}, ""},
		{"symlink to a fifo swapped in", func(t *testing.T, dir string) string {
			id := fileID(t, filepath.Join(dir, "authorized_keys"))
			if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
				t.Fatal(err)
			}
			swapIn(t, dir, func(p string) error { return os.Symlink("fifo", p) })
			return id
		}, ""},
		{"symlink to another file swapped in", func(t *testing.T, dir string) string {
			id := fileID(t, filepath.Join(dir, "authorized_keys"))
			if err := os.WriteFile(filepath.Join(dir, "other"), []byte("LEAK\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			swapIn(t, dir, func(p string) error { return os.Symlink("other", p) })
			return id
		}, ""},
		{"file changed after the check", func(t *testing.T, dir string) string {
			id := fileID(t, filepath.Join(dir, "authorized_keys"))
			time.Sleep(20 * time.Millisecond)
			if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte("changed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return id
		}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			id := c.setup(t, dir)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", hashFD, "sh", "./authorized_keys", id, hold, "", "1")
			cmd.Dir = dir
			cmd.WaitDelay = time.Second
			start := time.Now()
			out, _ := cmd.Output()
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("took %v", d)
			}
			got := strings.Fields(string(out))
			if c.want == "" {
				if len(got) != 0 {
					t.Errorf("hash %q of a swapped-in file", out)
				}
			} else if len(got) == 0 || got[0] != c.want {
				t.Errorf("output %q, want hash %s", out, c.want)
			}
		})
	}
}

// swapIn replaces dir/authorized_keys by what mk creates there.
func swapIn(t *testing.T, dir string, mk func(p string) error) {
	t.Helper()
	p := filepath.Join(dir, "authorized_keys")
	if err := os.Rename(p, filepath.Join(dir, "parked")); err != nil {
		t.Fatal(err)
	}
	if err := mk(p); err != nil {
		t.Fatal(err)
	}
}

func sha(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// fakeRootPath returns a PATH whose id says root and, with setpriv, whose
// setpriv logs its options to log and runs the command after "--" as is
// (a test cannot change users), marked as dropped: every sha256sum that
// reads its standard input (a home SSH file) logs "dropped" or "root" to
// log.sum.
func fakeRootPath(t *testing.T, setpriv bool, log string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write("id", "[ \"$1\" = -u ] && { echo 0; exit 0; }\nexec /usr/bin/id \"$@\"\n")
	if setpriv {
		sum, err := exec.LookPath("sha256sum")
		if err != nil {
			t.Fatal(err)
		}
		write("setpriv", "while [ \"$1\" != -- ]; do printf '%s ' \"$1\" >>'"+log+"'; shift; done\necho >>'"+log+"'\nshift\nNEBULA_TEST_DROPPED=1 exec \"$@\"\n")
		write("sha256sum", "w=root\n[ -n \"${NEBULA_TEST_DROPPED:-}\" ] && w=dropped\n[ $# -eq 0 ] && echo \"$w\" >>'"+log+".sum'\nexec '"+sum+"' \"$@\"\n")
		return dir + ":" + os.Getenv("PATH")
	}
	// A PATH without setpriv: the tools the script uses, linked one by one.
	for _, tool := range []string{"sed", "awk", "od", "find", "sha256sum", "date", "base64", "wc", "cat", "sleep", "nice", "ionice", "timeout"} {
		bin, err := exec.LookPath(tool)
		if err != nil {
			if tool == "ionice" {
				continue
			}
			t.Fatalf("%s: %v", tool, err)
		}
		if err := os.Symlink(bin, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestScriptRootOpensHomeFilesAsOwner: run as root, the scan opens a home
// SSH file only in a holder process that has dropped to the owner of the
// directory it lies in (setpriv), so root never opens a path the user can
// swap; without setpriv such a file is not hashed and counts unreadable.
func TestScriptRootOpensHomeFilesAsOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the fake root needs an unprivileged user")
	}
	uid := strconv.Itoa(os.Getuid())
	t.Run("setpriv", func(t *testing.T) {
		root := buildTree(t, treeOpts{})
		log := filepath.Join(t.TempDir(), "setpriv.log")
		res := runWith(t, root, ModeFull, fakeRootPath(t, true, log))
		want, sums := expectedRecords(t, root)
		compareRecords(t, res, want, sums, nil)
		b, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		// /root/.ssh: authorized_keys, authorized_keys2; alice: authorized_keys, known_hosts, .k5login.
		if len(lines) != 5 {
			t.Errorf("setpriv ran %d times, want 5:\n%s", len(lines), b)
		}
		for _, l := range lines {
			if strings.TrimSpace(l) != "--reuid="+uid+" --regid=65534 --clear-groups" {
				t.Errorf("setpriv options %q", l)
			}
		}
		// Every home SSH file is read and hashed by the dropped holder;
		// root never opens or reads one.
		b, err = os.ReadFile(log + ".sum")
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Fields(string(b)); len(got) != 5 || slices.ContainsFunc(got, func(s string) bool { return s != "dropped" }) {
			t.Errorf("home files hashed by %q, want 5 times by the dropped holder", got)
		}
	})
	t.Run("no setpriv", func(t *testing.T) {
		root := buildTree(t, treeOpts{})
		res := runWith(t, root, ModeFull, fakeRootPath(t, false, ""))
		for _, p := range []string{"/root/.ssh/authorized_keys", "/home/alice/.ssh/authorized_keys", "/home/alice/.k5login"} {
			if r := findRecord(t, res, p); r.Hash.Kind != HashNone {
				t.Errorf("%s hashed without dropping to its owner", p)
			}
		}
		if r := findRecord(t, res, "/etc/hostname"); r.Hash.Kind == HashNone {
			t.Error("/etc/hostname not hashed")
		}
		if res.Host.Unreadable != 5 {
			t.Errorf("host %+v, want 5 unreadable", res.Host)
		}
	})
}

// TestScriptRootOwnedHomeDirsOpenUser: run as root, a home SSH file in a
// root-owned directory that group or others can write is opened by a
// holder dropped to nobody (65534), and one in a root-owned directory only
// root can change is opened without dropping. A find wrapper reports every
// directory the open check looks at as owned by root (a test cannot chown).
func TestScriptRootOwnedHomeDirsOpenUser(t *testing.T) {
	realFind, err := exec.LookPath("find")
	if err != nil {
		t.Fatal(err)
	}
	const nobody = "--reuid=65534 --regid=65534 --clear-groups"
	for _, c := range []struct {
		name       string
		alice, ssh os.FileMode // modes of /home/alice and /home/alice/.ssh
		drops      []string    // setpriv options, one line per dropped open
		sums       []string    // who read each home SSH file, sorted
	}{
		{"group- and other-writable", 0o757, 0o770, []string{nobody, nobody, nobody}, []string{"dropped", "dropped", "dropped", "root", "root"}},
		{"other-writable sticky", os.ModeSticky | 0o777, 0o702, []string{nobody, nobody, nobody}, []string{"dropped", "dropped", "dropped", "root", "root"}},
		{"only root can change", 0o755, 0o700, nil, []string{"root", "root", "root", "root", "root"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := buildTree(t, treeOpts{})
			for p, m := range map[string]os.FileMode{"root/.ssh": 0o700, "home/alice": c.alice, "home/alice/.ssh": c.ssh} {
				if err := os.Chmod(filepath.Join(root, p), m); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(t.TempDir(), "setpriv.log")
			dir := t.TempDir()
			wrapper := "#!/bin/sh\n" +
				"if [ $# -eq 5 ] && [ \"$1\" = . ] && [ \"$2\" = -maxdepth ] && [ \"$3\" = 0 ] && [ \"$4\" = -printf ] && [ \"$5\" = '%U %m\\n' ]; then\n" +
				"\tm=$('" + realFind + "' . -maxdepth 0 -printf '%m') || exit 1\n\techo \"0 $m\"\n\texit 0\nfi\n" +
				"exec '" + realFind + "' \"$@\"\n"
			if err := os.WriteFile(filepath.Join(dir, "find"), []byte(wrapper), 0o700); err != nil {
				t.Fatal(err)
			}
			res := runWith(t, root, ModeFull, dir+":"+fakeRootPath(t, true, log))
			want, sums := expectedRecords(t, root)
			compareRecords(t, res, want, sums, nil)
			b, err := os.ReadFile(log)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			var drops []string
			for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					drops = append(drops, l)
				}
			}
			if !slices.Equal(drops, c.drops) {
				t.Errorf("setpriv ran with %q, want %q", drops, c.drops)
			}
			b, err = os.ReadFile(log + ".sum")
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Fields(string(b))
			slices.Sort(got)
			if !slices.Equal(got, c.sums) {
				t.Errorf("home files read by %q, want %q", got, c.sums)
			}
		})
	}
}

// TestScriptNewlineNamedKeyFileIsUnreadable: an authorized_keys* match whose
// name holds a newline cannot be a start point; it is not reported and
// counts as unreadable, so the run is partial.
func TestScriptNewlineNamedKeyFileIsUnreadable(t *testing.T) {
	root := buildTree(t, treeOpts{})
	if err := os.WriteFile(filepath.Join(root, "home/alice/.ssh/authorized_keys\nx"), []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runAndParse(t, "/bin/sh", root, ModeFull)
	if s := rootStates(res)["/home/*/.ssh/authorized_keys*"]; s != RootScanned {
		t.Errorf("state %v", s)
	}
	if res.Host.Unreadable != 1 || !slices.Contains(res.Partial, ReasonUnreadable) {
		t.Errorf("partial %v, host %+v", res.Partial, res.Host)
	}
	findRecord(t, res, "/home/alice/.ssh/authorized_keys")
}

func statesFor(patterns []string, s RootState) map[string]RootState {
	m := map[string]RootState{}
	for _, p := range patterns {
		m[p] = s
	}
	return m
}

// lock makes dir mode 000 until the test ends.
func lock(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}
