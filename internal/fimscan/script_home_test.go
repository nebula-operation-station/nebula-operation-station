// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"crypto/sha256"
	"math/rand/v2"
	"os"
	"path/filepath"
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
// device:inode:ctime it was read from, and the record keeps it only if the
// meta pass saw the same file in the same state. A file swapped (another
// inode) or changed in place (another ctime) between the passes has no
// hash and makes the run truncated, not unreadable; the old content's hash
// never stands for it.
func TestScriptHomeHashBoundToInode(t *testing.T) {
	const p = "/home/alice/.ssh/authorized_keys"
	h := strings.Repeat("a", 64)
	meta := func(ino, ctime string) string {
		return "M1 f 1 600 1000 1000 " + ino + " 1700000000.5 " + ctime + " 2049\x00" + p + "\x00\x00"
	}
	head := "B1700000000\x00Rscanned /home/*/.ssh/authorized_keys*\x00"
	for _, c := range []struct {
		name   string
		stream string
		hashed bool
	}{
		{"same file", "H2049:7:1700000000.5\x00" + h + "  " + p + "\x00" + meta("7", "1700000000.5"), true},
		{"swapped between the passes", "H2049:7:1700000000.5\x00" + h + "  " + p + "\x00" + meta("8", "1700000000.5"), false},
		{"changed in place between the passes", "H2049:7:1700000000.5\x00" + h + "  " + p + "\x00" + meta("7", "1700000001.25"), false},
		{"other device", "H2050:7:1700000000.5\x00" + h + "  " + p + "\x00" + meta("7", "1700000000.5"), false},
		{"malformed id", "H2049:7:x\x00" + h + "  " + p + "\x00" + meta("7", "1700000000.5"), false},
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
			time.Sleep(time.Duration(rand.IntN(3000)) * time.Microsecond)
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
	for range 10 {
		res := runWith(t, root, ModeFull, os.Getenv("PATH"))
		for _, r := range res.Records {
			if string(r.Path) != "/home/alice/.ssh/authorized_keys" || r.Hash.Kind == HashNone {
				continue
			}
			sum, ok := sums[r.Inode]
			if !ok || r.Hash != sealHash(scriptTestKey, r.Path, sum) {
				t.Errorf("record of inode %d carries a hash that is not its content's", r.Inode)
			}
		}
	}
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
