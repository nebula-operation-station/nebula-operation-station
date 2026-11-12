// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
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
