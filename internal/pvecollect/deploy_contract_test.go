// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// spoolMount is where install.sh and the container image put the spool.
const spoolMount = "/var/lib/nebula/pve"

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// octalMode renders a directory mode the way install -m takes it.
func octalMode(m os.FileMode) string {
	v := m.Perm()
	if m&os.ModeSetgid != 0 {
		v |= 0o2000
	}
	return fmt.Sprintf("%o", uint32(v))
}

// consumedDirs are the directories the server unlinks in (Spool.Remove,
// Spool.RemoveGuestNet).
func consumedDirs() []string { return []string{resultsDirName, guestNetDirName} }

// The modes spool.go expects are what both deployments provision: the
// collector checks them at start and the server unlinks through the group.
func TestDeploymentsProvisionSpoolModes(t *testing.T) {
	if got := octalMode(spoolDirMode); got != "2770" {
		t.Fatalf("spoolDirMode = %s, want 2770: the server unlinks through the group", got)
	}
	if got := octalMode(spoolRootMode); got != "2750" {
		t.Fatalf("spoolRootMode = %s, want 2750: the generation state is the collector's", got)
	}
	install := repoFile(t, "deploy", "install.sh")
	docker := repoFile(t, "deploy", "container", "Dockerfile")
	want := map[string]string{"": octalMode(spoolRootMode)}
	for _, d := range consumedDirs() {
		want["/"+d] = octalMode(spoolDirMode)
	}
	for sub, mode := range want {
		prefix := fmt.Sprintf("install -d -m %s -o nebula-pve-collector -g %s ", mode, spoolGroupName)
		line := prefix + `"${var_lib}/pve` + sub + `"`
		if !slices.Contains(strings.Split(install, "\n"), line) {
			t.Errorf("install.sh misses %q", line)
		}
		if !strings.Contains(docker, prefix+spoolMount+sub+" ") {
			t.Errorf("Dockerfile misses %s%s%s", prefix, spoolMount, sub)
		}
	}
}

// Exactly the directories the importers consume, plus the want-list, are
// writable for the server: not the root with the generation state, not the
// live samples.
func TestServerDropInGrantsOnlyWhatSpoolNeeds(t *testing.T) {
	var got []string
	for line := range strings.Lines(repoFile(t, "deploy", "install.sh")) {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "ReadWritePaths="); ok {
			got = append(got, path)
		}
	}
	want := []string{"${var_lib}/discovery/jobs", "${var_lib}/pve/requests"}
	for _, d := range consumedDirs() {
		want = append(want, "${var_lib}/pve/"+d)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("server ReadWritePaths = %q, want %q", got, want)
	}
}

type composeFile struct {
	Services map[string]struct {
		GroupAdd []string `yaml:"group_add"`
		Volumes  []string `yaml:"volumes"`
	} `yaml:"services"`
	Volumes map[string]any `yaml:"volumes"`
}

type composeMount struct {
	source   string
	readOnly bool
}

// spoolMounts returns a service's mounts in the spool by path below
// spoolMount ("" is the root itself).
func spoolMounts(t *testing.T, volumes []string) map[string]composeMount {
	t.Helper()
	out := map[string]composeMount{}
	for _, v := range volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 || len(parts) > 3 {
			t.Fatalf("volume %q is not source:target[:mode]", v)
		}
		rel, ok := strings.CutPrefix(parts[1], spoolMount)
		if !ok {
			continue
		}
		out[strings.TrimPrefix(rel, "/")] = composeMount{source: parts[0], readOnly: len(parts) == 3 && parts[2] == "ro"}
	}
	return out
}

// The container server sees the collector's results/ and guestnet/ with
// the rights to unlink, and nothing else of the spool beyond the live
// handoff. Without these mounts it would read the image's empty copies.
func TestComposeSharesConsumedDirsWithServer(t *testing.T) {
	var c composeFile
	if err := yaml.Unmarshal([]byte(repoFile(t, "deploy", "container", "compose.yaml")), &c); err != nil {
		t.Fatal(err)
	}
	server, collector := c.Services["server"], c.Services["pve-collector"]
	if !slices.Contains(server.GroupAdd, "10010") {
		t.Errorf("server group_add = %v, want the %s gid 10010", server.GroupAdd, spoolGroupName)
	}
	serverMounts := spoolMounts(t, server.Volumes)
	collectorMounts := spoolMounts(t, collector.Volumes)
	wantDirs := append(consumedDirs(), requestsDirName, liveDirName)
	var gotDirs []string
	for d := range serverMounts {
		gotDirs = append(gotDirs, d)
	}
	slices.Sort(gotDirs)
	slices.Sort(wantDirs)
	if !slices.Equal(gotDirs, wantDirs) {
		t.Errorf("server spool mounts = %q, want %q", gotDirs, wantDirs)
	}
	for _, d := range consumedDirs() {
		s, ok := serverMounts[d]
		if !ok {
			continue
		}
		if s.readOnly {
			t.Errorf("server mounts %s read-only, it must unlink there", d)
		}
		if co := collectorMounts[d]; co.source != s.source || co.readOnly {
			t.Errorf("collector mounts %s as %+v, want writable %s", d, co, s.source)
		}
		if _, declared := c.Volumes[s.source]; !declared {
			t.Errorf("volume %s is not declared", s.source)
		}
	}
	if !serverMounts[liveDirName].readOnly {
		t.Errorf("server must mount %s read-only", liveDirName)
	}
}
