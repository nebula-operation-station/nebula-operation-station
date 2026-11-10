// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// listUpdatesHost is a fake host for package.list_updates: apt-get prints
// the simulation, apt-cache records its arguments and prints the stanza
// of each requested pkg=version (ADR 0011 D8, VU-13).
func listUpdatesHost(t *testing.T, withAptCache bool) *fakeHost {
	t.Helper()
	d := t.TempDir()
	f := &fakeHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	f.write(t, "apt-get", `printf '%s\n' "Reading package lists..." \
  "Inst openssl [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])" \
  "Inst libssl3:i386 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [i386])" \
  "Inst libfoo1 [1.2-3] (1.2-3+b1 Debian:12/stable [amd64])" \
  "Inst linux-image-6.1.0-27-amd64 (6.1.115-1 Debian:12.8/stable [amd64])" \
  "Inst bad'name [1] (2 Debian:12/stable [amd64])" \
  "Conf openssl (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])"`)
	if withAptCache {
		f.write(t, "apt-cache", `for a in "$@"; do echo "$a" >> "`+f.calls+`"; done
for a in "$@"; do
  case "$a" in
    openssl=3.0.11-1~deb12u2) printf '%s\n' "Package: openssl" "Version: 3.0.11-1~deb12u2" "Priority: important" "Description: x" "" ;;
    libssl3:i386=3.0.11-1~deb12u2) printf '%s\n' "Package: libssl3" "Architecture: i386" "Version: 3.0.11-1~deb12u2" "Source: openssl" "" ;;
    libfoo1=1.2-3+b1) printf '%s\n' "Package: libfoo1" "Version: 1.2-3+b1" "Source: foo (1.2-3)" "" ;;
    linux-image-6.1.0-27-amd64=6.1.115-1) printf '%s\n' "Package: linux-image-6.1.0-27-amd64" "Version: 6.1.115-1" "Source: linux" "" ;;
  esac
done
exit 0`)
	}
	return f
}

func TestListUpdatesReportsCandidateSources(t *testing.T) {
	f := listUpdatesHost(t, true)
	code, doc := f.run(t, packageListUpdates)
	if code != 0 || doc["format"] != "apt-simulate-v1" {
		t.Fatalf("%d %v", code, doc)
	}
	calls, _ := os.ReadFile(f.calls)
	wantArgs := "show\nopenssl=3.0.11-1~deb12u2\nlibssl3:i386=3.0.11-1~deb12u2\nlibfoo1=1.2-3+b1\nlinux-image-6.1.0-27-amd64=6.1.115-1\n"
	if string(calls) != wantArgs {
		t.Fatalf("apt-cache args (the unsafe name must be filtered):\n%s", calls)
	}
	if c := b64(t, doc, "candidates"); strings.Contains(c, "Description") || strings.Contains(c, "Priority") {
		t.Fatalf("candidates not reduced to Package/Version/Source:\n%s", c)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	u, err := osdebian.ParseUpdates(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"openssl":                    {"openssl", "3.0.11-1~deb12u2"},
		"libssl3:i386":               {"openssl", "3.0.11-1~deb12u2"},
		"libfoo1":                    {"foo", "1.2-3"}, // binNMU: source, not binary version
		"linux-image-6.1.0-27-amd64": {"linux", "6.1.115-1"},
	}
	if len(u.Packages) != len(want) {
		t.Fatalf("packages %+v", u.Packages)
	}
	for _, p := range u.Packages {
		if w := want[p.Name]; p.SourceName != w[0] || p.SourceVersion != w[1] {
			t.Errorf("%s: source %q %q, want %q %q", p.Name, p.SourceName, p.SourceVersion, w[0], w[1])
		}
	}
}

func TestListUpdatesWithoutAptCacheLeavesSourcesUnknown(t *testing.T) {
	f := listUpdatesHost(t, false)
	// Only the fake bin plus the tools the script needs, without apt-cache.
	tools := filepath.Join(f.dir, "tools")
	if err := os.Mkdir(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"base64", "tr", "grep", "head", "sed", "stat", "xargs", "env", "cat"} {
		for _, dir := range []string{"/usr/bin", "/bin"} {
			if _, err := os.Stat(filepath.Join(dir, tool)); err == nil {
				if err := os.Symlink(filepath.Join(dir, tool), filepath.Join(tools, tool)); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
	}
	code, doc := f.runPath(t, packageListUpdates, f.bin+":"+tools)
	if code != 0 || doc["candidates"] != "" {
		t.Fatalf("%d %v", code, doc)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	u, err := osdebian.ParseUpdates(raw)
	if err != nil || len(u.Packages) != 4 {
		t.Fatalf("%+v %v", u, err)
	}
	for _, p := range u.Packages {
		if p.SourceName != "" || p.SourceVersion != "" {
			t.Errorf("%s: source known without apt-cache: %+v", p.Name, p)
		}
	}
}

// manyUpdatesHost is a fake host with n pending updates whose apt-cache
// prints copies stanzas per candidate: far more candidate bytes than fit
// next to the simulation in hostrun.MaxResult.
func manyUpdatesHost(t *testing.T, n, copies int) *fakeHost {
	t.Helper()
	d := t.TempDir()
	f := &fakeHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	f.write(t, "apt-get", `awk -v n=`+strconv.Itoa(n)+` 'BEGIN { for (i = 1; i <= n; i++) printf "Inst libexample-component-%05d [1.0-1] (1.0-1+b1 Debian:12/stable, Debian-Security:12/stable-security [amd64])\n", i }'`)
	f.write(t, "apt-cache", `for a in "$@"; do [ "$a" = show ] || echo "$a"; done | awk -F= -v c=`+strconv.Itoa(copies)+` '{ for (j = 0; j < c; j++) printf "Package: %s\nVersion: %s\nSource: example-source-%s (1.0-1)\n\n", $1, $2, substr($1, length($1) - 4) }'`)
	return f
}

func TestListUpdatesCandidatesStayWithinMaxResult(t *testing.T) {
	const n = 5000
	f := manyUpdatesHost(t, n, 8)
	p := filepath.Join(f.dir, "action.sh")
	if err := os.WriteFile(p, packageListUpdates, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", p)
	cmd.Dir = f.dir
	cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > hostrun.MaxResult {
		t.Fatalf("result is %d bytes, over hostrun.MaxResult %d", len(out), hostrun.MaxResult)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["candidates_truncated"] != true {
		t.Fatalf("candidates_truncated = %v, want true", doc["candidates_truncated"])
	}
	c := b64(t, doc, "candidates")
	if c == "" || !strings.HasSuffix(c, "\n\n") {
		t.Fatalf("truncated candidates must end with a closed stanza, got tail %q", c[max(0, len(c)-80):])
	}
	u, err := osdebian.ParseUpdates(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Packages) != n || u.Security != n || !u.CandidatesTruncated {
		t.Fatalf("simulation not intact: %d packages, %d security, truncated %v", len(u.Packages), u.Security, u.CandidatesTruncated)
	}
	known := 0
	for _, pkg := range u.Packages {
		if pkg.SourceVersion == "" {
			continue
		}
		known++
		if want := "example-source-" + pkg.Name[len(pkg.Name)-5:]; pkg.SourceName != want || pkg.SourceVersion != "1.0-1" {
			t.Fatalf("%s: source %q %q", pkg.Name, pkg.SourceName, pkg.SourceVersion)
		}
	}
	if known == 0 || known == n {
		t.Fatalf("%d of %d sources known, want a truncated part", known, n)
	}
}

func TestListUpdatesSmallCandidatesAreNotTruncated(t *testing.T) {
	code, doc := listUpdatesHost(t, true).run(t, packageListUpdates)
	if code != 0 || doc["candidates_truncated"] != false {
		t.Fatalf("%d %v", code, doc)
	}
}

func TestListUpdatesBudgetMatchesMaxResult(t *testing.T) {
	if !strings.Contains(string(packageListUpdates), "max_result="+strconv.Itoa(hostrun.MaxResult)+"\n") {
		t.Fatalf("package_list_updates.sh must budget against hostrun.MaxResult (%d)", hostrun.MaxResult)
	}
}
