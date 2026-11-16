// SPDX-License-Identifier: AGPL-3.0-or-later

package stage

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

func TestStageTwiceIsByteIdentical(t *testing.T) {
	d := newDist(t).write(t)
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	if _, err := run(t, d, a); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, d, b); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"payloads/builtins.tar", "payloads/installed-files.json", "SHA256SUMS"} {
		if !bytes.Equal(readFile(t, filepath.Join(a, p)), readFile(t, filepath.Join(b, p))) {
			t.Errorf("%s differs between two runs", p)
		}
	}
	if ta, tb := treeDigest(t, filepath.Join(a, "module-bytes")), treeDigest(t, filepath.Join(b, "module-bytes")); ta != tb {
		t.Errorf("module-bytes differ between two runs:\n%s\n%s", ta, tb)
	}
}

// treeDigest lists every file of a tree with its hash.
func treeDigest(t testing.TB, root string) string {
	t.Helper()
	var out strings.Builder
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(&out, "%s %s\n", rel, hexSum(readFile(t, p)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestStageLayoutMatchesSigningProcedure(t *testing.T) {
	d := newDist(t).write(t)
	out := filepath.Join(t.TempDir(), "out")
	res, err := run(t, d, out)
	if err != nil {
		t.Fatal(err)
	}
	top := dirNames(t, out)
	if want := []string{"SHA256SUMS", "installed", "module-bytes", "payloads"}; !slices.Equal(top, want) {
		t.Fatalf("out holds %v, want %v", top, want)
	}
	payloads := dirNames(t, filepath.Join(out, "payloads"))
	want := []string{
		"builtins.tar",
		"installed-files.json",
		"nebula-operation-station_0.1.0_amd64.deb",
		"nebula-operation-station_0.1.0_arm64.deb",
		"nebula_0.1.0_checksums.txt",
		"nebula_0.1.0_linux_amd64.tar.gz",
		"nebula_0.1.0_linux_arm64.tar.gz",
	}
	if !slices.Equal(payloads, want) {
		t.Fatalf("payloads/ holds %v, want %v", payloads, want)
	}
	var sums strings.Builder
	for i, name := range want {
		b := readFile(t, filepath.Join(out, "payloads", name))
		fmt.Fprintf(&sums, "%s  payloads/%s\n", hexSum(b), name)
		if a := res.Payloads[i]; a.Name != name || a.Size != int64(len(b)) || a.SHA256 != hexSum(b) {
			t.Errorf("result payload %d = %+v, want %s", i, a, name)
		}
	}
	if got := string(readFile(t, filepath.Join(out, "SHA256SUMS"))); got != sums.String() {
		t.Errorf("SHA256SUMS =\n%s\nwant\n%s", got, sums.String())
	}
	// Published dist files are copied byte for byte.
	for _, name := range want[2:] {
		if !bytes.Equal(readFile(t, filepath.Join(d, name)), readFile(t, filepath.Join(out, "payloads", name))) {
			t.Errorf("payloads/%s differs from the dist file", name)
		}
	}
	// module-bytes/<name>/<version>.tar, one version per module, exactly
	// the nested tars of builtins.tar.
	locks := repoLocks(t)
	if got := dirNames(t, filepath.Join(out, "module-bytes")); !slices.Equal(got, sortedKeys(locks)) {
		t.Fatalf("module-bytes holds %v, want %v", got, sortedKeys(locks))
	}
	nested := outerEntries(t, readFile(t, filepath.Join(out, "payloads", "builtins.tar")))
	if len(nested) != len(locks) || len(res.Modules) != len(locks) {
		t.Fatalf("builtins.tar holds %d modules, result %d, want %d", len(nested), len(res.Modules), len(locks))
	}
	for i, name := range sortedKeys(locks) {
		v := locks[name]
		if got := dirNames(t, filepath.Join(out, "module-bytes", name)); !slices.Equal(got, []string{v + ".tar"}) {
			t.Errorf("module-bytes/%s holds %v, want %s.tar", name, got, v)
		}
		b := readFile(t, filepath.Join(out, "module-bytes", name, v+".tar"))
		if nested[i].name != "modules/"+name+"/"+v+".tar" || !bytes.Equal(nested[i].data, b) {
			t.Errorf("builtins.tar entry %d is %s, not module-bytes/%s/%s.tar", i, nested[i].name, name, v)
		}
		if m := res.Modules[i]; m.Name != name || m.Version != v || m.SHA256 != hexSum(b) {
			t.Errorf("result module %d = %+v", i, m)
		}
	}
	// No manifest and no signature anywhere.
	_ = filepath.WalkDir(out, func(p string, _ fs.DirEntry, _ error) error {
		if base := filepath.Base(p); strings.HasPrefix(base, "release-manifest") || strings.HasSuffix(base, ".sig") {
			t.Errorf("staging holds %s", p)
		}
		return nil
	})
}

func dirNames(t testing.TB, p string) []string {
	t.Helper()
	ents, err := os.ReadDir(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var lockIDRe = regexp.MustCompile(`"format":"nebula-module-v1","name":"([a-z0-9_-]+)"`)
var lockVersionRe = regexp.MustCompile(`"version":"([0-9.]+)"\}$`)

// repoLocks maps every module of the repository to its lock version.
func repoLocks(t testing.TB) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(repoModules, "*", "*", "module.lock.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no module locks: %v", err)
	}
	out := map[string]string{}
	for _, p := range paths {
		b := bytes.TrimSpace(readFile(t, p))
		n, v := lockIDRe.FindSubmatch(b), lockVersionRe.FindSubmatch(b)
		if n == nil || v == nil {
			t.Fatalf("%s: cannot find name and version", p)
		}
		out[string(n[1])] = string(v[1])
	}
	return out
}

type entry struct {
	name string
	hdr  *tar.Header
	data []byte
}

func outerEntries(t testing.TB, b []byte) []entry {
	t.Helper()
	r := tar.NewReader(bytes.NewReader(b))
	var out []entry
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, entry{name: h.Name, hdr: h, data: data})
	}
}

func TestStageRejectsInvalidVersion(t *testing.T) {
	d := newDist(t).write(t)
	for _, v := range []string{"", "v0.1.0", "0.1", "01.0.0", "0.1.0 ", strings.Repeat("1", 70)} {
		_, err := Run(t.Context(), Options{Version: v, Dist: d, Out: filepath.Join(t.TempDir(), "o"), Modules: repoModules})
		if !errors.Is(err, ErrVersion) {
			t.Errorf("version %q: err = %v, want ErrVersion", v, err)
		}
	}
}

func TestStageRejectsVersionThatBreaksArtifactNames(t *testing.T) {
	// Valid SemVer, but "+" is not allowed in a manifest artifact name.
	_, err := Run(t.Context(), Options{Version: "0.1.0+build.1", Dist: t.TempDir(), Out: filepath.Join(t.TempDir(), "o"), Modules: repoModules})
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("err = %v, want ErrVersion", err)
	}
}

func TestStageRejectsUnusableOut(t *testing.T) {
	d := newDist(t).write(t)
	nonEmpty := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonEmpty, "old"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"non-empty": nonEmpty, "file": file, "symlink": link, "empty": ""} {
		if _, err := run(t, d, out); !errors.Is(err, ErrOut) {
			t.Errorf("%s: err = %v, want ErrOut", name, err)
		}
	}
	if got := dirNames(t, nonEmpty); !slices.Equal(got, []string{"old"}) {
		t.Errorf("non-empty out was changed: %v", got)
	}
}

func TestStageAcceptsExistingEmptyOut(t *testing.T) {
	d := newDist(t).write(t)
	if _, err := run(t, d, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestStageReportsEveryMissingFlavour(t *testing.T) {
	for _, f := range expectedFlavours(testVersion) {
		t.Run(f.name, func(t *testing.T) {
			ds := newDist(t)
			delete(ds.files, f.file)
			_, err := run(t, ds.write(t), filepath.Join(t.TempDir(), "out"))
			if !errors.Is(err, ErrMissingFlavour) || !strings.Contains(err.Error(), f.name) || !strings.Contains(err.Error(), f.file) {
				t.Fatalf("err = %v, want ErrMissingFlavour naming %s and %s", err, f.name, f.file)
			}
		})
	}
	ds := newDist(t)
	delete(ds.files, "nebula_0.1.0_linux_arm64.tar.gz")
	delete(ds.files, "nebula_0.1.0_container_linux_amd64.tar")
	_, err := run(t, ds.write(t), filepath.Join(t.TempDir(), "out"))
	if !errors.Is(err, ErrMissingFlavour) || !strings.Contains(err.Error(), "tarball:arm64") || !strings.Contains(err.Error(), "container:amd64") {
		t.Fatalf("err = %v, want both missing flavours named", err)
	}
}

func TestStageRejectsFlavourThatIsNotARegularFile(t *testing.T) {
	ds := newDist(t)
	delete(ds.files, "nebula-operation-station_0.1.0_arm64.deb")
	d := ds.write(t)
	if err := os.Symlink(filepath.Join(d, "nebula-operation-station_0.1.0_amd64.deb"), filepath.Join(d, "nebula-operation-station_0.1.0_arm64.deb")); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, d, filepath.Join(t.TempDir(), "out")); !errors.Is(err, ErrMissingFlavour) {
		t.Fatalf("err = %v, want ErrMissingFlavour", err)
	}
}

func TestInstalledFilesComeFromThePackages(t *testing.T) {
	d := newDist(t).write(t)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := run(t, d, out); err != nil {
		t.Fatal(err)
	}
	raw := readFile(t, filepath.Join(out, "payloads", "installed-files.json"))
	l, err := release.ParseInstalledFiles(raw)
	if err != nil {
		t.Fatal(err)
	}
	if l.ReleaseVersion != testVersion {
		t.Errorf("release_version = %q", l.ReleaseVersion)
	}
	var names []string
	for _, f := range l.Flavours {
		names = append(names, f.Name)
	}
	if want := []string{"container:amd64", "deb:amd64", "deb:arm64", "tarball:amd64", "tarball:arm64"}; !slices.Equal(names, want) {
		t.Fatalf("flavours = %v, want %v", names, want)
	}
	// The list equals an independent regeneration from the staged trees
	// (the offline recheck in docs/admin/release-signing.md).
	again, err := release.GenerateInstalledFiles(testVersion, filepath.Join(out, "installed"))
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("regenerated list differs (err %v)", err)
	}
	paths := func(name string) map[string]release.InstalledFile {
		f, ok := l.Flavour(name)
		if !ok {
			t.Fatalf("no flavour %s", name)
		}
		m := map[string]release.InstalledFile{}
		for _, e := range f.Files {
			m[e.Path] = e
		}
		return m
	}
	deb := paths("deb:arm64")
	if e := deb["/usr/bin/nebula-server"]; e.Type != release.FileRegular || e.Mode != 0o755 || e.SHA256 != hexSum([]byte("nebula-server arm64")) {
		t.Errorf("deb:arm64 nebula-server = %+v", e)
	}
	if e := deb["/usr/share/nebula/web/app.css"]; e.Type != release.FileSymlink || e.Target != "app.1234.css" {
		t.Errorf("deb symlink = %+v", e)
	}
	if e := deb["/lib/systemd/system/nebula-server.service"]; e.Mode != 0o644 {
		t.Errorf("deb unit = %+v", e)
	}
	tb := paths("tarball:amd64")
	if len(tb) != len(testBinaries)+len(tarballUnits) {
		t.Errorf("tarball:amd64 lists %d files, want %d", len(tb), len(testBinaries)+len(tarballUnits))
	}
	for _, b := range testBinaries {
		if e := tb["/usr/bin/"+b]; e.Mode != 0o755 || e.SHA256 != hexSum([]byte(b+" amd64")) {
			t.Errorf("tarball %s = %+v", b, e)
		}
	}
	for _, u := range tarballUnits {
		if e := tb["/etc/systemd/system/"+u]; e.Mode != 0o644 || e.SHA256 != hexSum([]byte("[Unit]\n# "+u+"\n")) {
			t.Errorf("tarball %s = %+v", u, e)
		}
	}
	ct := paths("container:amd64")
	if len(ct) != len(testBinaries) {
		t.Errorf("container lists %v, want only the binaries", ct)
	}
	if _, ok := ct["/usr/bin/nmap"]; ok {
		t.Error("container lists the base image's nmap")
	}
}

func TestTarballOwnerIsSetByInstallNotArchive(t *testing.T) {
	// goreleaser writes the build user's uid/gid into the tarball;
	// install.sh installs with -o root -g root, so the list says root:root.
	ds := newDist(t)
	files := tarballData("amd64")
	for i := range files {
		files[i].uid, files[i].gid = 1001, 1001
	}
	ds.files["nebula_0.1.0_linux_amd64.tar.gz"] = gz(t, tarBytes(t, files))
	out := filepath.Join(t.TempDir(), "out")
	if _, err := run(t, ds.write(t), out); err != nil {
		t.Fatal(err)
	}
	l, err := release.ParseInstalledFiles(readFile(t, filepath.Join(out, "payloads", "installed-files.json")))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := l.Flavour("tarball:amd64")
	for _, e := range f.Files {
		if e.Owner != release.GeneratedOwner {
			t.Errorf("%s owner %s", e.Path, e.Owner)
		}
	}
}

func TestStageRejectsBadPackages(t *testing.T) {
	amd := "nebula-operation-station_0.1.0_amd64.deb"
	tgz := "nebula_0.1.0_linux_amd64.tar.gz"
	ctr := "nebula_0.1.0_container_linux_amd64.tar"
	withDeb := func(extra ...tf) func(t *testing.T, ds *dist) {
		return func(t *testing.T, ds *dist) { ds.files[amd] = debBytes(t, append(debData("amd64"), extra...)) }
	}
	withContainer := func(extra ...tf) func(t *testing.T, ds *dist) {
		return func(t *testing.T, ds *dist) { ds.files[ctr] = tarBytes(t, append(containerData(), extra...)) }
	}
	cases := map[string]func(t *testing.T, ds *dist){
		"deb xz data": func(t *testing.T, ds *dist) {
			ds.files[amd] = arBytes([]arMember{{"debian-binary", []byte("2.0\n")}, {"data.tar.xz", []byte("x")}})
		},
		"deb no data":     func(t *testing.T, ds *dist) { ds.files[amd] = arBytes([]arMember{{"debian-binary", []byte("2.0\n")}}) },
		"deb not ar":      func(t *testing.T, ds *dist) { ds.files[amd] = []byte("PK\x03\x04") },
		"deb bad version": func(t *testing.T, ds *dist) { ds.files[amd] = arBytes([]arMember{{"debian-binary", []byte("3.0\n")}}) },
		"deb config file": withDeb(reg("./etc/nebula/server.json", 0o640, "{}")),
		"deb data file":   withDeb(reg("./var/lib/nebula/x", 0o644, "x")),
		"deb non-root":    withDeb(tf{name: "./usr/bin/nebula-x", typ: tar.TypeReg, mode: 0o755, uid: 1000}),
		"deb hardlink":    withDeb(tf{name: "./usr/bin/nebula-y", typ: tar.TypeLink, link: "./usr/bin/nebula"}),
		"deb device":      withDeb(tf{name: "./usr/share/nebula/dev", typ: tar.TypeChar}),
		"deb dotdot":      withDeb(reg("./usr/share/nebula/../../../tmp/x", 0o644, "x")),
		"deb absolute":    withDeb(reg("/usr/share/nebula/abs", 0o644, "x")),
		"deb duplicate":   withDeb(reg("./usr/bin/nebula", 0o755, "again")),
		"deb missing bin": func(t *testing.T, ds *dist) { ds.files[amd] = debBytes(t, debData("amd64")[4:]) },
		"tarball no list": func(t *testing.T, ds *dist) { ds.files[tgz] = gz(t, tarBytes(t, tarballData("amd64")[:6])) },
		"tarball no unit": func(t *testing.T, ds *dist) { ds.files[tgz] = gz(t, tarBytes(t, tarballData("amd64")[:9])) },
		"tarball bad list": func(t *testing.T, ds *dist) {
			files := tarballData("amd64")
			files[6] = reg("deploy/quickstart/binaries.txt", 0o644, "../x\n")
			ds.files[tgz] = gz(t, tarBytes(t, files))
		},
		"tarball two lists": func(t *testing.T, ds *dist) {
			ds.files[tgz] = gz(t, tarBytes(t, append(tarballData("amd64"), reg("deploy/quickstart/binaries.txt", 0o644, "nebula\n"))))
		},
		"tarball bin symlink": func(t *testing.T, ds *dist) {
			files := tarballData("amd64")
			files[0] = symlink("nebula", "/etc/shadow")
			ds.files[tgz] = gz(t, tarBytes(t, files))
		},
		"tarball not gzip": func(t *testing.T, ds *dist) { ds.files[tgz] = tarBytes(t, tarballData("amd64")) },
		"tarball lists differ": func(t *testing.T, ds *dist) {
			files := tarballData("amd64")
			files[6] = reg("deploy/quickstart/binaries.txt", 0o644, "nebula\n")
			ds.files[tgz] = gz(t, tarBytes(t, files))
		},
		"container non-root bin": withContainer(tf{name: "usr/bin/nebula-x", typ: tar.TypeReg, mode: 0o755, uid: 10001}),
		"container unit":         withContainer(reg("lib/systemd/system/nebula-server.service", 0o644, "x")),
		"container hardlink":     withContainer(tf{name: "usr/share/nebula/h", typ: tar.TypeLink, link: "usr/bin/nmap"}),
		"container odd name":     withContainer(reg("usr/share/nebula/a b", 0o644, "x")),
		"container missing bin":  func(t *testing.T, ds *dist) { ds.files[ctr] = tarBytes(t, containerData()[:10]) },
		"checksum mismatch": func(t *testing.T, ds *dist) {
			ds.files[checksumsName(testVersion)] = []byte(fmt.Sprintf("%s  %s\n", hexSum(nil), amd))
		},
		"checksum lists unpublished": func(t *testing.T, ds *dist) {
			var b strings.Builder
			for _, name := range []string{amd, "nebula-operation-station_0.1.0_arm64.deb", tgz, "nebula_0.1.0_linux_arm64.tar.gz"} {
				fmt.Fprintf(&b, "%s  %s\n", hexSum(ds.files[name]), name)
			}
			fmt.Fprintf(&b, "%s  nebula_0.1.0_sbom.json\n", hexSum(nil))
			ds.files[checksumsName(testVersion)] = []byte(b.String())
		},
		"checksum malformed": func(t *testing.T, ds *dist) {
			ds.files[checksumsName(testVersion)] = []byte("not a checksum line\n")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ds := newDist(t)
			mutate(t, ds)
			out := filepath.Join(t.TempDir(), "out")
			_, err := run(t, ds.write(t), out)
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
			if !errors.Is(err, ErrPackage) && !errors.Is(err, release.ErrFormat) && !errors.Is(err, ErrChecksums) {
				t.Fatalf("err = %v, want ErrPackage, ErrChecksums or release.ErrFormat", err)
			}
			// A failed run leaves no partial staging behind.
			if got := dirNames(t, out); len(got) != 0 {
				t.Errorf("out holds %v after the error", got)
			}
		})
	}
}

func TestTarballUnitsMatchInstallScript(t *testing.T) {
	b := string(readFile(t, "../../../deploy/install.sh"))
	start := strings.Index(b, "\ntarball_units=(\n")
	if start < 0 {
		t.Fatal("tarball_units not found in deploy/install.sh")
	}
	body := b[start+len("\ntarball_units=(\n"):]
	body = body[:strings.Index(body, ")")]
	var units []string
	for _, line := range strings.Split(body, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			units = append(units, line)
		}
	}
	if !slices.Equal(units, tarballUnits) {
		t.Fatalf("deploy/install.sh tarball_units = %v, stage uses %v", units, tarballUnits)
	}
}

func TestParseBinariesMatchesRepositoryList(t *testing.T) {
	got, err := parseBinaries(readFile(t, "../../../deploy/quickstart/binaries.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, testBinaries) {
		t.Fatalf("binaries = %v, want %v", got, testBinaries)
	}
	for _, bad := range []string{"", "# only comments\n", "a b\n", "../x\n", "-x\n", "x/y\n"} {
		if _, err := parseBinaries([]byte(bad)); !errors.Is(err, ErrPackage) {
			t.Errorf("%q: err = %v, want ErrPackage", bad, err)
		}
	}
	if got, err := parseBinaries([]byte("  # c\r\nnebula\r\n\t\nnebula-server")); err != nil || !slices.Equal(got, []string{"nebula", "nebula-server"}) {
		t.Errorf("CRLF/whitespace list = %v, %v", got, err)
	}
}
