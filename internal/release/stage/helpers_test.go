// SPDX-License-Identifier: AGPL-3.0-or-later

package stage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoModules is the repository's module tree.
const repoModules = "../../../modules"

const testVersion = "0.1.0"

// tf is one archive entry of a test package.
type tf struct {
	name     string
	typ      byte
	mode     int64
	data     string
	link     string
	uid, gid int
}

func reg(name string, mode int64, data string) tf {
	return tf{name: name, typ: tar.TypeReg, mode: mode, data: data}
}

func dir(name string) tf { return tf{name: name, typ: tar.TypeDir, mode: 0o755} }

func symlink(name, target string) tf {
	return tf{name: name, typ: tar.TypeSymlink, mode: 0o777, link: target}
}

func tarBytes(t testing.TB, files []tf) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, f := range files {
		h := &tar.Header{Name: f.name, Typeflag: f.typ, Mode: f.mode, Linkname: f.link,
			Uid: f.uid, Gid: f.gid, Format: tar.FormatGNU}
		if f.typ == tar.TypeReg {
			h.Size = int64(len(f.data))
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if f.typ == tar.TypeReg {
			if _, err := w.Write([]byte(f.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// arMember is one member of a test .deb.
type arMember struct {
	name string
	data []byte
}

func arBytes(members []arMember) []byte {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&buf, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", m.name, 0, 0, 0, "100644", len(m.data))
		buf.Write(m.data)
		if len(m.data)%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

func debBytes(t testing.TB, data []tf) []byte {
	t.Helper()
	return arBytes([]arMember{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", gz(t, tarBytes(t, []tf{reg("./control", 0o644, "Package: nebula-operation-station\n")}))},
		{"data.tar.gz", gz(t, tarBytes(t, data))},
	})
}

var testBinaries = []string{"nebula", "nebula-server", "nebula-executor", "nebula-discovery", "nebula-pve-collector", "nebula-netdev-collector"}

const binariesTxt = "# Binaries Nebula ships.\n\nnebula\nnebula-server\nnebula-executor\nnebula-discovery\nnebula-pve-collector\nnebula-netdev-collector\n"

func debData(arch string) []tf {
	files := []tf{dir("./"), dir("./usr/"), dir("./usr/bin/")}
	for _, b := range testBinaries {
		files = append(files, reg("./usr/bin/"+b, 0o755, b+" "+arch))
	}
	return append(files,
		dir("./lib/"), dir("./lib/systemd/"), dir("./lib/systemd/system/"),
		reg("./lib/systemd/system/nebula-server.service", 0o644, "[Unit]\n"),
		dir("./usr/share/nebula/release/"),
		reg("./usr/share/nebula/deploy/install.sh", 0o755, "#!/bin/sh\n"),
		symlink("./usr/share/nebula/web/app.css", "app.1234.css"),
		reg("./usr/share/doc/nebula-operation-station/guide.md", 0o644, "# guide\n"),
	)
}

func tarballData(arch string) []tf {
	var files []tf
	for _, b := range testBinaries {
		files = append(files, reg(b, 0o755, b+" "+arch))
	}
	files = append(files, reg("deploy/quickstart/binaries.txt", 0o644, binariesTxt),
		reg("deploy/install.sh", 0o755, "#!/bin/sh\n"))
	for _, u := range tarballUnits {
		files = append(files, reg("deploy/systemd/"+u, 0o644, "[Unit]\n# "+u+"\n"))
	}
	return append(files, reg("deploy/systemd/nebula-iconfetch.service", 0o644, "[Unit]\n"))
}

func containerData() []tf {
	files := []tf{dir("usr/"), dir("usr/bin/"), reg("usr/bin/nmap", 0o755, "nmap"),
		{name: "usr/bin/perl5", typ: tar.TypeLink, link: "usr/bin/nmap"},
		dir("etc/nebula/"), reg("etc/hostname", 0o644, ""), reg(".dockerenv", 0o755, ""),
		{name: "var/lib/nebula/executor/", typ: tar.TypeDir, mode: 0o700, uid: 10001, gid: 10001},
		dir("usr/share/nebula/"), dir("usr/share/nebula/release/")}
	for _, b := range testBinaries {
		files = append(files, reg("usr/bin/"+b, 0o755, b+" amd64"))
	}
	return files
}

// dist is a fake goreleaser output directory.
type dist struct {
	files map[string][]byte
}

func newDist(t testing.TB) *dist {
	t.Helper()
	d := &dist{files: map[string][]byte{}}
	for _, arch := range []string{"amd64", "arm64"} {
		d.files[fmt.Sprintf("nebula-operation-station_%s_%s.deb", testVersion, arch)] = debBytes(t, debData(arch))
		d.files[fmt.Sprintf("nebula_%s_linux_%s.tar.gz", testVersion, arch)] = gz(t, tarBytes(t, tarballData(arch)))
	}
	d.files[fmt.Sprintf("nebula_%s_container_linux_amd64.tar", testVersion)] = tarBytes(t, containerData())
	return d
}

// write writes the dist with a goreleaser checksum file over the
// archives and packages.
func (d *dist) write(t testing.TB) string {
	t.Helper()
	p := t.TempDir()
	var names []string
	for name, b := range d.files {
		if err := os.WriteFile(filepath.Join(p, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(name, "_container_linux_amd64.tar") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		fmt.Fprintf(&sums, "%s  %s\n", hexSum(d.files[name]), name)
	}
	if _, ok := d.files[checksumsName(testVersion)]; !ok {
		if err := os.WriteFile(filepath.Join(p, checksumsName(testVersion)), []byte(sums.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// goreleaser leaves more in dist; it must not be published.
	if err := os.MkdirAll(filepath.Join(p, "nebula_linux_amd64_v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "config.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func run(t testing.TB, distDir, out string) (Result, error) {
	t.Helper()
	return Run(t.Context(), Options{Version: testVersion, Dist: distDir, Out: out, Modules: repoModules})
}

func readFile(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
