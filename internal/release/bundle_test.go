// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// verifyRelease parses a manifest map and verifies bundle against it.
func verifyRelease(t *testing.T, man map[string]any, bundle []byte) ([]ModuleBundle, error) {
	t.Helper()
	m, err := ParseManifest(canon(t, man))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	return VerifyBundle(m, bundle)
}

func TestVerifyBundle(t *testing.T) {
	man, bundle := defaultRelease(t)
	mods, err := verifyRelease(t, man, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || mods[0].Lock.Name != "docker" || mods[1].Lock.Name != "os-debian" {
		t.Fatalf("modules = %+v", mods)
	}
	a := mods[1].Actions
	if len(a) != 1 || a[0].ActionID != "os-debian.restart" || a[0].Risk != "MEDIUM" || a[0].ScriptSHA256 != hexSum(testScript) ||
		a[0].SHA256 != hexSum(a[0].Bytes) || !bytes.Contains(a[0].Bytes, testScript[10:]) {
		t.Fatalf("actions = %+v", a)
	}
	if strings.Join(mods[0].Paths, ",") != "actions/restart.sh,module.lock.json" {
		t.Fatalf("paths = %v", mods[0].Paths)
	}
}

// rebuild re-points the manifest at a changed builtins.tar.
func rebuild(t *testing.T, man map[string]any, bundle []byte) map[string]any {
	a := man["artifacts"].([]any)[0].(map[string]any)
	a["size"], a["sha256"] = len(bundle), hexSum(bundle)
	return man
}

func TestVerifyBundleRejectsOuter(t *testing.T) {
	good := func() (map[string]any, []byte) { return defaultRelease(t) }
	cases := map[string]func() (map[string]any, []byte){
		"bundle hash": func() (map[string]any, []byte) {
			m, b := good()
			b = append([]byte{}, b...)
			b[600] ^= 1
			return m, b
		},
		"bundle size": func() (map[string]any, []byte) { m, b := good(); return m, append(b, make([]byte, 512)...) },
		"trailing nonzero": func() (map[string]any, []byte) {
			m, b := good()
			b = append(append([]byte{}, b...), bytes.Repeat([]byte{1}, 512)...)
			return rebuild(t, m, b), b
		},
		"missing end blocks": func() (map[string]any, []byte) {
			m, b := good()
			b = trimZeroTail(b)
			return rebuild(t, m, b), b
		},
		"module order": func() (map[string]any, []byte) {
			m, _ := good()
			b := buildTar(t, []tarFile{
				{name: "modules/os-debian/2.0.1.tar", data: moduleTar(t, "os-debian", "2.0.1")},
				{name: "modules/docker/1.2.0.tar", data: moduleTar(t, "docker", "1.2.0")},
			})
			return rebuild(t, m, b), b
		},
		"module missing": func() (map[string]any, []byte) {
			m, _ := good()
			b := buildTar(t, []tarFile{{name: "modules/docker/1.2.0.tar", data: moduleTar(t, "docker", "1.2.0")}})
			return rebuild(t, m, b), b
		},
		"extra module": func() (map[string]any, []byte) {
			m, _ := good()
			b := buildTar(t, []tarFile{
				{name: "modules/docker/1.2.0.tar", data: moduleTar(t, "docker", "1.2.0")},
				{name: "modules/os-debian/2.0.1.tar", data: moduleTar(t, "os-debian", "2.0.1")},
				{name: "modules/zz/1.0.0.tar", data: moduleTar(t, "zz", "1.0.0")},
			})
			return rebuild(t, m, b), b
		},
		"wrong version path": func() (map[string]any, []byte) {
			m, _ := good()
			b := buildTar(t, []tarFile{
				{name: "modules/docker/1.2.1.tar", data: moduleTar(t, "docker", "1.2.0")},
				{name: "modules/os-debian/2.0.1.tar", data: moduleTar(t, "os-debian", "2.0.1")},
			})
			return rebuild(t, m, b), b
		},
		"module bytes differ from manifest": func() (map[string]any, []byte) {
			m, _ := good()
			other := buildTar(t, []tarFile{
				{name: "actions/restart.sh", data: testScript},
				{name: LockFile, data: testLock(t, "docker", "1.2.0")},
				{name: "zz", data: []byte("x")},
			})
			b := buildTar(t, []tarFile{
				{name: "modules/docker/1.2.0.tar", data: other},
				{name: "modules/os-debian/2.0.1.tar", data: moduleTar(t, "os-debian", "2.0.1")},
			})
			return rebuild(t, m, b), b
		},
		"directory entry": func() (map[string]any, []byte) {
			m, _ := good()
			b := buildTar(t, []tarFile{{name: "modules/", typ: tar.TypeDir},
				{name: "modules/docker/1.2.0.tar", data: moduleTar(t, "docker", "1.2.0")},
				{name: "modules/os-debian/2.0.1.tar", data: moduleTar(t, "os-debian", "2.0.1")}})
			return rebuild(t, m, b), b
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			m, b := f()
			if _, err := verifyRelease(t, m, b); !errors.Is(err, ErrBundle) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func trimZeroTail(b []byte) []byte {
	end := len(b)
	for end >= tarBlock && allZero(b[end-tarBlock:end]) {
		end -= tarBlock
	}
	return append([]byte{}, b[:end]...)
}

func TestVerifyBundleRejectsModuleContent(t *testing.T) {
	lock := func() []byte { return testLock(t, "docker", "1.2.0") }
	cases := map[string][]byte{
		"missing lock":   buildTar(t, []tarFile{{name: "actions/restart.sh", data: testScript}}),
		"missing script": buildTar(t, []tarFile{{name: LockFile, data: lock()}}),
		"extra file": buildTar(t, []tarFile{{name: "actions/restart.sh", data: testScript}, {name: "extra.txt", data: []byte("x")},
			{name: LockFile, data: lock()}}),
		"unsorted":       buildTar(t, []tarFile{{name: LockFile, data: lock()}, {name: "actions/restart.sh", data: testScript}}),
		"duplicate":      buildTar(t, []tarFile{{name: "actions/restart.sh", data: testScript}, {name: "actions/restart.sh", data: testScript}, {name: LockFile, data: lock()}}),
		"changed script": buildTar(t, []tarFile{{name: "actions/restart.sh", data: append([]byte("#x\n"), testScript...)}, {name: LockFile, data: lock()}}),
		"lock names other module": buildTar(t, []tarFile{{name: "actions/restart.sh", data: testScript},
			{name: LockFile, data: testLock(t, "core", "1.2.0")}}),
		"lock names other version": buildTar(t, []tarFile{{name: "actions/restart.sh", data: testScript},
			{name: LockFile, data: testLock(t, "docker", "1.2.1")}}),
		"symlink":     buildTar(t, []tarFile{{name: "actions/restart.sh", typ: tar.TypeSymlink}, {name: LockFile, data: lock()}}),
		"hardlink":    buildTar(t, []tarFile{{name: "actions/restart.sh", typ: tar.TypeLink}, {name: LockFile, data: lock()}}),
		"fifo":        buildTar(t, []tarFile{{name: "actions/restart.sh", typ: tar.TypeFifo}, {name: LockFile, data: lock()}}),
		"traversal":   buildTar(t, []tarFile{{name: "../actions/restart.sh", data: testScript}, {name: LockFile, data: lock()}}),
		"absolute":    buildTar(t, []tarFile{{name: "/actions/restart.sh", data: testScript}, {name: LockFile, data: lock()}}),
		"uppercase":   buildTar(t, []tarFile{{name: "Actions/restart.sh", data: testScript}, {name: LockFile, data: lock()}}),
		"deep path":   buildTar(t, []tarFile{{name: "a/b/c/d/e.sh", data: testScript}, {name: LockFile, data: lock()}}),
		"pax record":  paxTar(t, lock()),
		"gnu header":  gnuTar(t, lock()),
		"nested gzip": []byte{0x1f, 0x8b, 8, 0},
	}
	for name, mt := range cases {
		t.Run(name, func(t *testing.T) {
			man, b := release(t, testModule{name: "docker", version: "1.2.0", tar: mt})
			if _, err := verifyRelease(t, man, b); !errors.Is(err, ErrBundle) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func paxTar(t *testing.T, lock []byte) []byte {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	h := &tar.Header{Name: "actions/restart.sh", Size: int64(len(testScript)), Mode: 0o644, Format: tar.FormatPAX,
		PAXRecords: map[string]string{"comment": "x"}}
	if err := w.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	w.Write(testScript)
	w.WriteHeader(&tar.Header{Name: LockFile, Size: int64(len(lock)), Mode: 0o644, Format: tar.FormatUSTAR})
	w.Write(lock)
	w.Close()
	return buf.Bytes()
}

func gnuTar(t *testing.T, lock []byte) []byte {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	if err := w.WriteHeader(&tar.Header{Name: "actions/restart.sh", Size: int64(len(testScript)), Mode: 0o644, Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	w.Write(testScript)
	w.WriteHeader(&tar.Header{Name: LockFile, Size: int64(len(lock)), Mode: 0o644, Format: tar.FormatGNU})
	w.Write(lock)
	w.Close()
	return buf.Bytes()
}

func TestReadUstarRejectsMalformedHeaders(t *testing.T) {
	good := buildTar(t, []tarFile{{name: "a", data: []byte("hello")}})
	lim := tarLimits{maxEntries: 4, maxFile: 1 << 10, maxTotal: 1 << 10}
	ok := func(string) bool { return true }
	if _, err := readUstar(good, lim, ok); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(b []byte)) []byte { b := append([]byte{}, good...); f(b); return b }
	for name, b := range map[string][]byte{
		"checksum":        mut(func(b []byte) { b[0] = 'b' }),
		"padding":         mut(func(b []byte) { b[512+5] = 'x' }),
		"base256 size":    mut(func(b []byte) { b[124] = 0x80; fixSum(b) }),
		"size overflow":   mut(func(b []byte) { copy(b[124:136], "77777777777\x00"); fixSum(b) }),
		"name not padded": mut(func(b []byte) { b[50] = 'x'; fixSum(b) }),
		"not multiple":    good[:len(good)-1],
		"empty":           {},
	} {
		if _, err := readUstar(b, lim, ok); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := readUstar(good, tarLimits{maxEntries: 4, maxFile: 4, maxTotal: 1 << 10}, ok); err == nil {
		t.Error("file over the limit accepted")
	}
	two := buildTar(t, []tarFile{{name: "a", data: []byte("x")}, {name: "b", data: []byte("y")}})
	if _, err := readUstar(two, tarLimits{maxEntries: 1, maxFile: 4, maxTotal: 1 << 10}, ok); err == nil {
		t.Error("too many entries accepted")
	}
	if _, err := readUstar(two, tarLimits{maxEntries: 4, maxFile: 4, maxTotal: 1}, ok); err == nil {
		t.Error("total over the limit accepted")
	}
}

func fixSum(b []byte) {
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	var s int64
	for _, c := range b[:512] {
		s += int64(c)
	}
	copy(b[148:156], []byte(strings.Repeat("0", 6-len(octal(s)))+octal(s)+"\x00 "))
}

func octal(n int64) string {
	if n == 0 {
		return "0"
	}
	var s []byte
	for n > 0 {
		s = append([]byte{byte('0' + n%8)}, s...)
		n /= 8
	}
	return string(s)
}

func FuzzReadUstar(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = readUstar(b, tarLimits{maxEntries: 8, maxFile: 1 << 16, maxTotal: 1 << 16}, validInnerPath)
	})
}

func writeBundleDir(t *testing.T, k *testSK) string {
	t.Helper()
	man, bundle := defaultRelease(t)
	raw := canon(t, man)
	dir := t.TempDir()
	for name, b := range map[string][]byte{ManifestFile: raw, SignatureFile: k.sign(t, raw), BundleArtifact: bundle} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReadBundleDir(t *testing.T) {
	k := newTestSK(t)
	roots := []Root{k.root("root-1")}
	c, err := ReadBundleDir(writeBundleDir(t, k), roots)
	if err != nil {
		t.Fatal(err)
	}
	if c.Manifest.SignedBy.ID != "root-1" || len(c.Modules) != 2 {
		t.Fatalf("candidate = %+v", c.Manifest)
	}
	// A key shipped beside the bundle establishes no trust.
	if _, err := ReadBundleDir(writeBundleDir(t, newTestSK(t)), roots); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("foreign signer: %v", err)
	}
	extra := writeBundleDir(t, k)
	os.WriteFile(filepath.Join(extra, "trusted.pub"), []byte(FormatRootKey(k.pub)), 0o600)
	if _, err := ReadBundleDir(extra, roots); !errors.Is(err, ErrBundle) {
		t.Fatalf("extra file: %v", err)
	}
	link := writeBundleDir(t, k)
	target := filepath.Join(t.TempDir(), "builtins.tar")
	os.Rename(filepath.Join(link, BundleArtifact), target)
	if err := os.Symlink(target, filepath.Join(link, BundleArtifact)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBundleDir(link, roots); !errors.Is(err, ErrBundle) {
		t.Fatalf("symlinked bundle: %v", err)
	}
	sub := writeBundleDir(t, k)
	os.Remove(filepath.Join(sub, SignatureFile))
	os.Mkdir(filepath.Join(sub, SignatureFile), 0o700)
	if _, err := ReadBundleDir(sub, roots); !errors.Is(err, ErrBundle) {
		t.Fatalf("directory as signature: %v", err)
	}
}
