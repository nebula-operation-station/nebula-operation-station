// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"golang.org/x/crypto/ssh"
)

// testSK is a software stand-in for the FIDO release root, test-only. It
// writes the same sk-ssh-ed25519 SSHSIG envelopes as the helpers in
// internal/release (which are _test.go files and cannot be imported), so
// the production verifier release.VerifyInstalledFiles runs end to end.
type testSK struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newTestSK(t testing.TB) *testSK {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Type        string
		PubKey      []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, release.Application}))
	if err != nil {
		t.Fatal(err)
	}
	return &testSK{priv: priv, pub: k}
}

// state returns a bootstrap root state trusting only k.
func (k *testSK) state(t testing.TB) release.RootState {
	t.Helper()
	s, err := release.Bootstrap([]release.Anchor{{ID: "root-1", Key: k.pub}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (k *testSK) sign(t testing.TB, msg []byte) []byte {
	t.Helper()
	h := sha512.Sum512(msg)
	var m [6]byte
	copy(m[:], "SSHSIG")
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{m, release.Namespace, "", "sha512", h[:]})
	app := sha256.Sum256([]byte(release.Application))
	data := sha256.Sum256(signed)
	fido := ssh.Marshal(struct {
		App     []byte `ssh:"rest"`
		Flags   byte
		Counter uint32
		Data    []byte `ssh:"rest"`
	}{app[:], 1, 0, data[:]})
	sig := ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(k.priv, fido),
		Rest: ssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{1, 0})}
	raw := ssh.Marshal(struct {
		Magic     [6]byte
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}{m, 1, k.pub.Marshal(), release.Namespace, "", "sha512", ssh.Marshal(sig)})
	return []byte("-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(raw) + "\n-----END SSH SIGNATURE-----\n")
}

func canon(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	c, err := jcs.Transform(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// signedRelease returns a manifest for version that covers list as
// installed-files.json, and k's signature over it.
func signedRelease(t testing.TB, k *testSK, version string, list []byte) (manifest, sig []byte) {
	t.Helper()
	bundle := []byte("builtins")
	mod := []byte("module tar")
	manifest = canon(t, map[string]any{
		"format":          release.ManifestFormat,
		"release_version": version,
		"artifacts": []any{
			map[string]any{"name": release.BundleArtifact, "size": len(bundle), "sha256": hexSum(bundle)},
			map[string]any{"name": release.InstalledFilesArtifact, "size": len(list), "sha256": hexSum(list)},
		},
		"modules": []any{map[string]any{"name": "docker", "version": "1.2.0", "size": len(mod), "sha256": hexSum(mod)}},
	})
	return manifest, k.sign(t, manifest)
}

const (
	testVersion = "1.4.0"
	testFlavour = "deb:amd64"
	testOwner   = "root:root"
)

// treeFile is one file of the test installation tree.
type treeFile struct {
	path   string // absolute installed path
	data   string
	mode   fs.FileMode
	target string // non-empty: a symlink
}

// defaultTree is a small deb installation. /lib is the merged-/usr
// symlink to usr/lib, as on current Debian.
func defaultTree() []treeFile {
	return []treeFile{
		{path: "/usr/bin/nebula", target: "nebula-server"},
		{path: "/usr/bin/nebula-executor", data: "executor binary", mode: 0o755},
		{path: "/usr/bin/nebula-server", data: "server binary", mode: 0o755},
		{path: "/lib/systemd/system/nebula-server.service", data: "[Unit]\n", mode: 0o644},
		{path: "/usr/lib/systemd/system/nebula-executor.service", data: "[Unit]\nexec\n", mode: 0o644},
		{path: "/usr/share/nebula/release/builtins.tar", data: "builtins", mode: 0o644},
		{path: "/usr/share/nebula/release/rootkeys.txt", data: "root-1 sk-ssh-ed25519\n", mode: 0o644},
		{path: "/usr/share/nebula/web/app.css", data: "body{}", mode: 0o644},
		{path: "/usr/share/doc/nebula-operation-station/guide.md", data: "# guide\n", mode: 0o644},
	}
}

// fixture is a signed list for a tree and the tree written under a
// temporary root.
type fixture struct {
	root      string
	k         *testSK
	ref       Reference
	manifest  []byte
	sig       []byte
	list      []byte
	installed []treeFile
}

// newFixture writes tree under a temp root (with /lib -> usr/lib) and
// admits a signed installed-files list describing it.
func newFixture(t *testing.T, tree []treeFile) *fixture {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	var files []release.InstalledFile
	for _, f := range tree {
		p := filepath.Join(root, f.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if f.target != "" {
			if err := os.Symlink(f.target, p); err != nil {
				t.Fatal(err)
			}
			files = append(files, release.InstalledFile{Path: f.path, Type: release.FileSymlink, Target: f.target, Owner: testOwner})
			continue
		}
		writeFile(t, p, f.data, f.mode)
		files = append(files, release.InstalledFile{Path: f.path, Type: release.FileRegular, Size: int64(len(f.data)),
			SHA256: hexSum([]byte(f.data)), Mode: uint32(f.mode), Owner: testOwner})
	}
	sortFiles(files)
	l := release.InstalledFiles{ReleaseVersion: testVersion, Flavours: []release.Flavour{{Name: testFlavour, Files: files}}}
	list, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k := newTestSK(t)
	man, sig := signedRelease(t, k, testVersion, list)
	ref, err := Admit(k.state(t), testVersion, man, sig, list)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{root: root, k: k, ref: ref, manifest: man, sig: sig, list: list, installed: tree}
}

func writeFile(t *testing.T, p, data string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func sortFiles(files []release.InstalledFile) {
	for i := 1; i < len(files); i++ {
		for j := i; j > 0 && files[j].Path < files[j-1].Path; j-- {
			files[j], files[j-1] = files[j-1], files[j]
		}
	}
}

// opts returns check options for f's tree; the test process owns the
// files, so "root:root" resolves to the current IDs.
func (f *fixture) opts() Options {
	return Options{
		Root:    f.root,
		Flavour: testFlavour,
		Owners: func(owner string) (uint32, uint32, error) {
			if owner != testOwner {
				return 0, 0, os.ErrNotExist
			}
			return uint32(os.Getuid()), uint32(os.Getgid()), nil
		},
	}
}

func (f *fixture) path(p string) string { return filepath.Join(f.root, p) }

// fakeClock advances by step on every call.
type fakeClock struct {
	now  time.Time
	step time.Duration
}

func (c *fakeClock) Now() time.Time { c.now = c.now.Add(c.step); return c.now }

// resultFor returns the result for path.
func resultFor(t *testing.T, r Report, path string) FileResult {
	t.Helper()
	for _, fr := range r.Files {
		if fr.Path == path {
			return fr
		}
	}
	t.Fatalf("no result for %s in %+v", path, r.Files)
	return FileResult{}
}
