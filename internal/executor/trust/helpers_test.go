// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"golang.org/x/crypto/ssh"
)

// testSK is a software stand-in for the FIDO release root, test-only.
type testSK struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newTestSK(t *testing.T) *testSK {
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

func (k *testSK) anchors() []release.Anchor {
	return []release.Anchor{{ID: "root-1", Key: k.pub}, {ID: "root-2"}}
}

func (k *testSK) sign(t *testing.T, msg []byte) []byte {
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

func canon(t *testing.T, v any) []byte {
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

func buildTar(t *testing.T, names []string, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, n := range names {
		if err := w.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		w.Write(files[n])
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// mod describes a module version: action name -> script.
type mod struct {
	name, version string
	actions       map[string]string
	risk          string
}

func (m mod) tar(t *testing.T) []byte {
	t.Helper()
	risk := m.risk
	if risk == "" {
		risk = "LOW"
	}
	l := modulelock.Lock{Format: modulelock.Format, Name: m.name, Version: m.version, Title: "Built-in", Description: "",
		Actions: map[string]modulelock.Action{}}
	files := map[string][]byte{}
	for a, script := range m.actions {
		p := "actions/" + a + ".sh"
		files[p] = []byte(script)
		l.Actions[a] = modulelock.Action{Title: a, Script: p, SHA256: hexSum([]byte(script)), Risk: risk, TimeoutS: 60,
			Params: []prelude.Param{}, Secrets: []string{}, Declares: []string{}}
	}
	files[release.LockFile] = canon(t, l)
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sortStrings(names)
	return buildTar(t, names, files)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// candidate builds, signs, writes and reads a release bundle directory.
func candidate(t *testing.T, k *testSK, roots []release.Root, version string, mods ...mod) release.Candidate {
	t.Helper()
	c, err := tryCandidate(t, k, roots, version, nil, mods...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tryCandidate allows overriding a module's tar bytes (substitution).
func tryCandidate(t *testing.T, k *testSK, roots []release.Root, version string, override map[string][]byte, mods ...mod) (release.Candidate, error) {
	t.Helper()
	sortMods(mods)
	var names []string
	files := map[string][]byte{}
	var mm []any
	for _, m := range mods {
		b := m.tar(t)
		if o, ok := override[m.name]; ok {
			b = o
		}
		p := "modules/" + m.name + "/" + m.version + ".tar"
		names = append(names, p)
		files[p] = b
		mm = append(mm, map[string]any{"name": m.name, "version": m.version, "size": len(b), "sha256": hexSum(b)})
	}
	bundle := buildTar(t, names, files)
	man := canon(t, map[string]any{"format": release.ManifestFormat, "release_version": version,
		"artifacts": []any{map[string]any{"name": release.BundleArtifact, "size": len(bundle), "sha256": hexSum(bundle)}},
		"modules":   mm})
	dir := t.TempDir()
	for n, b := range map[string][]byte{release.ManifestFile: man, release.SignatureFile: k.sign(t, man), release.BundleArtifact: bundle} {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return release.ReadBundleDir(dir, roots)
}

func sortMods(m []mod) {
	for i := 1; i < len(m); i++ {
		for j := i; j > 0 && m[j-1].name > m[j].name; j-- {
			m[j-1], m[j] = m[j], m[j-1]
		}
	}
}

// env is a store with a controllable clock.
type env struct {
	t    *testing.T
	k    *testSK
	dir  string
	now  time.Time
	s    *Store
	free uint64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, k: newTestSK(t), dir: filepath.Join(t.TempDir(), "trust"), now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), free: 1 << 40}
	e.reopen()
	return e
}

func (e *env) reopen() {
	e.t.Helper()
	s, err := Open(e.dir, e.k.anchors(), func() time.Time { return e.now })
	if err != nil {
		e.t.Fatal(err)
	}
	s.freeSpace = func(string) (uint64, error) { return e.free, nil }
	e.s = s
}

func (e *env) candidate(version string, mods ...mod) release.Candidate {
	e.t.Helper()
	return candidate(e.t, e.k, e.s.Roots(), version, mods...)
}

// admit reviews and admits a candidate.
func (e *env) admit(c release.Candidate) (Review, Result) {
	e.t.Helper()
	r, err := e.s.Review(c)
	if err != nil {
		e.t.Fatalf("review: %v", err)
	}
	res, err := e.s.Admit(c, r)
	if err != nil {
		e.t.Fatalf("admit: %v", err)
	}
	return r, res
}

func docker(version, script string) mod {
	return mod{name: "docker", version: version, actions: map[string]string{"restart": script}}
}
