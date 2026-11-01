// SPDX-License-Identifier: AGPL-3.0-or-later

package release

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
	"testing"

	"github.com/gowebpki/jcs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
	"golang.org/x/crypto/ssh"
)

// testSK is a software stand-in for a FIDO security key, test-only. It
// writes OpenSSH sk-ssh-ed25519 signatures (PROTOCOL.u2f) in SSHSIG
// envelopes, so the production verifier is exercised end to end.
type testSK struct {
	priv ed25519.PrivateKey
	app  string
	pub  ssh.PublicKey
}

func newTestSK(t *testing.T) *testSK { return newTestSKApp(t, Application) }

func newTestSKApp(t *testing.T, app string) *testSK {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Type        string
		PubKey      []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, app}))
	if err != nil {
		t.Fatal(err)
	}
	return &testSK{priv: priv, app: app, pub: k}
}

func (k *testSK) root(id string) Root { return Root{ID: id, Key: k.pub} }

// signNS signs msg in namespace ns with the given FIDO flags.
func (k *testSK) signNS(t *testing.T, ns string, flags byte, msg []byte) []byte {
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
	}{m, ns, "", "sha512", h[:]})
	app := sha256.Sum256([]byte(k.app))
	data := sha256.Sum256(signed)
	fido := ssh.Marshal(struct {
		App     []byte `ssh:"rest"`
		Flags   byte
		Counter uint32
		Data    []byte `ssh:"rest"`
	}{app[:], flags, 1, data[:]})
	sig := ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(k.priv, fido),
		Rest: ssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{flags, 1})}
	raw := ssh.Marshal(struct {
		Magic     [6]byte
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}{m, 1, k.pub.Marshal(), ns, "", "sha512", ssh.Marshal(sig)})
	return []byte("-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(raw) + "\n-----END SSH SIGNATURE-----\n")
}

func (k *testSK) sign(t *testing.T, msg []byte) []byte { return k.signNS(t, Namespace, 0x01, msg) }

// canon returns the JCS form of v.
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

// tarFile is one archive member for buildTar.
type tarFile struct {
	name string
	data []byte
	typ  byte
}

// buildTar writes a POSIX ustar archive with archive/tar.
func buildTar(t *testing.T, files []tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: typ, Format: tar.FormatUSTAR}
		if typ != tar.TypeReg {
			h.Size = 0
			if typ == tar.TypeSymlink || typ == tar.TypeLink {
				h.Linkname = "module.lock.json"
			}
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := w.Write(f.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var testScript = []byte("#!/bin/sh\nsystemctl restart docker\n")

func testLock(t *testing.T, name, version string) []byte {
	t.Helper()
	l := modulelock.Lock{Format: modulelock.Format, Name: name, Version: version, Title: "Docker", Description: "Built-in.",
		Actions: map[string]modulelock.Action{"restart": {Title: "Restart", Script: "actions/restart.sh", SHA256: hexSum(testScript),
			Risk: "LOW", TimeoutS: 60, Params: []prelude.Param{}, Secrets: []string{}, Declares: []string{"requires_root"}}}}
	return canon(t, l)
}

// moduleTar builds a valid module tar for name/version.
func moduleTar(t *testing.T, name, version string) []byte {
	return buildTar(t, []tarFile{
		{name: "actions/restart.sh", data: testScript},
		{name: LockFile, data: testLock(t, name, version)},
	})
}

type testModule struct {
	name, version string
	tar           []byte
}

// release builds a manifest (as a map, for mutation), builtins.tar and
// the module list for the given modules.
func release(t *testing.T, mods ...testModule) (map[string]any, []byte) {
	t.Helper()
	var entries []tarFile
	var mm []any
	for _, m := range mods {
		if m.tar == nil {
			m.tar = moduleTar(t, m.name, m.version)
		}
		entries = append(entries, tarFile{name: "modules/" + m.name + "/" + m.version + ".tar", data: m.tar})
		mm = append(mm, map[string]any{"name": m.name, "version": m.version, "size": len(m.tar), "sha256": hexSum(m.tar)})
	}
	bundle := buildTar(t, entries)
	man := map[string]any{
		"format":          ManifestFormat,
		"release_version": "1.4.0",
		"artifacts": []any{
			map[string]any{"name": BundleArtifact, "size": len(bundle), "sha256": hexSum(bundle)},
			map[string]any{"name": "nebula-server_1.4.0_amd64.deb", "size": 1234, "sha256": hexSum([]byte("deb"))},
		},
		"modules": mm,
	}
	return man, bundle
}

func defaultRelease(t *testing.T) (map[string]any, []byte) {
	return release(t, testModule{name: "docker", version: "1.2.0"}, testModule{name: "os-debian", version: "2.0.1"})
}
