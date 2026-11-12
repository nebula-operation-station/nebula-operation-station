// SPDX-License-Identifier: AGPL-3.0-or-later

package main

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
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"golang.org/x/crypto/ssh"
)

// testSK is a software stand-in for a FIDO security key, test-only (as in
// internal/release and internal/sshsig). It writes OpenSSH sk-ssh-ed25519
// signatures in SSHSIG envelopes, so the production verifier runs end to
// end.
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

// sign signs msg in the release namespace with the given FIDO flags
// (0x01 is user presence).
func (k *testSK) sign(t *testing.T, flags byte, msg []byte) []byte {
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

func buildTar(t *testing.T, names []string, data [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for i, n := range names {
		h := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(data[i])), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var testScript = []byte("#!/bin/sh\nsystemctl restart docker\n")

func moduleTar(t *testing.T, name, version string) []byte {
	t.Helper()
	l := modulelock.Lock{Format: modulelock.Format, Name: name, Version: version, Title: "Docker", Description: "Built-in.",
		Actions: map[string]modulelock.Action{"restart": {Title: "Restart", Script: "actions/restart.sh", SHA256: hexSum(testScript),
			Risk: "LOW", TimeoutS: 60, Params: []prelude.Param{}, Secrets: []string{}, Declares: []string{"requires_root"}}}}
	return buildTar(t, []string{"actions/restart.sh", release.LockFile}, [][]byte{testScript, canon(t, l)})
}

const (
	debName = "nebula-server_1.4.0_amd64.deb"
	version = "1.4.0"
)

// staging is a staged, signed release in a temporary directory.
type staging struct {
	dir      string
	sk       *testSK
	manifest []byte
	payloads map[string][]byte
}

// stageRelease writes release-manifest.json, its signature (made with
// flags) and payloads/ with builtins.tar, installed-files.json and a .deb.
func stageRelease(t *testing.T, flags byte) *staging {
	t.Helper()
	mod := moduleTar(t, "docker", "1.2.0")
	bundle := buildTar(t, []string{"modules/docker/1.2.0.tar"}, [][]byte{mod})
	list, err := release.InstalledFiles{ReleaseVersion: version, Flavours: []release.Flavour{{Name: "deb:amd64", Files: []release.InstalledFile{
		{Path: "/usr/bin/nebula", Type: release.FileRegular, Size: 3, SHA256: hexSum([]byte("bin")), Mode: 0o755, Owner: "root:root"},
	}}}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	payloads := map[string][]byte{
		release.BundleArtifact:         bundle,
		release.InstalledFilesArtifact: list,
		debName:                        []byte("debian package bytes"),
	}
	var arts []any
	for _, n := range []string{release.BundleArtifact, release.InstalledFilesArtifact, debName} {
		arts = append(arts, map[string]any{"name": n, "size": len(payloads[n]), "sha256": hexSum(payloads[n])})
	}
	man := canon(t, map[string]any{
		"format":          release.ManifestFormat,
		"release_version": version,
		"artifacts":       arts,
		"modules":         []any{map[string]any{"name": "docker", "version": "1.2.0", "size": len(mod), "sha256": hexSum(mod)}},
	})
	s := &staging{dir: t.TempDir(), sk: newTestSK(t), manifest: man, payloads: payloads}
	s.write(t, release.ManifestFile, man)
	s.write(t, release.SignatureFile, s.sk.sign(t, flags, man))
	if err := os.Mkdir(filepath.Join(s.dir, payloadsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range payloads {
		s.write(t, filepath.Join(payloadsDir, n), b)
	}
	return s
}

func (s *staging) write(t *testing.T, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *staging) check(t *testing.T) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := check(t.Context(), s.dir, s.sk.anchors(), &out)
	return code, out.String()
}

func wantFail(t *testing.T, code int, out string, needles ...string) {
	t.Helper()
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if !strings.HasPrefix(lines[len(lines)-1], "RESULT: FAILED") {
		t.Fatalf("last line is not the failure result\n%s", out)
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "RESULT: OK") {
			t.Fatalf("an OK result line in a failed check\n%s", out)
		}
	}
	for _, n := range needles {
		if !strings.Contains(out, n) {
			t.Errorf("output lacks %q\n%s", n, out)
		}
	}
}

func TestValidStagedReleasePasses(t *testing.T) {
	s := stageRelease(t, 0x01)
	// Other staging entries (module-bytes/, installed/, SHA256SUMS, the
	// helper scripts and even a public key) are outside the check and
	// never consulted.
	s.write(t, "SHA256SUMS", []byte("x\n"))
	s.write(t, "root-1.pub", []byte(release.FormatRootKey(newTestSK(t).pub)+"\n"))
	code, out := s.check(t)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, n := range []string{"user presence verified", "signed by root-1", "RESULT: OK",
		`ok "builtins.tar"`, `ok "installed-files.json"`, `ok "` + debName + `"`, "docker 1.2.0", "deb:amd64"} {
		if !strings.Contains(out, n) {
			t.Errorf("output lacks %q\n%s", n, out)
		}
	}
}

func TestSignatureByUntrustedKeyFails(t *testing.T) {
	s := stageRelease(t, 0x01)
	other := newTestSK(t)
	s.write(t, release.SignatureFile, other.sign(t, 0x01, s.manifest))
	code, out := s.check(t)
	wantFail(t, code, out, "not a trusted release root")
	if strings.Contains(out, `ok "`) {
		t.Errorf("payloads checked after a failed manifest signature\n%s", out)
	}
}

func TestTamperedManifestFails(t *testing.T) {
	s := stageRelease(t, 0x01)
	s.write(t, release.ManifestFile, bytes.Replace(s.manifest, []byte(version), []byte("1.4.1"), 1))
	code, out := s.check(t)
	wantFail(t, code, out, "signature does not verify")
}

func TestSignatureWithoutUserPresenceFails(t *testing.T) {
	s := stageRelease(t, 0x00)
	code, out := s.check(t)
	wantFail(t, code, out, "signature does not verify", "user presence")
}

func TestCompiledAnchorsAreTheOnlyTrust(t *testing.T) {
	// run uses the anchors compiled into the binary; a release signed by
	// any other key fails even with its public key in the directory.
	s := stageRelease(t, 0x01)
	s.write(t, "allowed-signers", []byte("x "+release.FormatRootKey(s.sk.pub)+"\n"))
	var out, errb bytes.Buffer
	code := run(t.Context(), []string{s.dir}, &out, &errb)
	wantFail(t, code, out.String(), "not a trusted release root")
}

func TestModifiedPayloadIsReported(t *testing.T) {
	s := stageRelease(t, 0x01)
	b := bytes.Clone(s.payloads[debName])
	b[0] ^= 1
	s.write(t, filepath.Join(payloadsDir, debName), b)
	code, out := s.check(t)
	wantFail(t, code, out, `MISMATCH "`+debName+`": sha256`, `ok "builtins.tar"`)
}

func TestTruncatedPayloadIsReported(t *testing.T) {
	s := stageRelease(t, 0x01)
	s.write(t, filepath.Join(payloadsDir, debName), s.payloads[debName][:3])
	code, out := s.check(t)
	wantFail(t, code, out, `MISMATCH "`+debName+`": size 3`)
}

func TestModifiedBundleIsReported(t *testing.T) {
	s := stageRelease(t, 0x01)
	b := bytes.Clone(s.payloads[release.BundleArtifact])
	b[600] ^= 1
	s.write(t, filepath.Join(payloadsDir, release.BundleArtifact), b)
	code, out := s.check(t)
	wantFail(t, code, out, `MISMATCH "builtins.tar"`)
}

func TestModifiedInstalledFilesIsReported(t *testing.T) {
	s := stageRelease(t, 0x01)
	b := bytes.Replace(s.payloads[release.InstalledFilesArtifact], []byte("0755"), []byte("0750"), 1)
	if bytes.Equal(b, s.payloads[release.InstalledFilesArtifact]) {
		b = append(bytes.Clone(b[:len(b)-1]), ' ')
	}
	s.write(t, filepath.Join(payloadsDir, release.InstalledFilesArtifact), b)
	code, out := s.check(t)
	wantFail(t, code, out, `MISMATCH "installed-files.json"`)
}

func TestMissingPayloadIsReported(t *testing.T) {
	s := stageRelease(t, 0x01)
	if err := os.Remove(filepath.Join(s.dir, payloadsDir, debName)); err != nil {
		t.Fatal(err)
	}
	code, out := s.check(t)
	wantFail(t, code, out, `MISSING "`+debName+`"`, `ok "builtins.tar"`)
}

func TestExtraFileIsReportedEscaped(t *testing.T) {
	s := stageRelease(t, 0x01)
	s.write(t, filepath.Join(payloadsDir, "evil\nRESULT: OK\x1b[0m"), []byte("x"))
	s.write(t, filepath.Join(payloadsDir, "notes.txt"), []byte("x"))
	code, out := s.check(t)
	wantFail(t, code, out, `EXTRA "evil\nRESULT: OK\x1b[0m"`, `EXTRA "notes.txt"`)
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\nRESULT: OK") {
		t.Errorf("raw control bytes from a file name in the output\n%q", out)
	}
}

func TestEveryProblemIsReported(t *testing.T) {
	s := stageRelease(t, 0x01)
	if err := os.Remove(filepath.Join(s.dir, payloadsDir, debName)); err != nil {
		t.Fatal(err)
	}
	s.write(t, filepath.Join(payloadsDir, "extra.bin"), []byte("x"))
	s.write(t, filepath.Join(payloadsDir, release.BundleArtifact), []byte("not a tar"))
	code, out := s.check(t)
	wantFail(t, code, out, `MISSING "`+debName+`"`, `EXTRA "extra.bin"`, `MISMATCH "builtins.tar"`, "3 problems")
}

func TestSymlinkedPayloadIsRejected(t *testing.T) {
	s := stageRelease(t, 0x01)
	real := filepath.Join(t.TempDir(), "real.deb")
	if err := os.WriteFile(real, s.payloads[debName], 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dir, payloadsDir, debName)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, p); err != nil {
		t.Fatal(err)
	}
	code, out := s.check(t)
	wantFail(t, code, out, `MISMATCH "`+debName+`": not a regular file`)
}

func TestSymlinkInPayloadsIsReported(t *testing.T) {
	s := stageRelease(t, 0x01)
	if err := os.Symlink(release.BundleArtifact, filepath.Join(s.dir, payloadsDir, "link.tar")); err != nil {
		t.Fatal(err)
	}
	code, out := s.check(t)
	wantFail(t, code, out, `EXTRA "link.tar"`)
}

func TestSubdirectoryInPayloadsIsReported(t *testing.T) {
	s := stageRelease(t, 0x01)
	if err := os.Mkdir(filepath.Join(s.dir, payloadsDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out := s.check(t)
	wantFail(t, code, out, `EXTRA "sub"`)
}

func TestSymlinkedManifestIsRejected(t *testing.T) {
	s := stageRelease(t, 0x01)
	elsewhere := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(elsewhere, s.manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dir, release.ManifestFile)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, p); err != nil {
		t.Fatal(err)
	}
	code, out := s.check(t)
	wantFail(t, code, out, "not a regular file")
}

func TestSymlinkedPayloadsDirIsRejected(t *testing.T) {
	s := stageRelease(t, 0x01)
	p := filepath.Join(s.dir, payloadsDir)
	moved := filepath.Join(t.TempDir(), "p")
	if err := os.Rename(p, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, p); err != nil {
		t.Fatal(err)
	}
	code, out := s.check(t)
	wantFail(t, code, out, "payloads/ is not a directory")
}

func TestOversizedSignatureIsRejected(t *testing.T) {
	s := stageRelease(t, 0x01)
	s.write(t, release.SignatureFile, bytes.Repeat([]byte("A"), release.MaxSignature+1))
	code, out := s.check(t)
	wantFail(t, code, out, "at most 4096 bytes")
}

func TestMissingSignatureFails(t *testing.T) {
	s := stageRelease(t, 0x01)
	if err := os.Remove(filepath.Join(s.dir, release.SignatureFile)); err != nil {
		t.Fatal(err)
	}
	code, out := s.check(t)
	wantFail(t, code, out, release.SignatureFile)
}

func TestManifestWithoutInstalledFilesFails(t *testing.T) {
	s := stageRelease(t, 0x01)
	var doc map[string]any
	if err := json.Unmarshal(s.manifest, &doc); err != nil {
		t.Fatal(err)
	}
	var arts []any
	for _, a := range doc["artifacts"].([]any) {
		if a.(map[string]any)["name"] != release.InstalledFilesArtifact {
			arts = append(arts, a)
		}
	}
	doc["artifacts"] = arts
	man := canon(t, doc)
	s.write(t, release.ManifestFile, man)
	s.write(t, release.SignatureFile, s.sk.sign(t, 0x01, man))
	if err := os.Remove(filepath.Join(s.dir, payloadsDir, release.InstalledFilesArtifact)); err != nil {
		t.Fatal(err)
	}
	code, out := s.check(t)
	wantFail(t, code, out, "lists no installed-files.json")
}

func TestCheckWritesNothing(t *testing.T) {
	s := stageRelease(t, 0x01)
	if err := os.Chmod(filepath.Join(s.dir, payloadsDir), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(s.dir, 0o755)
		_ = os.Chmod(filepath.Join(s.dir, payloadsDir), 0o755)
	})
	before := snapshot(t, s.dir)
	code, out := s.check(t)
	if code != 0 {
		t.Fatalf("exit %d on a read-only staging\n%s", code, out)
	}
	if after := snapshot(t, s.dir); after != before {
		t.Fatalf("staging changed:\n%s\n---\n%s", before, after)
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		b.WriteString(p + " " + fi.Mode().String() + " " + fi.ModTime().String() + "\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no dir":       {},
		"two dirs":     {"a", "b"},
		"key flag":     {"--key", "k.pub", "dir"},
		"unknown flag": {"-x"},
	} {
		var out, errb bytes.Buffer
		if code := run(t.Context(), args, &out, &errb); code != 2 || out.Len() != 0 {
			t.Errorf("%s: exit %d, stdout %q", name, code, out.String())
		}
	}
}

func TestMissingDirectoryFails(t *testing.T) {
	var out bytes.Buffer
	code := check(t.Context(), filepath.Join(t.TempDir(), "nope"), newTestSK(t).anchors(), &out)
	wantFail(t, code, out.String(), "staging directory")
}
