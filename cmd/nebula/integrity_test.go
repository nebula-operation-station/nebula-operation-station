// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

const (
	offVersion = "1.4.0"
	offFlavour = "deb:amd64"
)

// offSigner is a software stand-in for the FIDO release root, test-only,
// producing sk-ssh-ed25519 SSHSIG envelopes like the release root.
type offSigner struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newOffSigner(t *testing.T) *offSigner {
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
	return &offSigner{priv: priv, pub: k}
}

func (k *offSigner) anchors() ([]release.Anchor, error) {
	return []release.Anchor{{ID: "root-1", Key: k.pub}}, nil
}

func (k *offSigner) sign(msg []byte) []byte {
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

func offHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// offInstall is a signed release directory and a matching installation
// under a temporary mount root.
type offInstall struct {
	k      *offSigner
	relDir string
	root   string
}

type offFile struct {
	path, data, target string
	mode               fs.FileMode
}

func offTree() []offFile {
	return []offFile{
		{path: "/usr/bin/nebula", target: "nebula-server"},
		{path: "/usr/bin/nebula-executor", data: "executor binary", mode: 0o755},
		{path: "/usr/bin/nebula-server", data: "server binary", mode: 0o755},
		{path: "/usr/lib/systemd/system/nebula-executor.service", data: "[Unit]\n", mode: 0o644},
		{path: "/usr/share/nebula/web/app.css", data: "body{}", mode: 0o644},
	}
}

func newOffInstall(t *testing.T, version string) *offInstall {
	t.Helper()
	root := t.TempDir()
	var files []release.InstalledFile
	for _, f := range offTree() {
		p := filepath.Join(root, f.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if f.target != "" {
			if err := os.Symlink(f.target, p); err != nil {
				t.Fatal(err)
			}
			files = append(files, release.InstalledFile{Path: f.path, Type: release.FileSymlink, Target: f.target, Owner: release.GeneratedOwner})
			continue
		}
		offWrite(t, p, f.data, f.mode)
		files = append(files, release.InstalledFile{Path: f.path, Type: release.FileRegular, Size: int64(len(f.data)),
			SHA256: offHex([]byte(f.data)), Mode: uint32(f.mode), Owner: release.GeneratedOwner})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	list, err := release.InstalledFiles{ReleaseVersion: version, Flavours: []release.Flavour{{Name: offFlavour, Files: files}}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("builtins")
	raw, err := json.Marshal(map[string]any{
		"format":          release.ManifestFormat,
		"release_version": version,
		"artifacts": []any{
			map[string]any{"name": release.BundleArtifact, "size": len(bundle), "sha256": offHex(bundle)},
			map[string]any{"name": release.InstalledFilesArtifact, "size": len(list), "sha256": offHex(list)},
		},
		"modules": []any{map[string]any{"name": "docker", "version": "1.2.0", "size": len(bundle), "sha256": offHex(bundle)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	k := newOffSigner(t)
	relDir := t.TempDir()
	offWrite(t, filepath.Join(relDir, release.ManifestFile), string(manifest), 0o644)
	offWrite(t, filepath.Join(relDir, release.SignatureFile), string(k.sign(manifest)), 0o644)
	offWrite(t, filepath.Join(relDir, release.InstalledFilesArtifact), string(list), 0o644)
	return &offInstall{k: k, relDir: relDir, root: root}
}

func offWrite(t *testing.T, p, data string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func (o *offInstall) cfg() offlineConfig {
	return offlineConfig{
		releaseDir: o.relDir, root: o.root, version: offVersion, flavour: offFlavour,
		// The test process owns the files; root:root maps to its IDs.
		owners: func(owner string) (uint32, uint32, error) {
			if _, _, err := integrity.OfflineOwners(owner); err != nil {
				return 0, 0, err
			}
			return uint32(os.Getuid()), uint32(os.Getgid()), nil
		},
	}
}

func (o *offInstall) run(t *testing.T, cfg offlineConfig) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runOffline(context.Background(), cfg, o.k.anchors, &out)
	return out.String(), err
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}

// snapshot records every entry under dir: path, mode, size, mtime and,
// for symlinks, the target.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		b.WriteString(p + " " + fi.Mode().String() + " " + fi.ModTime().String())
		if fi.Mode().IsRegular() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			b.WriteString(" " + offHex(data))
		}
		b.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestOfflineVerifyCleanInstallationExitsZeroAndWritesNothing(t *testing.T) {
	o := newOffInstall(t, offVersion)
	before := snapshot(t, o.root) + snapshot(t, o.relDir)
	out, err := o.run(t, o.cfg())
	if err != nil {
		t.Fatalf("clean installation: %v\n%s", err, out)
	}
	for _, want := range []string{"release 1.4.0", "flavour deb:amd64", "signed by root-1", "5 matching", "result: clean"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		for _, s := range []string{"different", "missing", "extra", "unreadable"} {
			if strings.HasPrefix(line, s) {
				t.Errorf("clean output lists a file: %q", line)
			}
		}
	}
	if after := snapshot(t, o.root) + snapshot(t, o.relDir); after != before {
		t.Fatalf("the check changed the installation or release directory:\n%s\n---\n%s", before, after)
	}
}

func TestOfflineVerifyReportsDeviations(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
		want  string
	}{
		{"changed", func(t *testing.T, root string) {
			offWrite(t, filepath.Join(root, "usr/bin/nebula-server"), "server binarY", 0o755)
		}, "different  binary     /usr/bin/nebula-server (sha256)"},
		{"missing", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "usr/share/nebula/web/app.css")); err != nil {
				t.Fatal(err)
			}
		}, "missing    web-asset  /usr/share/nebula/web/app.css"},
		{"extra", func(t *testing.T, root string) {
			offWrite(t, filepath.Join(root, "usr/bin/nebula-backdoor"), "x", 0o755)
		}, "extra      binary     /usr/bin/nebula-backdoor"},
		{"symlink instead of file", func(t *testing.T, root string) {
			p := filepath.Join(root, "usr/bin/nebula-executor")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/tmp/evil", p); err != nil {
				t.Fatal(err)
			}
		}, "different  binary     /usr/bin/nebula-executor (type)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := newOffInstall(t, offVersion)
			tc.setup(t, o.root)
			out, err := o.run(t, o.cfg())
			if code := exitCode(err); code != ExitIntegrityDeviation {
				t.Fatalf("exit %d (%v), want %d\n%s", code, err, ExitIntegrityDeviation, out)
			}
			if !strings.Contains(out, tc.want+"\n") {
				t.Fatalf("output lacks %q:\n%s", tc.want, out)
			}
			if strings.Contains(out, "result: clean") {
				t.Fatalf("deviation reported clean:\n%s", out)
			}
			// Only deviations are listed per file.
			if strings.Contains(out, "/usr/lib/systemd/system/nebula-executor.service") {
				t.Fatalf("matching file listed:\n%s", out)
			}
		})
	}
}

func TestOfflineVerifyEscapesExtraNames(t *testing.T) {
	o := newOffInstall(t, offVersion)
	offWrite(t, filepath.Join(o.root, "usr/bin/nebula\x1b[2J\u00e9"), "x", 0o755)
	out, err := o.run(t, o.cfg())
	if code := exitCode(err); code != ExitIntegrityDeviation {
		t.Fatalf("exit %d, want %d", code, ExitIntegrityDeviation)
	}
	if strings.ContainsRune(out, 0x1b) || !strings.Contains(out, `/usr/bin/nebula\x1b[2J\u00e9`) {
		t.Fatalf("name not escaped:\n%q", out)
	}
}

func TestOfflineVerifyLimitIsIncompleteNotClean(t *testing.T) {
	o := newOffInstall(t, offVersion)
	cfg := o.cfg()
	cfg.maxBytes = 4
	out, err := o.run(t, cfg)
	if code := exitCode(err); code != ExitIntegrityIncomplete {
		t.Fatalf("exit %d (%v), want %d\n%s", code, err, ExitIntegrityIncomplete, out)
	}
	if !strings.Contains(out, "result: INCOMPLETE (byte-limit)") || strings.Contains(out, "result: clean") {
		t.Fatalf("output:\n%s", out)
	}
	cfg = o.cfg()
	cfg.maxFiles = 2
	out, err = o.run(t, cfg)
	if code := exitCode(err); code != ExitIntegrityIncomplete || !strings.Contains(out, "(file-limit)") {
		t.Fatalf("file limit: exit %d\n%s", code, out)
	}
}

func TestOfflineVerifyUnresolvableOwnerIsIncomplete(t *testing.T) {
	o := newOffInstall(t, offVersion)
	cfg := o.cfg()
	cfg.owners = func(string) (uint32, uint32, error) { return 0, 0, errors.New("no") }
	out, err := o.run(t, cfg)
	if code := exitCode(err); code != ExitIntegrityIncomplete {
		t.Fatalf("exit %d, want %d\n%s", code, ExitIntegrityIncomplete, out)
	}
	if !strings.Contains(out, "unreadable binary     /usr/bin/nebula-server (owner-unknown)") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestOfflineVerifyRejectsReleaseNotSignedByAnchors(t *testing.T) {
	o := newOffInstall(t, offVersion)
	other := newOffSigner(t)
	var out bytes.Buffer
	err := runOffline(context.Background(), o.cfg(), other.anchors, &out)
	if err == nil || exitCode(err) == ExitIntegrityDeviation || exitCode(err) == ExitIntegrityIncomplete {
		t.Fatalf("release signed by another key: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("output before admission:\n%s", out.String())
	}
	// A signature of the wrong document fails too.
	offWrite(t, filepath.Join(o.relDir, release.SignatureFile), string(o.k.sign([]byte("other"))), 0o644)
	if _, err := o.run(t, o.cfg()); err == nil {
		t.Fatal("wrong signature admitted")
	}
}

func TestOfflineVerifyUsesCompiledAnchors(t *testing.T) {
	// A release signed by a test key is rejected by the real command,
	// which trusts only the anchors compiled into the binary.
	o := newOffInstall(t, offVersion)
	var out bytes.Buffer
	err := integrityCmd([]string{"verify", "--offline", o.relDir, "--root", o.root, "--version", offVersion, "--flavour", offFlavour}, &out)
	if err == nil || !strings.Contains(err.Error(), "admit") {
		t.Fatalf("test-signed release with compiled anchors: %v", err)
	}
}

func TestOfflineVerifyWrongVersionRejected(t *testing.T) {
	o := newOffInstall(t, "1.3.0")
	_, err := o.run(t, o.cfg())
	if !errors.Is(err, integrity.ErrVersion) {
		t.Fatalf("old release checked as %s: %v", offVersion, err)
	}
}

func TestOfflineVerifyUnknownFlavourIsNotClean(t *testing.T) {
	o := newOffInstall(t, offVersion)
	cfg := o.cfg()
	cfg.flavour = "tarball:amd64"
	_, err := o.run(t, cfg)
	if !errors.Is(err, integrity.ErrFlavour) || exitCode(err) != ExitIntegrityIncomplete {
		t.Fatalf("unknown flavour: %v (exit %d)", err, exitCode(err))
	}
}

func TestOfflineVerifySymlinkedRootIsNotFollowed(t *testing.T) {
	o := newOffInstall(t, offVersion)
	link := filepath.Join(t.TempDir(), "mnt")
	if err := os.Symlink(o.root, link); err != nil {
		t.Fatal(err)
	}
	cfg := o.cfg()
	cfg.root = link
	if _, err := o.run(t, cfg); exitCode(err) != ExitIntegrityIncomplete {
		t.Fatalf("symlinked root: %v", err)
	}
}

func TestIntegrityVerifyArguments(t *testing.T) {
	cases := [][]string{
		nil,
		{"ack"},
		{"verify"},
		{"verify", "--root", "/mnt", "--version", "1.4.0", "--flavour", "deb:amd64"},
		{"verify", "--offline", "/rel", "--version", "1.4.0", "--flavour", "deb:amd64"},
		{"verify", "--offline", "/rel", "--root", "/mnt", "--flavour", "deb:amd64"},
		{"verify", "--offline", "/rel", "--root", "/mnt", "--version", "1.4.0"},
		{"verify", "--offline", "rel", "--root", "/mnt", "--version", "1.4.0", "--flavour", "deb:amd64"},
		{"verify", "--offline", "/rel", "--root", "mnt", "--version", "1.4.0", "--flavour", "deb:amd64"},
		{"verify", "--offline", "/rel", "--root", "/mnt", "--version", "1.4.0", "--flavour", "deb:amd64", "extra"},
	}
	for _, args := range cases {
		var out bytes.Buffer
		if err := integrityCmd(args, &out); err == nil || exitCode(err) == 0 {
			t.Errorf("%q accepted", args)
		}
	}
}
