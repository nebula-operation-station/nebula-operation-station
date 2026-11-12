// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// writeRelease writes the three release files of f into a new directory.
func (f *fixture) writeRelease(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, b := range map[string][]byte{
		release.ManifestFile:           f.manifest,
		release.SignatureFile:          f.sig,
		release.InstalledFilesArtifact: f.list,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func (f *fixture) anchors() []release.Anchor {
	return []release.Anchor{{ID: "root-1", Key: f.k.pub}}
}

func TestReadReleaseAndAdmitRelease(t *testing.T) {
	f := newFixture(t, defaultTree())
	rel, err := ReadRelease(f.writeRelease(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rel.Manifest, f.manifest) || !bytes.Equal(rel.Signature, f.sig) || !bytes.Equal(rel.List, f.list) || rel.Rotation != nil {
		t.Fatalf("release files not read as written: %+v", rel)
	}
	ref, err := AdmitRelease(f.anchors(), testVersion, rel)
	if err != nil {
		t.Fatal(err)
	}
	if ref.ReleaseVersion() != testVersion || ref.SignedBy() != "root-1" || ref.ListDigest() != hexSum(f.list) {
		t.Fatalf("reference identity: %s %s %s", ref.ReleaseVersion(), ref.SignedBy(), ref.ListDigest())
	}
	r, err := Check(context.Background(), ref, f.opts())
	if err != nil || !r.Clean() {
		t.Fatalf("check: %v %+v", err, r)
	}
}

func TestAdmitReleaseRejectsOtherRootWrongVersionAndTamperedList(t *testing.T) {
	f := newFixture(t, defaultTree())
	rel, err := ReadRelease(f.writeRelease(t))
	if err != nil {
		t.Fatal(err)
	}
	other := newTestSK(t)
	if _, err := AdmitRelease([]release.Anchor{{ID: "root-1", Key: other.pub}}, testVersion, rel); err == nil {
		t.Fatal("release signed by an unknown root admitted")
	}
	if _, err := AdmitRelease(f.anchors(), "1.5.0", rel); !errors.Is(err, ErrVersion) {
		t.Fatalf("wrong version: %v, want ErrVersion", err)
	}
	if _, err := AdmitRelease(f.anchors(), "", rel); !errors.Is(err, ErrVersion) {
		t.Fatalf("empty version: %v, want ErrVersion", err)
	}
	if _, err := AdmitRelease(nil, testVersion, rel); err == nil {
		t.Fatal("admitted without anchors")
	}
	bad := rel
	bad.List = append([]byte(nil), rel.List...)
	bad.List[len(bad.List)-2] ^= 1
	if _, err := AdmitRelease(f.anchors(), testVersion, bad); err == nil {
		t.Fatal("tampered list admitted")
	}
	bad = rel
	bad.Signature = f.k.sign(t, append([]byte(nil), f.list...))
	if _, err := AdmitRelease(f.anchors(), testVersion, bad); err == nil {
		t.Fatal("signature over another document admitted")
	}
}

func TestAdmitReleaseRejectsBadRotation(t *testing.T) {
	f := newFixture(t, defaultTree())
	rel, err := ReadRelease(f.writeRelease(t))
	if err != nil {
		t.Fatal(err)
	}
	rel.Rotation = &release.SignedRotation{Document: []byte(`{"format":"x"}`), Signature: f.sig}
	if _, err := AdmitRelease(f.anchors(), testVersion, rel); err == nil {
		t.Fatal("invalid rotation accepted")
	}
}

func TestReadReleaseRejectsUnsafeFiles(t *testing.T) {
	f := newFixture(t, defaultTree())
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"missing manifest", func(t *testing.T, dir string) { rm(t, dir, release.ManifestFile) }},
		{"missing signature", func(t *testing.T, dir string) { rm(t, dir, release.SignatureFile) }},
		{"missing list", func(t *testing.T, dir string) { rm(t, dir, release.InstalledFilesArtifact) }},
		{"symlinked list", func(t *testing.T, dir string) {
			other := filepath.Join(t.TempDir(), "list")
			if err := os.Rename(filepath.Join(dir, release.InstalledFilesArtifact), other); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, filepath.Join(dir, release.InstalledFilesArtifact)); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo signature", func(t *testing.T, dir string) {
			rm(t, dir, release.SignatureFile)
			if err := syscall.Mkfifo(filepath.Join(dir, release.SignatureFile), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory manifest", func(t *testing.T, dir string) {
			rm(t, dir, release.ManifestFile)
			if err := os.Mkdir(filepath.Join(dir, release.ManifestFile), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized signature", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, release.SignatureFile), strings.Repeat("x", release.MaxSignature+1), 0o644)
		}},
		{"rotation without signature", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, RotationFile), "{}", 0o644)
		}},
		{"rotation signature without rotation", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, RotationSignatureFile), "sig", 0o644)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := f.writeRelease(t)
			tc.setup(t, dir)
			if _, err := ReadRelease(dir); !errors.Is(err, ErrRelease) {
				t.Fatalf("got %v, want ErrRelease", err)
			}
		})
	}
}

func TestReadReleaseRefusesSymlinkedDirectory(t *testing.T) {
	f := newFixture(t, defaultTree())
	dir := f.writeRelease(t)
	link := filepath.Join(t.TempDir(), "rel")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRelease(link); !errors.Is(err, ErrRelease) {
		t.Fatalf("got %v, want ErrRelease", err)
	}
	if _, err := ReadRelease("relative"); !errors.Is(err, ErrRelease) {
		t.Fatalf("relative dir: %v, want ErrRelease", err)
	}
}

func TestReadReleaseReadsRotationPair(t *testing.T) {
	f := newFixture(t, defaultTree())
	dir := f.writeRelease(t)
	writeFile(t, filepath.Join(dir, RotationFile), "rot", 0o644)
	writeFile(t, filepath.Join(dir, RotationSignatureFile), "rotsig", 0o644)
	rel, err := ReadRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Rotation == nil || string(rel.Rotation.Document) != "rot" || string(rel.Rotation.Signature) != "rotsig" {
		t.Fatalf("rotation: %+v", rel.Rotation)
	}
}

func TestCheckRefusesSymlinkedRoot(t *testing.T) {
	f := newFixture(t, defaultTree())
	link := filepath.Join(t.TempDir(), "mnt")
	if err := os.Symlink(f.root, link); err != nil {
		t.Fatal(err)
	}
	o := f.opts()
	o.Root = link
	if _, err := Check(context.Background(), f.ref, o); err == nil {
		t.Fatal("symlinked root followed")
	}
}

func TestOfflineOwnersResolvesOnlyRoot(t *testing.T) {
	uid, gid, err := OfflineOwners("root:root")
	if err != nil || uid != 0 || gid != 0 {
		t.Fatalf("root:root: %d %d %v", uid, gid, err)
	}
	for _, o := range []string{"nebula:nebula", "root:adm", "", "root"} {
		if _, _, err := OfflineOwners(o); err == nil {
			t.Errorf("%q resolved", o)
		}
	}
}

func rm(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}
