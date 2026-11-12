// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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
	if !bytes.Equal(rel.Manifest, f.manifest) || !bytes.Equal(rel.Signature, f.sig) || !bytes.Equal(rel.List, f.list) || rel.Rotations != nil {
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
	rel.Rotations = []release.SignedRotation{{Document: []byte(`{"format":"x"}`), Signature: f.sig}}
	if _, err := AdmitRelease(f.anchors(), testVersion, rel); err == nil {
		t.Fatal("invalid rotation accepted")
	}
}

// rotationDoc returns a canonical rotation document with sequence seq
// following prev (nil: the bootstrap state), adding add and revoking
// revoke, signed by signer.
func rotationDoc(t *testing.T, signer *testSK, seq int64, prev []byte, add map[string]*testSK, revoke ...string) release.SignedRotation {
	t.Helper()
	previous := release.ZeroDigest
	if prev != nil {
		previous = hexSum(prev)
	}
	adds := []any{}
	for _, id := range []string{"root-1", "root-2", "root-3", "root-4", "root-5"} {
		if k, ok := add[id]; ok {
			adds = append(adds, map[string]any{"id": id, "public_key": release.FormatRootKey(k.pub)})
		}
	}
	revs := []any{}
	for _, id := range revoke {
		revs = append(revs, id)
	}
	doc := canon(t, map[string]any{
		"format": release.RotationFormat, "sequence": seq, "previous_sha256": previous,
		"add": adds, "revoke": revs,
	})
	return release.SignedRotation{Document: doc, Signature: signer.sign(t, doc)}
}

// rotationChain is root-1 (the compiled anchor) -> rotation 1 (signed by
// root-1, adds root-2) -> rotation 2 (signed by root-2, adds root-3 and
// revokes root-1).
type rotationChain struct {
	k1, k2, k3 *testSK
	rot1, rot2 release.SignedRotation
}

func newRotationChain(t *testing.T, k1 *testSK) rotationChain {
	t.Helper()
	c := rotationChain{k1: k1, k2: newTestSK(t), k3: newTestSK(t)}
	c.rot1 = rotationDoc(t, c.k1, 1, nil, map[string]*testSK{"root-2": c.k2})
	c.rot2 = rotationDoc(t, c.k2, 2, c.rot1.Document, map[string]*testSK{"root-3": c.k3}, "root-1")
	return c
}

// signedBy returns rel with its manifest re-signed by k.
func signedBy(t *testing.T, rel Release, k *testSK) Release {
	t.Helper()
	rel.Signature = k.sign(t, rel.Manifest)
	return rel
}

func TestAdmitReleaseAppliesRotationChain(t *testing.T) {
	f := newFixture(t, defaultTree())
	c := newRotationChain(t, f.k)
	base, err := ReadRelease(f.writeRelease(t))
	if err != nil {
		t.Fatal(err)
	}

	// One rotation: root-2, added by a signed rotation from the compiled
	// anchor, now signs releases; root-3 is still unknown.
	one := base
	one.Rotations = []release.SignedRotation{c.rot1}
	ref, err := AdmitRelease(f.anchors(), testVersion, signedBy(t, one, c.k2))
	if err != nil || ref.SignedBy() != "root-2" {
		t.Fatalf("release by root-2 after rotation 1: %v (signed by %q)", err, ref.SignedBy())
	}
	if _, err := AdmitRelease(f.anchors(), testVersion, signedBy(t, one, c.k3)); !errors.Is(err, release.ErrUntrusted) {
		t.Fatalf("release by root-3 before rotation 2: %v, want ErrUntrusted", err)
	}

	// Two rotations: root-3 signs releases, and the compiled root-1,
	// revoked in rotation 2, no longer does.
	two := base
	two.Rotations = []release.SignedRotation{c.rot1, c.rot2}
	ref, err = AdmitRelease(f.anchors(), testVersion, signedBy(t, two, c.k3))
	if err != nil || ref.SignedBy() != "root-3" {
		t.Fatalf("release by root-3 after rotation 2: %v (signed by %q)", err, ref.SignedBy())
	}
	if _, err := AdmitRelease(f.anchors(), testVersion, signedBy(t, two, c.k2)); err != nil {
		t.Fatalf("release by still-active root-2: %v", err)
	}
	if _, err := AdmitRelease(f.anchors(), testVersion, signedBy(t, two, f.k)); !errors.Is(err, release.ErrUntrusted) {
		t.Fatalf("release by revoked compiled root-1: %v, want ErrUntrusted", err)
	}
	r, err := Check(context.Background(), ref, f.opts())
	if err != nil || !r.Clean() {
		t.Fatalf("check after rotations: %v %+v", err, r)
	}
}

func TestAdmitReleaseRejectsBrokenRotationChain(t *testing.T) {
	f := newFixture(t, defaultTree())
	c := newRotationChain(t, f.k)
	base, err := ReadRelease(f.writeRelease(t))
	if err != nil {
		t.Fatal(err)
	}
	// rot2ByRoot1 is a well-formed rotation 2 that root-1 may sign, so
	// only its position is wrong.
	rot2ByRoot1 := rotationDoc(t, c.k1, 2, c.rot1.Document, map[string]*testSK{"root-3": c.k3})
	stranger := newTestSK(t)
	cases := []struct {
		name string
		rots []release.SignedRotation
		want error
	}{
		{"wrong order", []release.SignedRotation{c.rot2, c.rot1}, nil},
		{"wrong order, both signed by the anchor", []release.SignedRotation{rot2ByRoot1, c.rot1}, release.ErrRotation},
		{"gap: rotation 2 without rotation 1", []release.SignedRotation{rot2ByRoot1}, release.ErrRotation},
		{"replayed rotation 1", []release.SignedRotation{c.rot1, c.rot1}, release.ErrRotation},
		{"rotation 2 not chained to rotation 1", []release.SignedRotation{c.rot1,
			rotationDoc(t, c.k2, 2, []byte("other"), map[string]*testSK{"root-3": c.k3})}, release.ErrRotation},
		{"rotation signed by a key it adds", []release.SignedRotation{
			rotationDoc(t, stranger, 1, nil, map[string]*testSK{"root-2": stranger})}, release.ErrUntrusted},
		{"rotation 3 signed by root-1, revoked in rotation 2", []release.SignedRotation{c.rot1, c.rot2,
			rotationDoc(t, c.k1, 3, c.rot2.Document, map[string]*testSK{"root-4": newTestSK(t)})}, release.ErrUntrusted},
		{"tampered rotation", []release.SignedRotation{{Document: append(append([]byte(nil), c.rot1.Document[:len(c.rot1.Document)-1]...), ' ', '}'),
			Signature: c.rot1.Signature}}, release.ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel := base
			rel.Rotations = tc.rots
			_, err := AdmitRelease(f.anchors(), testVersion, signedBy(t, rel, c.k3))
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	rel := base
	rel.Rotations = make([]release.SignedRotation, release.MaxRotations+1)
	if _, err := AdmitRelease(f.anchors(), testVersion, rel); !errors.Is(err, release.ErrRotation) {
		t.Fatalf("too many rotations: %v, want ErrRotation", err)
	}
}

// writeRotation writes r as root-rotation-<n>.json (n == 0: the
// unnumbered root-rotation.json) and its signature into dir.
func writeRotation(t *testing.T, dir string, n int, r release.SignedRotation) {
	t.Helper()
	name := RotationFile
	if n != 0 {
		name = rotationName(n)
	}
	writeFile(t, filepath.Join(dir, name), string(r.Document), 0o644)
	writeFile(t, filepath.Join(dir, name+".sig"), string(r.Signature), 0o644)
}

func TestReadReleaseReadsNumberedRotationChain(t *testing.T) {
	f := newFixture(t, defaultTree())
	c := newRotationChain(t, f.k)
	dir := f.writeRelease(t)
	writeRotation(t, dir, 2, c.rot2)
	writeRotation(t, dir, 1, c.rot1)
	writeFile(t, filepath.Join(dir, release.SignatureFile), string(c.k3.sign(t, f.manifest)), 0o644)
	writeFile(t, filepath.Join(dir, "README.txt"), "other assets are ignored", 0o644)
	rel, err := ReadRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rel.Rotations) != 2 || !bytes.Equal(rel.Rotations[0].Document, c.rot1.Document) || !bytes.Equal(rel.Rotations[1].Document, c.rot2.Document) ||
		!bytes.Equal(rel.Rotations[1].Signature, c.rot2.Signature) {
		t.Fatalf("rotations not read in sequence order: %d", len(rel.Rotations))
	}
	ref, err := AdmitRelease(f.anchors(), testVersion, rel)
	if err != nil || ref.SignedBy() != "root-3" {
		t.Fatalf("admit: %v (signed by %q)", err, ref.SignedBy())
	}
}

func TestReadReleaseReadsUnnumberedFirstRotation(t *testing.T) {
	f := newFixture(t, defaultTree())
	c := newRotationChain(t, f.k)
	dir := f.writeRelease(t)
	writeRotation(t, dir, 0, c.rot1)
	writeRotation(t, dir, 2, c.rot2)
	writeFile(t, filepath.Join(dir, release.SignatureFile), string(c.k3.sign(t, f.manifest)), 0o644)
	rel, err := ReadRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rel.Rotations) != 2 || !bytes.Equal(rel.Rotations[0].Document, c.rot1.Document) {
		t.Fatalf("root-rotation.json not read as rotation 1: %d", len(rel.Rotations))
	}
	if _, err := AdmitRelease(f.anchors(), testVersion, rel); err != nil {
		t.Fatal(err)
	}
}

func TestReadReleaseRejectsBadRotationFiles(t *testing.T) {
	f := newFixture(t, defaultTree())
	c := newRotationChain(t, f.k)
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"gap: rotations 1 and 3", func(t *testing.T, dir string) {
			writeRotation(t, dir, 1, c.rot1)
			writeRotation(t, dir, 3, c.rot2)
		}},
		{"gap: only rotation 2", func(t *testing.T, dir string) { writeRotation(t, dir, 2, c.rot2) }},
		{"unnumbered and numbered rotation 1", func(t *testing.T, dir string) {
			writeRotation(t, dir, 0, c.rot1)
			writeRotation(t, dir, 1, c.rot1)
		}},
		{"numbered rotation without signature", func(t *testing.T, dir string) {
			writeRotation(t, dir, 1, c.rot1)
			writeFile(t, filepath.Join(dir, rotationName(2)), string(c.rot2.Document), 0o644)
		}},
		{"numbered signature without rotation", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, rotationName(1)+".sig"), string(c.rot1.Signature), 0o644)
		}},
		{"leading zero", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "root-rotation-01.json"), string(c.rot1.Document), 0o644)
			writeFile(t, filepath.Join(dir, "root-rotation-01.json.sig"), string(c.rot1.Signature), 0o644)
		}},
		{"sequence 0", func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, "root-rotation-0.json"), "x", 0o644) }},
		{"not a number", func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, "root-rotation-x.json"), "x", 0o644) }},
		{"above the rotation limit", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, rotationName(release.MaxRotations+1)), "x", 0o644)
		}},
		{"other rotation-like name", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "root-rotation-1.json.bak"), "x", 0o644)
		}},
		{"symlinked rotation", func(t *testing.T, dir string) {
			writeRotation(t, dir, 1, c.rot1)
			other := filepath.Join(t.TempDir(), "rot")
			writeFile(t, other, string(c.rot2.Document), 0o644)
			writeFile(t, filepath.Join(dir, rotationName(2)+".sig"), string(c.rot2.Signature), 0o644)
			if err := os.Symlink(other, filepath.Join(dir, rotationName(2))); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized rotation", func(t *testing.T, dir string) {
			writeRotation(t, dir, 1, c.rot1)
			writeFile(t, filepath.Join(dir, rotationName(1)), strings.Repeat(" ", release.MaxRotation+1), 0o644)
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

func TestReadReleaseRejectsWrongOrderRotationFiles(t *testing.T) {
	f := newFixture(t, defaultTree())
	c := newRotationChain(t, f.k)
	dir := f.writeRelease(t)
	writeRotation(t, dir, 1, c.rot2)
	writeRotation(t, dir, 2, c.rot1)
	writeFile(t, filepath.Join(dir, release.SignatureFile), string(c.k3.sign(t, f.manifest)), 0o644)
	rel, err := ReadRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitRelease(f.anchors(), testVersion, rel); err == nil {
		t.Fatal("rotations admitted in the wrong order")
	}
}

func TestReadReleaseRejectsTooManyDirectoryEntries(t *testing.T) {
	f := newFixture(t, defaultTree())
	dir := f.writeRelease(t)
	for i := 0; i < MaxReleaseDirEntries; i++ {
		writeFile(t, filepath.Join(dir, "asset-"+strconv.Itoa(i)), "", 0o644)
	}
	if _, err := ReadRelease(dir); !errors.Is(err, ErrRelease) {
		t.Fatalf("got %v, want ErrRelease", err)
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
	if len(rel.Rotations) != 1 || string(rel.Rotations[0].Document) != "rot" || string(rel.Rotations[0].Signature) != "rotsig" {
		t.Fatalf("rotation: %+v", rel.Rotations)
	}
}

// symlinkedParent returns target reached through a symlinked parent
// directory: <tmp>/link/<base> with <tmp>/link -> dir(target).
func symlinkedParent(t *testing.T, target string) string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Dir(target), link); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(link, filepath.Base(target))
}

func TestReadReleaseRefusesSymlinkInParentDirectory(t *testing.T) {
	f := newFixture(t, defaultTree())
	dir := f.writeRelease(t)
	if _, err := ReadRelease(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRelease(symlinkedParent(t, dir)); !errors.Is(err, ErrRelease) {
		t.Fatalf("got %v, want ErrRelease", err)
	}
}

func TestCheckRefusesSymlinkInParentOfRoot(t *testing.T) {
	f := newFixture(t, defaultTree())
	o := f.opts()
	o.Root = symlinkedParent(t, f.root)
	if _, err := Check(context.Background(), f.ref, o); err == nil {
		t.Fatal("root reached through a symlinked parent was followed")
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
