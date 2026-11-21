// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stageRoots is the trusted root set of the staging tests: one software
// stand-in for a security key, bound to "ssh:" like a release root.
func stageRoots(k *testSK) []Root { return []Root{k.root("root-1")} }

func mustCanon(t *testing.T, doc map[string]any) []byte { t.Helper(); return canon(t, doc) }

func TestStagedCatalogRoundTripVerifies(t *testing.T) {
	k := newTestSK(t)
	roots := stageRoots(k)
	input := mustCanon(t, testCatalogDoc())
	// The signing step signs the canonical bytes; staging must emit them unchanged.
	sig := k.sign(t, input)

	canonical, c, err := CheckCatalog(input, sig, roots)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, input) || c.Sequence != 3 || c.SignedBy.ID != "root-1" {
		t.Fatalf("staged %q, catalog %+v", canonical, c)
	}

	dir := t.TempDir()
	if err := WriteStagedCatalog(dir, roots, canonical, sig); err != nil {
		t.Fatal(err)
	}
	gotCat := readStaged(t, dir, CatalogFile)
	gotSig := readStaged(t, dir, CatalogSignatureFile)
	// The files on disk are exactly what VerifyCatalog admits, and the
	// verified catalog matches the one staging reported.
	back, err := VerifyCatalog(roots, gotCat, gotSig)
	if err != nil {
		t.Fatalf("staged files do not verify: %v", err)
	}
	if back.Digest != c.Digest || back.Sequence != c.Sequence || len(back.Images) != len(c.Images) {
		t.Fatalf("read back %+v, staged %+v", back, c)
	}
}

func TestStagingCanonicalisesInput(t *testing.T) {
	k := newTestSK(t)
	want := mustCanon(t, testCatalogDoc())
	// Same document with reordered keys and whitespace: not canonical.
	loose := []byte(`{ "sequence" : 3, "images": [
	  {"disk_format":"qcow2","sha256":"` + strings.Repeat("ab", 32) + `","arch":"amd64","release":"12","os":"debian","id":"debian-12-amd64",
	   "url":"https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"},
	  {"id":"ubuntu-24.04-amd64","os":"ubuntu","release":"24.04","arch":"amd64","url":"https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img","sha256":"` + testCatalogSHA + `","disk_format":"qcow2"}
	], "format": "` + CatalogFormat + `" }`)
	canonical, _, err := PrepareCatalog(loose)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, want) {
		t.Fatalf("canonical form\n got %s\nwant %s", canonical, want)
	}
	if _, err := VerifyCatalog(stageRoots(k), canonical, k.sign(t, want)); err != nil {
		t.Fatalf("signature over canonical bytes: %v", err)
	}
}

func TestStagingRefusesInvalidInput(t *testing.T) {
	mutate := func(f func(map[string]any)) []byte {
		doc := testCatalogDoc()
		f(doc)
		return mustCanon(t, doc)
	}
	images := func(doc map[string]any) []any { return doc["images"].([]any) }
	entry := func(doc map[string]any, i int) map[string]any { return images(doc)[i].(map[string]any) }

	for name, input := range map[string][]byte{
		"empty":            {},
		"larger than 256K": bytes.Repeat([]byte(" "), MaxCatalog+1),
		"BOM":              append([]byte{0xEF, 0xBB, 0xBF}, mustCanon(t, testCatalogDoc())...),
		"invalid UTF-8":    []byte("{\"format\":\"\xff\"}"),
		"not an object":    []byte(`["nebula-image-catalog-v1"]`),
		"duplicate key":    []byte(`{"format":"` + CatalogFormat + `","format":"x","sequence":1,"images":[]}`),
		"null value":       []byte(`{"format":null,"sequence":1,"images":[]}`),
		"unknown field":    mutate(func(d map[string]any) { d["mirror"] = "https://example.invalid/" }),
		"wrong format":     mutate(func(d map[string]any) { d["format"] = "nebula-release-v1" }),
		"sequence zero":    mutate(func(d map[string]any) { d["sequence"] = 0 }),
		"sequence too big": mutate(func(d map[string]any) { d["sequence"] = int64(maxCatalogSequence) + 1 }),
		"no images":        mutate(func(d map[string]any) { d["images"] = []any{} }),
		"local id": mutate(func(d map[string]any) {
			entry(d, 0)["id"] = LocalImagePrefix + "debian-12"
		}),
		"http url": mutate(func(d map[string]any) {
			entry(d, 0)["url"] = "http://cloud.debian.org/images/debian-12.qcow2"
		}),
		"url with query": mutate(func(d map[string]any) {
			entry(d, 1)["url"] = "https://cloud-images.ubuntu.com/a.img?x=1"
		}),
		"uppercase sha256": mutate(func(d map[string]any) {
			entry(d, 1)["sha256"] = strings.ToUpper(testCatalogSHA)
		}),
		"unknown arch": mutate(func(d map[string]any) { entry(d, 0)["arch"] = "i386" }),
		"unknown disk format": mutate(func(d map[string]any) {
			entry(d, 0)["disk_format"] = "vmdk"
		}),
		"entry field missing": mutate(func(d map[string]any) { delete(entry(d, 0), "os") }),
		"unsorted ids": mutate(func(d map[string]any) {
			imgs := images(d)
			imgs[0], imgs[1] = imgs[1], imgs[0]
		}),
		"duplicate ids": mutate(func(d map[string]any) {
			entry(d, 1)["id"] = entry(d, 0)["id"]
		}),
		"257 images": mustCanon(t, manyImages(MaxCatalogImages+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := PrepareCatalog(input); !errors.Is(err, ErrFormat) {
				t.Fatalf("PrepareCatalog: %v, want ErrFormat", err)
			}
		})
	}
}

// manyImages returns a sequence-1 catalog of n copies of the Debian entry
// with sorted IDs img-000, img-001, ...
func manyImages(n int) map[string]any {
	doc := map[string]any{"format": CatalogFormat, "sequence": 1}
	base := testCatalogDoc()["images"].([]any)[0].(map[string]any)
	var imgs []any
	for i := 0; i < n; i++ {
		img := map[string]any{}
		for k, v := range base {
			img[k] = v
		}
		img["id"] = fmt.Sprintf("img-%03d", i)
		imgs = append(imgs, img)
	}
	doc["images"] = imgs
	return doc
}

func TestStagingAcceptsMaximumImageCount(t *testing.T) {
	raw := mustCanon(t, manyImages(MaxCatalogImages))
	if len(raw) > MaxCatalog {
		t.Fatalf("fixture %d bytes exceeds the catalog limit", len(raw))
	}
	if _, c, err := PrepareCatalog(raw); err != nil || len(c.Images) != MaxCatalogImages {
		t.Fatalf("256 images: %v", err)
	}
}

func TestStagingRefusesBadSignature(t *testing.T) {
	trusted, other := newTestSK(t), newTestSK(t)
	roots := stageRoots(trusted)
	input := mustCanon(t, testCatalogDoc())
	other2 := append([]byte(nil), input...)
	other2 = bytes.Replace(other2, []byte(testCatalogSHA), []byte(strings.Repeat("0", 64)), 1)

	for name, c := range map[string]struct {
		sig  []byte
		want error
	}{
		"missing":          {nil, ErrFormat},
		"not a signature":  {[]byte("nope"), ErrFormat},
		"foreign key":      {other.sign(t, input), ErrUntrusted},
		"wrong namespace":  {trusted.signNS(t, "file", 0x01, input), ErrSignature},
		"no user presence": {trusted.signNS(t, Namespace, 0x00, input), ErrSignature},
		"other content":    {trusted.sign(t, other2), ErrSignature},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := CheckCatalog(input, c.sig, roots); !errors.Is(err, c.want) {
				t.Fatalf("CheckCatalog: %v, want %v", err, c.want)
			}
		})
	}
}

func TestLowerSequenceIsVisibleAfterStaging(t *testing.T) {
	k := newTestSK(t)
	roots := stageRoots(k)
	newer := mustCanon(t, testCatalogDoc()) // sequence 3
	older := mustCanon(t, func() map[string]any { d := testCatalogDoc(); d["sequence"] = 2; return d }())

	_, cNew, err := CheckCatalog(newer, k.sign(t, newer), roots)
	if err != nil {
		t.Fatal(err)
	}
	_, cOld, err := CheckCatalog(older, k.sign(t, older), roots)
	if err != nil {
		t.Fatalf("an older but validly signed catalog must verify: %v", err)
	}
	if cOld.Sequence >= cNew.Sequence {
		t.Fatalf("sequence %d not below %d: rollback not visible", cOld.Sequence, cNew.Sequence)
	}
}

func TestWriteStagedCatalogRefusesExistingFiles(t *testing.T) {
	k := newTestSK(t)
	roots := stageRoots(k)
	raw := mustCanon(t, testCatalogDoc())
	sig := k.sign(t, raw)
	dir := t.TempDir()
	if err := WriteStagedCatalog(dir, roots, raw, sig); err != nil {
		t.Fatal(err)
	}
	if err := WriteStagedCatalog(dir, roots, raw, sig); err == nil {
		t.Fatal("second write over existing catalog succeeded")
	}
	// A symlink planted at the target is not followed.
	dir2 := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(dir2, CatalogFile)); err != nil {
		t.Fatal(err)
	}
	if err := WriteStagedCatalog(dir2, roots, raw, sig); err == nil {
		t.Fatal("write through a planted symlink succeeded")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("symlink target was written: %v", err)
	}
}

func TestAnchorRootsAreCompiledKeysOnly(t *testing.T) {
	roots, err := AnchorRoots()
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) == 0 {
		t.Fatal("no compiled root")
	}
	for _, r := range roots {
		if r.Key == nil || !ValidRootID(r.ID) {
			t.Fatalf("root %+v: want a key with a valid ID; placeholders are not roots", r)
		}
	}
}

func readStaged(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
