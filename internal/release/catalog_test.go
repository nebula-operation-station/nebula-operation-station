// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"errors"
	"strings"
	"testing"
)

const testCatalogSHA = "5c1a6c1ee1e1d6b0e8fbd3f0d3a7c3f2b4c5d6e7f8091a2b3c4d5e6f708192a3"

func testCatalogDoc() map[string]any {
	return map[string]any{
		"format":   CatalogFormat,
		"sequence": 3,
		"images": []any{
			map[string]any{"id": "debian-12-amd64", "os": "debian", "release": "12", "arch": "amd64",
				"url": "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2", "sha256": strings.Repeat("ab", 32), "disk_format": "qcow2"},
			map[string]any{"id": "ubuntu-24.04-amd64", "os": "ubuntu", "release": "24.04", "arch": "amd64",
				"url": "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img", "sha256": testCatalogSHA, "disk_format": "qcow2"},
		},
	}
}

func TestVerifyCatalogAcceptsSignedCatalog(t *testing.T) {
	k := newTestSK(t)
	raw := canon(t, testCatalogDoc())
	c, err := VerifyCatalog([]Root{k.root("root-1")}, raw, k.sign(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sequence != 3 || len(c.Images) != 2 || c.Digest != hexSum(raw) || c.SignedBy.ID != "root-1" {
		t.Fatalf("catalog = %+v", c)
	}
	img, ok := c.Image("ubuntu-24.04-amd64")
	if !ok || img.SHA256 != testCatalogSHA || img.OS != "ubuntu" || img.Release != "24.04" || img.Arch != "amd64" || img.DiskFormat != "qcow2" ||
		!strings.HasPrefix(img.URL, "https://cloud-images.ubuntu.com/") {
		t.Fatalf("image = %+v %v", img, ok)
	}
	if _, ok := c.Image("missing"); ok {
		t.Fatal("unknown image found")
	}
}

func TestVerifyCatalogRejectsUntrustedOrBadSignature(t *testing.T) {
	trusted, other := newTestSK(t), newTestSK(t)
	raw := canon(t, testCatalogDoc())
	roots := []Root{trusted.root("root-1")}
	if _, err := VerifyCatalog(roots, raw, other.sign(t, raw)); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("foreign signer: %v", err)
	}
	if _, err := VerifyCatalog(roots, raw, trusted.signNS(t, "file", 0x01, raw)); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong namespace: %v", err)
	}
	if _, err := VerifyCatalog(roots, raw, trusted.signNS(t, Namespace, 0x00, raw)); !errors.Is(err, ErrSignature) {
		t.Fatalf("no user presence: %v", err)
	}
	tampered := []byte(strings.Replace(string(raw), testCatalogSHA, strings.Repeat("0", 64), 1))
	if _, err := VerifyCatalog(roots, tampered, trusted.sign(t, raw)); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered checksum: %v", err)
	}
	if _, err := VerifyCatalog(nil, raw, trusted.sign(t, raw)); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("no roots: %v", err)
	}
}

// A signed release manifest is not a catalog: the format separates the
// documents that share the release namespace.
func TestVerifyCatalogRejectsSignedManifest(t *testing.T) {
	k := newTestSK(t)
	man, _ := defaultRelease(t)
	raw := canon(t, man)
	if _, err := VerifyCatalog([]Root{k.root("root-1")}, raw, k.sign(t, raw)); !errors.Is(err, ErrFormat) {
		t.Fatalf("manifest as catalog: %v", err)
	}
}

func TestParseCatalogRejectsMalformedEntries(t *testing.T) {
	img := func(mut func(m map[string]any)) map[string]any {
		d := testCatalogDoc()
		mut(d["images"].([]any)[1].(map[string]any))
		return d
	}
	cases := map[string]map[string]any{
		"http url":        img(func(m map[string]any) { m["url"] = "http://cloud-images.ubuntu.com/a.img" }),
		"url query":       img(func(m map[string]any) { m["url"] = "https://cloud-images.ubuntu.com/a.img?x=1" }),
		"url fragment":    img(func(m map[string]any) { m["url"] = "https://cloud-images.ubuntu.com/a.img#x" }),
		"url userinfo":    img(func(m map[string]any) { m["url"] = "https://u:p@cloud-images.ubuntu.com/a.img" }),
		"url space":       img(func(m map[string]any) { m["url"] = "https://cloud-images.ubuntu.com/a b.img" }),
		"url long":        img(func(m map[string]any) { m["url"] = "https://x.example/" + strings.Repeat("a", MaxImageURL) }),
		"sha upper":       img(func(m map[string]any) { m["sha256"] = strings.ToUpper(testCatalogSHA) }),
		"sha short":       img(func(m map[string]any) { m["sha256"] = testCatalogSHA[:62] }),
		"arch":            img(func(m map[string]any) { m["arch"] = "x86" }),
		"disk format":     img(func(m map[string]any) { m["disk_format"] = "iso" }),
		"id slash":        img(func(m map[string]any) { m["id"] = "ubuntu/24.04" }),
		"id local prefix": img(func(m map[string]any) { m["id"] = "local-ubuntu" }),
		"os":              img(func(m map[string]any) { m["os"] = "Ubuntu" }),
		"release":         img(func(m map[string]any) { m["release"] = "" }),
		"extra field":     img(func(m map[string]any) { m["cicustom"] = "x" }),
		"missing field":   img(func(m map[string]any) { delete(m, "sha256") }),
		"unsorted": func() map[string]any {
			d := testCatalogDoc()
			im := d["images"].([]any)
			d["images"] = []any{im[1], im[0]}
			return d
		}(),
		"duplicate": func() map[string]any {
			d := testCatalogDoc()
			im := d["images"].([]any)
			d["images"] = []any{im[0], im[0]}
			return d
		}(),
		"empty":      func() map[string]any { d := testCatalogDoc(); d["images"] = []any{}; return d }(),
		"format":     func() map[string]any { d := testCatalogDoc(); d["format"] = ManifestFormat; return d }(),
		"sequence 0": func() map[string]any { d := testCatalogDoc(); d["sequence"] = 0; return d }(),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCatalog(canon(t, doc)); !errors.Is(err, ErrFormat) {
				t.Fatalf("err = %v, want ErrFormat", err)
			}
		})
	}
}

func TestParseCatalogRejectsNoncanonicalAndOversize(t *testing.T) {
	raw := canon(t, testCatalogDoc())
	if _, err := ParseCatalog(append([]byte(" "), raw...)); !errors.Is(err, ErrFormat) {
		t.Fatalf("noncanonical: %v", err)
	}
	if _, err := ParseCatalog(make([]byte, MaxCatalog+1)); !errors.Is(err, ErrFormat) {
		t.Fatalf("oversize: %v", err)
	}
	if _, err := ParseCatalog(nil); !errors.Is(err, ErrFormat) {
		t.Fatalf("empty: %v", err)
	}
}

func TestValidateImageEntry(t *testing.T) {
	good := Image{ID: "local-rocky-9", OS: "rocky", Release: "9", Arch: "amd64", URL: "https://dl.rockylinux.org/a.qcow2",
		SHA256: testCatalogSHA, DiskFormat: "qcow2"}
	if err := ValidateImage(good, true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateImage(good, false); !errors.Is(err, ErrFormat) {
		t.Fatalf("local- prefix accepted for a signed entry: %v", err)
	}
	bad := good
	bad.ID = "rocky-9"
	if err := ValidateImage(bad, true); !errors.Is(err, ErrFormat) {
		t.Fatalf("local entry without local- prefix: %v", err)
	}
}
