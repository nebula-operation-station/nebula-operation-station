// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"bytes"
	"fmt"
	"os"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// Staged layout of the image catalog (PV-03e, decided in
// docs/implementation/pve-image-prepare-wiring.md D2): the release staging
// directory holds two more top-level files next to release-manifest.json.
//
//	image-catalog.json      canonical JCS catalog, format CatalogFormat
//	image-catalog.json.sig  detached SSHSIG over those exact bytes,
//	                        namespace "nebula-release", by a release root
//
// The catalog is a separate signed file, not a part of
// release-manifest.json: the manifest grammar and its artifact list stay
// unchanged. The signature is the existing release-signing step (offline
// security key, user presence required), and VerifyCatalog is the only
// admission check. Staging writes both files only after VerifyCatalog
// accepts them against the compiled anchors. Nothing here reads the
// network or signs.
//
// ReadBundleDir accepts exactly the manifest, its signature and
// builtins.tar, so the catalog pair is not in that directory until the
// executor's catalog load (PV-03c) admits it.
const (
	// CatalogFile is the staged image catalog.
	CatalogFile = "image-catalog.json"
	// CatalogSignatureFile is the detached signature of CatalogFile.
	CatalogSignatureFile = "image-catalog.json.sig"
)

// PrepareCatalog turns an operator's catalog input into the canonical
// catalog bytes and their parsed form. The input may be any JSON document
// with the catalog grammar; it is canonicalised with RFC 8785 (JCS), and
// every image is checked with ValidateImage(img, false), so an entry
// with the LocalImagePrefix is refused. The input is limited to MaxCatalog
// bytes before any parsing; duplicate keys, nulls, unknown fields and bad
// UTF-8 or BOM are refused as ErrFormat.
func PrepareCatalog(input []byte) ([]byte, Catalog, error) {
	if len(input) == 0 || len(input) > MaxCatalog {
		return nil, Catalog{}, fmt.Errorf("%w: catalog input must be 1 to %d bytes", ErrFormat, MaxCatalog)
	}
	if bytes.HasPrefix(input, []byte{0xEF, 0xBB, 0xBF}) || !utf8.Valid(input) {
		return nil, Catalog{}, fmt.Errorf("%w: catalog input is not UTF-8 without BOM", ErrFormat)
	}
	if err := checkStructure(input); err != nil {
		return nil, Catalog{}, fmt.Errorf("%w: catalog input: %v", ErrFormat, err)
	}
	canon, err := jcs.Transform(input)
	if err != nil {
		return nil, Catalog{}, fmt.Errorf("%w: catalog input is not JSON: %v", ErrFormat, err)
	}
	c, err := ParseCatalog(canon)
	if err != nil {
		return nil, Catalog{}, err
	}
	for i, img := range c.Images {
		if err := ValidateImage(img, false); err != nil {
			return nil, Catalog{}, fmt.Errorf("catalog images[%d]: %w", i, err)
		}
	}
	return canon, c, nil
}

// CheckCatalog prepares the catalog input (PrepareCatalog) and verifies
// sig over the canonical bytes with roots (VerifyCatalog). It returns
// the canonical bytes that were verified, the catalog and no error only
// when both checks pass. Nothing is written.
func CheckCatalog(input, sig []byte, roots []Root) ([]byte, Catalog, error) {
	canon, _, err := PrepareCatalog(input)
	if err != nil {
		return nil, Catalog{}, err
	}
	c, err := VerifyCatalog(roots, canon, sig)
	if err != nil {
		return nil, Catalog{}, err
	}
	return canon, c, nil
}

// AnchorRoots returns the active release roots compiled into this binary,
// the trust that staging checks a catalog signature against. Placeholder
// slots are not roots.
func AnchorRoots() ([]Root, error) {
	anchors, err := Anchors()
	if err != nil {
		return nil, err
	}
	var out []Root
	for _, a := range anchors {
		if a.Key != nil {
			out = append(out, Root{ID: a.ID, Key: a.Key})
		}
	}
	return out, nil
}

// WriteStagedCatalog writes canon and sig as CatalogFile and
// CatalogSignatureFile into the existing directory dir. It verifies the
// pair with roots first and writes nothing unless VerifyCatalog accepts
// it. Both files are created exclusively (O_EXCL, through an os.Root), so
// an existing file or a planted symlink is an error, never overwritten.
func WriteStagedCatalog(dir string, roots []Root, canon, sig []byte) error {
	if _, err := VerifyCatalog(roots, canon, sig); err != nil {
		return err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open staging directory: %w", err)
	}
	defer r.Close()
	if err := writeNewFile(r, CatalogFile, canon); err != nil {
		return err
	}
	return writeNewFile(r, CatalogSignatureFile, sig)
}

func writeNewFile(r *os.Root, name string, data []byte) error {
	f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	return f.Close()
}
