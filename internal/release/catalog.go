// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// This file is the signed image catalog (ADR 0008 section 2, PV-03): the
// vendor cloud images NOS offers for template preparation, shipped as
// release data and signed by a release root through the same chain as the
// release manifest (E15). The catalog's format member separates it from
// the other documents signed in the release namespace.

// CatalogFormat is the "format" of the image catalog.
const CatalogFormat = "nebula-image-catalog-v1"

// LocalImagePrefix starts the ID of every operator-added (trust "Local")
// image and of no signed one, so a local entry never shadows a signed one.
const LocalImagePrefix = "local-"

// Image catalog limits.
const (
	// MaxCatalog bounds image-catalog.json.
	MaxCatalog = 256 << 10
	// MaxCatalogImages bounds the catalog's images.
	MaxCatalogImages = 256
	// MaxImageURL bounds an image's source URL.
	MaxImageURL = 2048
	// maxCatalogSequence bounds the catalog sequence (2^53 - 1).
	maxCatalogSequence = 1<<53 - 1
)

var (
	imageIDRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	imageOSRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	imageReleaseRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,31}$`)
)

// Allowed image architectures and disk formats.
var (
	imageArches  = map[string]bool{"amd64": true, "arm64": true}
	imageFormats = map[string]bool{"qcow2": true, "raw": true}
)

// Image is one catalog entry: a vendor cloud image and its SHA-256.
type Image struct {
	// ID names the entry, e.g. "ubuntu-24.04-amd64".
	ID string
	// OS and Release name the distribution, e.g. "ubuntu" and "24.04".
	OS      string
	Release string
	// Arch is "amd64" or "arm64".
	Arch string
	// URL is the https vendor cloud-image URL, without user info, query
	// or fragment.
	URL string
	// SHA256 is the lowercase hex digest of the image file.
	SHA256 string
	// DiskFormat is "qcow2" or "raw", the format of the image file.
	DiskFormat string
}

// Catalog is a verified image catalog.
type Catalog struct {
	// Sequence increases with every published catalog.
	Sequence int64
	// Images are sorted by ID.
	Images []Image
	// Digest is the SHA-256 of the exact catalog bytes.
	Digest string
	// SignedBy is the root that signed the catalog.
	SignedBy Root
}

// Image returns the entry with id.
func (c Catalog) Image(id string) (Image, bool) {
	for _, img := range c.Images {
		if img.ID == id {
			return img, true
		}
	}
	return Image{}, false
}

// VerifyCatalog checks sig over raw with the currently trusted roots and
// parses the catalog. Callers pass the active roots of the executor's
// durable root state, never keys supplied with the catalog.
func VerifyCatalog(roots []Root, raw, sig []byte) (Catalog, error) {
	if len(raw) == 0 || len(raw) > MaxCatalog {
		return Catalog{}, fmt.Errorf("%w: catalog must be 1 to %d bytes", ErrFormat, MaxCatalog)
	}
	root, err := verifyDocument(roots, raw, sig)
	if err != nil {
		return Catalog{}, err
	}
	c, err := ParseCatalog(raw)
	if err != nil {
		return Catalog{}, err
	}
	c.SignedBy = root
	return c, nil
}

// ParseCatalog parses a canonical catalog without verifying a signature.
// Use VerifyCatalog for admission.
func ParseCatalog(raw []byte) (Catalog, error) {
	doc, err := decodeCanonical(raw, MaxCatalog)
	if err != nil {
		return Catalog{}, err
	}
	top, err := fields(doc, "format", "sequence", "images")
	if err != nil {
		return Catalog{}, fmt.Errorf("%w: catalog: %v", ErrFormat, err)
	}
	if f, err := str(top, "format"); err != nil || f != CatalogFormat {
		return Catalog{}, fmt.Errorf("%w: catalog format must be %q", ErrFormat, CatalogFormat)
	}
	var c Catalog
	if c.Sequence, err = integer(top, "sequence", 1, maxCatalogSequence); err != nil {
		return Catalog{}, fmt.Errorf("%w: catalog: %v", ErrFormat, err)
	}
	imgs, err := array(top, "images", 1, MaxCatalogImages)
	if err != nil {
		return Catalog{}, fmt.Errorf("%w: catalog: %v", ErrFormat, err)
	}
	ids := make([]string, 0, len(imgs))
	for i, v := range imgs {
		img, err := parseImage(v)
		if err != nil {
			return Catalog{}, fmt.Errorf("%w: catalog images[%d]: %v", ErrFormat, i, err)
		}
		ids = append(ids, img.ID)
		c.Images = append(c.Images, img)
	}
	if !sortedUnique(ids) {
		return Catalog{}, fmt.Errorf("%w: catalog images must be sorted by id without duplicates", ErrFormat)
	}
	sum := sha256.Sum256(raw)
	c.Digest = hex.EncodeToString(sum[:])
	return c, nil
}

func parseImage(v any) (Image, error) {
	o, err := fields(v, "id", "os", "release", "arch", "url", "sha256", "disk_format")
	if err != nil {
		return Image{}, err
	}
	var img Image
	for _, f := range []struct {
		key string
		dst *string
	}{{"id", &img.ID}, {"os", &img.OS}, {"release", &img.Release}, {"arch", &img.Arch}, {"url", &img.URL}, {"sha256", &img.SHA256}, {"disk_format", &img.DiskFormat}} {
		if *f.dst, err = str(o, f.key); err != nil {
			return Image{}, err
		}
	}
	if err := checkImage(img, false); err != nil {
		return Image{}, err
	}
	return img, nil
}

// ValidateImage checks one image entry with the catalog grammar. A local
// entry (trust "Local", added by an operator) must have an ID starting
// with LocalImagePrefix; a signed entry must not.
func ValidateImage(img Image, local bool) error {
	if err := checkImage(img, local); err != nil {
		return fmt.Errorf("%w: image: %v", ErrFormat, err)
	}
	return nil
}

func checkImage(img Image, local bool) error {
	switch {
	case !imageIDRe.MatchString(img.ID) || strings.Contains(img.ID, ".."):
		return fmt.Errorf("id must match [a-z0-9][a-z0-9.-]{0,63}")
	case strings.HasPrefix(img.ID, LocalImagePrefix) != local:
		if local {
			return fmt.Errorf("a local image id must start with %q", LocalImagePrefix)
		}
		return fmt.Errorf("a signed image id must not start with %q", LocalImagePrefix)
	case !imageOSRe.MatchString(img.OS):
		return fmt.Errorf("os must match [a-z][a-z0-9-]{0,31}")
	case !imageReleaseRe.MatchString(img.Release):
		return fmt.Errorf("release must match [a-z0-9][a-z0-9.-]{0,31}")
	case !imageArches[img.Arch]:
		return fmt.Errorf("arch must be amd64 or arm64")
	case !validImageURL(img.URL):
		return fmt.Errorf("url must be an absolute https URL without user info, query or fragment, at most %d bytes", MaxImageURL)
	case !validSHA256(img.SHA256):
		return fmt.Errorf("sha256 must be 64 lowercase hex digits")
	case !imageFormats[img.DiskFormat]:
		return fmt.Errorf("disk_format must be qcow2 or raw")
	}
	return nil
}

// validImageURL accepts an absolute https URL with a host, without user
// info, query or fragment, of printable ASCII only.
func validImageURL(s string) bool {
	if s == "" || len(s) > MaxImageURL {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7F {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" &&
		!u.ForceQuery && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(s, "#")
}
