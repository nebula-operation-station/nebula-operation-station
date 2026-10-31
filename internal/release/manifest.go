// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ManifestFormat is the "format" of a release manifest.
const ManifestFormat = "nebula-release-v1"

// BundleArtifact is the artifact name of the built-in bundle.
const BundleArtifact = "builtins.tar"

// Manifest limits (spec 10, hard limits).
const (
	// MaxManifest bounds release-manifest.json.
	MaxManifest = 1 << 20
	// MaxArtifacts and MaxModules bound the manifest's arrays.
	MaxArtifacts = 128
	MaxModules   = 128
	// MaxArtifactSize bounds one release payload; MaxArtifactsTotal
	// their sum.
	MaxArtifactSize   = 4 << 30
	MaxArtifactsTotal = 8 << 30
	// MaxModuleTar bounds one module tar, headers and padding included.
	MaxModuleTar = 4 << 20
	// MaxReleaseVersion bounds the release version string.
	MaxReleaseVersion = 64
	// maxVersionComponent bounds each numeric version component.
	maxVersionComponent = 999999
)

var (
	moduleNameRe   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	artifactNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	semverIdentRe  = regexp.MustCompile(`^[0-9A-Za-z-]+$`)
)

// Artifact is one signed release payload.
type Artifact struct {
	// Name is the release attachment basename.
	Name string
	// Size is the exact byte count.
	Size int64
	// SHA256 is the lowercase hex digest of the exact bytes.
	SHA256 string
}

// Module is one built-in module version shipped in the release.
type Module struct {
	// Name is the module family.
	Name string
	// Version is the module version, X.Y.Z.
	Version string
	// Size is the exact byte count of the module tar.
	Size int64
	// SHA256 is the digest of the complete module tar.
	SHA256 string
}

// Manifest is a verified release manifest.
type Manifest struct {
	// ReleaseVersion is the release SemVer.
	ReleaseVersion string
	// Artifacts are sorted by name; exactly one is builtins.tar.
	Artifacts []Artifact
	// Modules are sorted by name, one per family.
	Modules []Module
	// Digest is the SHA-256 of the exact manifest bytes.
	Digest string
	// SignedBy is the root that signed the manifest.
	SignedBy Root
}

// Bundle returns the builtins.tar artifact.
func (m Manifest) Bundle() Artifact {
	for _, a := range m.Artifacts {
		if a.Name == BundleArtifact {
			return a
		}
	}
	return Artifact{}
}

// VerifyManifest checks sig over raw with the currently trusted roots and
// parses the manifest. Callers pass the active roots of the executor's
// durable root state, never keys supplied with the bundle.
func VerifyManifest(roots []Root, raw, sig []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifest {
		return Manifest{}, fmt.Errorf("%w: manifest must be 1 to %d bytes", ErrFormat, MaxManifest)
	}
	root, err := verifyDocument(roots, raw, sig)
	if err != nil {
		return Manifest{}, err
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return Manifest{}, err
	}
	m.SignedBy = root
	return m, nil
}

// ParseManifest parses a canonical manifest without verifying a
// signature. Use VerifyManifest for admission.
func ParseManifest(raw []byte) (Manifest, error) {
	doc, err := decodeCanonical(raw, MaxManifest)
	if err != nil {
		return Manifest{}, err
	}
	m, err := parseManifest(doc)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: manifest: %v", ErrFormat, err)
	}
	sum := sha256.Sum256(raw)
	m.Digest = hex.EncodeToString(sum[:])
	return m, nil
}

func parseManifest(doc map[string]any) (Manifest, error) {
	top, err := fields(doc, "format", "release_version", "artifacts", "modules")
	if err != nil {
		return Manifest{}, err
	}
	if f, err := str(top, "format"); err != nil || f != ManifestFormat {
		return Manifest{}, fmt.Errorf("format must be %q", ManifestFormat)
	}
	var m Manifest
	if m.ReleaseVersion, err = str(top, "release_version"); err != nil {
		return Manifest{}, err
	}
	if !ValidReleaseVersion(m.ReleaseVersion) {
		return Manifest{}, fmt.Errorf("release_version must be SemVer 2.0.0 without a leading v")
	}
	arts, err := array(top, "artifacts", 1, MaxArtifacts)
	if err != nil {
		return Manifest{}, err
	}
	var total int64
	names := make([]string, 0, len(arts))
	bundles := 0
	for i, v := range arts {
		o, err := fields(v, "name", "size", "sha256")
		if err != nil {
			return Manifest{}, fmt.Errorf("artifacts[%d]: %v", i, err)
		}
		var a Artifact
		if a.Name, err = str(o, "name"); err != nil || !artifactNameRe.MatchString(a.Name) || a.Name == "." || a.Name == ".." {
			return Manifest{}, fmt.Errorf("artifacts[%d]: name must be a basename of [A-Za-z0-9._-], at most 128 bytes", i)
		}
		if a.Size, err = integer(o, "size", 1, MaxArtifactSize); err != nil {
			return Manifest{}, fmt.Errorf("artifacts[%d]: %v", i, err)
		}
		if a.SHA256, err = sha256Hex(o, "sha256"); err != nil {
			return Manifest{}, fmt.Errorf("artifacts[%d]: %v", i, err)
		}
		if total += a.Size; total > MaxArtifactsTotal {
			return Manifest{}, fmt.Errorf("artifact sizes exceed %d bytes in total", int64(MaxArtifactsTotal))
		}
		if a.Name == BundleArtifact {
			bundles++
			if a.Size > MaxBundle {
				return Manifest{}, fmt.Errorf("%s exceeds %d bytes", BundleArtifact, MaxBundle)
			}
		}
		names = append(names, a.Name)
		m.Artifacts = append(m.Artifacts, a)
	}
	if !sortedUnique(names) {
		return Manifest{}, fmt.Errorf("artifacts must be sorted by name without duplicates")
	}
	if bundles != 1 {
		return Manifest{}, fmt.Errorf("artifacts must list exactly one %s", BundleArtifact)
	}
	mods, err := array(top, "modules", 1, MaxModules)
	if err != nil {
		return Manifest{}, err
	}
	names = names[:0]
	for i, v := range mods {
		o, err := fields(v, "name", "version", "size", "sha256")
		if err != nil {
			return Manifest{}, fmt.Errorf("modules[%d]: %v", i, err)
		}
		var md Module
		if md.Name, err = str(o, "name"); err != nil || !moduleNameRe.MatchString(md.Name) {
			return Manifest{}, fmt.Errorf("modules[%d]: name must match [a-z][a-z0-9_-]{0,63}", i)
		}
		if md.Version, err = str(o, "version"); err != nil || !ValidModuleVersion(md.Version) {
			return Manifest{}, fmt.Errorf("modules[%d]: version must be X.Y.Z", i)
		}
		if md.Size, err = integer(o, "size", 1, MaxModuleTar); err != nil {
			return Manifest{}, fmt.Errorf("modules[%d]: %v", i, err)
		}
		if md.SHA256, err = sha256Hex(o, "sha256"); err != nil {
			return Manifest{}, fmt.Errorf("modules[%d]: %v", i, err)
		}
		names = append(names, md.Name)
		m.Modules = append(m.Modules, md)
	}
	if !sortedUnique(names) {
		return Manifest{}, fmt.Errorf("modules must be sorted by name without duplicates")
	}
	return m, nil
}

// ValidModuleVersion reports whether v is X.Y.Z with each component
// 0..999999 without leading zeros, at most 20 bytes.
func ValidModuleVersion(v string) bool {
	if len(v) == 0 || len(v) > 20 {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if !validNumeric(p, true) {
			return false
		}
	}
	return true
}

// ValidReleaseVersion reports whether v is SemVer 2.0.0 without a
// leading v, 1 to 64 bytes, with core components 0..999999.
func ValidReleaseVersion(v string) bool {
	if len(v) == 0 || len(v) > MaxReleaseVersion {
		return false
	}
	rest, build, hasBuild := strings.Cut(v, "+")
	core, pre, hasPre := strings.Cut(rest, "-")
	if !ValidModuleVersion(core) {
		return false
	}
	if hasPre && !validIdents(pre, true) {
		return false
	}
	if hasBuild && !validIdents(build, false) {
		return false
	}
	return true
}

// validIdents checks dot-separated SemVer identifiers; numeric
// prerelease identifiers may not have leading zeros.
func validIdents(s string, prerelease bool) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if !semverIdentRe.MatchString(id) {
			return false
		}
		if prerelease && isDigits(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

func validNumeric(p string, bounded bool) bool {
	if !isDigits(p) || (len(p) > 1 && p[0] == '0') {
		return false
	}
	if bounded {
		n, err := strconv.Atoi(p)
		return err == nil && n <= maxVersionComponent
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
