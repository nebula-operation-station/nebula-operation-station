// SPDX-License-Identifier: AGPL-3.0-or-later
package dockerhost

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// image.packages (ADR 0011 D3, VU-06) lists the packages of one local image
// platform digest with the operator-installed host Trivy (no install, no
// pull, no database refresh). This file is the pure parser of that listing:
// the Trivy JSON document is untrusted host data, reduced here to bounded
// (ecosystem, name, version, source name, source version) tuples. The raw
// output is never kept, logged or quoted in a result or error.

const (
	// MaxImagePackages is the per-image package limit (ADR 0011 D3). A read
	// that reaches it is partial: the listing may have been cut.
	MaxImagePackages = 5000
	// MaxImagePackagesOutput bounds the Trivy JSON output the parser
	// accepts. Larger output is not parsed at all (unparseable, partial).
	MaxImagePackagesOutput = 32 << 20

	// maxImagePkgName bounds a package or source package name.
	maxImagePkgName = 256
	// maxImagePkgVersion bounds a composed version ([epoch:]version[-release]).
	maxImagePkgVersion = 128
	// maxImagePkgEpoch bounds a Debian/RPM epoch.
	maxImagePkgEpoch = 100000
	// maxImageOSName bounds the OS release string.
	maxImageOSName = 64
	// maxImageOSFamily bounds the OS family string.
	maxImageOSFamily = 48
	// maxImageEcosystem bounds a Trivy result type.
	maxImageEcosystem = 32
	// maxImageRef bounds an artifact name or repo digest Trivy reports.
	maxImageRef = 512
	// trivySchemaVersion is the only Trivy JSON schema the parser accepts.
	trivySchemaVersion = 2
)

// Fixed reason codes for an image.packages read that is not complete. A
// result carries every condition that applies, comma separated, in this
// order. Reasons never contain host data.
const (
	ReasonTrivyAbsent    = "trivy_absent"    // no Trivy on the host: packages unknown
	ReasonExitNonZero    = "exit_nonzero"    // Trivy exited with a non-zero status
	ReasonUnparseable    = "unparseable"     // output empty, oversized, not UTF-8 or not Trivy JSON v2
	ReasonEntryDropped   = "entry_dropped"   // at least one invalid entry was dropped
	ReasonLimitReached   = "limit_reached"   // MaxImagePackages reached
	ReasonDigestMismatch = "digest_mismatch" // scanned image is not the requested digest
	ReasonOSUndetected   = "os_undetected"   // Trivy did not detect OS family and release
)

// ErrImagePackagesDigest is returned when the requested image is not a
// valid "<repo>@sha256:<64 hex>" platform digest reference. It signals a
// caller error, not a host result.
var ErrImagePackagesDigest = errors.New("dockerhost: invalid image packages digest")

var (
	imageEcosystemRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	imageOSFamilyRe  = regexp.MustCompile(`^[a-z][a-z0-9._-]*( [a-z0-9._-]+)*$`)
	imageOSNameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~/-]*$`)
	imagePkgClasses  = map[string]bool{"os-pkgs": true, "lang-pkgs": true}
)

// TrivyPackagesRun is what the host reported for one Trivy package listing.
// Output is only read by ParseImagePackages and never retained.
type TrivyPackagesRun struct {
	Present  bool   // Trivy is installed on the host
	ExitCode int    // Trivy exit status
	Output   []byte // Trivy JSON (--list-all-pkgs --format json)
}

// ImageOS is the OS Trivy detected in the image.
type ImageOS struct {
	Family string // e.g. "debian", "alpine"
	Name   string // release, e.g. "12.5"
}

// ImagePackage is one installed package of an image.
type ImagePackage struct {
	Ecosystem  string // Trivy result type, e.g. "debian", "alpine", "gobinary"
	Name       string // binary/package name
	Version    string // [epoch:]version[-release]
	SrcName    string // source package name, "" when Trivy reports none
	SrcVersion string // [epoch:]source version[-release], "" when none
}

// ImagePackages is a parsed image.packages read for one image digest.
//
// Known is false when no package listing was obtained (Trivy absent or
// output unparseable): the packages are unknown, never empty. Complete is
// true only for a known read with none of the partial conditions; only a
// complete read may prove a package removal or a fixed version (ADR 0011
// D5). The zero value is an unknown, partial read.
type ImagePackages struct {
	Digest   string // requested image platform digest reference
	OS       ImageOS
	Packages []ImagePackage
	Known    bool
	Complete bool
	Reason   string // comma-separated Reason* codes, "" when complete
}

type trivyPkgDoc struct {
	Name       string `json:"Name"`
	Version    string `json:"Version"`
	Release    string `json:"Release"`
	Epoch      int    `json:"Epoch"`
	SrcName    string `json:"SrcName"`
	SrcVersion string `json:"SrcVersion"`
	SrcRelease string `json:"SrcRelease"`
	SrcEpoch   int    `json:"SrcEpoch"`
}

type trivyResultDoc struct {
	Class    string         `json:"Class"`
	Type     string         `json:"Type"`
	Packages []*trivyPkgDoc `json:"Packages"`
}

type trivyDoc struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	Metadata      struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []*trivyResultDoc `json:"Results"`
}

// partialSet collects the partial conditions of one read.
type partialSet struct {
	exit, unparseable, dropped, limit, digest, os bool
}

func (p partialSet) reason() string {
	var r []string
	for _, c := range []struct {
		on   bool
		code string
	}{
		{p.exit, ReasonExitNonZero},
		{p.unparseable, ReasonUnparseable},
		{p.dropped, ReasonEntryDropped},
		{p.limit, ReasonLimitReached},
		{p.digest, ReasonDigestMismatch},
		{p.os, ReasonOSUndetected},
	} {
		if c.on {
			r = append(r, c.code)
		}
	}
	return strings.Join(r, ",")
}

// ParseImagePackages parses the host-local Trivy package listing for the
// requested image digest. Every value is untrusted host data: names,
// versions, ecosystems and the OS are bounded, UTF-8 checked and free of
// whitespace and unsafe runes; invalid entries are dropped and mark the
// read partial. Host problems never return an error; they produce an
// unknown or partial ImagePackages. The only error is an invalid requested
// digest (ErrImagePackagesDigest).
func ParseImagePackages(digest string, run TrivyPackagesRun) (ImagePackages, error) {
	if len(digest) > maxImageRef || !digestRe.MatchString(digest) {
		return ImagePackages{}, ErrImagePackagesDigest
	}
	out := ImagePackages{Digest: digest}
	if !run.Present {
		out.Reason = ReasonTrivyAbsent
		return out, nil
	}
	var p partialSet
	p.exit = run.ExitCode != 0
	doc, ok := decodeTrivyDoc(run.Output)
	if !ok {
		p.unparseable = true
		out.Reason = p.reason()
		return out, nil
	}
	out.Known = true
	out.Packages = make([]ImagePackage, 0)
	p.digest = !trivyDigestMatches(digest, doc)
	if detected, ok := trivyOS(doc); ok {
		out.OS = detected
	} else {
		p.os = true
	}
	seen := make(map[ImagePackage]bool)
	for _, res := range doc.Results {
		if res == nil {
			p.dropped = true
			continue
		}
		if len(res.Packages) == 0 {
			continue // results of other classes (secrets, config) carry no packages
		}
		if !imagePkgClasses[res.Class] || !imageToken(res.Type, maxImageEcosystem) || !imageEcosystemRe.MatchString(res.Type) {
			p.dropped = true
			continue
		}
		for _, raw := range res.Packages {
			pkg, ok := imagePackage(res.Type, raw)
			if !ok {
				p.dropped = true
				continue
			}
			if seen[pkg] {
				continue
			}
			if len(out.Packages) >= MaxImagePackages {
				p.limit = true
				continue
			}
			seen[pkg] = true
			out.Packages = append(out.Packages, pkg)
		}
	}
	// Reaching the limit exactly is partial too: the host side may have cut
	// the listing at the limit.
	if len(out.Packages) >= MaxImagePackages {
		p.limit = true
	}
	out.Reason = p.reason()
	out.Complete = out.Reason == ""
	return out, nil
}

// decodeTrivyDoc decodes a bounded, valid UTF-8 Trivy JSON v2 document.
// The decode error is discarded: it can quote host bytes.
func decodeTrivyDoc(b []byte) (trivyDoc, bool) {
	if len(b) == 0 || len(b) > MaxImagePackagesOutput || !utf8.Valid(b) {
		return trivyDoc{}, false
	}
	var doc trivyDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return trivyDoc{}, false
	}
	if doc.SchemaVersion != trivySchemaVersion {
		return trivyDoc{}, false
	}
	return doc, true
}

// trivyDigestMatches reports whether Trivy scanned the requested digest:
// the artifact name or one repo digest ends in the requested
// "@sha256:<hex>" (the repository part may be spelled differently).
func trivyDigestMatches(digest string, doc trivyDoc) bool {
	suffix := digest[strings.LastIndex(digest, "@"):]
	match := func(ref string) bool {
		return len(ref) <= maxImageRef && digestRe.MatchString(ref) && strings.HasSuffix(ref, suffix)
	}
	if match(doc.ArtifactName) {
		return true
	}
	for _, r := range doc.Metadata.RepoDigests {
		if match(r) {
			return true
		}
	}
	return false
}

// trivyOS returns the detected OS when Trivy reported a valid family and
// release.
func trivyOS(doc trivyDoc) (ImageOS, bool) {
	o := doc.Metadata.OS
	if o == nil {
		return ImageOS{}, false
	}
	if !printable(o.Family, maxImageOSFamily) || !imageOSFamilyRe.MatchString(o.Family) {
		return ImageOS{}, false
	}
	if !imageToken(o.Name, maxImageOSName) || !imageOSNameRe.MatchString(o.Name) {
		return ImageOS{}, false
	}
	return ImageOS{Family: o.Family, Name: o.Name}, true
}

// imagePackage validates and reduces one Trivy package entry.
func imagePackage(ecosystem string, d *trivyPkgDoc) (ImagePackage, bool) {
	if d == nil || !imageToken(d.Name, maxImagePkgName) {
		return ImagePackage{}, false
	}
	version, ok := imageVersion(d.Version, d.Release, d.Epoch)
	if !ok {
		return ImagePackage{}, false
	}
	pkg := ImagePackage{Ecosystem: ecosystem, Name: d.Name, Version: version}
	if d.SrcName == "" {
		if d.SrcVersion != "" || d.SrcRelease != "" || d.SrcEpoch != 0 {
			return ImagePackage{}, false // source version without a source package
		}
		return pkg, true
	}
	if !imageToken(d.SrcName, maxImagePkgName) {
		return ImagePackage{}, false
	}
	pkg.SrcName = d.SrcName
	if d.SrcVersion == "" {
		if d.SrcRelease != "" || d.SrcEpoch != 0 {
			return ImagePackage{}, false
		}
		return pkg, true
	}
	src, ok := imageVersion(d.SrcVersion, d.SrcRelease, d.SrcEpoch)
	if !ok {
		return ImagePackage{}, false
	}
	pkg.SrcVersion = src
	return pkg, true
}

// imageVersion composes [epoch:]version[-release] from Trivy's split
// version fields and bounds the result.
func imageVersion(version, release string, epoch int) (string, bool) {
	if epoch < 0 || epoch > maxImagePkgEpoch || !imageToken(version, maxImagePkgVersion) {
		return "", false
	}
	v := version
	if release != "" {
		if !imageToken(release, maxImagePkgVersion) {
			return "", false
		}
		v += "-" + release
	}
	if epoch > 0 {
		v = strconv.Itoa(epoch) + ":" + v
	}
	if len(v) > maxImagePkgVersion {
		return "", false
	}
	return v, true
}

// imageToken is a non-empty, bounded, valid UTF-8 value without unsafe
// runes and without whitespace.
func imageToken(s string, limit int) bool {
	if s == "" || !printable(s, limit) {
		return false
	}
	return strings.IndexFunc(s, unicode.IsSpace) < 0
}
