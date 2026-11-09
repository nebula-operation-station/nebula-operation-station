// SPDX-License-Identifier: AGPL-3.0-or-later
package dockerhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
//
// The document is decoded as a token stream, never materialised as a whole:
// package entries are decoded one at a time into a reused struct and reduced
// at once, and every streamed array and object is capped. Allocation of one
// read is bounded by the decoder buffer for the largest single value (a
// small multiple of MaxImagePackagesOutput, for one huge skipped value or
// string) plus maxImagePkgEntries decoded entries; it never grows per
// element of hostile output.

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

	// maxImagePkgEntries bounds the raw package entries (valid, invalid and
	// duplicate) one read decodes. Decoding stops there and the read is
	// partial (limit_reached), so the work and memory of one read do not
	// grow with the number of entries in hostile output.
	maxImagePkgEntries = 2 * MaxImagePackages
	// maxTrivyResults bounds the results (including null ones) one read
	// decodes; decoding stops there and the read is partial (limit_reached).
	maxTrivyResults = 4096
	// maxTrivyObjectKeys bounds the keys of each object the parser walks key
	// by key (document, Metadata, result). More keys are unparseable.
	maxTrivyObjectKeys = 64
	// maxTrivyRepoDigests bounds Metadata.RepoDigests. More are unparseable.
	maxTrivyRepoDigests = 256
)

// Fixed reason codes for an image.packages read that is not complete. A
// result carries every condition that applies, comma separated, in this
// order. Reasons never contain host data.
const (
	ReasonTrivyAbsent    = "trivy_absent"    // no Trivy on the host: packages unknown
	ReasonExitNonZero    = "exit_nonzero"    // Trivy exited with a non-zero status
	ReasonUnparseable    = "unparseable"     // output empty, oversized, not UTF-8 or not Trivy JSON v2
	ReasonEntryDropped   = "entry_dropped"   // at least one invalid entry was dropped
	ReasonLimitReached   = "limit_reached"   // MaxImagePackages or a decode cap reached
	ReasonDigestMismatch = "digest_mismatch" // scanned image is not the requested digest
	ReasonOSUndetected   = "os_undetected"   // Trivy did not detect OS family and release
	// ReasonOSPackagesMissing: an OS was detected but no os-pkgs result of
	// that OS family was read (unreadable package DB, library-only scan).
	ReasonOSPackagesMissing = "os_pkgs_missing"
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
	// trivyOSFamilies are Trivy OS result types. A lang-pkgs result must not
	// use one: it would place language packages under an OS ecosystem.
	trivyOSFamilies = map[string]bool{
		"alma": true, "alpine": true, "amazon": true, "azurelinux": true,
		"bottlerocket": true, "cbl-mariner": true, "centos": true,
		"chainguard": true, "coreos": true, "debian": true, "echo": true,
		"fedora": true, "minimos": true, "opensuse": true,
		"opensuse.leap": true, "opensuse.tumbleweed": true, "oracle": true,
		"photon": true, "redhat": true, "rocky": true, "slem": true,
		"sles": true, "ubuntu": true, "wolfi": true,
	}
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

type trivyOSDoc struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// partialSet collects the partial conditions of one read.
type partialSet struct {
	exit, unparseable, dropped, limit, digest, os, osPkgs bool
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
		{p.osPkgs, ReasonOSPackagesMissing},
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
// whitespace and unsafe runes; invalid entries (including entries of the
// wrong JSON type) are dropped and mark the read partial. A detected OS
// without an os-pkgs result of that family is partial. Host problems never
// return an error; they produce an unknown or partial ImagePackages. The
// only error is an invalid requested digest (ErrImagePackagesDigest).
func ParseImagePackages(digest string, run TrivyPackagesRun) (ImagePackages, error) {
	if len(digest) > maxImageRef || !digestRe.MatchString(digest) {
		return ImagePackages{}, ErrImagePackagesDigest
	}
	out := ImagePackages{Digest: digest}
	if !run.Present {
		out.Reason = ReasonTrivyAbsent
		return out, nil
	}
	t, ok := decodeTrivy(digest, run.Output)
	p := t.p
	p.exit = run.ExitCode != 0
	if !ok {
		p = partialSet{exit: p.exit, unparseable: true}
		out.Reason = p.reason()
		return out, nil
	}
	out.Known = true
	out.Packages = make([]ImagePackage, 0, len(t.kept))
	p.digest = !t.digestMatch
	if t.osOK {
		out.OS = t.os
	} else {
		p.os = true
	}
	for _, k := range t.kept {
		// With a detected OS, OS packages must carry its family and language
		// packages must not; the result order may have hidden it before.
		if t.osOK && k.os != (k.pkg.Ecosystem == t.os.Family) {
			p.dropped = true
			continue
		}
		out.Packages = append(out.Packages, k.pkg)
	}
	if t.osOK && !t.osTypes[t.os.Family] {
		p.osPkgs = true
	}
	// Reaching the limit exactly is partial too: the host side may have cut
	// the listing at the limit.
	if len(t.kept) >= MaxImagePackages {
		p.limit = true
	}
	out.Reason = p.reason()
	out.Complete = out.Reason == ""
	return out, nil
}

// errTrivyStop ends decoding early at a cap; the read is partial, not
// unparseable. errTrivyShape is a structural mismatch (unparseable). Both
// stay inside this file and carry no host data.
var (
	errTrivyStop  = errors.New("trivy decode stopped at cap")
	errTrivyShape = errors.New("trivy document shape")
)

// keptPkg is a validated package and whether it came from an os-pkgs result.
type keptPkg struct {
	pkg ImagePackage
	os  bool
}

// trivyDecoder is the state of one streaming decode.
type trivyDecoder struct {
	dec         *json.Decoder
	ref         refJSON // reused for every reference, holds the digest suffix
	schemaOK    bool
	digestMatch bool
	os          ImageOS
	osOK        bool
	osTypes     map[string]bool // valid os-pkgs result types seen
	kept        []keptPkg
	seen        map[keptPkg]bool
	entries     int
	results     int
	pkgDoc      trivyPkgDoc // reused for every entry
	p           partialSet
}

// resultState collects one result object; Class and Type may follow
// Packages, so the entries wait in pending until the object ends.
type resultState struct {
	class, typ string
	bad        bool // Class or Type of the wrong JSON type
	entries    int
	dropped    bool
	pending    []ImagePackage
}

// decodeTrivy stream-decodes a bounded, valid UTF-8 Trivy JSON v2
// document. It reports false when the output is unparseable. Decode errors
// are discarded: they can quote host bytes.
func decodeTrivy(digest string, b []byte) (*trivyDecoder, bool) {
	t := &trivyDecoder{
		ref:     refJSON{suffix: []byte(digest[strings.LastIndex(digest, "@"):])},
		osTypes: make(map[string]bool),
		seen:    make(map[keptPkg]bool),
	}
	if len(b) == 0 || len(b) > MaxImagePackagesOutput || !utf8.Valid(b) {
		return t, false
	}
	t.dec = json.NewDecoder(bytes.NewReader(b))
	err := t.document()
	if errors.Is(err, errTrivyStop) {
		t.p.limit = true
		return t, t.schemaOK
	}
	if err != nil || !t.schemaOK {
		return t, false
	}
	if _, err := t.dec.Token(); !errors.Is(err, io.EOF) {
		return t, false // trailing data
	}
	return t, true
}

func (t *trivyDecoder) document() error {
	if err := t.expect(json.Delim('{')); err != nil {
		return err
	}
	return t.object(func(key string) error {
		switch key {
		case "SchemaVersion":
			var v int
			if err := t.dec.Decode(&v); err != nil {
				return err
			}
			t.schemaOK = v == trivySchemaVersion
			if !t.schemaOK {
				return errTrivyShape
			}
			return nil
		case "ArtifactName":
			return t.refMatch()
		case "Metadata":
			return t.metadata()
		case "Results":
			return t.resultList()
		}
		return t.skip()
	})
}

// object walks the keys of an object whose '{' was consumed, through the
// closing '}'. Keys are capped and must be unique.
func (t *trivyDecoder) object(field func(key string) error) error {
	var keys []string
	for t.dec.More() {
		if len(keys) >= maxTrivyObjectKeys {
			return errTrivyShape
		}
		tok, err := t.dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errTrivyShape
		}
		for _, k := range keys {
			if k == key {
				return errTrivyShape // duplicate key: which value counts is ambiguous
			}
		}
		keys = append(keys, key)
		if err := field(key); err != nil {
			return err
		}
	}
	return t.expect(json.Delim('}'))
}

// open consumes the start of an optional array or object: it reports false
// for null and fails for any other value.
func (t *trivyDecoder) open(d json.Delim) (bool, error) {
	tok, err := t.dec.Token()
	if err != nil {
		return false, err
	}
	if tok == nil {
		return false, nil
	}
	if tok != d {
		return false, errTrivyShape
	}
	return true, nil
}

func (t *trivyDecoder) expect(d json.Delim) error {
	tok, err := t.dec.Token()
	if err != nil {
		return err
	}
	if tok != d {
		return errTrivyShape
	}
	return nil
}

// skip consumes one value of a key the parser does not use, without
// allocating per element.
func (t *trivyDecoder) skip() error {
	return t.dec.Decode(&skipJSON{})
}

// skipJSON accepts and discards any JSON value.
type skipJSON struct{}

// UnmarshalJSON discards the value.
func (*skipJSON) UnmarshalJSON([]byte) error { return nil }

// refJSON checks a reference value against the requested digest suffix on
// the raw JSON bytes, without allocating per element. Escaped or non-string
// values never match.
type refJSON struct {
	suffix  []byte
	matched bool
}

// UnmarshalJSON records whether the value is the requested digest.
func (r *refJSON) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || len(b) > maxImageRef+2 || b[0] != '"' || b[len(b)-1] != '"' {
		return nil
	}
	ref := b[1 : len(b)-1]
	if bytes.IndexByte(ref, '\\') < 0 && digestRe.Match(ref) && bytes.HasSuffix(ref, r.suffix) {
		r.matched = true
	}
	return nil
}

// refMatch decodes one artifact or repo digest reference: it matches when it
// ends in the requested "@sha256:<hex>" (the repository part may be spelled
// differently).
func (t *trivyDecoder) refMatch() error {
	t.ref.matched = false
	if err := t.dec.Decode(&t.ref); err != nil {
		return err
	}
	t.digestMatch = t.digestMatch || t.ref.matched
	return nil
}

func (t *trivyDecoder) metadata() error {
	ok, err := t.open(json.Delim('{'))
	if err != nil || !ok {
		return err
	}
	return t.object(func(key string) error {
		switch key {
		case "OS":
			var o *trivyOSDoc
			err := t.dec.Decode(&o)
			if typeMismatch(err) {
				return nil // OS stays undetected
			}
			if err != nil {
				return err
			}
			if o != nil {
				t.os, t.osOK = trivyOS(o.Family, o.Name)
			}
			return nil
		case "RepoDigests":
			ok, err := t.open(json.Delim('['))
			if err != nil || !ok {
				return err
			}
			for n := 0; t.dec.More(); n++ {
				if n >= maxTrivyRepoDigests {
					return errTrivyShape
				}
				if err := t.refMatch(); err != nil {
					return err
				}
			}
			return t.expect(json.Delim(']'))
		}
		return t.skip()
	})
}

func (t *trivyDecoder) resultList() error {
	ok, err := t.open(json.Delim('['))
	if err != nil || !ok {
		return err
	}
	for t.dec.More() {
		if t.results >= maxTrivyResults {
			return errTrivyStop
		}
		t.results++
		obj, err := t.open(json.Delim('{'))
		if err != nil {
			return err
		}
		if !obj {
			t.p.dropped = true // null result
			continue
		}
		if err := t.result(); err != nil {
			return err
		}
	}
	return t.expect(json.Delim(']'))
}

// result decodes one result object whose '{' was consumed.
func (t *trivyDecoder) result() error {
	var r resultState
	err := t.object(func(key string) error {
		switch key {
		case "Class":
			return t.resultString(&r.class, &r.bad)
		case "Type":
			return t.resultString(&r.typ, &r.bad)
		case "Packages":
			return t.packages(&r)
		}
		return t.skip()
	})
	if err != nil && !errors.Is(err, errTrivyStop) {
		return err
	}
	// At a cap the entries read so far still count if Class and Type are
	// already known.
	if t.finishResult(&r) {
		return errTrivyStop
	}
	return err
}

func (t *trivyDecoder) resultString(dst *string, bad *bool) error {
	err := t.dec.Decode(dst)
	if typeMismatch(err) {
		*bad = true
		return nil
	}
	return err
}

// packages decodes the entries of one result one at a time; an entry of the
// wrong JSON type is dropped, the rest of the result is still read.
func (t *trivyDecoder) packages(r *resultState) error {
	ok, err := t.open(json.Delim('['))
	if err != nil || !ok {
		return err
	}
	for t.dec.More() {
		if t.entries >= maxImagePkgEntries {
			return errTrivyStop
		}
		t.entries++
		r.entries++
		t.pkgDoc = trivyPkgDoc{}
		err := t.dec.Decode(&t.pkgDoc)
		if typeMismatch(err) {
			r.dropped = true
			continue
		}
		if err != nil {
			return err
		}
		pkg, ok := imagePackage(&t.pkgDoc)
		if !ok {
			r.dropped = true
			continue
		}
		r.pending = append(r.pending, pkg)
	}
	return t.expect(json.Delim(']'))
}

// finishResult validates a result's class and type and keeps its packages.
// It reports true when MaxImagePackages is reached and decoding stops.
func (t *trivyDecoder) finishResult(r *resultState) bool {
	isOS := r.class == "os-pkgs"
	valid := !r.bad && imagePkgClasses[r.class] &&
		imageToken(r.typ, maxImageEcosystem) && imageEcosystemRe.MatchString(r.typ) &&
		(isOS || !trivyOSFamilies[r.typ])
	if !valid {
		if r.entries > 0 {
			t.p.dropped = true // results of other classes (secrets, config) carry no packages
		}
		return false
	}
	// Only an os-pkgs result with at least one valid package shows the OS
	// package DB was read: a detected OS with no OS package is not complete.
	if isOS && len(r.pending) > 0 {
		t.osTypes[r.typ] = true
	}
	if r.dropped {
		t.p.dropped = true
	}
	for _, pkg := range r.pending {
		pkg.Ecosystem = r.typ
		k := keptPkg{pkg: pkg, os: isOS}
		if t.seen[k] {
			continue
		}
		if len(t.kept) >= MaxImagePackages {
			return true
		}
		t.seen[k] = true
		t.kept = append(t.kept, k)
	}
	return len(t.kept) >= MaxImagePackages
}

// typeMismatch reports a JSON value of the wrong type; the decoder has
// consumed the value and can continue.
func typeMismatch(err error) bool {
	var te *json.UnmarshalTypeError
	return errors.As(err, &te)
}

// trivyOS returns the detected OS when Trivy reported a valid family and
// release.
func trivyOS(family, name string) (ImageOS, bool) {
	if !printable(family, maxImageOSFamily) || !imageOSFamilyRe.MatchString(family) {
		return ImageOS{}, false
	}
	if !imageToken(name, maxImageOSName) || !imageOSNameRe.MatchString(name) {
		return ImageOS{}, false
	}
	return ImageOS{Family: family, Name: name}, true
}

// imagePackage validates and reduces one Trivy package entry. The ecosystem
// is set once the result's type is known.
func imagePackage(d *trivyPkgDoc) (ImagePackage, bool) {
	if !imageToken(d.Name, maxImagePkgName) {
		return ImagePackage{}, false
	}
	version, ok := imageVersion(d.Version, d.Release, d.Epoch)
	if !ok {
		return ImagePackage{}, false
	}
	pkg := ImagePackage{Name: d.Name, Version: version}
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
