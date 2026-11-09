// SPDX-License-Identifier: AGPL-3.0-or-later
package dockerhost

import (
	"bytes"
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
//
// The document is checked with json.Valid and then walked on its raw bytes
// (trivyScan), never materialised or buffered: skipped values are stepped
// over, and a string, key or number is decoded only when the parser keeps
// it and only after its raw length was checked against the field limit.
// Package entries are reduced one at a time and every walked array and
// object is capped. Allocation of one read is therefore bounded by small
// fixed amounts (maxImagePkgEntries entries of bounded fields, the kept
// packages) whatever a single value of the output holds; it never grows
// with the size of one value or per element of hostile output.

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
	// maxTrivyKey bounds a decoded key of an object the parser walks key by
	// key (document, Metadata, result). A longer key is unparseable; Trivy
	// keys are short identifiers.
	maxTrivyKey = 64
	// maxTrivyFieldKey bounds a key of a package entry or OS object that
	// can name a field. Longer keys are ignored like any unknown field.
	maxTrivyFieldKey = 16
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

// trivyPkgDoc holds the fields of one package entry (trivyPkgFields).
type trivyPkgDoc struct {
	Name       string
	Version    string
	Release    string
	Epoch      int
	SrcName    string
	SrcVersion string
	SrcRelease string
	SrcEpoch   int
}

// trivyOSDoc holds the fields of Metadata.OS (trivyOSFields).
type trivyOSDoc struct {
	Family string
	Name   string
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
	s           trivyScan
	buf         []byte  // reused unescape buffer, bounded by the field limits
	ref         refJSON // holds the digest suffix
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
	// json.Valid allocates nothing per value; after it the raw bytes are
	// walked in place.
	if len(b) == 0 || len(b) > MaxImagePackagesOutput || !utf8.Valid(b) || !json.Valid(b) {
		return t, false
	}
	t.s = trivyScan{b: b}
	err := t.document()
	if errors.Is(err, errTrivyStop) {
		t.p.limit = true
		return t, t.schemaOK
	}
	if err != nil || !t.schemaOK {
		return t, false
	}
	if t.s.peek() != 0 {
		return t, false // trailing data
	}
	return t, true
}

func (t *trivyDecoder) document() error {
	return t.object(func(key string) error {
		switch key {
		case "SchemaVersion":
			v, ok, err := t.intValue()
			if err != nil {
				return err
			}
			t.schemaOK = ok && v == trivySchemaVersion
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

// object walks the object at the cursor key by key. Keys are capped in
// number and length and must be unique; field must consume the value.
func (t *trivyDecoder) object(field func(key string) error) error {
	var keys []string
	return t.s.members(func(raw []byte) error {
		if len(keys) >= maxTrivyObjectKeys || len(raw) > maxJSONEscapeRatio*maxTrivyKey {
			return errTrivyShape
		}
		k, ok := t.unescape(raw, maxTrivyKey)
		if !ok {
			return errTrivyShape
		}
		for _, seen := range keys {
			if seen == string(k) {
				return errTrivyShape // duplicate key: which value counts is ambiguous
			}
		}
		key := string(k)
		keys = append(keys, key)
		return field(key)
	})
}

// skip consumes one value of a key the parser does not use, without
// allocating.
func (t *trivyDecoder) skip() error { return t.s.skip() }

// unescape decodes a raw JSON string of at most limit decoded bytes into
// the reused buffer. The result is valid until the next call.
func (t *trivyDecoder) unescape(raw []byte, limit int) ([]byte, bool) {
	if len(raw) > maxJSONEscapeRatio*limit {
		return nil, false
	}
	if bytes.IndexByte(raw, '\\') < 0 {
		return raw, len(raw) <= limit
	}
	buf, ok := unescapeJSON(t.buf[:0], raw)
	t.buf = buf[:0]
	return buf, ok && len(buf) <= limit
}

// stringValue consumes the value at the cursor. A string of at most limit
// decoded bytes is returned; null is "". Any other type or a longer string
// is reported as not ok without being decoded.
func (t *trivyDecoder) stringValue(limit int) (string, bool, error) {
	switch t.s.peek() {
	case '"':
		raw, err := t.s.str()
		if err != nil {
			return "", false, err
		}
		v, ok := t.unescape(raw, limit)
		if !ok {
			return "", false, nil
		}
		return string(v), true, nil
	case 'n':
		return "", true, t.s.skip()
	}
	return "", false, t.s.skip()
}

// intValue consumes the value at the cursor. A small integer is returned;
// null is 0. Any other type or number is reported as not ok.
func (t *trivyDecoder) intValue() (int, bool, error) {
	switch c := t.s.peek(); {
	case c == '-' || (c >= '0' && c <= '9'):
		raw, err := t.s.span()
		if err != nil {
			return 0, false, err
		}
		v, ok := smallInt(raw)
		return v, ok, nil
	case c == 'n':
		return 0, true, t.s.skip()
	}
	return 0, false, t.s.skip()
}

// fieldIndex returns the index of a raw entry or OS key in names, -1 for
// an unknown key. Long keys are unknown without being decoded.
func (t *trivyDecoder) fieldIndex(raw []byte, names []string) int {
	k, ok := t.unescape(raw, maxTrivyFieldKey)
	if !ok {
		return -1
	}
	for i, n := range names {
		if string(k) == n {
			return i
		}
	}
	return -1
}

// refJSON checks a reference value against the requested digest suffix on
// the raw JSON bytes. Escaped or non-string values never match.
type refJSON struct {
	suffix []byte
}

// match reports whether the raw value is the requested digest.
func (r *refJSON) match(b []byte) bool {
	if len(b) < 2 || len(b) > maxImageRef+2 || b[0] != '"' || b[len(b)-1] != '"' {
		return false
	}
	ref := b[1 : len(b)-1]
	return bytes.IndexByte(ref, '\\') < 0 && digestRe.Match(ref) && bytes.HasSuffix(ref, r.suffix)
}

// refMatch consumes one artifact or repo digest reference: it matches when
// it ends in the requested "@sha256:<hex>" (the repository part may be
// spelled differently).
func (t *trivyDecoder) refMatch() error {
	raw, err := t.s.span()
	if err != nil {
		return err
	}
	t.digestMatch = t.digestMatch || t.ref.match(raw)
	return nil
}

func (t *trivyDecoder) metadata() error {
	ok, err := t.s.open('{')
	if err != nil || !ok {
		return err
	}
	return t.object(func(key string) error {
		switch key {
		case "OS":
			return t.osValue()
		case "RepoDigests":
			ok, err := t.s.open('[')
			if err != nil || !ok {
				return err
			}
			n := 0
			return t.s.elements(func() error {
				if n >= maxTrivyRepoDigests {
					return errTrivyShape
				}
				n++
				return t.refMatch()
			})
		}
		return t.skip()
	})
}

// trivyOSFields are the OS keys the parser reads, in trivyOSDoc order.
var trivyOSFields = []string{"Family", "Name"}

// osValue consumes Metadata.OS. A value of the wrong JSON type, a field of
// the wrong type or length and a repeated field leave the OS undetected.
func (t *trivyDecoder) osValue() error {
	if t.s.peek() != '{' {
		return t.skip() // null or wrong type: OS stays undetected
	}
	var o trivyOSDoc
	var seen [2]bool
	valid := true
	err := t.s.members(func(raw []byte) error {
		f := t.fieldIndex(raw, trivyOSFields)
		if f < 0 || !valid {
			return t.skip()
		}
		if seen[f] {
			valid = false
			return t.skip()
		}
		seen[f] = true
		var ok bool
		var err error
		if f == 0 {
			o.Family, ok, err = t.stringValue(maxImageOSFamily)
		} else {
			o.Name, ok, err = t.stringValue(maxImageOSName)
		}
		valid = valid && ok
		return err
	})
	if err != nil || !valid {
		return err
	}
	t.os, t.osOK = trivyOS(o.Family, o.Name)
	return nil
}

func (t *trivyDecoder) resultList() error {
	ok, err := t.s.open('[')
	if err != nil || !ok {
		return err
	}
	return t.s.elements(func() error {
		if t.results >= maxTrivyResults {
			return errTrivyStop
		}
		t.results++
		obj, err := t.s.open('{')
		if err != nil {
			return err
		}
		if !obj {
			t.p.dropped = true // null result
			return nil
		}
		return t.result()
	})
}

// result decodes the result object at the cursor.
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

// resultString reads Class or Type; a value of the wrong JSON type or
// longer than any valid one marks the result bad.
func (t *trivyDecoder) resultString(dst *string, bad *bool) error {
	v, ok, err := t.stringValue(maxImageEcosystem)
	if !ok {
		*bad = true
	}
	*dst = v
	return err
}

// packages decodes the entries of one result one at a time; an entry of the
// wrong JSON type is dropped, the rest of the result is still read.
func (t *trivyDecoder) packages(r *resultState) error {
	ok, err := t.s.open('[')
	if err != nil || !ok {
		return err
	}
	return t.s.elements(func() error {
		if t.entries >= maxImagePkgEntries {
			return errTrivyStop
		}
		t.entries++
		r.entries++
		if t.s.peek() != '{' {
			r.dropped = true // null or wrong type
			return t.skip()
		}
		valid, err := t.entry()
		if err != nil {
			return err
		}
		var pkg ImagePackage
		if valid {
			pkg, valid = imagePackage(&t.pkgDoc)
		}
		if !valid {
			r.dropped = true
			return nil
		}
		r.pending = append(r.pending, pkg)
		return nil
	})
}

// trivyPkgFields are the entry keys the parser reads; matching is exact.
var trivyPkgFields = []string{"Name", "Version", "Release", "Epoch", "SrcName", "SrcVersion", "SrcRelease", "SrcEpoch"}

// entry decodes the package entry object at the cursor into t.pkgDoc. It
// reports false for a field of the wrong type or length or a repeated
// field; after that, the remaining values are only skipped.
func (t *trivyDecoder) entry() (bool, error) {
	d := &t.pkgDoc
	*d = trivyPkgDoc{}
	var seen [8]bool
	valid := true
	err := t.s.members(func(raw []byte) error {
		f := t.fieldIndex(raw, trivyPkgFields)
		if f < 0 || !valid {
			return t.skip()
		}
		if seen[f] {
			valid = false // repeated field: which value counts is ambiguous
			return t.skip()
		}
		seen[f] = true
		var ok bool
		var err error
		switch f {
		case 0:
			d.Name, ok, err = t.stringValue(maxImagePkgName)
		case 1:
			d.Version, ok, err = t.stringValue(maxImagePkgVersion)
		case 2:
			d.Release, ok, err = t.stringValue(maxImagePkgVersion)
		case 3:
			d.Epoch, ok, err = t.intValue()
		case 4:
			d.SrcName, ok, err = t.stringValue(maxImagePkgName)
		case 5:
			d.SrcVersion, ok, err = t.stringValue(maxImagePkgVersion)
		case 6:
			d.SrcRelease, ok, err = t.stringValue(maxImagePkgVersion)
		default:
			d.SrcEpoch, ok, err = t.intValue()
		}
		valid = valid && ok
		return err
	})
	return valid, err
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
