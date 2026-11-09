// SPDX-License-Identifier: AGPL-3.0-or-later

// Package osdebian reads the results of the os-debian built-in actions
// (spec 10/11). All input is untrusted host output (spec 09): bounded,
// UTF-8 checked, parsed with a strict line format, and reduced to printable
// text.
package osdebian

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// Limits.
const (
	MaxPackages = 20000
	maxLine     = 2000
	maxRawSize  = 8 << 20
	maxRebootPk = 500
	// MaxCandidateStanzas bounds the apt-cache stanzas of the optional
	// candidates section; a longer section is ignored as a whole, so every
	// candidate's source stays unknown.
	MaxCandidateStanzas = 2 * MaxPackages
)

// Package is one pending update.
type Package struct {
	Name     string
	From     string // installed version, empty for a new package
	To       string
	Archives []string
	Arch     string
	Security bool
	Kernel   bool
	// SourceName and SourceVersion are the source package and source
	// version of the candidate version To (ADR 0011 D8, VU-13), from the
	// candidate's apt "Source:" field; for a binNMU the source version
	// differs from To. Both are empty when unknown: the result has no
	// candidates section (an older script), the candidate has no stanza,
	// its stanzas disagree, or a value does not validate.
	SourceName    string
	SourceVersion string
}

// Updates is a parsed package.list_updates result.
type Updates struct {
	Packages       []Package
	Security       int
	Kernel         int
	RebootRequired bool
	RebootPackages []string
	ListsUpdated   time.Time // zero if unknown
	Proxmox        bool
	Mode           string
}

// ErrFormat is returned for a result that is not package.list_updates@1.
var ErrFormat = errors.New("osdebian: not a package.list_updates result")

var (
	// Inst NAME [OLD] (NEW ARCHIVE[, ARCHIVE...] [ARCH]) [...]
	instRe   = regexp.MustCompile(`^Inst ([a-z0-9][a-z0-9+.\-]*(?::[a-z0-9]+)?) (?:\[([^\]\s]{1,200})\] )?\(([^\s()]{1,200}) ([^()\[\]]{1,1000}) \[([a-z0-9]{1,32})\]\)`)
	pkgRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]{0,200}$`)
	kernelRe = regexp.MustCompile(`^(linux-image|linux-headers|linux-modules|linux-generic|linux-signed|pve-kernel|proxmox-kernel|proxmox-default-kernel)`)
)

// IsSecurity reports whether an archive is a security archive
// ("-security" on Ubuntu, "Debian-Security"/"debian-security" on Debian).
func IsSecurity(archive string) bool {
	a := strings.ToLower(archive)
	return strings.Contains(a, "-security") || strings.Contains(a, "debian-security")
}

// ParseUpdates reads the JSON document of package.list_updates 1.0.0.
func ParseUpdates(result []byte) (Updates, error) {
	var doc struct {
		Format         string `json:"format"`
		Mode           string `json:"mode"`
		Simulate       string `json:"simulate"`
		RebootRequired bool   `json:"reboot_required"`
		RebootPkgs     string `json:"reboot_pkgs"`
		ListsMtime     int64  `json:"lists_mtime"`
		Proxmox        bool   `json:"proxmox"`
		Candidates     string `json:"candidates"`
	}
	if err := json.Unmarshal(result, &doc); err != nil || doc.Format != "apt-simulate-v1" {
		return Updates{}, ErrFormat
	}
	u := Updates{RebootRequired: doc.RebootRequired, Proxmox: doc.Proxmox}
	if doc.Mode == "upgrade" || doc.Mode == "dist-upgrade" {
		u.Mode = doc.Mode
	}
	if doc.ListsMtime > 0 {
		u.ListsUpdated = time.Unix(doc.ListsMtime, 0)
	}
	raw, err := base64.StdEncoding.DecodeString(doc.Simulate)
	if err != nil || len(raw) > maxRawSize || !utf8.Valid(raw) {
		return Updates{}, ErrFormat
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 4096), maxLine)
	seen := map[string]bool{}
	for sc.Scan() {
		m := instRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if len(u.Packages) >= MaxPackages {
			return Updates{}, errors.New("osdebian: too many packages")
		}
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		p := Package{Name: name, From: m[2], To: m[3], Arch: m[5]}
		for _, a := range strings.Split(m[4], ",") {
			if a = strings.TrimSpace(a); a != "" {
				p.Archives = append(p.Archives, a)
				if IsSecurity(a) {
					p.Security = true
				}
			}
		}
		p.Kernel = kernelRe.MatchString(name)
		if p.Security {
			u.Security++
		}
		if p.Kernel {
			u.Kernel++
		}
		u.Packages = append(u.Packages, p)
	}
	if err := sc.Err(); err != nil {
		return Updates{}, ErrFormat
	}
	addCandidateSources(u.Packages, doc.Candidates)
	if pk, err := base64.StdEncoding.DecodeString(doc.RebootPkgs); err == nil && utf8.Valid(pk) {
		for _, l := range strings.Split(string(pk), "\n") {
			l = strings.TrimSpace(l)
			if pkgRe.MatchString(l) && len(u.RebootPackages) < maxRebootPk {
				u.RebootPackages = append(u.RebootPackages, l)
			}
		}
	}
	return u, nil
}

// sourceRe is an apt "Source:" value: "name" or "name (version)".
var sourceRe = regexp.MustCompile(`^([a-z0-9][a-z0-9+.\-]{0,200})(?: \(([^\s()]{1,200})\))?$`)

// candidateKey identifies a binary package version.
type candidateKey struct{ name, version string }

// candidateSource is the source of one binary package version; conflict
// marks stanzas that disagree.
type candidateSource struct {
	name, version string
	conflict      bool
}

// addCandidateSources fills SourceName and SourceVersion of pkgs from the
// optional candidates section: base64 of `apt-cache show` output for the
// candidate versions, reduced to Package, Version and Source lines. It is
// untrusted host output. Anything unusable leaves the source unknown
// rather than failing the whole update list: an unknown source only means
// "fix not verified" (ADR 0011 D8). A broken section (bad base64, invalid
// UTF-8, an over-long line, too many stanzas) is ignored as a whole.
func addCandidateSources(pkgs []Package, b64 string) {
	if b64 == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) > maxRawSize || !utf8.Valid(raw) {
		return
	}
	sources, ok := parseCandidateStanzas(raw)
	if !ok {
		return
	}
	for i := range pkgs {
		name, _, _ := strings.Cut(pkgs[i].Name, ":") // drop the ":arch" qualifier
		s, found := sources[candidateKey{name, pkgs[i].To}]
		if !found || s.conflict {
			continue
		}
		pkgs[i].SourceName, pkgs[i].SourceVersion = s.name, s.version
	}
}

// candidateStanza is one apt-cache stanza being read.
type candidateStanza struct {
	pkg, version, source  string
	hasVersion, hasSource bool
	// bad: a field was repeated.
	bad bool
}

// resolve returns the stanza's binary key and its source; ok is false
// for a stanza with a missing, repeated or invalid field. Without a
// Source field the source is the binary package itself; a Source field
// without a version means the source version equals the binary version;
// "name (version)" (binNMUs and renamed binaries) names it explicitly.
func (s candidateStanza) resolve() (candidateKey, candidateSource, bool) {
	if s.bad || !s.hasVersion || !pkgRe.MatchString(s.pkg) || vulnver.Validate(vulnver.SchemeDpkg, s.version) != nil {
		return candidateKey{}, candidateSource{}, false
	}
	src := candidateSource{name: s.pkg, version: s.version}
	if s.hasSource {
		m := sourceRe.FindStringSubmatch(s.source)
		if m == nil {
			return candidateKey{}, candidateSource{}, false
		}
		src.name = m[1]
		if m[2] != "" {
			src.version = m[2]
		}
	}
	if vulnver.Validate(vulnver.SchemeDpkg, src.version) != nil {
		return candidateKey{}, candidateSource{}, false
	}
	return candidateKey{s.pkg, s.version}, src, true
}

// parseCandidateStanzas reads the stanzas. A stanza starts with a Package
// line and counts only once a blank line closes it, as apt-cache prints
// it. A stanza cut short (by the next Package line or the end of the
// section, e.g. by the script's line cap) is dropped, so a lost Source line
// never turns the binary version into a claimed source version. Lines
// outside a stanza and other fields are ignored, an unusable stanza is dropped, and
// stanzas of one binary version that disagree mark it as a conflict. ok
// is false for a broken section.
func parseCandidateStanzas(raw []byte) (map[candidateKey]candidateSource, bool) {
	out := map[candidateKey]candidateSource{}
	var cur *candidateStanza
	stanzas := 0
	finish := func() {
		if cur == nil {
			return
		}
		k, src, ok := cur.resolve()
		cur = nil
		if !ok {
			return
		}
		if prev, seen := out[k]; seen {
			if prev != src {
				out[k] = candidateSource{conflict: true}
			}
			return
		}
		out[k] = src
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 4096), maxLine)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			finish()
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if field == "Package" {
			cur = nil // an unclosed stanza is incomplete: dropped
			if stanzas++; stanzas > MaxCandidateStanzas {
				return nil, false
			}
			cur = &candidateStanza{pkg: value}
			continue
		}
		if cur == nil {
			continue
		}
		switch field {
		case "Version":
			cur.bad = cur.bad || cur.hasVersion
			cur.version, cur.hasVersion = value, true
		case "Source":
			cur.bad = cur.bad || cur.hasSource
			cur.source, cur.hasSource = value, true
		}
	}
	if sc.Err() != nil {
		return nil, false
	}
	// An unclosed last stanza may be truncated: dropped, not finished.
	return out, true
}
