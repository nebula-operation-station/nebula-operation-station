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
)

// Limits.
const (
	MaxPackages = 20000
	maxLine     = 2000
	maxRawSize  = 8 << 20
	maxRebootPk = 500
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
