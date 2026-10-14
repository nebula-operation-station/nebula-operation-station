// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// Install is a parsed package.install_security / package.install_all
// result (apt-install-v1).
type Install struct {
	Phase          string // "precheck" or "done"
	Reason         string // precheck failure reason
	Mode           string
	AptExit        int
	Packages       []string
	AuditClean     bool
	RebootRequired bool
	NewFailedUnits []string
	Docker         []string
}

// Warning reports whether the install worked but left something to look
// at (newly failed units).
func (i Install) Warning() bool { return i.Phase == "done" && len(i.NewFailedUnits) > 0 }

const maxListItems = 2000

func b64Lines(s string, valid func(string) bool) []string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) > maxRawSize || !utf8.Valid(b) {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && valid(l) && len(out) < maxListItems {
			out = append(out, l)
		}
	}
	return out
}

func printableLine(s string) bool {
	if len(s) > 300 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	return true
}

// ParseInstall reads an apt-install-v1 result.
func ParseInstall(result []byte) (Install, error) {
	var doc struct {
		Format         string `json:"format"`
		Phase          string `json:"phase"`
		Reason         string `json:"reason"`
		Mode           string `json:"mode"`
		AptExit        int    `json:"apt_exit"`
		Packages       string `json:"packages"`
		AuditClean     bool   `json:"dpkg_audit_clean"`
		RebootRequired bool   `json:"reboot_required"`
		NewFailed      string `json:"new_failed_units"`
		Docker         string `json:"docker"`
	}
	if err := json.Unmarshal(result, &doc); err != nil || doc.Format != "apt-install-v1" {
		return Install{}, ErrFormat
	}
	i := Install{AptExit: doc.AptExit, AuditClean: doc.AuditClean, RebootRequired: doc.RebootRequired}
	switch doc.Phase {
	case "precheck", "done":
		i.Phase = doc.Phase
	default:
		return Install{}, ErrFormat
	}
	if doc.Mode == "install_security" || doc.Mode == "install_all" {
		i.Mode = doc.Mode
	}
	if printableLine(doc.Reason) {
		i.Reason = doc.Reason
	}
	i.Packages = b64Lines(doc.Packages, pkgRe.MatchString)
	i.NewFailedUnits = b64Lines(doc.NewFailed, printableLine)
	i.Docker = b64Lines(doc.Docker, printableLine)
	return i, nil
}
