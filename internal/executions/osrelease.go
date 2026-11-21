// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// maxOSReleaseLines bounds how many os-release lines are read. A real
// os-release file has a few dozen lines; the rest of a longer file is
// ignored, as DecodeFacts does.
const maxOSReleaseLines = 100

// osReleaseValueRe is the shape of an accepted ID, VERSION_ID or
// VERSION_CODENAME: lower-case letters, digits and dots, 1 to 32 bytes. Any
// other value is treated as absent, so a managed host cannot place control
// or markup characters into what NOS derives from its release.
var osReleaseValueRe = regexp.MustCompile(`^[a-z0-9.]{1,32}$`)

// OSRelease reads the os-release values NOS needs from a core.facts result
// (untrusted host output, spec 09). The os_release member is base64 text of
// the first maxOSReleaseLines lines of /etc/os-release. It returns the ID,
// VERSION_ID and VERSION_CODENAME values; a value that is missing or does
// not match osReleaseValueRe is returned as "". ok is false only when the
// result is not a core.facts document with a base64 os_release member; in
// that case all three values are "".
func OSRelease(result []byte) (id, versionID, codename string, ok bool) {
	var doc struct {
		OSRelease string `json:"os_release"`
	}
	if json.Unmarshal(result, &doc) != nil {
		return "", "", "", false
	}
	text, err := base64.StdEncoding.DecodeString(doc.OSRelease)
	if err != nil {
		return "", "", "", false
	}
	vals := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(text)))
	for n := 0; n < maxOSReleaseLines && sc.Scan(); n++ {
		k, v, found := strings.Cut(sc.Text(), "=")
		if !found {
			continue
		}
		k = strings.TrimSpace(k)
		if k != "ID" && k != "VERSION_ID" && k != "VERSION_CODENAME" {
			continue
		}
		v = strings.TrimSpace(v)
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		vals[k] = v
	}
	return checkedOSValue(vals["ID"]), checkedOSValue(vals["VERSION_ID"]), checkedOSValue(vals["VERSION_CODENAME"]), true
}

// checkedOSValue returns v if it has the accepted shape, else "".
func checkedOSValue(v string) string {
	if !osReleaseValueRe.MatchString(v) {
		return ""
	}
	return v
}
