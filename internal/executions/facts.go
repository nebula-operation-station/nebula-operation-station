// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
)

// Limits of the core.facts display values.
const (
	// maxFactRunes is the length limit of every displayed value, in runes;
	// a longer value is cut and marked with "…".
	maxFactRunes = 200
	// maxUptimeDays bounds the displayed uptime. A larger or non-finite
	// value is not a plausible uptime, so no uptime line is shown for it.
	maxUptimeDays = 36500
)

// Fact is one decoded value of a core.facts result, for display as text.
type Fact struct {
	Name  string
	Value string
}

// DecodeFacts reads a core.facts result (untrusted, spec 09): the values
// are base64; os-release is parsed for a few keys. It returns nil if the
// document does not have the expected form.
func DecodeFacts(result []byte) []Fact {
	var doc struct {
		OSRelease string `json:"os_release"`
		Uname     string `json:"uname"`
		Hostname  string `json:"hostname"`
		Uptime    string `json:"uptime"`
		Proxmox   bool   `json:"proxmox"`
	}
	if json.Unmarshal(result, &doc) != nil {
		return nil
	}
	dec := func(s string) string {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return ""
		}
		return printable(strings.TrimSpace(string(b)), maxFactRunes)
	}
	var out []Fact
	osr := map[string]string{}
	if b, err := base64.StdEncoding.DecodeString(doc.OSRelease); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for n := 0; sc.Scan() && n < 100; n++ {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			if uq, err := strconv.Unquote(v); err == nil {
				v = uq
			} else {
				v = strings.Trim(v, `"'`)
			}
			osr[k] = printable(v, maxFactRunes)
		}
	}
	add := func(name, v string) {
		if v != "" {
			out = append(out, Fact{Name: name, Value: v})
		}
	}
	add("Operating system", osr["PRETTY_NAME"])
	// Bounded after joining: each part is already bounded on its own, so
	// the joined value could otherwise be twice the limit.
	add("OS ID", printable(strings.TrimSpace(osr["ID"]+" "+osr["VERSION_ID"]), maxFactRunes))
	add("Kernel", dec(doc.Uname))
	add("Hostname", dec(doc.Hostname))
	if up, err := strconv.ParseFloat(dec(doc.Uptime), 64); err == nil {
		days := up / 86400
		// NaN and ±Inf fail both comparisons; a value above the bound is
		// not a plausible uptime and gets no line.
		if days >= 0 && days <= maxUptimeDays {
			add("Uptime", strconv.FormatFloat(days, 'f', 1, 64)+" days")
		}
	}
	if doc.Proxmox {
		add("Proxmox VE", "yes")
	}
	return out
}

func printable(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= limit {
			b.WriteString("…")
			break
		}
		if !unicode.IsPrint(r) || unicode.Is(unicode.Bidi_Control, r) {
			r = '�'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
