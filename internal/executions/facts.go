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
		return printable(strings.TrimSpace(string(b)), 200)
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
			osr[k] = printable(v, 200)
		}
	}
	add := func(name, v string) {
		if v != "" {
			out = append(out, Fact{Name: name, Value: v})
		}
	}
	add("Operating system", osr["PRETTY_NAME"])
	add("OS ID", strings.TrimSpace(osr["ID"]+" "+osr["VERSION_ID"]))
	add("Kernel", dec(doc.Uname))
	add("Hostname", dec(doc.Hostname))
	if up, err := strconv.ParseFloat(dec(doc.Uptime), 64); err == nil && up >= 0 {
		add("Uptime", strconv.FormatFloat(up/86400, 'f', 1, 64)+" days")
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
