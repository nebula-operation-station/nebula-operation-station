// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Unit is one line of `systemctl list-units --plain`.
type Unit struct {
	Name, Load, Active, Sub, Description string
}

// Limits of the journal block of a service status result.
const (
	// maxJournalLines is the number of kept journal lines.
	maxJournalLines = 50
	// maxJournalLineBytes is the length limit of one kept journal line.
	maxJournalLineBytes = 1000
)

// ServiceStatus is a parsed service.status / service.<verb> result.
type ServiceStatus struct {
	Phase   string
	Reason  string
	Verb    string
	Exit    int
	Props   []Prop
	Journal []string
	// JournalDropped counts the journal lines that were not valid UTF-8 and
	// were left out of Journal. It is at most the number of lines in the
	// block, which is bounded by maxRawSize.
	JournalDropped int
}

// Prop is one `systemctl show` property.
type Prop struct{ Name, Value string }

var (
	unitNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:\\-]{0,255}$`)
	propRe     = regexp.MustCompile(`^(Id|Description|LoadState|ActiveState|SubState|UnitFileState|ActiveEnterTimestamp|MainPID)=(.{0,300})$`)
)

// decodeRaw decodes a base64 block within maxRawSize. It does not check UTF-8;
// callers decide per line or per block.
func decodeRaw(s string) (string, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) > maxRawSize {
		return "", false
	}
	return string(b), true
}

func decodeText(s string) (string, bool) {
	t, ok := decodeRaw(s)
	if !ok || !utf8.ValidString(t) {
		return "", false
	}
	return t, true
}

// ParseUnits reads a service.list result.
func ParseUnits(result []byte) ([]Unit, error) {
	var doc struct {
		Format string `json:"format"`
		Units  string `json:"units"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "systemd-units-v1" {
		return nil, ErrFormat
	}
	text, ok := decodeText(doc.Units)
	if !ok {
		return nil, ErrFormat
	}
	var out []Unit
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || !unitNameRe.MatchString(f[0]) || len(out) >= 5000 {
			continue
		}
		u := Unit{Name: f[0], Load: f[1], Active: f[2], Sub: f[3]}
		if len(f) > 4 {
			u.Description = strings.Join(f[4:], " ")
		}
		if printableLine(u.Description) && printableLine(u.Load+u.Active+u.Sub) {
			out = append(out, u)
		}
	}
	return out, nil
}

// ParseServiceStatus reads a systemd-status-v1 result.
func ParseServiceStatus(result []byte) (ServiceStatus, error) {
	var doc struct {
		Format  string `json:"format"`
		Phase   string `json:"phase"`
		Reason  string `json:"reason"`
		Verb    string `json:"verb"`
		Exit    int    `json:"exit"`
		Show    string `json:"show"`
		Journal string `json:"journal"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "systemd-status-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return ServiceStatus{}, ErrFormat
	}
	st := ServiceStatus{Phase: doc.Phase, Exit: doc.Exit}
	if printableLine(doc.Reason) {
		st.Reason = doc.Reason
	}
	switch doc.Verb {
	case "", "start", "stop", "restart", "reload":
		st.Verb = doc.Verb
	}
	if show, ok := decodeText(doc.Show); ok {
		for _, l := range strings.Split(show, "\n") {
			if m := propRe.FindStringSubmatch(l); m != nil && printableLine(m[2]) {
				st.Props = append(st.Props, Prop{Name: m[1], Value: m[2]})
			}
		}
	}
	if j, ok := decodeRaw(doc.Journal); ok {
		for _, l := range strings.Split(strings.TrimRight(j, "\n"), "\n") {
			if len(st.Journal) >= maxJournalLines {
				break
			}
			// A line that is not valid UTF-8 is dropped on its own; the valid
			// lines around it are kept.
			if !utf8.ValidString(l) {
				st.JournalDropped++
				continue
			}
			st.Journal = append(st.Journal, cutRunes(l, maxJournalLineBytes))
		}
	}
	return st, nil
}

// cutRunes shortens s to at most n bytes without splitting a UTF-8 sequence.
// s must be valid UTF-8.
func cutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
