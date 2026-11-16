// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// factsDoc builds a core.facts result whose only field is the uptime text.
func factsDoc(uptime string) []byte {
	return []byte(`{"uptime":"` + base64.StdEncoding.EncodeToString([]byte(uptime+"\n")) + `"}`)
}

// uptimeLine returns the Uptime value shown for an uptime text, and whether
// a line is shown at all.
func uptimeLine(uptime string) (string, bool) {
	for _, f := range DecodeFacts(factsDoc(uptime)) {
		if f.Name == "Uptime" {
			return f.Value, true
		}
	}
	return "", false
}

// TestUptimeOutOfRangeHasNoLine holds the uptime to the same bounds as the
// other facts: a value that is not a plausible uptime shows no line at all.
func TestUptimeOutOfRangeHasNoLine(t *testing.T) {
	bound := strconv.FormatFloat(maxUptimeDays*86400, 'f', -1, 64)
	over := strconv.FormatFloat(maxUptimeDays*86400+1, 'f', -1, 64)
	dayOver := strconv.FormatFloat((maxUptimeDays+1)*86400, 'f', -1, 64)
	for name, tc := range map[string]struct {
		uptime string
		want   string
		shown  bool
	}{
		"normal":           {uptime: "172800.5", want: "2.0 days", shown: true},
		"zero":             {uptime: "0", want: "0.0 days", shown: true},
		"at the bound":     {uptime: bound, want: "36500.0 days", shown: true},
		"one s over":       {uptime: over},
		"one day over":     {uptime: dayOver},
		"1e308":            {uptime: "1e308"},
		"max float":        {uptime: "1.7976931348623157e308"},
		"Inf":              {uptime: "Inf"},
		"+Inf":             {uptime: "+Inf"},
		"NaN":              {uptime: "NaN"},
		"negative":         {uptime: "-5"},
		"negative Inf":     {uptime: "-Inf"},
		"not a number":     {uptime: "soon"},
		"overflowing text": {uptime: "1" + strings.Repeat("0", 400)},
	} {
		got, shown := uptimeLine(tc.uptime)
		if shown != tc.shown || (shown && got != tc.want) {
			t.Errorf("%s: uptime %q shows %q (%v), want %q (%v)", name, tc.uptime, got, shown, tc.want, tc.shown)
		}
	}
}

// TestUptimeBoundIsNotNaNOrInf checks that a NaN or infinite uptime never
// passes the bound comparison.
func TestUptimeBoundIsNotNaNOrInf(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, shown := uptimeLine(strconv.FormatFloat(v, 'g', -1, 64)); shown {
			t.Errorf("%v shows an uptime line", v)
		}
	}
}

// TestOSIDIsBoundedAfterJoining: ID and VERSION_ID are each bounded, but the
// joined "OS ID" value must be bounded too.
func TestOSIDIsBoundedAfterJoining(t *testing.T) {
	osRelease := "ID=" + strings.Repeat("a", 300) + "\nVERSION_ID=" + strings.Repeat("b", 300) + "\n"
	doc := []byte(`{"os_release":"` + base64.StdEncoding.EncodeToString([]byte(osRelease)) + `"}`)
	for _, f := range DecodeFacts(doc) {
		if f.Name == "OS ID" {
			checkDisplayText(t, f.Value)
			return
		}
	}
	t.Fatal("no OS ID fact")
}

// checkDisplayText asserts the rules of a displayed fact value: valid UTF-8,
// at most maxFactRunes runes plus the "…" marker, and no control, bidi
// control or non-printable rune.
func checkDisplayText(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("value is not UTF-8: %q", s)
	}
	if n := utf8.RuneCountInString(s); n > maxFactRunes+1 {
		t.Fatalf("value has %d runes, limit %d: %q", n, maxFactRunes+1, s)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || !unicode.IsPrint(r) {
			t.Fatalf("value contains rune %U: %q", r, s)
		}
	}
}

// FuzzDecodeFacts: a malicious host controls every byte of a core.facts result.
func FuzzDecodeFacts(f *testing.F) {
	b := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	f.Add([]byte(`{"os_release":"` + b("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n") + `","uname":"` + b("Linux 6.1.0 x86_64\n") +
		`","hostname":"` + b("web‮01\n") + `","uptime":"` + b("172800.5\n") + `","proxmox":true}`))
	f.Add(factsDoc("1e308"))
	f.Add(factsDoc("Inf"))
	f.Add(factsDoc("NaN"))
	f.Add([]byte(`{"os_release":"` + b("ID=x\nVERSION_ID=y\n") + `"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, doc []byte) {
		for _, fact := range DecodeFacts(doc) {
			checkDisplayText(t, fact.Value)
		}
	})
}
