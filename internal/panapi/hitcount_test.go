// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// hcBody wraps rule entries in a success response of the rule-hit-count
// operational command for vsys1/security.
func hcBody(entries string) []byte {
	return wrapResult(`<rule-hit-count><vsys><entry name="vsys1"><rule-base><entry name="security"><rules>` +
		entries + `</rules></entry></rule-base></entry></vsys></rule-hit-count>`)
}

// hcEntry is one rule entry with the given hit count and extra elements.
func hcEntry(name, hits, extra string) string {
	return `<entry name="` + name + `"><hit-count>` + hits + `</hit-count>` + extra + `</entry>`
}

func unix(s int64) time.Time { return time.Unix(s, 0).UTC() }

func TestParseRuleHitCountsFixture(t *testing.T) {
	got, err := ParseRuleHitCounts(readFixture(t, "hitcount.xml"))
	if err != nil {
		t.Fatalf("ParseRuleHitCounts: %v", err)
	}
	want := HitCountSet{Rules: map[string]RuleHitCount{
		"zz-allow-mgmt": {
			HitCount:         math.MaxUint64,
			LastHit:          unix(1767225600),
			FirstHit:         unix(1764547260),
			LastReset:        unix(1764547200),
			ResetKnown:       true,
			RuleCreation:     unix(1735689600),
			RuleModification: unix(1740000000),
		},
		"never hit": {
			ResetKnown:       true,
			RuleCreation:     unix(1735689600),
			RuleModification: unix(1735689600),
		},
		"no-reset-field": {
			HitCount:         7,
			LastHit:          unix(1767225600),
			FirstHit:         unix(1735689700),
			RuleCreation:     unix(1735689600),
			RuleModification: unix(1735689600),
		},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRuleHitCounts =\n%+v\nwant\n%+v", got, want)
	}
	if s := fmt.Sprintf("%+v", got); strings.Contains(s, "must-not-leak") || strings.Contains(s, "Used") {
		t.Fatalf("non-allowlisted content leaked: %s", s)
	}
}

func TestParseRuleHitCountsKeepsResetTime(t *testing.T) {
	got, err := ParseRuleHitCounts(hcBody(hcEntry("r", "0", `<last-reset-timestamp>1764547200</last-reset-timestamp>`)))
	if err != nil {
		t.Fatalf("ParseRuleHitCounts: %v", err)
	}
	if r := got.Rules["r"]; !r.LastReset.Equal(unix(1764547200)) || r.LastReset.Location() != time.UTC || !r.ResetKnown {
		t.Fatalf("LastReset = %v, want %v UTC", r.LastReset, unix(1764547200))
	}
}

func TestParseRuleHitCountsMissingResetTimeIsZero(t *testing.T) {
	for _, tt := range []struct {
		extra string
		known bool
	}{
		{``, false},
		{`<last-reset-timestamp>0</last-reset-timestamp>`, true},
	} {
		got, err := ParseRuleHitCounts(hcBody(hcEntry("r", "3", tt.extra)))
		if err != nil {
			t.Fatalf("ParseRuleHitCounts(%q): %v", tt.extra, err)
		}
		if r, ok := got.Rules["r"]; !ok || !r.LastReset.IsZero() || r.HitCount != 3 || r.ResetKnown != tt.known {
			t.Fatalf("ParseRuleHitCounts(%q) = %+v, want zero LastReset, 3 hits, ResetKnown %v", tt.extra, got, tt.known)
		}
	}
}

func TestParseRuleHitCountsCounterLimits(t *testing.T) {
	tests := []struct {
		name string
		hits string
		want uint64
		ok   bool
	}{
		{"zero", "0", 0, true},
		{"max uint64", "18446744073709551615", math.MaxUint64, true},
		{"2^64 overflows", "18446744073709551616", 0, false},
		{"far over", "99999999999999999999999", 0, false},
		{"negative", "-1", 0, false},
		{"negative zero", "-0", 0, false},
		{"plus sign", "+5", 0, false},
		{"leading zero", "05", 0, false},
		{"hex", "0x10", 0, false},
		{"underscore", "1_000", 0, false},
		{"space", " 5", 0, false},
		{"trailing newline", "5\n", 0, false},
		{"fraction", "1.5", 0, false},
		{"exponent", "1e3", 0, false},
		{"empty", "", 0, false},
		{"unicode digit", "١", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRuleHitCounts(hcBody(hcEntry("r", tt.hits, "")))
			if !tt.ok {
				if !errors.Is(err, ErrInvalidHitCount) {
					t.Fatalf("err = %v, want ErrInvalidHitCount", err)
				}
				if got.Rules != nil || got.Incomplete {
					t.Fatalf("non-zero result with error: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRuleHitCounts: %v", err)
			}
			if got.Rules["r"].HitCount != tt.want {
				t.Fatalf("HitCount = %d, want %d", got.Rules["r"].HitCount, tt.want)
			}
		})
	}
}

func TestParseRuleHitCountsTimestampsStrict(t *testing.T) {
	fields := []string{
		"last-hit-timestamp", "first-hit-timestamp", "last-reset-timestamp",
		"rule-creation-timestamp", "rule-modification-timestamp",
	}
	bad := []string{
		"", " 1", "1 ", "-1", "+1", "01", "1.0", "1e9", "0x1",
		"2026-01-01T00:00:00Z", "2026/01/01 00:00:00",
		"253402300800",         // first second of year 10000
		"18446744073709551616", // over uint64
		"9223372036854775808",  // over int64
	}
	for _, f := range fields {
		for _, v := range bad {
			// hits 1 so that hit times are consistent with the count
			body := hcBody(hcEntry("r", "1", "<"+f+">"+v+"</"+f+">"))
			if _, err := ParseRuleHitCounts(body); !errors.Is(err, ErrInvalidHitCount) {
				t.Errorf("%s=%q: err = %v, want ErrInvalidHitCount", f, v, err)
			}
		}
		body := hcBody(hcEntry("r", "1", "<"+f+">253402300799</"+f+">"))
		if _, err := ParseRuleHitCounts(body); err != nil {
			t.Errorf("%s at year 9999: %v", f, err)
		}
		body = hcBody(hcEntry("r", "1", "<"+f+">1</"+f+"><"+f+">1</"+f+">"))
		if _, err := ParseRuleHitCounts(body); !errors.Is(err, ErrInvalidHitCount) {
			t.Errorf("%s repeated: err = %v, want ErrInvalidHitCount", f, err)
		}
	}
}

func TestParseRuleHitCountsRefusesBadEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries string
	}{
		{"duplicate name", hcEntry("r", "1", "") + hcEntry("r", "2", "")},
		{"invalid name", hcEntry("bad\tname", "1", "")},
		{"empty name", hcEntry("", "1", "")},
		{"name too long", hcEntry(strings.Repeat("a", MaxNameLength+1), "1", "")},
		{"missing hit-count", `<entry name="r"><last-hit-timestamp>0</last-hit-timestamp></entry>`},
		{"repeated hit-count", `<entry name="r"><hit-count>1</hit-count><hit-count>1</hit-count></entry>`},
		{"hits zero with last hit", hcEntry("r", "0", `<last-hit-timestamp>1767225600</last-hit-timestamp>`)},
		{"hits zero with first hit", hcEntry("r", "0", `<first-hit-timestamp>1767225600</first-hit-timestamp>`)},
		{"last hit before first hit", hcEntry("r", "2",
			`<first-hit-timestamp>1767225600</first-hit-timestamp><last-hit-timestamp>1767225599</last-hit-timestamp>`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRuleHitCounts(hcBody(tt.entries))
			if !errors.Is(err, ErrInvalidHitCount) {
				t.Fatalf("err = %v, want ErrInvalidHitCount", err)
			}
			if got.Rules != nil || got.Incomplete {
				t.Fatalf("non-zero result with error: %+v", got)
			}
			if strings.Contains(err.Error(), "bad") {
				t.Fatalf("error repeats device text: %v", err)
			}
		})
	}
}

func TestParseRuleHitCountsStructure(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"no rule-hit-count", wrapResult(``), ErrMalformedResponse},
		{"empty rule-hit-count", wrapResult(`<rule-hit-count/>`), ErrMalformedResponse},
		{"no rules element", wrapResult(`<rule-hit-count><vsys><entry name="vsys1"><rule-base><entry name="security"/></rule-base></entry></vsys></rule-hit-count>`), ErrMalformedResponse},
		{"other vsys", wrapResult(`<rule-hit-count><vsys><entry name="vsys2"><rule-base><entry name="security"><rules/></entry></rule-base></entry></vsys></rule-hit-count>`), ErrInvalidHitCount},
		{"two vsys", wrapResult(`<rule-hit-count><vsys><entry name="vsys1"/><entry name="vsys1"/></vsys></rule-hit-count>`), ErrInvalidHitCount},
		{"other rule base", wrapResult(`<rule-hit-count><vsys><entry name="vsys1"><rule-base><entry name="nat"><rules/></entry></rule-base></entry></vsys></rule-hit-count>`), ErrInvalidHitCount},
		{"repeated rules", wrapResult(`<rule-hit-count><vsys><entry name="vsys1"><rule-base><entry name="security"><rules/><rules/></entry></rule-base></entry></vsys></rule-hit-count>`), ErrInvalidHitCount},
		{"repeated rule-hit-count", wrapResult(`<rule-hit-count/><rule-hit-count/>`), ErrInvalidHitCount},
		{"repeated result", []byte(`<response status="success"><result/><result/></response>`), ErrInvalidHitCount},
		{"status error", readFixture(t, "status-error.xml"), ErrAPIStatus},
		{"not XML", []byte(`not xml`), ErrMalformedResponse},
		{"doctype", []byte(`<!DOCTYPE x [<!ENTITY a "b">]><response status="success"><result/></response>`), ErrMalformedResponse},
		{"too deep", wrapResult(strings.Repeat("<a>", netdevcontract.MaxXMLDepth) + strings.Repeat("</a>", netdevcontract.MaxXMLDepth)), ErrXMLLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRuleHitCounts(tt.data)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if got.Rules != nil || got.Incomplete {
				t.Fatalf("non-zero result with error: %+v", got)
			}
		})
	}
}

func TestParseRuleHitCountsEmptyRulebase(t *testing.T) {
	got, err := ParseRuleHitCounts(hcBody(``))
	if err != nil {
		t.Fatalf("ParseRuleHitCounts: %v", err)
	}
	if got.Rules == nil || len(got.Rules) != 0 || got.Incomplete {
		t.Fatalf("ParseRuleHitCounts = %+v, want empty complete set", got)
	}
}

func TestParseRuleHitCountsOverLimitIsIncomplete(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxHitCountEntries; i++ {
		fmt.Fprintf(&b, `<entry name="r%d"><hit-count>%d</hit-count></entry>`, i, i%2)
	}
	got, err := ParseRuleHitCounts(hcBody(b.String()))
	if err != nil {
		t.Fatalf("ParseRuleHitCounts: %v", err)
	}
	if !got.Incomplete || len(got.Rules) != MaxHitCountEntries {
		t.Fatalf("Incomplete = %v, %d rules; want incomplete with %d", got.Incomplete, len(got.Rules), MaxHitCountEntries)
	}
	if _, ok := got.Rules[fmt.Sprintf("r%d", MaxHitCountEntries)]; ok {
		t.Fatalf("entry beyond the limit kept")
	}
}

func TestObservedSince(t *testing.T) {
	created := unix(1735689600) // 2025-01-01
	reset := unix(1764547200)   // 2025-12-01
	tests := []struct {
		name string
		h    RuleHitCount
		want time.Time
		ok   bool
	}{
		{"reset after creation", RuleHitCount{RuleCreation: created, LastReset: reset, ResetKnown: true}, reset, true},
		{"creation after reset", RuleHitCount{RuleCreation: reset, LastReset: created, ResetKnown: true}, reset, true},
		{"never reset", RuleHitCount{RuleCreation: created, ResetKnown: true}, created, true},
		{"reset equals creation", RuleHitCount{RuleCreation: created, LastReset: created, ResetKnown: true}, created, true},
		{"reset not reported", RuleHitCount{RuleCreation: created}, time.Time{}, false},
		{"reset time without report flag", RuleHitCount{RuleCreation: created, LastReset: reset}, time.Time{}, false},
		{"creation unknown", RuleHitCount{LastReset: reset, ResetKnown: true}, time.Time{}, false},
		{"nothing known", RuleHitCount{}, time.Time{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ObservedSince(tt.h)
			if ok != tt.ok || !got.Equal(tt.want) {
				t.Fatalf("ObservedSince = %v, %v; want %v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestUnusedRules(t *testing.T) {
	created := unix(1735689600) // 2025-01-01
	reset := unix(1764547200)   // 2025-12-01
	since := unix(1765000000)   // after reset
	early := unix(1760000000)   // before reset, after creation
	rules := []Rule{
		{Index: 0, Name: "never-hit"},
		{Index: 1, Name: "hit-after-since"},
		{Index: 2, Name: "hit-before-since"},
		{Index: 3, Name: "no-data"},
		{Index: 4, Name: "hit-at-since"},
		{Index: 5, Name: "hits-without-last-hit"},
		{Index: 6, Name: "hit-before-reset-zero-now"},
		{Index: 7, Name: "never-reset-zero"},
		{Index: 8, Name: "reset-unknown-zero"},
		{Index: 9, Name: "creation-unknown-zero"},
		{Index: 10, Name: "created-after-early-zero"},
	}
	hits := map[string]RuleHitCount{
		"never-hit":                 {LastReset: reset, ResetKnown: true, RuleCreation: created},
		"hit-after-since":           {HitCount: 4, LastHit: since.Add(time.Hour), LastReset: reset, ResetKnown: true, RuleCreation: created},
		"hit-before-since":          {HitCount: 4, FirstHit: reset.Add(time.Hour), LastHit: since.Add(-time.Second), LastReset: reset, ResetKnown: true, RuleCreation: created},
		"hit-at-since":              {HitCount: 1, LastHit: since, ResetKnown: true, RuleCreation: created},
		"hits-without-last-hit":     {HitCount: 9, ResetKnown: true, RuleCreation: created},
		"hit-before-reset-zero-now": {LastReset: reset, ResetKnown: true, RuleCreation: created},
		"never-reset-zero":          {ResetKnown: true, RuleCreation: created},
		"reset-unknown-zero":        {RuleCreation: created},
		"creation-unknown-zero":     {ResetKnown: true},
		"created-after-early-zero":  {ResetKnown: true, RuleCreation: early.Add(time.Second)},
		"not-in-rulebase":           {ResetKnown: true, RuleCreation: created},
	}

	type res struct {
		Name  string
		Start time.Time
	}
	flat := func(us []UnusedRule) []res {
		out := []res{}
		for _, u := range us {
			out = append(out, res{u.Rule.Name, u.WindowStart})
		}
		return out
	}

	// reset and creation both before since: zero-hit rules are reported
	// with the later of the two as window start; a rule with hits is used
	// even if its last hit is before since (the ADR hint is "zero hits");
	// an unknown reset or creation time is never reported (fail safe)
	got := flat(UnusedRules(rules, hits, since))
	want := []res{
		{"never-hit", reset},
		{"hit-before-reset-zero-now", reset},
		{"never-reset-zero", created},
		{"created-after-early-zero", early.Add(time.Second)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnusedRules(since after reset) = %v, want %v", got, want)
	}

	// reset after since: the counter has not observed the requested
	// window, so a zero count is no hint; created after since: likewise
	got = flat(UnusedRules(rules, hits, early))
	want = []res{{"never-reset-zero", created}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnusedRules(since before reset) = %v, want %v", got, want)
	}

	// a window start equal to since counts as observed, one second later
	// does not
	got = flat(UnusedRules(rules, hits, reset))
	want = []res{
		{"never-hit", reset},
		{"hit-before-reset-zero-now", reset},
		{"never-reset-zero", created},
		{"created-after-early-zero", early.Add(time.Second)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnusedRules(since at reset) = %v, want %v", got, want)
	}
	got = flat(UnusedRules(rules, hits, early.Add(time.Second)))
	want = []res{{"never-reset-zero", created}, {"created-after-early-zero", early.Add(time.Second)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnusedRules(since at creation) = %v, want %v", got, want)
	}
	got = flat(UnusedRules(rules, hits, reset.Add(-time.Second)))
	want = []res{{"never-reset-zero", created}, {"created-after-early-zero", early.Add(time.Second)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnusedRules(one second before reset) = %v, want %v", got, want)
	}

	if got := UnusedRules(nil, hits, since); len(got) != 0 {
		t.Fatalf("UnusedRules(nil) = %v", flat(got))
	}
	if got := UnusedRules(rules, nil, since); len(got) != 0 {
		t.Fatalf("UnusedRules without hit counts = %v, want none (no data is no hint)", flat(got))
	}
	if got := UnusedRules(rules, hits, time.Time{}); len(got) != 0 {
		t.Fatalf("UnusedRules(zero since) = %v, want none", flat(got))
	}
}

// bigHitCountEntry is a worst-case rule entry: a name of maximum length,
// a 20-digit counter, every timestamp at full width and the
// non-allowlisted elements PAN-OS adds. With indent it is laid out as an
// indented reply; without, compact.
func bigHitCountEntry(i int, indent bool) string {
	name := fmt.Sprintf("%0*d", MaxNameLength, i)
	const ts = "1767225600"
	in, out := "", ""
	if indent {
		in, out = "\n                  ", "\n                "
	}
	return out + "<entry name=\"" + name + "\">" +
		in + "<latest>yes</latest>" +
		in + "<hit-count>18446744073709551615</hit-count>" +
		in + "<last-hit-timestamp>" + ts + "</last-hit-timestamp>" +
		in + "<last-reset-timestamp>" + ts + "</last-reset-timestamp>" +
		in + "<first-hit-timestamp>" + ts + "</first-hit-timestamp>" +
		in + "<rule-creation-timestamp>" + ts + "</rule-creation-timestamp>" +
		in + "<rule-modification-timestamp>" + ts + "</rule-modification-timestamp>" +
		in + "<rule-state>Used</rule-state>" +
		in + "<all-connected>yes</all-connected>" +
		out + "</entry>"
}

func TestHitCountCapFitsLargeRulebase(t *testing.T) {
	var indented, compact strings.Builder
	for i := 0; i <= MaxHitCountEntries; i++ {
		indented.WriteString(bigHitCountEntry(i, true))
		compact.WriteString(bigHitCountEntry(i, false))
	}
	// the indented reply bounds the size the transport cap must admit
	if n := int64(len(hcBody(indented.String()))); n > MaxHitCountResponseBytes {
		t.Fatalf("%d indented worst-case entries take %d bytes, over the %d byte cap", MaxHitCountEntries+1, n, MaxHitCountResponseBytes)
	}
	// the compact form is parsed: CheckXML counts inter-element whitespace
	// as element text (MaxXMLTextBytes), which an indented list of this
	// length exceeds
	body := hcBody(compact.String())
	if int64(len(body)) <= MaxOtherResponseBytes {
		t.Fatalf("test body of %d bytes does not exceed the generic cap", len(body))
	}
	if got := RuleHitCountRequest().maxBytes; got != MaxHitCountResponseBytes {
		t.Fatalf("RuleHitCountRequest cap = %d, want MaxHitCountResponseBytes", got)
	}
	got, err := ParseRuleHitCounts(body)
	if err != nil {
		t.Fatalf("ParseRuleHitCounts: %v", err)
	}
	if !got.Incomplete || len(got.Rules) != MaxHitCountEntries {
		t.Fatalf("Incomplete = %v, %d rules; want incomplete with %d", got.Incomplete, len(got.Rules), MaxHitCountEntries)
	}
}

func TestParseRuleHitCountsByteCap(t *testing.T) {
	pad := func(n int64) []byte {
		b := hcBody("")
		return append(b, strings.Repeat(" ", int(n)-len(b))...)
	}
	if _, err := ParseRuleHitCounts(pad(MaxHitCountResponseBytes)); err != nil {
		t.Fatalf("at cap: %v", err)
	}
	got, err := ParseRuleHitCounts(pad(MaxHitCountResponseBytes + 1))
	if !errors.Is(err, ErrXMLLimit) {
		t.Fatalf("over cap: err = %v, want ErrXMLLimit", err)
	}
	if got.Rules != nil || got.Incomplete {
		t.Fatalf("non-zero result with error: %+v", got)
	}
}

func FuzzParseRuleHitCounts(f *testing.F) {
	f.Add(readFixture(f, "hitcount.xml"))
	f.Add(hcBody(hcEntry("r", "18446744073709551616", "")))
	f.Add(hcBody(hcEntry("r", "-1", "")))
	f.Add(hcBody(hcEntry("r", "1", `<last-hit-timestamp>253402300800</last-hit-timestamp>`)))
	f.Add(hcBody(hcEntry("r", "1", "") + hcEntry("r", "1", "")))
	f.Add(hcBody(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseRuleHitCounts(data)
		if err != nil {
			if got.Rules != nil || got.Incomplete {
				t.Fatalf("error with non-zero result: %v", err)
			}
			return
		}
		if len(got.Rules) > MaxHitCountEntries {
			t.Fatalf("%d entries over limit", len(got.Rules))
		}
		for name, h := range got.Rules {
			if ValidateName(name) != nil {
				t.Fatalf("invalid rule name accepted")
			}
			for _, ts := range []time.Time{h.FirstHit, h.LastHit, h.LastReset, h.RuleCreation, h.RuleModification} {
				if !ts.IsZero() && (ts.Location() != time.UTC || ts.Year() < 1970 || ts.Year() > netdevcontract.MaxObservedYear) {
					t.Fatalf("timestamp out of range: %v", ts)
				}
			}
			if h.HitCount == 0 && (!h.FirstHit.IsZero() || !h.LastHit.IsZero()) {
				t.Fatalf("hit times without hits")
			}
			if !h.FirstHit.IsZero() && !h.LastHit.IsZero() && h.LastHit.Before(h.FirstHit) {
				t.Fatalf("last hit before first hit")
			}
		}
	})
}
