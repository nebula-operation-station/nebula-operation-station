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
			RuleCreation:     unix(1735689600),
			RuleModification: unix(1740000000),
		},
		"never hit": {
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
	if r := got.Rules["r"]; !r.LastReset.Equal(unix(1764547200)) || r.LastReset.Location() != time.UTC {
		t.Fatalf("LastReset = %v, want %v UTC", r.LastReset, unix(1764547200))
	}
}

func TestParseRuleHitCountsMissingResetTimeIsZero(t *testing.T) {
	for _, extra := range []string{``, `<last-reset-timestamp>0</last-reset-timestamp>`} {
		got, err := ParseRuleHitCounts(hcBody(hcEntry("r", "3", extra)))
		if err != nil {
			t.Fatalf("ParseRuleHitCounts(%q): %v", extra, err)
		}
		if r, ok := got.Rules["r"]; !ok || !r.LastReset.IsZero() || r.HitCount != 3 {
			t.Fatalf("ParseRuleHitCounts(%q) = %+v, want zero LastReset and 3 hits", extra, got)
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

func TestUnusedRules(t *testing.T) {
	reset := unix(1764547200) // 2025-12-01
	since := unix(1765000000) // after reset
	early := unix(1760000000) // before reset
	rules := []Rule{
		{Index: 0, Name: "never-hit"},
		{Index: 1, Name: "hit-after-since"},
		{Index: 2, Name: "hit-before-since"},
		{Index: 3, Name: "no-data"},
		{Index: 4, Name: "hit-at-since"},
		{Index: 5, Name: "hits-without-last-hit"},
		{Index: 6, Name: "hit-before-reset-zero-now"},
	}
	hits := map[string]RuleHitCount{
		"never-hit":                 {LastReset: reset},
		"hit-after-since":           {HitCount: 4, LastHit: since.Add(time.Hour), LastReset: reset},
		"hit-before-since":          {HitCount: 4, FirstHit: reset.Add(time.Hour), LastHit: since.Add(-time.Second), LastReset: reset},
		"hit-at-since":              {HitCount: 1, LastHit: since},
		"hits-without-last-hit":     {HitCount: 9},
		"hit-before-reset-zero-now": {LastReset: reset},
		"not-in-rulebase":           {},
	}

	names := func(rs []Rule) []string {
		out := []string{}
		for _, r := range rs {
			out = append(out, r.Name)
		}
		return out
	}

	// since is later than the reset: hits before since do not count
	got := names(UnusedRules(rules, hits, since))
	want := []string{"never-hit", "hit-before-since", "hit-before-reset-zero-now"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnusedRules(since after reset) = %v, want %v", got, want)
	}

	// since is earlier than the reset: the counter covers only the time
	// after the reset, so the reset is the effective start and any
	// counted hit makes the rule used
	got = names(UnusedRules(rules, hits, early))
	want = []string{"never-hit", "hit-before-reset-zero-now"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnusedRules(since before reset) = %v, want %v", got, want)
	}

	// a reset later than since overrides since for that rule
	late := map[string]RuleHitCount{
		"r": {HitCount: 2, FirstHit: unix(1767225000), LastHit: unix(1767225600), LastReset: unix(1767220000)},
	}
	if got := UnusedRules([]Rule{{Name: "r"}}, late, since); len(got) != 0 {
		t.Fatalf("rule hit after a reset later than since reported unused: %v", names(got))
	}

	if got := UnusedRules(nil, hits, since); len(got) != 0 {
		t.Fatalf("UnusedRules(nil) = %v", got)
	}
	if got := UnusedRules(rules, nil, since); len(got) != 0 {
		t.Fatalf("UnusedRules without hit counts = %v, want none (no data is no hint)", names(got))
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
