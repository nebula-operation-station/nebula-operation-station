// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBothCriticalityValuesAreShownLabelled(t *testing.T) {
	r := baseRecord("pve1", "pve1", "192.168.22.1")
	r.InventoryCriticality = "LOW"
	r.ExecutorCriticality = "CRITICAL"
	res := mustProject(t, request("pve1", fakeSource{hosts: []Record{r}}, visibleOnly("pve1")))
	f := res.Hosts[0]
	if f.InventoryCriticality != "LOW" || f.ExecutorCriticality != "CRITICAL" {
		t.Fatalf("inventory=%q executor=%q, want LOW and CRITICAL", f.InventoryCriticality, f.ExecutorCriticality)
	}
}

func TestVisibilityIsAskedOnlyForNamedHosts(t *testing.T) {
	src := fakeSource{hosts: []Record{
		baseRecord("pve1", "pve1", "192.168.22.1"),
		baseRecord("other-1", "other-1", "10.0.0.1"),
		baseRecord("other-2", "other-2", "10.0.0.2"),
	}}
	var asked []string
	vis := func(_ context.Context, id string) (bool, error) {
		asked = append(asked, id)
		return true, nil
	}
	res := mustProject(t, request("why is pve1 slow?", src, vis))
	if !reflect.DeepEqual(asked, []string{"pve1"}) {
		t.Fatalf("visibility asked for %v, want [pve1]", asked)
	}
	if got := hostIDs(res); !reflect.DeepEqual(got, []string{"pve1"}) {
		t.Fatalf("hosts = %v, want [pve1]", got)
	}
}

func TestHiddenAddressIsNotInInventoryLikeAnUnknownOne(t *testing.T) {
	src := fakeSource{hosts: []Record{baseRecord("secret", "secret", "10.9.9.9")}}
	res := mustProject(t, request("is 10.9.9.9 up?", src, visibleOnly()))
	if len(res.Hosts) != 0 || !reflect.DeepEqual(res.NotInInventory, []string{"10.9.9.9"}) {
		t.Fatalf("result = %+v, want no hosts and NotInInventory [10.9.9.9]", res)
	}
}

func TestUnicodeLookalikeNameDoesNotMatch(t *testing.T) {
	// U+212A KELVIN SIGN folds to 'k' under Unicode case folding.
	r := baseRecord("h1", "Kube", "10.0.0.1")
	res := mustProject(t, request("is kube healthy?", fakeSource{hosts: []Record{r}}, visibleOnly("h1")))
	if len(res.Hosts) != 0 {
		t.Fatalf("Unicode look-alike matched the name literal: %+v", res.Hosts)
	}
	// An ASCII name still matches case-insensitively.
	r = baseRecord("h2", "KUBE-1", "10.0.0.2")
	res = mustProject(t, request("is kube-1 healthy?", fakeSource{hosts: []Record{r}}, visibleOnly("h2")))
	if got := hostIDs(res); !reflect.DeepEqual(got, []string{"h2"}) {
		t.Fatalf("ASCII name hosts = %v, want [h2]", got)
	}
}

func TestBroadCIDRQuestionProjectsNothing(t *testing.T) {
	src := fakeSource{hosts: []Record{
		baseRecord("a", "a", "10.0.0.1"),
		baseRecord("b", "b", "2001:db8::1"),
	}}
	res := mustProject(t, request("which hosts are in 0.0.0.0/0 or ::/0?", src, visibleOnly("a", "b")))
	if len(res.Hosts) != 0 || len(res.NotInInventory) != 0 {
		t.Fatalf("all-hosts CIDR produced facts: %+v", res)
	}
	if !res.Truncated {
		t.Fatal("refused CIDR must set Truncated")
	}
}

func TestAddressAfterManyWordsIsStillProjected(t *testing.T) {
	var q strings.Builder
	for i := 0; i < 60; i++ {
		q.WriteString("word")
		q.WriteString(strings.Repeat("x", i%5))
		q.WriteString(" ")
	}
	q.WriteString("is 10.4.4.4 up?")
	src := fakeSource{hosts: []Record{baseRecord("far", "far", "10.4.4.4")}}
	res := mustProject(t, request(q.String(), src, visibleOnly("far")))
	if got := hostIDs(res); !reflect.DeepEqual(got, []string{"far"}) || res.Truncated {
		t.Fatalf("hosts = %v truncated=%v, want [far] and not truncated", got, res.Truncated)
	}
}

func TestHostPortAndURLTokensSelectTheirHost(t *testing.T) {
	src := fakeSource{hosts: []Record{
		baseRecord("pve1", "pve1", "192.168.22.1"),
		baseRecord("nas", "nas", "10.0.0.7"),
	}}
	vis := visibleOnly("pve1", "nas")
	for q, want := range map[string]string{
		"pve1:8006 is slow":                 "pve1",
		"192.168.22.1:22 refuses":           "pve1",
		"https://10.0.0.7:5001/login fails": "nas",
	} {
		res := mustProject(t, request(q, src, vis))
		if got := hostIDs(res); !reflect.DeepEqual(got, []string{want}) {
			t.Fatalf("%q: hosts = %v, want [%s]", q, got, want)
		}
	}
}

func TestEnrollmentSinceIsValidated(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cest := time.FixedZone("CET", 2*3600)
	tests := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{"zero stays zero", time.Time{}, time.Time{}},
		{"future date dropped", time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC), time.Time{}},
		{"before 2000 dropped", time.Date(1999, 12, 31, 0, 0, 0, 0, time.UTC), time.Time{}},
		{"today kept", time.Date(2026, 11, 12, 23, 0, 0, 0, time.UTC), time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)},
		{"non-UTC location normalised to UTC day", time.Date(2026, 11, 1, 1, 0, 0, 0, cest),
			time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := baseRecord("h", "h", "10.0.0.1")
			r.EnrollmentSince = tc.in
			req := request("h", fakeSource{hosts: []Record{r}}, visibleOnly("h"))
			req.Now = func() time.Time { return now }
			res := mustProject(t, req)
			if got := res.Hosts[0].EnrollmentSince; !got.Equal(tc.want) || got.Location() != time.UTC {
				t.Fatalf("EnrollmentSince = %v (%v), want %v UTC", got, got.Location(), tc.want)
			}
		})
	}
}

func TestCleanTextDropsNonPrintableCodePoints(t *testing.T) {
	tests := map[string]string{
		"private use":         "pve" + "1",
		"noncharacter":        "pve￾" + "1",
		"unassigned":          "pve͸" + "1",
		"unassigned plane 14": "pve\U000e0001" + "1", // U+E0001 LANGUAGE TAG (Cf)
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			got := cleanText(in, MaxNameBytes)
			if !got.Altered {
				t.Fatalf("Altered = false for %q", in)
			}
			for _, c := range got.Value {
				if c != ' ' && !printable(c) {
					t.Fatalf("non-printable %U survived in %q", c, got.Value)
				}
			}
			if strings.ContainsAny(got.Value, "￾͸\U000e0001") {
				t.Fatalf("code point survived: %q", got.Value)
			}
		})
	}
}

func TestCleanTextWorkIsBoundedByOutputSize(t *testing.T) {
	// A huge run of separators must not be scanned to the end.
	in := strings.Repeat("\x00", 1<<20) + "abc"
	got := cleanText(in, MaxNameBytes)
	if got.Value != "" || !got.Altered {
		t.Fatalf("got %+v, want empty and altered", got)
	}
	long := cleanText(strings.Repeat("a", 1<<20), MaxNameBytes)
	if len(long.Value) != MaxNameBytes || !long.Altered {
		t.Fatalf("long value length %d altered %v", len(long.Value), long.Altered)
	}
}

func TestCleanTextCollapsesSeparatorsAndTrims(t *testing.T) {
	got := cleanText("  pve \t\n  1 ", MaxNameBytes)
	if got.Value != "pve 1" || !got.Altered {
		t.Fatalf("got %+v, want \"pve 1\" altered", got)
	}
	if plain := cleanText("pve 1", MaxNameBytes); plain.Altered || plain.Value != "pve 1" {
		t.Fatalf("plain value altered: %+v", plain)
	}
}

func TestSharedTokenizerAdmitsSameHostsAsSelection(t *testing.T) {
	// The question's tokens decide the hosts; both paths use parseLiterals.
	const q = "pve1:22, 10.0.0.1:22; (web-2.)"
	if got, want := Tokenize(q), []string{"pve1:22", "10.0.0.1:22", "web-2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Tokenize = %q, want %q", got, want)
	}
	v := ParseQuestionHostValues(q)
	if !reflect.DeepEqual(v.Addresses, []string{"10.0.0.1"}) || !reflect.DeepEqual(v.Names, []string{"pve1", "web-2"}) {
		t.Fatalf("values = %+v", v)
	}
}
