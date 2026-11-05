// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture reads a parser fixture of internal/netfacts.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "netfacts", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type sec struct {
	Status    string `json:"status"`
	Truncated bool   `json:"truncated"`
	Data      string `json:"data"`
}

func ok(b []byte) sec { return sec{Status: "ok", Data: base64.StdEncoding.EncodeToString(b)} }

// goodSections is a complete result as the script prints it on a host
// without lldpd and without CAP_NET_ADMIN for conntrack.
func goodSections(t *testing.T) map[string]any {
	return map[string]any{
		"format":      "net-facts-v1",
		"phase":       "done",
		"addr":        ok(fixture(t, "proxmox-addr.json")),
		"link":        ok(fixture(t, "proxmox-link.json")),
		"route":       ok(fixture(t, "debian12-route.json")),
		"route6":      ok(fixture(t, "ipv6-route.json")),
		"neigh":       ok(fixture(t, "debian12-neigh.json")),
		"neigh6":      ok([]byte("[]\n")),
		"bridge_vlan": ok(fixture(t, "proxmox-bridgevlan.json")),
		"lldp":        sec{Status: "absent"},
		"sockets":     ok(fixture(t, "debian12-ss.txt")),
		"conntrack":   sec{Status: "failed"},
	}
}

func encode(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeCompleteResult(t *testing.T) {
	f, err := Decode(encode(t, goodSections(t)))
	if err != nil {
		t.Fatal(err)
	}
	if f.Incomplete() {
		t.Fatalf("complete result marked incomplete: %+v", f.Sections)
	}
	if len(f.Addrs.Entries) == 0 || len(f.Links.Entries) == 0 || len(f.Routes.Entries) == 0 ||
		len(f.Routes6.Entries) == 0 || len(f.Neigh.Entries) == 0 || len(f.BridgeVLAN.Ports) == 0 ||
		len(f.Sockets.Entries) == 0 {
		t.Fatalf("tables not parsed: %+v", f)
	}
	if len(f.Neigh6.Entries) != 0 {
		t.Fatalf("neigh6 %+v", f.Neigh6)
	}
	// net.facts runs ss without -p: process names stay empty.
	for _, s := range f.Sockets.Entries {
		if s.Process != "" {
			t.Fatalf("process name %q without ss -p", s.Process)
		}
	}
	if f.LLDP != nil || f.Conntrack != nil {
		t.Fatalf("absent/failed sections carry data: %q %q", f.LLDP, f.Conntrack)
	}
	for _, name := range SectionNames {
		if _, ok := f.Sections[name]; !ok {
			t.Errorf("section %s missing from Sections", name)
		}
	}
	if f.Sections["lldp"].Status != StatusAbsent || f.Sections["conntrack"].Status != StatusFailed {
		t.Fatalf("sections %+v", f.Sections)
	}
}

func TestDecodeKeepsOptionalRawSections(t *testing.T) {
	m := goodSections(t)
	m["lldp"] = ok([]byte(`{"lldp":{"interface":[]}}`))
	m["conntrack"] = ok([]byte("tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.9\n"))
	f, err := Decode(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if string(f.LLDP) != `{"lldp":{"interface":[]}}` || !strings.HasPrefix(string(f.Conntrack), "tcp 6") || f.Incomplete() {
		t.Fatalf("%q %q %v", f.LLDP, f.Conntrack, f.Incomplete())
	}
}

// A required section that is absent, failed, skipped, cut or not
// parseable makes the result incomplete; the other sections still decode.
func TestDecodeIncompleteSections(t *testing.T) {
	addr := fixture(t, "proxmox-addr.json")
	for _, tc := range []struct {
		name    string
		section string
		s       sec
		invalid bool
	}{
		{"required absent", "addr", sec{Status: "absent"}, false},
		{"required failed", "sockets", sec{Status: "failed"}, false},
		{"skipped by budget", "neigh6", sec{Status: "skipped", Truncated: true}, false},
		{"cut JSON", "addr", sec{Status: "ok", Truncated: true, Data: base64.StdEncoding.EncodeToString(addr[:len(addr)/2])}, true},
		{"malformed JSON", "route", ok([]byte(`{"not":"an array"}`)), true},
		{"empty JSON section", "route6", ok(nil), true},
		{"cut optional section", "lldp", sec{Status: "ok", Truncated: true, Data: base64.StdEncoding.EncodeToString([]byte(`{"lldp":`))}, false},
		{"dropped entry", "neigh", ok([]byte(`[{"dst":"not-an-ip","dev":"eth0","state":["REACHABLE"]}]`)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := goodSections(t)
			m[tc.section] = tc.s
			f, err := Decode(encode(t, m))
			if err != nil {
				t.Fatal(err)
			}
			if !f.Incomplete() {
				t.Fatalf("%s: not incomplete: %+v", tc.section, f.Sections[tc.section])
			}
			if f.Sections[tc.section].Invalid != tc.invalid {
				t.Fatalf("%s: %+v", tc.section, f.Sections[tc.section])
			}
			if tc.section != "link" && len(f.Links.Entries) == 0 {
				t.Fatal("other sections not decoded")
			}
		})
	}
}

// A cut ss section is still parsed; its truncated last line is dropped.
func TestDecodeTruncatedSocketsParsed(t *testing.T) {
	ss := fixture(t, "debian12-ss.txt")
	m := goodSections(t)
	m["sockets"] = sec{Status: "ok", Truncated: true, Data: base64.StdEncoding.EncodeToString(ss[:len(ss)-5])}
	f, err := Decode(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Incomplete() || !f.Sections["sockets"].Truncated || len(f.Sockets.Entries) == 0 {
		t.Fatalf("%+v %d", f.Sections["sockets"], len(f.Sockets.Entries))
	}
}

func TestDecodeRejectsMalformedDocuments(t *testing.T) {
	big := make([]byte, MaxSection+1)
	half := make([]byte, MaxSection)
	for _, tc := range []struct {
		name string
		edit func(m map[string]any)
		raw  []byte
	}{
		{name: "not JSON", raw: []byte("not json")},
		{name: "array", raw: []byte("[]")},
		{name: "trailing data", raw: append(encode(t, goodSections(t)), []byte(` {}`)...)},
		{name: "oversize document", raw: append(encode(t, goodSections(t)), make([]byte, MaxDocument)...)},
		{name: "wrong format", edit: func(m map[string]any) { m["format"] = "net-facts-v2" }},
		{name: "precheck phase", edit: func(m map[string]any) { m["phase"] = "precheck"; m["reason"] = "x" }},
		{name: "unknown member", edit: func(m map[string]any) { m["processes"] = ok([]byte("x")) }},
		{name: "missing section", edit: func(m map[string]any) { delete(m, "sockets") }},
		{name: "section not an object", edit: func(m map[string]any) { m["addr"] = "W10=" }},
		{name: "unknown section member", edit: func(m map[string]any) {
			m["addr"] = map[string]any{"status": "ok", "truncated": false, "data": "W10=", "rc": 0}
		}},
		{name: "missing status", edit: func(m map[string]any) { m["addr"] = map[string]any{"truncated": false, "data": "W10="} }},
		{name: "missing data", edit: func(m map[string]any) { m["addr"] = map[string]any{"status": "ok", "truncated": false} }},
		{name: "missing truncated", edit: func(m map[string]any) { m["addr"] = map[string]any{"status": "ok", "data": "W10="} }},
		{name: "unknown status", edit: func(m map[string]any) { m["addr"] = sec{Status: "partial"} }},
		{name: "bad base64", edit: func(m map[string]any) { m["addr"] = sec{Status: "ok", Data: "W10*"} }},
		{name: "base64 with newline", edit: func(m map[string]any) { m["addr"] = sec{Status: "ok", Data: "W1\n0="} }},
		{name: "unpadded base64", edit: func(m map[string]any) { m["addr"] = sec{Status: "ok", Data: "W10"} }},
		{name: "data on absent section", edit: func(m map[string]any) { m["lldp"] = sec{Status: "absent", Data: "W10="} }},
		{name: "data on failed section", edit: func(m map[string]any) { m["conntrack"] = sec{Status: "failed", Data: "W10="} }},
		{name: "data on skipped section", edit: func(m map[string]any) { m["conntrack"] = sec{Status: "skipped", Truncated: true, Data: "W10="} }},
		{name: "skipped not truncated", edit: func(m map[string]any) { m["conntrack"] = sec{Status: "skipped"} }},
		{name: "unavailable on an IPv4 section", edit: func(m map[string]any) { m["route"] = sec{Status: "unavailable"} }},
		{name: "unavailable on sockets", edit: func(m map[string]any) { m["sockets"] = sec{Status: "unavailable"} }},
		{name: "unavailable with data", edit: func(m map[string]any) { m["route6"] = sec{Status: "unavailable", Data: "W10="} }},
		{name: "unavailable truncated", edit: func(m map[string]any) { m["neigh6"] = sec{Status: "unavailable", Truncated: true} }},
		{name: "absent truncated", edit: func(m map[string]any) { m["lldp"] = sec{Status: "absent", Truncated: true} }},
		{name: "section over the cap", edit: func(m map[string]any) { m["conntrack"] = ok(big) }},
		{name: "sections over the total", edit: func(m map[string]any) {
			m["conntrack"] = sec{Status: "ok", Truncated: true, Data: base64.StdEncoding.EncodeToString(half)}
			m["lldp"] = sec{Status: "ok", Truncated: true, Data: base64.StdEncoding.EncodeToString(half)}
			m["neigh6"] = sec{Status: "ok", Truncated: true, Data: base64.StdEncoding.EncodeToString(half)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == nil {
				m := goodSections(t)
				tc.edit(m)
				raw = encode(t, m)
			}
			if _, err := Decode(raw); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err %v, want ErrInvalidResult", err)
			}
		})
	}
}

func TestDecodeAcceptsSectionAtCap(t *testing.T) {
	m := goodSections(t)
	m["conntrack"] = ok(bytes.Repeat([]byte("x"), MaxSection))
	f, err := Decode(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Conntrack) != MaxSection {
		t.Fatalf("len %d", len(f.Conntrack))
	}
}

// Decode never panics and never returns an error other than
// ErrInvalidResult on arbitrary input.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"format":"net-facts-v1","phase":"done"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if _, err := Decode(raw); err != nil && !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("err %v", err)
		}
	})
}

// net.facts runs ss without -p: a sockets section with a users:((...))
// column (a wrapped or replaced ss) is refused, never handed out as
// process names.
func TestDecodeRefusesProcessNames(t *testing.T) {
	ss := fixture(t, "debian12-ss.txt")
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"users column", []byte("tcp   LISTEN 0      128            0.0.0.0:22         0.0.0.0:*    users:((\"sshd\",pid=1,fd=3))\n")},
		{"users column among real lines", append(append([]byte{}, ss...),
			[]byte("tcp   LISTEN 0      128            0.0.0.0:2222       0.0.0.0:*    users:((\"sshd\",pid=1,fd=3))\n")...)},
		{"malformed users column", []byte("tcp   LISTEN 0      128            0.0.0.0:22         0.0.0.0:*    users:((\"sshd\"\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := goodSections(t)
			m["sockets"] = ok(tc.data)
			f, err := Decode(encode(t, m))
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range f.Sockets.Entries {
				if s.Process != "" {
					t.Fatalf("process name %q without ss -p", s.Process)
				}
			}
			if len(f.Sockets.Entries) != 0 || !f.Sections["sockets"].Invalid || !f.Incomplete() {
				t.Fatalf("users column accepted: %+v %d entries", f.Sections["sockets"], len(f.Sockets.Entries))
			}
		})
	}
}

// The raw LLDP and conntrack sections are handed out only as valid UTF-8
// text without control characters other than newline and tab.
func TestDecodeValidatesRawSections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		data      []byte
		truncated bool
		want      []byte // nil: refused
	}{
		{"text", []byte("tcp\t6 431999 ESTABLISHED src=10.0.0.2\n"), false, []byte("tcp\t6 431999 ESTABLISHED src=10.0.0.2\n")},
		{"utf-8", []byte(`{"descr":"Schalter Küche"}`), false, []byte(`{"descr":"Schalter Küche"}`)},
		{"empty", []byte{}, false, []byte{}},
		{"escape", []byte("a\x1b[31mred\n"), false, nil},
		{"carriage return", []byte("a\rb\n"), false, nil},
		{"nul", []byte("a\x00b"), false, nil},
		{"c1 control", []byte("a\u0085b"), false, nil},
		{"bidi override", []byte("a\u202eb"), false, nil},
		{"invalid utf-8", []byte("a\xffb"), false, nil},
		{"cut rune not truncated", []byte("K\xc3"), false, nil},
		{"cut rune truncated", []byte("K\xc3"), true, []byte("K")},
		{"cut 3-byte rune truncated", []byte("a\xe2\x82"), true, []byte("a")},
		{"invalid inside truncated", []byte("a\xffb\xc3"), true, nil},
	} {
		for _, name := range []string{"lldp", "conntrack"} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				m := goodSections(t)
				m[name] = sec{Status: "ok", Truncated: tc.truncated, Data: base64.StdEncoding.EncodeToString(tc.data)}
				f, err := Decode(encode(t, m))
				if err != nil {
					t.Fatal(err)
				}
				got := f.LLDP
				if name == "conntrack" {
					got = f.Conntrack
				}
				if tc.want == nil {
					if got != nil || !f.Sections[name].Invalid || !f.Incomplete() {
						t.Fatalf("accepted %q: %+v", got, f.Sections[name])
					}
					return
				}
				if got == nil || !bytes.Equal(got, tc.want) || f.Sections[name].Invalid || f.Incomplete() != tc.truncated {
					t.Fatalf("got %q %+v, want %q", got, f.Sections[name], tc.want)
				}
			})
		}
	}
}

// On a host with IPv6 disabled both IPv6 sections are "unavailable": the
// result is complete and says so.
func TestDecodeIPv6Unavailable(t *testing.T) {
	m := goodSections(t)
	m["route6"] = sec{Status: "unavailable"}
	m["neigh6"] = sec{Status: "unavailable"}
	f, err := Decode(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if f.Incomplete() || !f.IPv6Unavailable() || len(f.Routes6.Entries) != 0 || len(f.Routes.Entries) == 0 {
		t.Fatalf("%+v", f.Sections)
	}
	g, err := Decode(encode(t, goodSections(t)))
	if err != nil {
		t.Fatal(err)
	}
	if g.IPv6Unavailable() {
		t.Fatal("IPv6 unavailable on a host with IPv6")
	}
	// A failed IPv6 command is still lost data.
	m = goodSections(t)
	m["route6"] = sec{Status: "failed"}
	if f, err := Decode(encode(t, m)); err != nil || !f.Incomplete() || f.IPv6Unavailable() {
		t.Fatalf("%v %+v", err, f.Sections)
	}
}
