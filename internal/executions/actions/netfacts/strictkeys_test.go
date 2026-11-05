// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/base64"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// goodDoc is the encoded complete result; json.Marshal sorts the keys, so
// it starts with `{"addr":` and conntrack is a failed section.
func goodDoc(t *testing.T) string {
	t.Helper()
	return string(encode(t, goodSections(t)))
}

const failedConntrack = `"conntrack":{"status":"failed","truncated":false,"data":""}`

// splice replaces exactly one occurrence of old in doc.
func splice(t *testing.T, doc, old, repl string) []byte {
	t.Helper()
	if strings.Count(doc, old) != 1 {
		t.Fatalf("%q occurs %d times", old, strings.Count(doc, old))
	}
	return []byte(strings.Replace(doc, old, repl, 1))
}

// A case-variant or duplicate member of the document or of a section
// object rejects the whole result: encoding/json alone would match it
// case-insensitively or let the last value win.
func TestDecodeRejectsCaseVariantAndDuplicateKeys(t *testing.T) {
	doc := goodDoc(t)
	if _, err := Decode([]byte(doc)); err != nil {
		t.Fatalf("good document rejected: %v", err)
	}
	insertTop := func(member string) []byte { return []byte("{" + member + "," + doc[1:]) }
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"top case variant", insertTop(`"Format":"net-facts-v1"`)},
		{"top upper case", insertTop(`"PHASE":"done"`)},
		{"top duplicate", insertTop(`"format":"net-facts-v1"`)},
		{"top duplicate escaped", insertTop(`"format":"net-facts-v1"`)},
		{"top duplicate section", insertTop(`"conntrack":{"status":"absent","truncated":false,"data":""}`)},
		{"top section case variant", insertTop(`"Conntrack":{"status":"absent","truncated":false,"data":""}`)},
		{"top section fold variant", splice(t, doc, `"conntrack":`, `"Conntrack":`)},
		{"top kelvin sign", splice(t, doc, `"link":`, "\"linK\":")},
		{"section case variant", splice(t, doc, failedConntrack, `"conntrack":{"Status":"failed","truncated":false,"data":""}`)},
		{"section long s", splice(t, doc, failedConntrack, "\"conntrack\":{\"ſtatus\":\"failed\",\"truncated\":false,\"data\":\"\"}")},
		{"section duplicate", splice(t, doc, failedConntrack, `"conntrack":{"status":"failed","truncated":false,"data":"","data":""}`)},
		{"section duplicate status", splice(t, doc, failedConntrack, `"conntrack":{"status":"ok","truncated":false,"data":"","status":"failed"}`)},
		{"section case duplicate", splice(t, doc, failedConntrack, `"conntrack":{"status":"failed","truncated":false,"data":"","DATA":""}`)},
		{"section nested object", splice(t, doc, failedConntrack, `"conntrack":{"status":"failed","truncated":false,"data":"","x":{"y":1}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.raw); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("Decode = %v, want ErrInvalidResult", err)
			}
		})
	}
}

// A parsed (JSON) section with a duplicate member, a case variant of a
// member or a case variant of a parser field at any level is invalid: its
// table stays empty and the result is incomplete; the other sections
// still decode.
func TestDecodeRefusesCaseVariantAndDuplicateKeysInParsedSections(t *testing.T) {
	for _, tc := range []struct {
		name    string
		section string
		data    string
	}{
		{"addr duplicate", "addr", `[{"ifname":"lo","ifname":"eth0","address":"00:00:00:00:00:00","link_type":"loopback","operstate":"UNKNOWN","addr_info":[]}]`},
		{"addr case variant", "addr", `[{"IFNAME":"eth0","address":"00:00:00:00:00:00","link_type":"ether","operstate":"UP","addr_info":[]}]`},
		{"addr case pair", "addr", `[{"ifname":"lo","IfName":"eth0","address":"00:00:00:00:00:00","link_type":"loopback","operstate":"UNKNOWN","addr_info":[]}]`},
		{"addr nested duplicate", "addr", `[{"ifname":"lo","address":"00:00:00:00:00:00","link_type":"loopback","operstate":"UNKNOWN","addr_info":[{"family":"inet","local":"127.0.0.1","local":"10.0.0.1","prefixlen":8}]}]`},
		{"addr nested case variant", "addr", `[{"ifname":"lo","address":"00:00:00:00:00:00","link_type":"loopback","operstate":"UNKNOWN","addr_info":[{"family":"inet","Local":"10.0.0.1","prefixlen":8}]}]`},
		{"route kelvin sign", "route", "[{\"dst\":\"default\",\"gateway\":\"10.0.0.1\",\"dev\":\"eth0\",\"metric\":1,\"K\":1,\"k\":2}]"},
		{"route unknown duplicate", "route", `[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","flags":[],"flags":[]}]`},
		{"route escaped duplicate", "route", `[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","dev":"eth1"}]`},
		{"neigh case variant", "neigh", `[{"Dst":"10.0.0.1","dev":"eth0","lladdr":"52:54:00:00:00:01","state":["REACHABLE"]}]`},
		{"link deep case variant", "link", `[{"ifname":"vmbr0","address":"52:54:00:00:00:01","link_type":"ether","linkinfo":{"info_kind":"vlan","info_data":{"ID":5}}}]`},
		{"bridge_vlan case variant", "bridge_vlan", `[{"ifname":"vmbr0","vlans":[{"vlan":1,"VlanEnd":9,"flags":[]}]}]`},
		{"too deep", "route", "[" + strings.Repeat(`{"a":`, maxKeyDepth+1) + "1" + strings.Repeat("}", maxKeyDepth+1) + "]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := goodSections(t)
			m[tc.section] = ok([]byte(tc.data))
			f, err := Decode(encode(t, m))
			if err != nil {
				t.Fatal(err)
			}
			if !f.Sections[tc.section].Invalid || !f.Incomplete() {
				t.Fatalf("section %s not invalid: %+v", tc.section, f.Sections[tc.section])
			}
			empty := map[string]bool{
				"addr": len(f.Addrs.Entries) == 0, "link": len(f.Links.Entries) == 0,
				"route": len(f.Routes.Entries) == 0, "neigh": len(f.Neigh.Entries) == 0,
				"bridge_vlan": len(f.BridgeVLAN.Ports) == 0,
			}
			if !empty[tc.section] {
				t.Fatalf("section %s kept a table: %+v", tc.section, f)
			}
			if len(f.Sockets.Entries) == 0 {
				t.Fatal("other sections not decoded")
			}
		})
	}
}

// The strict key check accepts what the parsers accept on real hosts: the
// fixtures, unknown keys in exact case, nesting up to maxKeyDepth, and
// keys that differ in more than case.
func TestStrictKeysAcceptsWellFormedSections(t *testing.T) {
	for _, data := range []string{
		"",
		"[]\n",
		`[{"ifname":"lo","vlanEnd":1,"vlan":1,"Vlan_x":1}]`,
		"[" + strings.Repeat(`{"a":`, maxKeyDepth-1) + "1e999" + strings.Repeat("}", maxKeyDepth-1) + "]",
	} {
		if err := checkSectionKeys([]byte(data)); err != nil {
			t.Errorf("checkSectionKeys(%q) = %v", data, err)
		}
	}
	for _, name := range []string{
		"proxmox-addr.json", "proxmox-link.json", "debian12-route.json",
		"ipv6-route.json", "debian12-neigh.json", "proxmox-bridgevlan.json",
	} {
		if err := checkSectionKeys(fixture(t, name)); err != nil {
			t.Errorf("fixture %s: %v", name, err)
		}
	}
}

// A section cut inside a key is not valid JSON and is invalid, as the
// parser would decide.
func TestDecodeCutParsedSectionStaysInvalid(t *testing.T) {
	m := goodSections(t)
	m["addr"] = sec{Status: "ok", Truncated: true, Data: base64.StdEncoding.EncodeToString([]byte(`[{"ifna`))}
	f, err := Decode(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Sections["addr"].Invalid {
		t.Fatalf("%+v", f.Sections["addr"])
	}
}

// parserFields must list every JSON field name the internal/netfacts
// parsers bind, so a case variant of a new field is refused as well.
func TestParserFieldsMatchNetfactsParsers(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "netfacts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			f, isField := n.(*ast.Field)
			if !isField || f.Tag == nil {
				return true
			}
			tag, err := strconv.Unquote(f.Tag.Value)
			if err != nil {
				t.Fatal(err)
			}
			name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
			if name != "" && name != "-" {
				found[name] = true
			}
			return true
		})
	}
	if len(found) == 0 {
		t.Fatal("no json tags found in internal/netfacts")
	}
	for name := range found {
		if _, listed := parserFieldFold[foldKey(name)]; !listed {
			t.Errorf("internal/netfacts binds %q, which parserFields lacks", name)
		}
	}
}

func TestFoldKeyMatchesEqualFold(t *testing.T) {
	for _, tc := range []struct {
		a, b string
	}{
		{"format", "FORMAT"}, {"k", "K"}, {"s", "ſ"}, {"vlanEnd", "VLANEND"},
		{"ifname", "ifnamе"}, // Cyrillic e: not a fold of e
		{"a", "aa"}, {"", ""}, {"é", "É"}, {"�", "�"},
	} {
		if got, want := foldKey(tc.a) == foldKey(tc.b), strings.EqualFold(tc.a, tc.b); got != want {
			t.Errorf("foldKey(%q)==foldKey(%q) is %v, EqualFold %v", tc.a, tc.b, got, want)
		}
	}
}
