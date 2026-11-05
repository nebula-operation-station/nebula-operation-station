// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
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
		{"top duplicate escaped", insertTop(`"\u0066ormat":"net-facts-v1"`)},
		{"top case variant escaped", insertTop(`"\u0046ormat":"net-facts-v1"`)},
		{"top dotted capital I", splice(t, doc, `"lldp":`, "\"\\u0130ldp\":")},
		{"top dotless i", insertTop("\"ph\\u0131se\":\"done\"")},
		{"top dotless i raw", insertTop("\"phıse\":\"done\"")},
		{"section dotted capital I", splice(t, doc, failedConntrack, "\"conntrack\":{\"status\":\"failed\",\"truncated\":false,\"data\":\"\",\"İ\":1}")},
		{"section escaped duplicate", splice(t, doc, failedConntrack, `"conntrack":{"status":"failed","truncated":false,"data":"","\u0064ata":""}`)},
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
		{"route escaped duplicate", "route", `[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","\u0064ev":"eth1"}]`},
		{"route escaped case variant", "route", `[{"dst":"default","gateway":"10.0.0.1","\u0044ev":"eth1"}]`},
		{"addr dotted capital I", "addr", `[{"ifname":"lo","İfname":"evil","address":"00:00:00:00:00:00","link_type":"loopback","operstate":"UNKNOWN","addr_info":[]}]`},
		{"addr dotless i escaped", "addr", `[{"ifname":"lo","\u0131fname":"evil","address":"00:00:00:00:00:00","link_type":"loopback","operstate":"UNKNOWN","addr_info":[]}]`},
		{"link nested dotted capital I", "link", `[{"ifname":"vmbr0","address":"52:54:00:00:00:01","link_type":"ether","linkinfo":{"info_kind":"vlan","info_data":{"id":5,"\u0130d":6}}}]`},
		{"link nested dotless i", "link", `[{"ifname":"vmbr0","address":"52:54:00:00:00:01","link_type":"ether","linkinfo":{"ınfo_kind":"vlan"}}]`},
		{"route unknown non-ASCII", "route", `[{"dst":"default","dev":"eth0","métrique":1}]`},
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

// jsonStruct returns a struct type with one json.RawMessage field per
// name, tagged with that name; encoding/json matches member names to it
// exactly as it matches them to the real parser and document structs,
// whose tags the tests below keep identical to these name lists.
func jsonStruct(names []string) reflect.Type {
	fields := make([]reflect.StructField, len(names))
	for i, n := range names {
		fields[i] = reflect.StructField{
			Name: "F" + strconv.Itoa(i),
			Type: reflect.TypeFor[json.RawMessage](),
			Tag:  reflect.StructTag(`json:"` + n + `"`),
		}
	}
	return reflect.StructOf(fields)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	parserStruct   = jsonStruct(parserFields)
	documentNames  = sortedKeys(documentKeys)
	documentStruct = jsonStruct(documentNames)
	sectionNames   = sortedKeys(sectionKeys)
	sectionStruct  = jsonStruct(sectionNames)
)

// jsonBinds reports the field name encoding/json binds the member named
// key to, decoding {key: 1} into typ, whose fields are named names.
func jsonBinds(t testing.TB, typ reflect.Type, names []string, key string) (string, bool) {
	t.Helper()
	k, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	v := reflect.New(typ)
	if err := json.Unmarshal([]byte("{"+string(k)+":1}"), v.Interface()); err != nil {
		t.Fatalf("oracle decode of %q: %v", key, err)
	}
	for i, n := range names {
		if v.Elem().Field(i).Len() > 0 {
			return n, true
		}
	}
	return "", false
}

// assertStrictAgainstJSON checks the strict key rule against what
// encoding/json actually does with the member name key: whenever the
// decoder would bind key to a field, the check rejects it unless key is
// the exact field name, and it rejects a second member bound to the same
// field. Every non-ASCII name is rejected.
func assertStrictAgainstJSON(t testing.TB, key string) {
	t.Helper()
	k, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	ks := string(k)
	ascii := isASCII(key)
	if !utf8.ValidString(key) {
		ascii = false // json.Marshal turned the bad bytes into U+FFFD
	}
	section := func(data string) error { return checkSectionKeys([]byte(data)) }
	if tag, bound := jsonBinds(t, parserStruct, parserFields, key); bound {
		if err := section(`[{"` + tag + `":0,` + ks + `:1}]`); err == nil {
			t.Errorf("json binds %q to %q; second member accepted", key, tag)
		}
		if err := section(`[{"linkinfo":{"info_data":{"` + tag + `":0,` + ks + `:1}}}]`); err == nil {
			t.Errorf("json binds %q to %q; nested second member accepted", key, tag)
		}
		if key != tag {
			for _, data := range []string{`{` + ks + `:1}`, `[{"x":[{` + ks + `:1}]}]`} {
				if err := section(data); err == nil {
					t.Errorf("json binds %q to %q; %s accepted", key, tag, data)
				}
			}
		}
	}
	if !ascii {
		if err := section(`[{` + ks + `:1}]`); err == nil {
			t.Errorf("non-ASCII section member %q accepted", key)
		}
	}
	doc := func(data string) error { return checkDocumentKeys([]byte(data)) }
	if tag, bound := jsonBinds(t, documentStruct, documentNames, key); (bound && key != tag) || !ascii {
		if err := doc(`{` + ks + `:1}`); err == nil {
			t.Errorf("document member %q (json binds %q) accepted", key, tag)
		}
	}
	if tag, bound := jsonBinds(t, documentStruct, documentNames, key); bound {
		if err := doc(`{"` + tag + `":0,` + ks + `:1}`); err == nil {
			t.Errorf("document member %q duplicating %q accepted", key, tag)
		}
	}
	if tag, bound := jsonBinds(t, sectionStruct, sectionNames, key); (bound && key != tag) || !ascii {
		if err := doc(`{"addr":{` + ks + `:1}}`); err == nil {
			t.Errorf("section object member %q (json binds %q) accepted", key, tag)
		}
	}
	if tag, bound := jsonBinds(t, sectionStruct, sectionNames, key); bound {
		if err := doc(`{"addr":{"` + tag + `":0,` + ks + `:1}}`); err == nil {
			t.Errorf("section object member %q duplicating %q accepted", key, tag)
		}
	}
}

// strictKeyCandidates returns case and fold variants of every schema and
// parser name: ASCII case changes, U+0130/U+0131 for i, U+212A for k,
// U+017F for s and mixes of them.
func strictKeyCandidates() []string {
	var names []string
	names = append(names, parserFields...)
	names = append(names, documentNames...)
	names = append(names, sectionNames...)
	subst := []*strings.Replacer{
		strings.NewReplacer("i", "İ"), strings.NewReplacer("i", "ı"),
		strings.NewReplacer("i", "I"), strings.NewReplacer("k", "K"),
		strings.NewReplacer("s", "ſ"), strings.NewReplacer("i", "İ", "k", "K", "s", "S"),
		strings.NewReplacer("i", "ı", "k", "K", "s", "ſ"),
		strings.NewReplacer("i", "I", "k", "K", "a", "A"),
	}
	out := []string{"", "x", "İ", "ı", "I", "K", "ſ", "�", "\xff"}
	for _, n := range names {
		out = append(out, n, strings.ToUpper(n), strings.ToUpper(n[:1])+n[1:], n+"̇", "İ"+n[1:])
		for _, r := range subst {
			out = append(out, r.Replace(n), strings.ToUpper(r.Replace(n)))
		}
	}
	return out
}

// The oracle is encoding/json itself, not a model of its folding.
func TestStrictKeysMatchJSON(t *testing.T) {
	// Sanity: the oracle sees the decoder's case-insensitive matching.
	for key, want := range map[string]string{"IFNAME": "ifname", "linK": "link", "ſtatus": "status", "VLANEND": "vlanEnd"} {
		names, typ := parserFields, parserStruct
		if want == "status" {
			names, typ = sectionNames, sectionStruct
		}
		if got, _ := jsonBinds(t, typ, names, key); got != want {
			t.Fatalf("oracle: %q binds %q, want %q", key, got, want)
		}
	}
	for _, key := range strictKeyCandidates() {
		assertStrictAgainstJSON(t, key)
	}
}

// FuzzStrictKeysMatchJSON checks the strict key rule against encoding/json
// for arbitrary member names (bounded to 256 bytes).
func FuzzStrictKeysMatchJSON(f *testing.F) {
	for _, key := range strictKeyCandidates() {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if len(key) > 256 {
			return // bounded: longer keys add nothing
		}
		assertStrictAgainstJSON(t, key)
		// Accepted names are ASCII and never a case variant of a field.
		k, _ := json.Marshal(key)
		if checkSectionKeys([]byte("[{"+string(k)+":1}]")) == nil {
			if !isASCII(key) || !utf8.ValidString(key) {
				t.Fatalf("non-ASCII %q accepted", key)
			}
			if tag, bound := jsonBinds(t, parserStruct, parserFields, key); bound && tag != key {
				t.Fatalf("%q accepted, json binds it to %q", key, tag)
			}
		}
	})
}

// documentKeys and sectionKeys are exactly the tags of resultDoc and
// sectionDoc.
func TestDocumentKeysMatchDecodeStructs(t *testing.T) {
	for _, tc := range []struct {
		typ  reflect.Type
		want []string
	}{
		{reflect.TypeFor[resultDoc](), documentNames},
		{reflect.TypeFor[sectionDoc](), sectionNames},
	} {
		var got []string
		for i := range tc.typ.NumField() {
			f := tc.typ.Field(i)
			got = append(got, jsonFieldName(f.Name, string(f.Tag)))
		}
		sort.Strings(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%v binds %q, key list is %q", tc.typ, got, tc.want)
		}
	}
}

// jsonFieldName returns the member name encoding/json uses for an
// exported field: its json tag name, else the field name; "" for "-".
func jsonFieldName(field, tag string) string {
	name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
	switch {
	case name == "-" && !strings.HasPrefix(reflect.StructTag(tag).Get("json"), "-,"):
		return ""
	case name == "":
		return field
	}
	return name
}

// parserFields must be exactly the JSON field names the internal/netfacts
// parsers bind, spelled as encoding/json sees them (the tag, or the field
// name of an exported untagged field), so a case variant of any field is
// refused and no exact field name is.
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
		// Named struct types by their struct node; every other struct
		// type (an anonymous inline struct such as []struct{...}) is
		// walked as well.
		named := map[*ast.StructType]string{}
		ast.Inspect(file, func(n ast.Node) bool {
			if ts, isType := n.(*ast.TypeSpec); isType {
				if st, isStruct := ts.Type.(*ast.StructType); isStruct {
					named[st] = ts.Name.Name
				}
			}
			return true
		})
		ast.Inspect(file, func(n ast.Node) bool {
			st, isStruct := n.(*ast.StructType)
			if !isStruct {
				return true
			}
			name, isNamed := named[st]
			if !isNamed {
				name = "anonymous struct at " + fset.Position(st.Pos()).String()
			}
			// A JSON document struct: named *Doc or carrying a json tag.
			isDoc := strings.HasSuffix(name, "Doc")
			tags := make([]string, len(st.Fields.List))
			for i, f := range st.Fields.List {
				if f.Tag == nil {
					continue
				}
				tag, err := strconv.Unquote(f.Tag.Value)
				if err != nil {
					t.Fatal(err)
				}
				tags[i] = tag
				if _, has := reflect.StructTag(tag).Lookup("json"); has {
					isDoc = true
				}
			}
			if !isDoc {
				return true
			}
			for i, f := range st.Fields.List {
				if len(f.Names) == 0 {
					t.Errorf("%s: embedded field in a JSON struct is not supported by this check", name)
					continue
				}
				for _, id := range f.Names {
					if !id.IsExported() {
						continue
					}
					if name := jsonFieldName(id.Name, tags[i]); name != "" {
						found[name] = true
					}
				}
			}
			return true
		})
	}
	if len(found) == 0 {
		t.Fatal("no JSON structs found in internal/netfacts")
	}
	got := sortedKeys(found)
	want := slices.Sorted(slices.Values(parserFields))
	if !slices.Equal(got, want) {
		t.Errorf("internal/netfacts binds %q, parserFields is %q", got, want)
	}
}

func TestFoldKeyIsASCIIFold(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"format", "FORMAT", true}, {"vlanEnd", "VLANEND", true}, {"a_b", "A_B", true},
		{"k", "K", false}, {"s", "ſ", false}, {"i", "İ", false}, {"I", "ı", false},
		{"a", "aa", false}, {"", "", true},
	} {
		if got := foldKey(tc.a) == foldKey(tc.b); got != tc.same {
			t.Errorf("foldKey(%q)==foldKey(%q) is %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}

// No rejection error carries an unbounded amount of host-supplied text:
// a long unknown member, a long format or phase value or a long number
// literal is quoted at most in part.
func TestDecodeErrorsAreBounded(t *testing.T) {
	doc := goodDoc(t)
	long := strings.Repeat("x", 100<<10)
	digits := "1" + strings.Repeat("0", 100<<10)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"top unknown key", []byte(`{"` + long + `":1,` + doc[1:])},
		{"top unknown non-ASCII key", []byte(`{"İ` + long + `":1,` + doc[1:])},
		{"section unknown key", splice(t, doc, failedConntrack, `"conntrack":{"status":"failed","truncated":false,"data":"","`+long+`":1}`)},
		{"section case-variant key", splice(t, doc, failedConntrack, `"conntrack":{"status":"failed","truncated":false,"data":"","DATA`+long+`":1}`)},
		{"long format", splice(t, doc, `"format":"net-facts-v1"`, `"format":"`+long+`"`)},
		{"long status", splice(t, doc, failedConntrack, `"conntrack":{"status":"`+long+`","truncated":false,"data":""}`)},
		{"long number", splice(t, doc, failedConntrack, `"conntrack":{"status":"failed","truncated":`+digits+`,"data":""}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.raw)
			if !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("Decode = %v, want ErrInvalidResult", err)
			}
			if n := len(err.Error()); n > 512 {
				t.Fatalf("error message is %d bytes: %.200s", n, err.Error())
			}
		})
	}
	if got := quoteKey(long); len(got) > maxQuotedKey+8 {
		t.Fatalf("quoteKey returned %d bytes", len(got))
	}
}
