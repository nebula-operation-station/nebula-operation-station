// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcontract

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestParseLimitValuesMatchADR pins every D3 limit to the value in ADR 0010
// D3, so a changed constant fails here and needs an ADR change first.
func TestParseLimitValuesMatchADR(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"MaxLineBytes", MaxLineBytes, 4096},
		{"MaxConfigLines", MaxConfigLines, 100000},
		{"MaxInterfacesPerDevice", MaxInterfacesPerDevice, 1024},
		{"MaxVLANsPerDevice", MaxVLANsPerDevice, 4094},
		{"MaxMACEntriesPerDevice", MaxMACEntriesPerDevice, 8192},
		{"MaxLLDPNeighborsPerDevice", MaxLLDPNeighborsPerDevice, 1024},
		{"MaxLLDPNeighborsPerPort", MaxLLDPNeighborsPerPort, 16},
		{"MaxXMLDepth", MaxXMLDepth, 64},
		{"MaxXMLElements", MaxXMLElements, 500000},
		{"MaxXMLTextBytes", MaxXMLTextBytes, 4096},
		{"MaxSecurityRules", MaxSecurityRules, 10000},
		{"MaxNATRules", MaxNATRules, 5000},
		{"MaxAddressObjects", MaxAddressObjects, 20000},
		{"MaxServiceObjects", MaxServiceObjects, 20000},
		{"MaxAddressGroups", MaxAddressGroups, 5000},
		{"MaxServiceGroups", MaxServiceGroups, 5000},
		{"MaxGroupMembers", MaxGroupMembers, 2500},
		{"MaxGroupNestingDepth", MaxGroupNestingDepth, 8},
		{"MaxZones", MaxZones, 256},
		{"MaxFirewallInterfaces", MaxFirewallInterfaces, 1024},
		{"MaxHitCountEntries", MaxHitCountEntries, MaxSecurityRules},
		{"MaxCBSConfigOutputBytes", MaxCBSConfigOutputBytes, 4 << 20},
		{"MaxCBSCommandOutputBytes", MaxCBSCommandOutputBytes, 1 << 20},
		{"MaxPANOSConfigResponseBytes", MaxPANOSConfigResponseBytes, 8 << 20},
		{"MaxPANOSResponseBytes", MaxPANOSResponseBytes, 1 << 20},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, ADR 0010 D3 says %d", c.name, c.got, c.want)
		}
	}
}

func TestCheckCountAtLimitAndOver(t *testing.T) {
	if err := CheckCount("x", 5, 5); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	if err := CheckCount("x", 6, 5); !errors.Is(err, ErrOverLimit) {
		t.Fatalf("over limit: got %v, want ErrOverLimit", err)
	}
}

func lines(n, width int) []byte {
	line := strings.Repeat("a", width)
	var b bytes.Buffer
	b.Grow(n * (width + 1))
	for range n {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func TestLineLengthLimit(t *testing.T) {
	cases := []struct {
		name string
		text []byte
		over bool
	}{
		{"at limit", lines(1, MaxLineBytes), false},
		{"at limit crlf", []byte(strings.Repeat("a", MaxLineBytes) + "\r\n"), false},
		{"at limit no newline", []byte(strings.Repeat("a", MaxLineBytes)), false},
		{"limit+1", lines(1, MaxLineBytes+1), true},
		{"limit+1 no newline", []byte(strings.Repeat("a", MaxLineBytes+1)), true},
		{"far over", lines(1, 10*MaxLineBytes), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckLines(c.text, MaxCBSCommandOutputBytes, MaxConfigLines)
			if c.over != (err != nil) {
				t.Fatalf("over=%v, err=%v", c.over, err)
			}
			if c.over && !errors.Is(err, ErrOverLimit) {
				t.Fatalf("err %v does not match ErrOverLimit", err)
			}
		})
	}
}

func TestConfigLinesLimit(t *testing.T) {
	if err := CheckLines(lines(MaxConfigLines, 1), MaxCBSConfigOutputBytes, MaxConfigLines); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	if err := CheckLines(lines(MaxConfigLines+1, 1), MaxCBSConfigOutputBytes, MaxConfigLines); !errors.Is(err, ErrOverLimit) {
		t.Fatalf("limit+1: got %v, want ErrOverLimit", err)
	}
}

// TestCBSOutputByteCaps checks both CBS transport caps at the cap and one
// byte over, with lines short enough that only the byte cap can trip.
func TestCBSOutputByteCaps(t *testing.T) {
	for _, c := range []struct {
		name string
		cap  int
	}{
		{"show running-config", MaxCBSConfigOutputBytes},
		{"other command", MaxCBSCommandOutputBytes},
	} {
		t.Run(c.name, func(t *testing.T) {
			at := lines(c.cap/64, 63) // 64 bytes per line including newline
			if len(at) != c.cap {
				t.Fatalf("built %d bytes, want %d", len(at), c.cap)
			}
			if err := CheckLines(at, c.cap, MaxConfigLines); err != nil {
				t.Fatalf("at cap: %v", err)
			}
			over := append(at, 'a')
			if err := CheckLines(over, c.cap, MaxConfigLines); !errors.Is(err, ErrOverLimit) {
				t.Fatalf("cap+1: got %v, want ErrOverLimit", err)
			}
		})
	}
}

func TestPANOSConfigResponseByteCap(t *testing.T) {
	body := bytes.Repeat([]byte(" "), MaxPANOSConfigResponseBytes-len("<r/>"))
	at := append([]byte("<r/>"), body...)
	if err := CheckXML(at, MaxPANOSConfigResponseBytes); err != nil {
		t.Fatalf("at cap: %v", err)
	}
	if err := CheckXML(append(at, ' '), MaxPANOSConfigResponseBytes); !errors.Is(err, ErrOverLimit) {
		t.Fatalf("cap+1: got %v, want ErrOverLimit", err)
	}
}

func TestCheckLinesRejectsInvalidUTF8(t *testing.T) {
	if err := CheckLines([]byte("ok\n\xff\xfe\n"), MaxCBSCommandOutputBytes, MaxConfigLines); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func nested(depth int) []byte {
	return []byte(strings.Repeat("<a>", depth) + strings.Repeat("</a>", depth))
}

func elements(n int) []byte {
	var b bytes.Buffer
	b.Grow(n*4 + 16)
	b.WriteString("<r>")
	for range n - 1 {
		b.WriteString("<e/>")
	}
	b.WriteString("</r>")
	return b.Bytes()
}

func TestXMLLimits(t *testing.T) {
	text := func(n int) []byte { return []byte("<r>" + strings.Repeat("x", n) + "</r>") }
	attr := func(n int) []byte { return []byte(`<r a="` + strings.Repeat("x", n) + `"/>`) }
	cases := []struct {
		name string
		doc  []byte
		max  int
		over bool
	}{
		{"depth at limit", nested(MaxXMLDepth), MaxPANOSResponseBytes, false},
		{"depth limit+1", nested(MaxXMLDepth + 1), MaxPANOSResponseBytes, true},
		{"elements at limit", elements(MaxXMLElements), MaxPANOSConfigResponseBytes, false},
		{"elements limit+1", elements(MaxXMLElements + 1), MaxPANOSConfigResponseBytes, true},
		{"text at limit", text(MaxXMLTextBytes), MaxPANOSResponseBytes, false},
		{"text limit+1", text(MaxXMLTextBytes + 1), MaxPANOSResponseBytes, true},
		{"split text limit+1", []byte("<r>" + strings.Repeat("x", MaxXMLTextBytes) + "<!-- c -->y</r>"), MaxPANOSResponseBytes, true},
		{"attribute at limit", attr(MaxXMLTextBytes), MaxPANOSResponseBytes, false},
		{"attribute limit+1", attr(MaxXMLTextBytes + 1), MaxPANOSResponseBytes, true},
		{"bytes at response cap", append([]byte("<r>"), append(bytes.Repeat([]byte("<e/>"), (MaxPANOSResponseBytes-7)/4), []byte("</r>")...)...), MaxPANOSResponseBytes, false},
		{"bytes over response cap", bytes.Repeat([]byte(" "), MaxPANOSResponseBytes+1), MaxPANOSResponseBytes, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckXML(c.doc, c.max)
			if c.over != (err != nil) {
				t.Fatalf("over=%v, err=%v", c.over, err)
			}
			if c.over && !errors.Is(err, ErrOverLimit) {
				t.Fatalf("err %v does not match ErrOverLimit", err)
			}
		})
	}
}

func TestXMLMalformedRejected(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"unclosed":         "<a>",
		"two roots":        "<a/><b/>",
		"doctype":          `<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>`,
		"text outside":     "x<a/>",
		"invalid utf8":     "<a>\xff</a>",
		"bad entity":       "<a>&nope;</a>",
		"charset":          `<?xml version="1.0" encoding="ISO-8859-1"?><a/>`,
		"mismatched close": "<a></b>",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := CheckXML([]byte(doc), MaxPANOSResponseBytes); err == nil {
				t.Fatalf("accepted %q", doc)
			}
		})
	}
	if err := CheckXML([]byte(`<?xml version="1.0"?><response status="success"><result/></response>`+"\n"), MaxPANOSResponseBytes); err != nil {
		t.Fatalf("well-formed response rejected: %v", err)
	}
}

func TestJSONDocumentLimits(t *testing.T) {
	var v any
	cases := []struct {
		name string
		doc  string
		over bool
		bad  bool
	}{
		{"string at limit", `"` + strings.Repeat("a", MaxJSONStringBytes) + `"`, false, false},
		{"string limit+1", `"` + strings.Repeat("a", MaxJSONStringBytes+1) + `"`, true, true},
		{"nesting at limit", strings.Repeat("[", MaxJSONNesting) + strings.Repeat("]", MaxJSONNesting), false, false},
		{"nesting limit+1", strings.Repeat("[", MaxJSONNesting+1) + strings.Repeat("]", MaxJSONNesting+1), true, true},
		{"objects at limit", "[" + strings.Repeat("{},", MaxJSONObjects-1) + "{}]", false, false},
		{"objects limit+1", "[" + strings.Repeat("{},", MaxJSONObjects) + "{}]", true, true},
		{"null", `{"a":null}`, false, true},
		{"duplicate key", `{"a":1,"a":2}`, false, true},
		{"trailing", `{} {}`, false, true},
		{"invalid utf8", "\"\xff\"", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := decodeStrict([]byte(c.doc), &v)
			if c.bad != (err != nil) {
				t.Fatalf("bad=%v, err=%v", c.bad, err)
			}
			if c.over != errors.Is(err, ErrOverLimit) {
				t.Fatalf("over=%v, err=%v", c.over, err)
			}
		})
	}
	big := bytes.Repeat([]byte(" "), MaxDocumentBytes+1)
	if err := decodeStrict(big, &v); !errors.Is(err, ErrOverLimit) {
		t.Fatalf("document over MaxDocumentBytes: %v", err)
	}
}

// wrap returns r between two ASCII letters. Code points are spelled as hex
// so no invisible or bidi characters appear in the source.
func wrap(r rune) string { return "a" + string(r) + "b" }

func TestValidTextRejectsControlAndReplacement(t *testing.T) {
	cases := []struct {
		s  string
		ok bool
	}{
		{"GigabitEthernet1/0/1", true},
		{"Zürich ✓", true},
		{"a\nb", false},
		{"a\x1bb", false},
		{"a\u0085b", false},
		{"a�b", false},
		// spec 09: every rune must pass unicode.IsPrint
		{wrap(0x202E), false},  // RIGHT-TO-LEFT OVERRIDE (Cf)
		{wrap(0x202A), false},  // LEFT-TO-RIGHT EMBEDDING (Cf)
		{wrap(0x2066), false},  // LEFT-TO-RIGHT ISOLATE (Cf)
		{wrap(0x2067), false},  // RIGHT-TO-LEFT ISOLATE (Cf)
		{wrap(0x2068), false},  // FIRST STRONG ISOLATE (Cf)
		{wrap(0x2069), false},  // POP DIRECTIONAL ISOLATE (Cf)
		{wrap(0x200B), false},  // ZERO WIDTH SPACE (Cf)
		{wrap(0x200D), false},  // ZERO WIDTH JOINER (Cf)
		{wrap(0xFEFF), false},  // BYTE ORDER MARK (Cf)
		{wrap(0x00AD), false},  // SOFT HYPHEN (Cf)
		{wrap(0x2028), false},  // LINE SEPARATOR (Zl)
		{wrap(0x2029), false},  // PARAGRAPH SEPARATOR (Zp)
		{wrap(0x00A0), false},  // NO-BREAK SPACE (Zs, not ASCII space)
		{wrap(0xE000), false},  // private use (Co)
		{wrap(0xF0000), false}, // supplementary private use (Co)
		{wrap(0x0378), false},  // unassigned (Cn)
		{"a b", true},
		{"\xff", false},
		{strings.Repeat("a", MaxLabelBytes), true},
		{strings.Repeat("a", MaxLabelBytes+1), false},
	}
	for _, c := range cases {
		if got := validText(c.s, MaxLabelBytes); got != c.ok {
			t.Errorf("validText(%q) = %v, want %v", c.s, got, c.ok)
		}
	}
	if !validLine("a\tb") || validLine("a\rb") {
		t.Error("validLine must allow tab and reject CR")
	}
	for _, r := range []rune{0x202E, 0x2066, 0x200B, 0x2028, 0x2029, 0xE000, 0x00A0, 0xFFFD} {
		if s := wrap(r); validLine(s) {
			t.Errorf("validLine(%q) = true, want false", s)
		}
	}
}

func TestJSONKeysMustBeExactLowercaseNames(t *testing.T) {
	type doc struct {
		DeviceID string `json:"device_id"`
		Kind     string `json:"kind"`
		Source   string `json:"source"`
	}
	cases := map[string]string{
		"upper duplicate": `{"device_id":"a","DEVICE_ID":"b"}`,
		"upper only":      `{"DEVICE_ID":"b"}`,
		"mixed case":      `{"Device_Id":"b"}`,
		"kelvin sign":     `{"kind":"a","` + string(rune(0x212A)) + `ind":"b"}`,
		"long s":          `{"source":"a","` + string(rune(0x017F)) + `ource":"b"}`,
		"nested upper":    `[{"device_id":"a"},{"DEVICE_ID":"b"}]`,
		"empty key":       `{"":"b"}`,
		"key with space":  `{"device id":"b"}`,
		"key with hyphen": `{"device-id":"b"}`,
		"key limit+1":     `{"` + strings.Repeat("k", MaxJSONKeyBytes+1) + `":"b"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var v any
			if err := decodeStrict([]byte(raw), &v); err == nil {
				t.Fatalf("accepted %q", raw)
			}
			var d doc
			if err := decodeStrict([]byte(raw), &d); err == nil {
				t.Fatalf("accepted %q into struct, device_id=%q", raw, d.DeviceID)
			}
		})
	}
	var d doc
	if err := decodeStrict([]byte(`{"device_id":"a"}`), &d); err != nil || d.DeviceID != "a" {
		t.Fatalf("exact lowercase key rejected: %v", err)
	}
	var v any
	if err := decodeStrict([]byte(`{"`+strings.Repeat("k", MaxJSONKeyBytes)+`":1}`), &v); err != nil {
		t.Fatalf("key at limit rejected: %v", err)
	}
}
