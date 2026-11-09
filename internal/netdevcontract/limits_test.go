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
			err := CheckLines(c.text, MaxConfigLines)
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
	if err := CheckLines(lines(MaxConfigLines, 1), MaxConfigLines); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	if err := CheckLines(lines(MaxConfigLines+1, 1), MaxConfigLines); !errors.Is(err, ErrOverLimit) {
		t.Fatalf("limit+1: got %v, want ErrOverLimit", err)
	}
}

func TestCheckLinesRejectsInvalidUTF8(t *testing.T) {
	if err := CheckLines([]byte("ok\n\xff\xfe\n"), MaxConfigLines); err == nil {
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
}
