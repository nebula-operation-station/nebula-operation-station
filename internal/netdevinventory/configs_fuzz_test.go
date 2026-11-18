// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// panosFuzzSeeds are PAN-OS documents in the shapes configs_test.go and
// the normalization tests exercise: hostile text, deep nesting, DOCTYPE,
// long text, a wide element, namespaces, comments, attributes with quotes
// and line breaks, volatile attributes, and malformed input.
func panosFuzzSeeds() []string {
	return []string{
		`<config><address><entry name="a&#10;  entry[name=&quot;forged&quot;]"><description>&lt;script&gt;x&lt;/script&gt;&#10;line2</description></entry></address></config>`,
		`<config><rules><entry name="b"/><entry name="a"/></rules><address><entry name="z"/><entry name="y"/></address></config>`,
		`<config admin="x" dirtyId="1" time="2024/01/01 00:00:00" loc="vsys1"><entry name="a" admin="y" time="3"/></config>`,
		`<config xmlns="urn:x"><x:a xmlns:x="urn:y" x:mode="a"/></config>`,
		`<config xmlns:x="urn:x"><x:rules><x:entry name="a"/><x:entry name="b"/></x:rules></config>`,
		`<config><!-- a comment --><a/></config>`,
		`<config><entry name="a&#10;&quot;b&quot;&#13;c"/></config>`,
		`<!DOCTYPE config [<!ENTITY x "y">]><config>&x;</config>`,
		`<config><d>` + strings.Repeat("a", 4096) + `</d></config>`,
		`<config><d>` + strings.Repeat("a", 4097) + `</d></config>`,
		strings.Repeat("<n>", 60) + "x" + strings.Repeat("</n>", 60),
		strings.Repeat("<n>", 70) + "x" + strings.Repeat("</n>", 70),
		panosWide(300),
		`<config>`,
		`not xml at all`,
		``,
	}
}

// panosWide is a root with n empty children, each one line of output.
func panosWide(n int) string {
	return "<config>" + strings.Repeat(`<a/>`, n) + "</config>"
}

// panosHeavy is a root with children elements, each with the largest text
// MaxXMLTextBytes allows. A DEL byte is valid XML and Go-quotes to four
// bytes, so each child renders 4*MaxXMLTextBytes bytes of text.
func panosHeavy(children int) string {
	child := "<a>" + strings.Repeat("\x7f", netdevcontract.MaxXMLTextBytes) + "</a>"
	return "<r>" + strings.Repeat(child, children) + "</r>"
}

// checkPANOSLines checks the properties every successful normalization
// promises: the documented bounds, one element per line, and determinism.
func checkPANOSLines(t *testing.T, text string, lines []string) {
	t.Helper()
	if len(lines) > netdevcontract.MaxConfigLines {
		t.Fatalf("%d lines, limit %d", len(lines), netdevcontract.MaxConfigLines)
	}
	if n := len(strings.Join(lines, "\n")); n > MaxNormalizedConfigBytes {
		t.Fatalf("rendered %d bytes, limit %d", n, MaxNormalizedConfigBytes)
	}
	for i, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			t.Fatalf("line %d breaks the line structure: %q", i, l)
		}
	}
	again, ok := NormalizePANOSConfig(text)
	if !ok || !slices.Equal(lines, again) {
		t.Fatalf("second normalization differs: ok=%v", ok)
	}
}

// FuzzNormalizePANOSConfig feeds arbitrary text to NormalizePANOSConfig,
// which takes redacted PAN-OS XML from a device. It must never panic. A
// refused input returns no lines. An input that netdevcontract.CheckXML
// refuses is refused. An accepted input stays within MaxConfigLines and
// MaxNormalizedConfigBytes, every line is one line of text, and the same
// input renders the same lines.
func FuzzNormalizePANOSConfig(f *testing.F) {
	for _, s := range panosFuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		xmlErr := netdevcontract.CheckXML([]byte(text), netdevcontract.MaxRedactedConfigBytes)
		lines, ok := NormalizePANOSConfig(text)
		if !ok {
			if lines != nil {
				t.Fatalf("refused input returned %d lines", len(lines))
			}
			return
		}
		if xmlErr != nil {
			t.Fatalf("accepted input that CheckXML refuses: %v", xmlErr)
		}
		checkPANOSLines(t, text, lines)
	})
}

// TestPANOSDeviceTextCannotForgeLine checks that a line break in device
// text cannot make an extra line that looks like an element of its own.
// Each document renders the same as the one with the break replaced by a
// space, so the break adds no line and no line starts with the forged
// element name.
func TestPANOSDeviceTextCannotForgeLine(t *testing.T) {
	cases := []struct{ name, with string }{
		{"attribute value", `<config><entry name="a&#10;  forged[x=&quot;y&quot;]"/></config>`},
		{"element text entity", "<config><description>a&#10;  forged</description></config>"},
		{"element text carriage return", "<config><description>a&#13;  forged</description></config>"},
		{"element text raw newline", "<config><description>a\n  forged</description></config>"},
		{"comment", "<config><!-- a\n  forged --></config>"},
		{"namespace", "<config xmlns=\"urn:a\n  forged\"/>"},
	}
	breaks := strings.NewReplacer("\n", " ", "&#10;", " ", "&#13;", " ")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			with, ok := NormalizePANOSConfig(tc.with)
			if !ok {
				t.Fatal("well-formed document refused")
			}
			without, ok := NormalizePANOSConfig(breaks.Replace(tc.with))
			if !ok {
				t.Fatal("well-formed document without the break refused")
			}
			if len(with) != len(without) {
				t.Fatalf("break adds lines: %d lines with it, %d without: %q", len(with), len(without), with)
			}
			for _, l := range with {
				if strings.HasPrefix(strings.TrimLeft(l, " "), "forged") {
					t.Fatalf("device text forged an element line: %q", l)
				}
			}
		})
	}
}

// TestPANOSLineLimitIsInclusive checks MaxConfigLines at the line: a
// document of exactly MaxConfigLines lines is accepted, one more line is
// refused.
func TestPANOSLineLimitIsInclusive(t *testing.T) {
	// One root line plus n child lines.
	atLimit, ok := NormalizePANOSConfig(panosWide(netdevcontract.MaxConfigLines - 1))
	if !ok {
		t.Fatalf("document of %d lines refused", netdevcontract.MaxConfigLines)
	}
	if len(atLimit) != netdevcontract.MaxConfigLines {
		t.Fatalf("got %d lines, want %d", len(atLimit), netdevcontract.MaxConfigLines)
	}
	if _, ok := NormalizePANOSConfig(panosWide(netdevcontract.MaxConfigLines)); ok {
		t.Fatalf("document of %d lines accepted, limit %d", netdevcontract.MaxConfigLines+1, netdevcontract.MaxConfigLines)
	}
}

// TestPANOSByteLimitIsInclusive checks MaxNormalizedConfigBytes at the
// byte. Each child line is 2 (indent) + 5 (`a = "`) + 4*MaxXMLTextBytes
// (the DEL bytes, Go-quoted) + 1 (the closing quote) bytes, plus one for
// its newline. The root line is 2 bytes with its newline. Expected is the
// largest child count that fits, then one more child that does not.
func TestPANOSByteLimitIsInclusive(t *testing.T) {
	const perChild = 2 + 5 + 4*netdevcontract.MaxXMLTextBytes + 1 + 1
	const rootBytes = 2
	fit := (MaxNormalizedConfigBytes - rootBytes) / perChild
	lines, ok := NormalizePANOSConfig(panosHeavy(fit))
	if !ok {
		t.Fatalf("%d children refused, expected to fit %d bytes", fit, MaxNormalizedConfigBytes)
	}
	checkPANOSLines(t, panosHeavy(fit), lines)
	if _, ok := NormalizePANOSConfig(panosHeavy(fit + 1)); ok {
		t.Fatalf("%d children accepted, expected to exceed %d bytes", fit+1, MaxNormalizedConfigBytes)
	}
}
