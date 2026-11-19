// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strconv"
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
		`<config><entry name="a&quot; forged=&quot;y&#x85;&#x2028;&#x2029;"/></config>`,
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

// expectedPANOSLines renders data by a token walk of its own, independent
// of parsePANOS and the renderer: one line per element and per comment,
// indented two spaces per depth. An element line is its Go-quoted namespace
// and local name, then its non-volatile attributes in brackets (name and
// uuid first, the others by key then value), then its non-whitespace text
// as " = " and the quoted text. A comment line is "# " and its quoted text.
// The order of the lines is not significant: siblings may be sorted.
func expectedPANOSLines(data []byte) ([]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	type open struct {
		head string
		text []byte
	}
	var lines []string
	var stack []*open
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, &open{head: expectedPANOSHead(t)})
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("end element without start")
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			line := strings.Repeat("  ", len(stack)) + top.head
			if len(bytes.TrimSpace(top.text)) > 0 {
				line += " = " + strconv.Quote(string(top.text))
			}
			lines = append(lines, line)
		case xml.CharData:
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				top.text = append(top.text, t...)
			}
		case xml.Comment:
			lines = append(lines, strings.Repeat("  ", len(stack))+"# "+strconv.Quote(string(t)))
		}
	}
	if len(stack) != 0 {
		return nil, errors.New("document ends inside an element")
	}
	return lines, nil
}

// expectedPANOSName renders an XML name: the local name, prefixed with the
// Go-quoted namespace in braces when there is one.
func expectedPANOSName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return "{" + strconv.Quote(n.Space) + "}" + n.Local
}

// expectedPANOSHead renders an element's name and attributes.
func expectedPANOSHead(t xml.StartElement) string {
	type attr struct{ key, value string }
	var attrs []attr
	for _, a := range t.Attr {
		if a.Name.Space == "" && (a.Name.Local == "admin" || a.Name.Local == "dirtyId" || a.Name.Local == "time") {
			continue
		}
		attrs = append(attrs, attr{key: expectedPANOSName(a.Name), value: a.Value})
	}
	rank := func(key string) int {
		switch key {
		case "name":
			return 0
		case "uuid":
			return 1
		}
		return 2
	}
	slices.SortFunc(attrs, func(a, b attr) int {
		if d := rank(a.key) - rank(b.key); d != 0 {
			return d
		}
		if c := strings.Compare(a.key, b.key); c != 0 {
			return c
		}
		return strings.Compare(a.value, b.value)
	})
	head := expectedPANOSName(t.Name)
	if len(attrs) > 0 {
		parts := make([]string, len(attrs))
		for i, a := range attrs {
			parts[i] = a.key + "=" + strconv.Quote(a.value)
		}
		head += "[" + strings.Join(parts, " ") + "]"
	}
	return head
}

// mustExpectedPANOSLines is expectedPANOSLines for a document a test wrote
// itself, so a failure is a test bug.
func mustExpectedPANOSLines(t *testing.T, text string) []string {
	t.Helper()
	want, err := expectedPANOSLines([]byte(text))
	if err != nil {
		t.Fatalf("token walk of a test document: %v", err)
	}
	return want
}

// fitsPANOSLimits reports whether a rendering stays within the two bounds
// NormalizePANOSConfig promises: MaxConfigLines lines and
// MaxNormalizedConfigBytes bytes.
func fitsPANOSLimits(lines []string) bool {
	return len(lines) <= netdevcontract.MaxConfigLines && renderedBytes(lines) <= MaxNormalizedConfigBytes
}

// checkPANOSLines checks an accepted rendering against want, the independent
// rendering of the same document: the same lines in any order, within the
// limits, no line break inside a line, and determinism.
func checkPANOSLines(t *testing.T, text string, lines, want []string) {
	t.Helper()
	if len(lines) > netdevcontract.MaxConfigLines {
		t.Fatalf("%d lines, limit %d", len(lines), netdevcontract.MaxConfigLines)
	}
	if n := renderedBytes(lines); n > MaxNormalizedConfigBytes {
		t.Fatalf("rendered %d bytes, limit %d", n, MaxNormalizedConfigBytes)
	}
	for i, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			t.Fatalf("line %d breaks the line structure: %q", i, l)
		}
	}
	got := slices.Sorted(slices.Values(lines))
	exp := slices.Sorted(slices.Values(want))
	if !slices.Equal(got, exp) {
		t.Fatalf("%d lines, independent rendering has %d; first difference: %s",
			len(got), len(exp), firstPANOSDiff(got, exp))
	}
	again, ok := NormalizePANOSConfig(text)
	if !ok || !slices.Equal(lines, again) {
		t.Fatalf("second normalization differs: ok=%v", ok)
	}
}

// firstPANOSDiff describes the first position where two sorted renderings
// differ, for a failure message.
func firstPANOSDiff(got, want []string) string {
	for i := 0; i < len(got) || i < len(want); i++ {
		var g, w string
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g != w {
			return strconv.Quote(g) + " against " + strconv.Quote(w)
		}
	}
	return "none"
}

// FuzzNormalizePANOSConfig feeds arbitrary text to NormalizePANOSConfig,
// which takes redacted PAN-OS XML from a device. It must never panic. An
// input that netdevcontract.CheckXML refuses is refused. For an input that
// CheckXML accepts, the independent rendering decides both ways: when it
// fits MaxConfigLines and MaxNormalizedConfigBytes the input is accepted,
// and when it does not the input is refused. An accepted input renders the
// independent lines, one line of text each, and the same input renders the
// same lines.
func FuzzNormalizePANOSConfig(f *testing.F) {
	for _, s := range panosFuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		xmlErr := netdevcontract.CheckXML([]byte(text), netdevcontract.MaxRedactedConfigBytes)
		lines, ok := NormalizePANOSConfig(text)
		if xmlErr != nil {
			if ok {
				t.Fatalf("accepted input that CheckXML refuses: %v", xmlErr)
			}
			return
		}
		want, err := expectedPANOSLines([]byte(text))
		if err != nil {
			t.Fatalf("CheckXML accepts input that the token walk refuses: %v", err)
		}
		fits := fitsPANOSLimits(want)
		if !ok {
			if lines != nil {
				t.Fatalf("refused input returned %d lines", len(lines))
			}
			if fits {
				t.Fatalf("refused input whose rendering fits the limits: %d lines, %d bytes", len(want), renderedBytes(want))
			}
			return
		}
		if !fits {
			t.Fatalf("accepted input whose rendering exceeds the limits: %d lines, %d bytes", len(want), renderedBytes(want))
		}
		checkPANOSLines(t, text, lines, want)
	})
}

// quotedBody is s as strconv.Quote writes it, without the surrounding
// quotes: the escaped form device text takes in a rendered line.
func quotedBody(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

// TestPANOSDeviceTextCannotForgeLine checks that device text cannot put a
// line break, a quote or a Unicode line separator into the output. Device
// text is Go-quoted, so each case renders its escaped form, which must
// appear in the output. The twin with the break replaced by a space renders
// the same number of lines. No line holds a raw CR, LF, NEL, LS or PS, and
// no line starts with the forged text.
func TestPANOSDeviceTextCannotForgeLine(t *testing.T) {
	// Separators are built from code points, not written as escapes, so
	// each case names exactly the character it tests.
	nel := string(rune(0x85))
	ls := string(rune(0x2028))
	ps := string(rune(0x2029))
	rawBreaks := "\r\n" + nel + ls + ps
	cases := []struct{ name, with, without, want string }{
		{
			"attribute value LF entity",
			`<config><entry name="a&#10;  forged[x=&quot;y&quot;]"/></config>`,
			`<config><entry name="a   forged[x=&quot;y&quot;]"/></config>`,
			`a\n  forged[x=\"y\"]`,
		},
		{
			"attribute value quote",
			`<config><entry name="a&quot; forged=&quot;y"/></config>`,
			`<config><entry name="a forged=y"/></config>`,
			`a\" forged=\"y`,
		},
		{
			"element text entity LF",
			`<config><description>a&#10;  forged</description></config>`,
			`<config><description>a   forged</description></config>`,
			`a\n  forged`,
		},
		{
			"element text entity CR",
			`<config><description>a&#13;  forged</description></config>`,
			`<config><description>a   forged</description></config>`,
			`a\r  forged`,
		},
		{
			"element text raw LF",
			"<config><description>a\n  forged</description></config>",
			"<config><description>a   forged</description></config>",
			`a\n  forged`,
		},
		{
			"comment raw LF",
			"<config><!-- a\n  forged --></config>",
			"<config><!-- a   forged --></config>",
			`a\n  forged`,
		},
		{
			"namespace raw LF",
			"<config xmlns=\"urn:a\n  forged\"/>",
			"<config xmlns=\"urn:a   forged\"/>",
			`urn:a\n  forged`,
		},
		{
			"attribute value raw NEL",
			`<config><entry name="a` + nel + `forged"/></config>`,
			`<config><entry name="a forged"/></config>`,
			quotedBody("a" + nel + "forged"),
		},
		{
			"element text entity LS",
			`<config><description>a&#x2028;forged</description></config>`,
			`<config><description>a forged</description></config>`,
			quotedBody("a" + ls + "forged"),
		},
		{
			"element text raw PS",
			`<config><description>a` + ps + `forged</description></config>`,
			`<config><description>a forged</description></config>`,
			quotedBody("a" + ps + "forged"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			with, ok := NormalizePANOSConfig(tc.with)
			if !ok {
				t.Fatal("well-formed document refused")
			}
			without, ok := NormalizePANOSConfig(tc.without)
			if !ok {
				t.Fatal("well-formed document without the break refused")
			}
			if len(with) != len(without) {
				t.Fatalf("break adds lines: %d lines with it, %d without: %q", len(with), len(without), with)
			}
			if joined := strings.Join(with, "\n"); !strings.Contains(joined, tc.want) {
				t.Fatalf("rendering lacks the escaped device text %q: %q", tc.want, with)
			}
			for i, l := range with {
				if strings.ContainsAny(l, rawBreaks) {
					t.Fatalf("line %d holds a raw line break or separator: %q", i, l)
				}
				if strings.HasPrefix(strings.TrimLeft(l, " "), "forged") {
					t.Fatalf("device text forged an element line: %q", l)
				}
			}
		})
	}
}

// TestPANOSLineLimitIsInclusive checks MaxConfigLines at the line: a
// document of exactly MaxConfigLines lines is accepted, one more line is
// refused. The independent rendering agrees with both documents' sizes.
func TestPANOSLineLimitIsInclusive(t *testing.T) {
	// One root line plus n child lines.
	atDoc := panosWide(netdevcontract.MaxConfigLines - 1)
	atLimit, ok := NormalizePANOSConfig(atDoc)
	if !ok {
		t.Fatalf("document of %d lines refused", netdevcontract.MaxConfigLines)
	}
	if len(atLimit) != netdevcontract.MaxConfigLines {
		t.Fatalf("got %d lines, want %d", len(atLimit), netdevcontract.MaxConfigLines)
	}
	checkPANOSLines(t, atDoc, atLimit, mustExpectedPANOSLines(t, atDoc))

	overDoc := panosWide(netdevcontract.MaxConfigLines)
	if fitsPANOSLimits(mustExpectedPANOSLines(t, overDoc)) {
		t.Fatalf("test document of %d lines fits; the test is wrong", netdevcontract.MaxConfigLines+1)
	}
	if _, ok := NormalizePANOSConfig(overDoc); ok {
		t.Fatalf("document of %d lines accepted, limit %d", netdevcontract.MaxConfigLines+1, netdevcontract.MaxConfigLines)
	}
}

// renderedChildBytes is the number of bytes a child element with text
// renders to, newline included: two spaces of indent, the name "a", " = ",
// and the Go-quoted text.
func renderedChildBytes(text string) int {
	return len("  a = " + strconv.Quote(text) + "\n")
}

// panosPadText returns raw text whose child line renders to exactly cost
// bytes, using DEL bytes (four rendered bytes each) and then letters (one
// each). cost must be at least 10 and at most renderedChildBytes of a full
// MaxXMLTextBytes DEL text.
func panosPadText(cost int) string {
	inner := cost - renderedChildBytes("")
	return strings.Repeat("\x7f", inner/4) + strings.Repeat("a", inner%4)
}

// panosChildren is a root with n child elements: n-1 full DEL children and
// a last child with the given text.
func panosChildren(n int, last string) string {
	full := "<a>" + strings.Repeat("\x7f", netdevcontract.MaxXMLTextBytes) + "</a>"
	return "<r>" + strings.Repeat(full, n-1) + "<a>" + last + "</a></r>"
}

// TestPANOSByteLimitIsInclusive checks MaxNormalizedConfigBytes at the byte.
// The root line is 2 bytes with its newline. Full children render
// fullChild bytes each. The fit full children and a last child padded to the
// remaining bytes render to exactly MaxNormalizedConfigBytes and are
// accepted; the same document with one more byte in its last child is
// refused.
func TestPANOSByteLimitIsInclusive(t *testing.T) {
	const rootBytes = len("r\n")
	fullChild := renderedChildBytes(strings.Repeat("\x7f", netdevcontract.MaxXMLTextBytes))
	fit := (MaxNormalizedConfigBytes - rootBytes) / fullChild
	rest := MaxNormalizedConfigBytes - rootBytes - fit*fullChild
	if rest < renderedChildBytes("a") || rest+1 > fullChild {
		t.Fatalf("remaining %d bytes cannot be padded to exactly the limit", rest)
	}

	atDoc := panosChildren(fit+1, panosPadText(rest))
	lines, ok := NormalizePANOSConfig(atDoc)
	if !ok {
		t.Fatalf("document rendering to exactly %d bytes refused", MaxNormalizedConfigBytes)
	}
	checkPANOSLines(t, atDoc, lines, mustExpectedPANOSLines(t, atDoc))
	if got := renderedBytes(lines); got != MaxNormalizedConfigBytes {
		t.Fatalf("document renders to %d bytes, want exactly %d", got, MaxNormalizedConfigBytes)
	}

	overDoc := panosChildren(fit+1, panosPadText(rest+1))
	if fitsPANOSLimits(mustExpectedPANOSLines(t, overDoc)) {
		t.Fatalf("test document of %d bytes fits; the test is wrong", MaxNormalizedConfigBytes+1)
	}
	if _, ok := NormalizePANOSConfig(overDoc); ok {
		t.Fatalf("document rendering to %d bytes accepted, limit %d", MaxNormalizedConfigBytes+1, MaxNormalizedConfigBytes)
	}
	if _, ok := NormalizePANOSConfig(panosHeavy(fit + 1)); ok {
		t.Fatalf("%d full children accepted, expected to exceed %d bytes", fit+1, MaxNormalizedConfigBytes)
	}
}

// renderedBytes is the byte count the renderer bounds: each line plus its
// newline.
func renderedBytes(lines []string) int {
	n := 0
	for _, l := range lines {
		n += len(l) + 1
	}
	return n
}
