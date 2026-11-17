// SPDX-License-Identifier: AGPL-3.0-or-later

package mdsafe_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
)

// maxOutputFactor and maxOutputSlack bound the output length in bytes:
// len(out) ≤ maxOutputFactor·len(src) + maxOutputSlack. The factor is the
// worst case over the renderer's output, derived from mdsafe.go:
//   - a heading "#\n" (2 bytes) becomes `<h1 id="section-N"></h1>\n`; with
//     N ≤ 524288 (the most headings a MaxSourceBytes source has) that is
//     30 bytes, i.e. 15 per input byte. This is the worst case.
//   - a table row "|" (2 bytes) becomes `<tr><td></td></tr>` (18 bytes),
//     i.e. 9 per input byte. Body rows are not padded to the header width,
//     so this is the per-row bound for every table.
//   - escaping grows text at most 5 times (`&#34;`, `&amp;`), and NUL and
//     tab (1 byte each) grow to 3 and 4 bytes.
//
// 16 covers the worst case (15). Output beyond it is a regression in
// output amplification. maxOutputSlack covers the fixed wrapper of a
// short source.
const (
	maxOutputFactor = 16
	maxOutputSlack  = 1024
)

var (
	// headingIDRE matches the opening tag of a rendered heading.
	headingIDRE = regexp.MustCompile(`<h[1-6] id="([^"]*)">`)
	// duplicateSuffixRE is the only allowed suffix of a heading id: "-N"
	// with N a decimal number, added to make the id unique.
	duplicateSuffixRE = regexp.MustCompile(`^-[0-9]+$`)
	// helpHrefRE is the form of a Relative result that may become a link:
	// /help, /help/<segment>..., optional #fragment. Segments are lower-case
	// letters, digits, "_" and "-" (the page slugs), so "." and ".." and
	// "//" never match. It is a subset of assertInert's "a" allowlist.
	helpHrefRE = regexp.MustCompile(`^/help(/[a-z0-9_-]+)*(#[\pL\pN_-]+)?$`)
	// tagTokenRE matches any tag, for measuring element nesting.
	tagTokenRE = regexp.MustCompile(`<(/?)([a-zA-Z0-9]+)[^>]*>`)
	// hrefAttrRE matches one href attribute of a rendered link.
	hrefAttrRE = regexp.MustCompile(` href="[^"]*"`)
)

// hostileHrefs are Relative results that must never become a link
// target: scheme URLs, quotes, spaces, protocol-relative and backslash
// forms. They seed FuzzRender and are used by the resolver tests.
var hostileHrefs = []string{
	"javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "//evil.example/",
	"https://evil.example/", "https://user@evil.example/", "/a\"b", "/a b", "/a'b",
	"/x\\y", "relative/path", "", "#frag", "/help/hosts#x\"onclick=\"y", "/help/ok",
}

// fuzzSeeds are the sources of TestHostileMarkdownIsInert and
// TestSupportedSubset, plus long runs of the delimiters that drive the
// inline and table scanners.
var fuzzSeeds = []string{
	"<script>alert(1)</script>", "# Hi <script>x</script>",
	"<div onclick=\"x()\">\n<img src=x onerror=alert(1)>\n</div>", "<!-- hidden -->",
	"[click](javascript:alert(1))", "[click](JaVaScRiPt:alert(1))", "[click](java&#115;cript:alert(1))",
	"[x](data:text/html;base64,PHNjcmlwdD4=)", "[x](vbscript:msgbox)", "[x](http://example.org/)",
	"[x](mailto:a@example.org)", "[x](//evil.example/)", "[x](/\\evil.example/)",
	"[x](https://user@evil.example/)", "[x](https:///path)", "[guide](../admin/guide.md#x)",
	`[x](https://example.org/"onmouseover="alert(1))`, `[x](#a"onclick="b)`,
	"[<b>bold</b>](https://example.org/)", "`<script>`", "```html\n<script>alert(1)</script>\n```",
	"| a | b |\n| --- | --- |\n| <script>x</script> | [y](javascript:z) |",
	"- <iframe src=x>\n- ok", "**<svg onload=x>**", "![x](https://example.org/a.png)",
	"## a\" onclick=\"x", `say "hi" & 'bye'`, "a\x00b",
	"# Title here\n\nIntro **bold** and *em* and `code`.\nSecond line.\n\n" +
		"## Add a host (CSV)\n\n1. First step\n   continued\n\n   ```\n   nebula host add\n   ```\n2. Second [hosts](hosts.md#add-a-host)\n\n" +
		"- a\n- b [ext](https://example.org/x?y=1&z=2)\n  - nested\n\n" +
		"| Col | Other |\n| --- | --- |\n| `c` | [h](hosts.md) |\n\n" +
		"See [above](#title-here).\n\n## Add a host (CSV)\n",
	"# a-1\n\n## a\n\n## a\n", "# a\n# a\n# a-1\n## a\n",
	strings.Repeat("*", 4096), strings.Repeat("**", 2048) + "x", strings.Repeat("*a ", 2048),
	strings.Repeat("[", 4096), strings.Repeat("[a](", 1024), strings.Repeat("[a](b", 1024),
	strings.Repeat("`", 4096), strings.Repeat("`a ", 2048), strings.Repeat("``", 2048) + "x",
	strings.Repeat("|", 4096), strings.Repeat("| a ", 1024) + "\n|---|\n" + strings.Repeat("| x ", 1024),
	strings.Repeat("- ", 1024) + "x", strings.Repeat("  ", 1024) + "- x",
	"# " + strings.Repeat("#", 4096), "#\n#\n#\n#\n", strings.Repeat("#\n", 2048),
}

// assertOutput runs every output check on one Render result: no error,
// valid UTF-8, the assertInert allowlist on the output as it is (local
// links included), heading ids unique and derived from Slug, and the
// output length bound.
func assertOutput(t *testing.T, src string, res mdsafe.Result) {
	t.Helper()
	out := string(res.HTML)
	if !utf8.ValidString(out) {
		t.Fatalf("Render(%q) output is not valid UTF-8", src)
	}
	assertInert(t, src, out)
	checkHeadingIDs(t, src, out, res)
	// href values come from Options.Relative, not from src, so they are
	// left out of the amplification bound. Render caps each at
	// maxLinkDestBytes, and assertInert checks each one above.
	body := hrefAttrRE.ReplaceAllString(out, "")
	if limit := maxOutputFactor*len(src) + maxOutputSlack; len(body) > limit {
		t.Errorf("Render: output %d bytes (without hrefs) for %d input bytes exceeds the bound %d", len(body), len(src), limit)
	}
}

// checkHeadingIDs checks that the rendered heading ids match
// res.Headings in order, are unique, and are either Slug of the heading
// text ("section" when empty) or that slug followed by "-N" with N a
// decimal number.
func checkHeadingIDs(t *testing.T, src, out string, res mdsafe.Result) {
	t.Helper()
	ids := headingIDRE.FindAllStringSubmatch(out, -1)
	if len(ids) != len(res.Headings) {
		t.Fatalf("Render(%q): %d heading tags, %d Headings", src, len(ids), len(res.Headings))
	}
	seen := map[string]bool{}
	for i, m := range ids {
		id := m[1]
		if seen[id] {
			t.Errorf("Render(%q): duplicate heading id %q:\n%s", src, id, out)
		}
		seen[id] = true
		h := res.Headings[i]
		if id != h.ID {
			t.Errorf("Render(%q): heading %d tag id %q, Headings id %q", src, i, id, h.ID)
		}
		base := mdsafe.Slug(h.Text)
		if base == "" {
			base = "section"
		}
		suffix, found := strings.CutPrefix(id, base)
		if !found || (suffix != "" && !duplicateSuffixRE.MatchString(suffix)) {
			t.Errorf("Render(%q): heading id %q does not derive from Slug %q", src, id, base)
		}
	}
}

// FuzzRender renders arbitrary sources with hostile, valid, or
// unusable Relative results. Every successful output must pass assertInert
// and the other checks in assertOutput; invalid input must fail with the
// documented error.
func FuzzRender(f *testing.F) {
	for i, s := range fuzzSeeds {
		// Cycle through the hostile hrefs and all three resolver modes.
		f.Add(s, hostileHrefs[i%len(hostileHrefs)], uint8(i))
	}
	f.Fuzz(func(t *testing.T, src, href string, mode uint8) {
		if len(src) > mdsafe.MaxSourceBytes {
			return
		}
		// Mode 0 hands the fuzzed href to the renderer unfiltered, so
		// traversal-shaped, uppercase, "//" and oversized results all reach
		// the renderer's own check. A link that escapes it fails assertInert
		// on the output.
		rel := func(p, frag string) (string, bool) {
			switch mode % 3 {
			case 0:
				return href, true
			case 1:
				return href, false
			default:
				return pageLinks(p, frag)
			}
		}
		res, err := mdsafe.Render([]byte(src), mdsafe.Options{Relative: rel})
		if !utf8.ValidString(src) {
			if !errors.Is(err, mdsafe.ErrInvalidUTF8) {
				t.Fatalf("Render(%q): err = %v, want ErrInvalidUTF8", src, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("Render(%q): %v", src, err)
		}
		assertOutput(t, src, res)
	})
}

// TestHeadingIDsNeverCollide checks that a generated "-N" suffix never
// reuses an id an explicit slug already has. The first case is the fuzz
// seed that found the collision.
func TestHeadingIDsNeverCollide(t *testing.T) {
	for _, src := range []string{
		"# a-1\n\n## a\n\n## a\n",
		"# a\n\n# a\n\n# a-1\n\n# a\n",
		"# a-1\n# a-1\n# a\n# a\n",
		"# \n# \n# section\n# section-1\n",
	} {
		res := render(t, src)
		assertOutput(t, src, res)
	}
	res := render(t, "# a-1\n\n## a\n\n## a\n")
	want := []string{"a-1", "a", "a-2"}
	for i, h := range res.Headings {
		if h.ID != want[i] {
			t.Errorf("heading %d id = %q, want %q", i, h.ID, want[i])
		}
	}
}

// TestSourceSizeLimitIsExact checks the size limit at its boundary.
func TestSourceSizeLimitIsExact(t *testing.T) {
	ok := []byte(strings.Repeat("a", mdsafe.MaxSourceBytes))
	res, err := mdsafe.Render(ok, mdsafe.Options{})
	if err != nil {
		t.Fatalf("source of exactly MaxSourceBytes: %v", err)
	}
	assertOutput(t, string(ok), res)

	tooBig := append(ok, 'a')
	if _, err := mdsafe.Render(tooBig, mdsafe.Options{}); !errors.Is(err, mdsafe.ErrTooLarge) {
		t.Errorf("source of MaxSourceBytes+1: err = %v, want ErrTooLarge", err)
	}
}

// TestNestingIsBounded renders deep nesting of lists, emphasis and links
// at several depths. Nesting must stay within MaxNesting levels per
// construct, with no panic.
//
// The tag bound follows from the code: a list may open only at depth
// below MaxNesting, so at most MaxNesting nested lists exist, each with a
// ul/ol and an li. Emphasis and links recurse only while depth is below
// MaxNesting. A list item at the deepest level may hold one more level of
// inline markup, so the element depth is at most 2*MaxNesting plus one
// level of inline nesting (MaxNesting) plus a small constant for the
// table and paragraph wrappers.
func TestNestingIsBounded(t *testing.T) {
	maxDepth := 3*mdsafe.MaxNesting + 4
	for _, n := range []int{10, 100, 10000} {
		for name, src := range map[string]string{
			"list":     strings.Repeat("- ", n) + "x",
			"indent":   strings.Repeat("  ", n) + "- x",
			"emphasis": strings.Repeat("*", n) + "x" + strings.Repeat("*", n),
			"strong":   strings.Repeat("**", n) + "x" + strings.Repeat("**", n),
			"link":     strings.Repeat("[", n) + "x" + strings.Repeat("](https://example.org/)", n),
			"mixed":    strings.Repeat("- *[**", n) + "x",
			"ordered":  strings.Repeat("1. ", n) + "x",
		} {
			res, err := mdsafe.Render([]byte(src), mdsafe.Options{Relative: pageLinks})
			if err != nil {
				t.Fatalf("%s n=%d: %v", name, n, err)
			}
			assertOutput(t, src, res)
			if d := elementDepth(t, string(res.HTML)); d > maxDepth {
				t.Errorf("%s n=%d: element depth %d exceeds %d", name, n, d, maxDepth)
			}
		}
	}
}

// elementDepth returns the maximum number of simultaneously open
// elements in html, which the renderer emits balanced.
func elementDepth(t *testing.T, html string) int {
	t.Helper()
	depth, maxD := 0, 0
	for _, m := range tagTokenRE.FindAllStringSubmatch(html, -1) {
		if m[1] == "/" {
			depth--
			if depth < 0 {
				t.Fatalf("unbalanced closing tag </%s>", m[2])
			}
			continue
		}
		depth++
		maxD = max(maxD, depth)
		if strings.HasSuffix(m[0], "/>") {
			depth--
		}
	}
	return maxD
}

// TestEffortOutputIsBounded checks the output bound on long runs of the
// delimiters that the inline, link and table scanners look for, at
// MaxSourceBytes. The work bound (not only the output) is checked by
// TestScanStepsAreLinear in effort_internal_test.go.
func TestEffortOutputIsBounded(t *testing.T) {
	for _, unit := range []string{"*", "**", "[", "](", "`", "|", "- ", "[a](b", "| a |\n|-|\n", "&"} {
		src := strings.Repeat(unit, mdsafe.MaxSourceBytes/len(unit))
		res, err := mdsafe.Render([]byte(src), mdsafe.Options{Relative: pageLinks})
		if err != nil {
			t.Fatalf("unit %q: %v", unit, err)
		}
		assertOutput(t, src, res)
	}
}

// TestTableAmplificationIsBounded is the worst table case: a header with
// maxTableColumns (32) columns and then rows of "|", two bytes each. The
// output must stay within maxOutputFactor per input byte.
func TestTableAmplificationIsBounded(t *testing.T) {
	header := "|" + strings.Repeat(" a |", 32) + "\n|" + strings.Repeat("-|", 32) + "\n"
	src := header + strings.Repeat("|\n", (mdsafe.MaxSourceBytes-len(header))/2)
	res, err := mdsafe.Render([]byte(src), mdsafe.Options{})
	if err != nil {
		t.Fatalf("table: %v", err)
	}
	assertOutput(t, src, res)
}

// TestRelativeHostileResultsNeverLink checks hostile resolver results for
// every link form, without the page policy. The output must pass
// assertInert, and a resolved link ("a.md" forms) must exist only when the
// result is in the /help form.
func TestRelativeHostileResultsNeverLink(t *testing.T) {
	for _, h := range hostileHrefs {
		for _, src := range []string{"[x](a.md)", "[x](a.md#frag)", "[x](#frag)", "[x](https://example.org/)"} {
			res, err := mdsafe.Render([]byte(src), mdsafe.Options{
				Relative: func(string, string) (string, bool) { return h, true },
			})
			if err != nil {
				t.Fatal(err)
			}
			out := string(res.HTML)
			assertInert(t, src, out)
			if strings.Contains(src, ".md") && strings.Contains(out, "<a ") && !helpHrefRE.MatchString(h) {
				t.Errorf("resolver result %q produced a link: %s", h, out)
			}
		}
	}
}

// TestRelativeTraversalNeverLinks checks resolver results that leave the
// /help page form. Each must render without a link, and the output must
// pass assertInert.
func TestRelativeTraversalNeverLinks(t *testing.T) {
	for _, h := range []string{
		"/help/../admin", "/help/..", "/help/./x", "/HELP/x", "/Help/hosts",
		"//evil.example/", "/help//x", "/help/", "/help/x/", "/helpx",
		"/admin", "/help/hosts.md", "/help/a b",
	} {
		res, err := mdsafe.Render([]byte("[x](a.md)"), mdsafe.Options{
			Relative: func(string, string) (string, bool) { return h, true },
		})
		if err != nil {
			t.Fatal(err)
		}
		out := string(res.HTML)
		assertInert(t, h, out)
		if strings.Contains(out, "<a ") {
			t.Errorf("resolver result %q produced a link: %s", h, out)
		}
	}
}

// TestRelativeOversizedResultNeverLinks checks that a resolver result over
// the destination limit is not emitted, even when it is a /help path, and
// that a short source with such a result stays inside the output bound.
func TestRelativeOversizedResultNeverLinks(t *testing.T) {
	long := "/help/" + strings.Repeat("a", 4096)
	res, err := mdsafe.Render([]byte("[x](a.md)"), mdsafe.Options{
		Relative: func(string, string) (string, bool) { return long, true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.HTML), "<a ") {
		t.Errorf("result of %d bytes produced a link", len(long))
	}
	assertOutput(t, "[x](a.md)", res)
}
