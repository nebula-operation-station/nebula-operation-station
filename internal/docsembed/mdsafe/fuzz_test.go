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

// maxOutputFactor and maxOutputSlack bound the output length. Derivation
// from the code in mdsafe.go:
//   - html.EscapeString turns one byte into at most 5 bytes ("&#34;",
//     "&amp;"), so escaped text grows by a factor of 5 at most;
//   - NUL is replaced by the 3-byte U+FFFD, and a tab by 4 spaces (both
//     are 1-byte inputs that grow, so they are within the factor);
//   - the largest fixed wrapper is a heading: the 2-byte line "#\n"
//     becomes `<h1 id="section"></h1>\n` (24 bytes) plus the "-N"
//     suffix of duplicate ids (O(log n) bytes); that is at most 16 bytes
//     per input byte for inputs of this size.
//
// 32 covers all of these with margin. A parser that was quadratic in
// output or repeated work per byte would exceed it on the long seeds.
const (
	maxOutputFactor = 32
	maxOutputSlack  = 1024
)

var (
	// headingIDRE matches the opening tag of a rendered heading.
	headingIDRE = regexp.MustCompile(`<h[1-6] id="([^"]*)">`)
	// linkRE matches an opening <a> tag with a local href.
	linkRE = regexp.MustCompile(`<a href="(/[^"]*)"[^>]*>`)
	// localPathRE is the Relative contract of mdsafe.go (localHrefRE).
	localPathRE = regexp.MustCompile(`^/[A-Za-z0-9._/-]*(#[\pL\pN_-]+)?$`)
	// tagTokenRE matches any tag, for measuring element nesting.
	tagTokenRE = regexp.MustCompile(`<(/?)([a-zA-Z0-9]+)[^>]*>`)
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
// valid UTF-8, the assertInert allowlist, heading ids unique and derived
// from Slug, and the output length bound.
func assertOutput(t *testing.T, src string, res mdsafe.Result) {
	t.Helper()
	out := string(res.HTML)
	if !utf8.ValidString(out) {
		t.Fatalf("Render(%q) output is not valid UTF-8", src)
	}
	assertInert(t, src, normalizeForeignLinks(t, out))
	checkHeadingIDs(t, src, out, res)
	if limit := maxOutputFactor*len(src) + maxOutputSlack; len(out) > limit {
		t.Errorf("Render: output %d bytes for %d input bytes exceeds the bound %d", len(out), len(src), limit)
	}
}

// normalizeForeignLinks handles links to local paths outside /help. The
// Relative contract (localPathRE) allows any local path, but assertInert
// only admits /help. Such a link is checked against the contract here,
// then removed so the rest of the output is still checked by assertInert.
func normalizeForeignLinks(t *testing.T, out string) string {
	t.Helper()
	return linkRE.ReplaceAllStringFunc(out, func(tag string) string {
		href := linkRE.FindStringSubmatch(tag)[1]
		if strings.HasPrefix(href, "/help") {
			return tag
		}
		if !localPathRE.MatchString(href) {
			t.Errorf("link %q is not a local path form", href)
		}
		return ""
	})
}

// checkHeadingIDs checks that the rendered heading ids match
// res.Headings in order, are unique, and equal Slug of the heading text
// or Slug with a "-N" suffix ("section" when the slug is empty).
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
		if id != base && !strings.HasPrefix(id, base+"-") {
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
// delimiters that the inline, link and table scanners look for, at 32 KiB.
// The check is on output length only (no timing). It does NOT catch
// superlinear CPU work: a "*" run is quadratic in mdsafe.findRun (see the
// report for tw09), and that needs a timing or operation-count check that
// is outside this test. The size is kept small so the suite stays fast;
// at MaxSourceBytes the same "*" input takes minutes.
func TestEffortOutputIsBounded(t *testing.T) {
	for _, unit := range []string{"*", "**", "[", "](", "`", "|", "- ", "[a](b", "| a |\n|-|\n"} {
		src := strings.Repeat(unit, (1<<15)/len(unit))
		res, err := mdsafe.Render([]byte(src), mdsafe.Options{Relative: pageLinks})
		if err != nil {
			t.Fatalf("unit %q: %v", unit, err)
		}
		assertOutput(t, src, res)
	}
}

// TestRelativeHostileResultsNeverLink checks hostile resolver results for
// every link form. The output must hold no link to a non-local target.
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
			assertInert(t, src, normalizeForeignLinks(t, out))
			for _, m := range linkRE.FindAllStringSubmatch(out, -1) {
				if strings.HasPrefix(m[1], "/help") && !localPathRE.MatchString(m[1]) {
					t.Errorf("resolver %q: link %q is not a local path", h, m[1])
				}
			}
		}
	}
}
