// SPDX-License-Identifier: AGPL-3.0-or-later

package mdsafe_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
)

// pageLinks resolves "x.md#frag" like the help pages do.
func pageLinks(p, frag string) (string, bool) {
	if p != "hosts.md" {
		return "", false
	}
	if frag != "" {
		return "/help/hosts#" + frag, true
	}
	return "/help/hosts", true
}

func render(t *testing.T, src string) mdsafe.Result {
	t.Helper()
	res, err := mdsafe.Render([]byte(src), mdsafe.Options{Relative: pageLinks})
	if err != nil {
		t.Fatalf("Render(%q): %v", src, err)
	}
	return res
}

// allowedTag lists every tag the renderer may emit, with the only
// attributes it may carry.
var tagRE = regexp.MustCompile(`<(/?)([a-zA-Z0-9]+)([^>]*)>`)

var allowedTags = map[string]*regexp.Regexp{
	"h1": regexp.MustCompile(`^( id="[\pL\pN_-]+")?$`),"h2": regexp.MustCompile(`^( id="[\pL\pN_-]+")?$`),
	"h3": regexp.MustCompile(`^( id="[\pL\pN_-]+")?$`), "h4": regexp.MustCompile(`^( id="[\pL\pN_-]+")?$`),
	"h5": regexp.MustCompile(`^( id="[\pL\pN_-]+")?$`), "h6": regexp.MustCompile(`^( id="[\pL\pN_-]+")?$`),
	"p": regexp.MustCompile(`^$`), "ul": regexp.MustCompile(`^$`), "ol": regexp.MustCompile(`^$`),
	"li": regexp.MustCompile(`^$`), "pre": regexp.MustCompile(`^$`), "code": regexp.MustCompile(`^$`),
	"strong": regexp.MustCompile(`^$`), "em": regexp.MustCompile(`^$`),
	"table": regexp.MustCompile(`^$`), "thead": regexp.MustCompile(`^$`), "tbody": regexp.MustCompile(`^$`),
	"tr": regexp.MustCompile(`^$`), "th": regexp.MustCompile(`^$`), "td": regexp.MustCompile(`^$`),
	"div": regexp.MustCompile(`^ class="table-wrap"$`),
	"a":   regexp.MustCompile(`^ href="(/help[a-z0-9/#_-]*|#[\pL\pN_-]+|https://[^"<>\s]+)"( rel="noopener noreferrer")?$`),
}

// assertInert checks that out contains only allowed tags and attributes
// and no executable markup.
func assertInert(t *testing.T, src, out string) {
	t.Helper()
	for _, m := range tagRE.FindAllStringSubmatch(out, -1) {
		re, ok := allowedTags[m[2]]
		if !ok {
			t.Errorf("Render(%q) emitted tag <%s%s>:\n%s", src, m[2], m[3], out)
			continue
		}
		if m[1] == "" && !re.MatchString(m[3]) {
			t.Errorf("Render(%q) emitted <%s> with attributes %q:\n%s", src, m[2], m[3], out)
		}
		if m[1] == "/" && m[3] != "" {
			t.Errorf("Render(%q) emitted closing tag with attributes %q", src, m[3])
		}
	}
	lower := strings.ToLower(out)
	for _, bad := range []string{"href=\"javascript:", "href=\"vbscript:", "href=\"data:", "href=\"http:", "href=\"//"} {
		if strings.Contains(lower, bad) {
			t.Errorf("Render(%q) contains %q:\n%s", src, bad, out)
		}
	}
	// Every tag was checked above; no raw '<' or '>' may remain in text.
	stripped := tagRE.ReplaceAllString(out, "")
	if strings.ContainsAny(stripped, "<>") {
		t.Errorf("Render(%q) has an unescaped < or > in text:\n%s", src, out)
	}
}

func TestHostileMarkdownIsInert(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		// mustContain are substrings the escaped output must have.
		mustContain []string
		// mustNot are substrings it must not have.
		mustNot []string
	}{
		{name: "script tag", src: "<script>alert(1)</script>",
			mustContain: []string{"&lt;script&gt;alert(1)&lt;/script&gt;"}, mustNot: []string{"<script"}},
		{name: "script in heading", src: "# Hi <script>x</script>",
			mustContain: []string{"&lt;script&gt;"}, mustNot: []string{"<script"}},
		{name: "raw html block", src: "<div onclick=\"x()\">\n<img src=x onerror=alert(1)>\n</div>",
			mustContain: []string{"&lt;img src=x onerror=alert(1)&gt;"}, mustNot: []string{"<img", "<div onclick"}},
		{name: "html comment", src: "<!-- hidden -->", mustContain: []string{"&lt;!-- hidden --&gt;"}},
		{name: "javascript link", src: "[click](javascript:alert(1))",
			mustContain: []string{"click"}, mustNot: []string{"href", "<a"}},
		{name: "javascript link upper case", src: "[click](JaVaScRiPt:alert(1))", mustNot: []string{"href", "<a"}},
		{name: "javascript link with entity", src: "[click](java&#115;cript:alert(1))", mustNot: []string{"href", "<a"}},
		{name: "javascript link with tab", src: "[click](java\tscript:alert(1))", mustNot: []string{"href", "<a"}},
		{name: "data link", src: "[x](data:text/html;base64,PHNjcmlwdD4=)", mustNot: []string{"href", "<a"}},
		{name: "vbscript link", src: "[x](vbscript:msgbox)", mustNot: []string{"href", "<a"}},
		{name: "http link", src: "[x](http://example.org/)", mustNot: []string{"href", "<a"}},
		{name: "mailto link", src: "[x](mailto:a@example.org)", mustNot: []string{"href", "<a"}},
		{name: "protocol relative link", src: "[x](//evil.example/)", mustNot: []string{"href", "<a"}},
		{name: "backslash link", src: "[x](/\\evil.example/)", mustNot: []string{"href", "<a"}},
		{name: "https with userinfo", src: "[x](https://user@evil.example/)", mustNot: []string{"href", "<a"}},
		{name: "https without host", src: "[x](https:///path)", mustNot: []string{"href", "<a"}},
		{name: "unknown relative link", src: "[guide](../admin/guide.md#x)",
			mustContain: []string{"guide"}, mustNot: []string{"href", "<a"}},
		{name: "attribute breakout in https link", src: `[x](https://example.org/"onmouseover="alert(1))`,
			mustNot: []string{`"onmouseover`, "onmouseover=\"alert"}},
		{name: "attribute breakout in fragment", src: `[x](#a"onclick="b)`, mustNot: []string{"onclick=\"", "<a"}},
		{name: "html in link text", src: "[<b>bold</b>](https://example.org/)",
			mustContain: []string{"&lt;b&gt;bold&lt;/b&gt;"}, mustNot: []string{"<b>"}},
		{name: "html in code span", src: "`<script>`", mustContain: []string{"<code>&lt;script&gt;</code>"}},
		{name: "html in code block", src: "```html\n<script>alert(1)</script>\n```",
			mustContain: []string{"<pre><code>&lt;script&gt;alert(1)&lt;/script&gt;\n</code></pre>"}},
		{name: "html in table", src: "| a | b |\n| --- | --- |\n| <script>x</script> | [y](javascript:z) |",
			mustContain: []string{"&lt;script&gt;"}, mustNot: []string{"<script", "href"}},
		{name: "html in list", src: "- <iframe src=x>\n- ok", mustContain: []string{"&lt;iframe src=x&gt;"}},
		{name: "html in bold", src: "**<svg onload=x>**", mustContain: []string{"<strong>&lt;svg onload=x&gt;</strong>"}},
		{name: "image syntax is text", src: "![x](https://example.org/a.png)", mustNot: []string{"<img"}},
		{name: "heading id cannot inject", src: "## a\" onclick=\"x", mustNot: []string{`onclick="x`}},
		{name: "quotes escaped", src: `say "hi" & 'bye'`, mustContain: []string{"&#34;hi&#34; &amp; &#39;bye&#39;"}},
		{name: "nul byte", src: "a\x00b", mustNot: []string{"\x00"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := string(render(t, tc.src).HTML)
			assertInert(t, tc.src, out)
			for _, s := range tc.mustContain {
				if !strings.Contains(out, s) {
					t.Errorf("output lacks %q:\n%s", s, out)
				}
			}
			for _, s := range tc.mustNot {
				if strings.Contains(out, s) {
					t.Errorf("output contains %q:\n%s", s, out)
				}
			}
		})
	}
}

func TestSupportedSubset(t *testing.T) {
	src := "# Title here\n\nIntro **bold** and *em* and `code`.\nSecond line.\n\n" +
		"## Add a host (CSV)\n\n1. First step\n   continued\n\n   ```\n   nebula host add\n   ```\n2. Second [hosts](hosts.md#add-a-host)\n\n" +
		"- a\n- b [ext](https://example.org/x?y=1&z=2)\n  - nested\n\n" +
		"| Col | Other |\n| --- | --- |\n| `c` | [h](hosts.md) |\n\n" +
		"See [above](#title-here).\n\n## Add a host (CSV)\n"
	res := render(t, src)
	out := string(res.HTML)
	assertInert(t, src, out)
	for _, want := range []string{
		`<h1 id="title-here">Title here</h1>`,
		"<p>Intro <strong>bold</strong> and <em>em</em> and <code>code</code>.\nSecond line.</p>",
		`<h2 id="add-a-host-csv">Add a host (CSV)</h2>`,
		"<ol>", "First step\ncontinued", "<pre><code>nebula host add\n</code></pre>",
		`<a href="/help/hosts#add-a-host">hosts</a>`,
		`<a href="https://example.org/x?y=1&amp;z=2" rel="noopener noreferrer">ext</a>`,
		"<ul>", "<li>nested</li>",
		`<div class="table-wrap"><table><thead><tr><th>Col</th><th>Other</th></tr></thead>`,
		`<td><code>c</code></td><td><a href="/help/hosts">h</a></td>`,
		`<a href="#title-here">above</a>`,
		`<h2 id="add-a-host-csv-1">Add a host (CSV)</h2>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if res.Title != "Title here" {
		t.Errorf("Title = %q", res.Title)
	}
	wantHeads := []mdsafe.Heading{
		{Level: 1, Text: "Title here", ID: "title-here"},
		{Level: 2, Text: "Add a host (CSV)", ID: "add-a-host-csv"},
		{Level: 2, Text: "Add a host (CSV)", ID: "add-a-host-csv-1"},
	}
	if len(res.Headings) != len(wantHeads) {
		t.Fatalf("Headings = %+v", res.Headings)
	}
	for i, h := range wantHeads {
		if res.Headings[i] != h {
			t.Errorf("Headings[%d] = %+v, want %+v", i, res.Headings[i], h)
		}
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"3.3 In containers":                    "33-in-containers",
		"Enroll a host reachable over a VPN (NetBird, WireGuard, Tailscale)": "enroll-a-host-reachable-over-a-vpn-netbird-wireguard-tailscale",
		"Run read-only checks on a schedule (read lease)":                    "run-read-only-checks-on-a-schedule-read-lease",
		"Übergabe `nebula` **jetzt**":                                        "übergabe-nebula-jetzt",
		"<script>":                                                           "script",
	} {
		if got := mdsafe.Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderLimits(t *testing.T) {
	if _, err := mdsafe.Render(make([]byte, mdsafe.MaxSourceBytes+1), mdsafe.Options{}); !errors.Is(err, mdsafe.ErrTooLarge) {
		t.Errorf("oversized source: err = %v, want ErrTooLarge", err)
	}
	if _, err := mdsafe.Render([]byte("ok \xff\xfe"), mdsafe.Options{}); !errors.Is(err, mdsafe.ErrInvalidUTF8) {
		t.Errorf("invalid UTF-8: err = %v, want ErrInvalidUTF8", err)
	}
	// Deep nesting must neither panic nor recurse without bound.
	deep := strings.Repeat("- ", 5000) + "x\n" + strings.Repeat("*", 5000) + strings.Repeat("[", 5000) + "\n" + strings.Repeat(">", 5000)
	res, err := mdsafe.Render([]byte(deep), mdsafe.Options{})
	if err != nil {
		t.Fatalf("deep input: %v", err)
	}
	assertInert(t, "deep", string(res.HTML))
	if n := strings.Count(string(res.HTML), "<ul>"); n > mdsafe.MaxNesting+1 {
		t.Errorf("deep list rendered %d nested lists, limit %d", n, mdsafe.MaxNesting)
	}
}

func TestRelativeResolverOutputIsChecked(t *testing.T) {
	// A resolver that returns something unsafe must not produce a link.
	for _, bad := range []string{"javascript:alert(1)", "//evil.example/", "https://evil.example/", "/a\"b", "relative/path", "/x\\y"} {
		res, err := mdsafe.Render([]byte("[x](a.md)"), mdsafe.Options{Relative: func(string, string) (string, bool) { return bad, true }})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(res.HTML), "<a") {
			t.Errorf("resolver result %q produced a link: %s", bad, res.HTML)
		}
	}
}
