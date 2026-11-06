// SPDX-License-Identifier: AGPL-3.0-or-later

// Package static_test pins the screen-size contract of the inventory
// bulk action bar: the bar is fixed at every width, so the script
// measures the distance from the bar's top to the bottom of the
// viewport into --bulkbar-h and the stylesheet consumes it as extra
// bottom padding of the content area and scroll-padding-bottom of the
// scroll container. Without this, the last list rows and focused
// controls sit hidden behind the bar.
package static_test

import (
	"embed"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/web/static"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

func mustRead(t *testing.T, fs embed.FS, name string) string {
	t.Helper()
	b, err := fs.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// stripCSSComments removes /* ... */ comments so a comment cannot
// satisfy a rule check.
func stripCSSComments(css string) string {
	return regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, " ")
}

// cssRule is one rule: its selector list, declaration body, and the
// @media condition it sits in ("" at the top level).
type cssRule struct {
	sel  string
	body string
	cond string
}

// directRules parses the rules directly inside css (a whole stylesheet
// or the block of an at-rule): each entry's sel is the selector list
// or at-rule header, body the declarations or the at-rule's block.
func directRules(css string) []cssRule {
	var out []cssRule
	depth := 0
	preStart, openAt := 0, 0
	for i := 0; i < len(css); i++ {
		switch css[i] {
		case '{':
			if depth == 0 {
				out = append(out, cssRule{sel: css[preStart:i]})
				openAt = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				out[len(out)-1].body = css[openAt+1 : i]
				preStart = i + 1
			}
		}
	}
	return out
}

// rules returns every rule in css in document order, including the
// rules inside @media blocks (cond is the media condition, "" at the
// top level).
func rules(css string) []cssRule {
	css = stripCSSComments(css)
	var out []cssRule
	var walk func(s, cond string)
	walk = func(s, cond string) {
		for _, r := range directRules(s) {
			pre := strings.TrimSpace(r.sel)
			if strings.HasPrefix(pre, "@media") {
				i := strings.Index(pre, "(")
				if i < 0 {
					continue
				}
				walk(r.body, pre[i:])
			} else {
				out = append(out, cssRule{sel: pre, body: r.body, cond: cond})
			}
		}
	}
	walk(css, "")
	return out
}

// exactSelector reports whether the selector list selList contains sel
// as a whole entry (".foo .main" does not match ".main").
func exactSelector(selList, sel string) bool {
	for _, s := range strings.Split(selList, ",") {
		if strings.TrimSpace(s) == sel {
			return true
		}
	}
	return false
}

// mediaMatches reports whether the media condition cond applies at
// viewport width w (px); cond is "" at the top level.
func mediaMatches(cond string, w int) bool {
	if cond == "" {
		return true
	}
	for _, part := range strings.Split(cond, "and") {
		part = strings.TrimSpace(part)
		if m := regexp.MustCompile(`max-width:\s*(\d+)px`).FindStringSubmatch(part); m != nil {
			if w > atoi(m[1]) {
				return false
			}
		} else if m := regexp.MustCompile(`min-width:\s*(\d+)px`).FindStringSubmatch(part); m != nil {
			if w < atoi(m[1]) {
				return false
			}
		}
	}
	return true
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// effectivePaddingBottom returns the padding-bottom a rule body
// actually produces: the last padding-bottom declaration, or the
// bottom component of a padding shorthand declared after it (a
// shorthand resets the longhands).
func effectivePaddingBottom(body string) string {
	var pbVal, padVal string
	pbAt, padAt := -1, -1
	for _, m := range regexp.MustCompile(`([a-z-]+)\s*:\s*([^;{}]+);`).FindAllStringSubmatchIndex(body, -1) {
		switch strings.ToLower(body[m[2]:m[3]]) {
		case "padding-bottom":
			pbVal, pbAt = strings.TrimSpace(body[m[4]:m[5]]), m[0]
		case "padding":
			padVal, padAt = strings.TrimSpace(body[m[4]:m[5]]), m[0]
		}
	}
	if padAt > pbAt {
		parts := strings.Fields(padVal)
		switch len(parts) {
		case 0:
			return ""
		case 1, 2:
			return parts[0]
		default:
			return parts[2]
		}
	}
	return pbVal
}

// effectiveMainPaddingBottom returns the effective .main
// padding-bottom at viewport width w: the last .main rule that applies
// at w wins the cascade.
func effectiveMainPaddingBottom(rs []cssRule, w int) string {
	var eff string
	for _, r := range rs {
		if !exactSelector(r.sel, ".main") || !mediaMatches(r.cond, w) {
			continue
		}
		if pb := effectivePaddingBottom(r.body); pb != "" {
			eff = pb
		}
	}
	return eff
}

// ruleBody returns the declaration text of the first rule in css whose
// selector list contains sel as a whole entry, so a rule for a
// different selector (".foo .main") cannot satisfy a check.
func ruleBody(css, sel string) string {
	css = stripCSSComments(css)
	re := regexp.MustCompile(`(?:^|[},;{]\s*)` + regexp.QuoteMeta(sel) + `\s*\{`)
	loc := re.FindStringIndex(css)
	if loc == nil {
		return ""
	}
	rest := css[loc[1]:]
	end := strings.IndexByte(rest, '}')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// decl returns the value of the first declaration named name in the
// rule body body (e.g. "padding-bottom" -> "calc(...)"), or "". The
// property name must not be part of a longer name (so
// "scroll-padding-bottom" does not match "padding-bottom").
func decl(body, name string) string {
	re := regexp.MustCompile(`[^a-zA-Z-]` + regexp.QuoteMeta(name) + `:\s*([^;]+);`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// stripJSComments removes // and /* */ comments from js so a comment
// cannot satisfy a code check; string literals are kept.
func stripJSComments(js string) string {
	js = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(js, " ")
	var b strings.Builder
	for _, line := range strings.Split(js, "\n") {
		inS, inD := false, false
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case c == '/' && !inS && !inD && i+1 < len(line) && line[i+1] == '/':
				i = len(line)
			case c == '\'' && !inD:
				inS = !inS
				b.WriteByte(c)
			case c == '"' && !inS:
				inD = !inD
				b.WriteByte(c)
			default:
				b.WriteByte(c)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// funcBody returns the body between the braces of the first arrow
// function whose definition starts with prefix (e.g.
// "update = () =>"), or "".
func funcBody(code, prefix string) string {
	i := strings.Index(code, prefix)
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(code[i:], '{')
	if j < 0 {
		return ""
	}
	start := i + j
	depth := 0
	for k := start; k < len(code); k++ {
		switch code[k] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return code[start+1 : k]
			}
		}
	}
	return ""
}

// TestBulkBarClearancePadsContentAtEveryWidth: the bar is fixed at
// every width, so the content area must gain bottom padding equal to
// the bar's clearance at every width, not only below a single
// breakpoint. The check evaluates the cascade: at each width the last
// .main rule that applies wins, and a padding shorthand after a
// padding-bottom declaration in the same rule resets it — so a
// shorthand or a later breakpoint override that drops the clearance
// fails the test.
func TestBulkBarClearancePadsContentAtEveryWidth(t *testing.T) {
	rs := rules(mustRead(t, static.FS, "app.css"))
	for _, w := range []int{320, 480, 599, 600, 601, 700, 899, 900, 1000, 1440, 1920} {
		eff := effectiveMainPaddingBottom(rs, w)
		if !strings.Contains(eff, "--bulkbar-h") {
			t.Errorf("app.css: at %dpx the effective .main padding-bottom is %q without the --bulkbar-h clearance; the fixed bulk bar covers the last rows", w, eff)
		}
	}
	// The base rule keeps the desktop space-3 base, the phone rule the
	// phone's space-2 base (otherwise phones gain the desktop space-3
	// as uneven bottom padding even with no bar present).
	if eff := effectiveMainPaddingBottom(rs, 1440); !strings.Contains(eff, "var(--space-3)") {
		t.Errorf("app.css: the desktop .main padding-bottom must keep the space-3 base, got %q", eff)
	}
	if eff := effectiveMainPaddingBottom(rs, 500); !strings.Contains(eff, "var(--space-2)") {
		t.Errorf("app.css: the phone .main padding-bottom must keep the space-2 base, got %q", eff)
	}
}

// TestBulkBarClearanceKeepsFocusClear: a keyboard or switch user
// tabbing through row checkboxes and host links must not land on
// focused elements underneath the fixed bar (WCAG 2.2 2.4.11 Focus Not
// Obscured), so the scroll container needs scroll-padding-bottom from
// the same clearance. The rule must sit on the scroll container
// itself (html) at the top level: a non-scrolling element such as
// .main or .bulkbar accepts scroll-padding-bottom without effect, and
// a media-block rule would only cover part of the widths.
func TestBulkBarClearanceKeepsFocusClear(t *testing.T) {
	for _, r := range rules(mustRead(t, static.FS, "app.css")) {
		if r.cond != "" || !exactSelector(r.sel, "html") {
			continue
		}
		if pb := decl(r.body, "scroll-padding-bottom"); strings.Contains(pb, "--bulkbar-h") {
			return
		}
	}
	t.Error("app.css: the scroll container html must set scroll-padding-bottom from the --bulkbar-h clearance at the top level; a rule on a non-scrolling element (e.g. .main or .bulkbar) leaves focused row checkboxes and host links under the fixed bulk bar")
}

// TestBulkBarJSKeepsClearanceInSync: the script must measure the
// bar's clearance into --bulkbar-h and react to every height change
// (toggle, inline confirms, text wrap, viewport resize). The checks
// run on comment-stripped code and match the actual statements, not
// bare tokens: the test must fail if the .observe(bulkbar) call is
// removed, if the else branch becomes r.height (which under-clears
// the bar's bottom offset), or if the tokens only exist in a comment.
func TestBulkBarJSKeepsClearanceInSync(t *testing.T) {
	js := stripJSComments(mustRead(t, static.FS, "bulkbar.js"))
	for _, re := range []string{
		`setProperty\(\s*--bulkbar-h`, // the variable the stylesheet consumes
		`getBoundingClientRect`,       // the bar's position, not just its size
		`new\s+ResizeObserver\(\s*setBarClearance\s*\)\s*\.\s*observe\(\s*bulkbar\s*\)`,
		`addEventListener\(\s*'resize'`,
		`innerHeight\s*-\s*r\.top`, // the distance to the viewport bottom, not the bar's height
	} {
		if !regexp.MustCompile(re).MatchString(js) {
			t.Errorf("bulkbar.js: missing code matching %q; the bulk bar clearance is not kept in sync with the bar", re)
		}
	}
	if strings.Contains(js, "r.height") {
		t.Error("bulkbar.js: the clearance must be innerHeight - r.top, not r.height, which under-clears the bar's bottom offset")
	}
}

// TestBulkBarJSScrollsCoveredFocusClear: scroll-padding-bottom only
// applies when a scroll happens, so a focused control can still sit
// under the fixed bar (Space on a row checkbox near the viewport
// bottom, the sheet expanding, tabbing to a covered control). The
// script must scroll a covered focused element above the bar when the
// bar appears, when its clearance changes, and when focus moves.
func TestBulkBarJSScrollsCoveredFocusClear(t *testing.T) {
	js := stripJSComments(mustRead(t, static.FS, "bulkbar.js"))
	for _, want := range []string{
		"document.activeElement", // the focused control
		"window.scrollBy",        // actually move it clear
		`addEventListener('focusin'`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("bulkbar.js: missing %q; a focused control can sit under the fixed bulk bar", want)
		}
	}
	for _, prefix := range []string{"update = () =>", "setBarClearance = () =>"} {
		body := funcBody(js, prefix)
		if body == "" {
			t.Errorf("bulkbar.js: cannot find %q", prefix)
			continue
		}
		if !strings.Contains(body, "clearFocus") {
			t.Errorf("bulkbar.js: %s must call clearFocus, so a focused control covered by the bar is scrolled above it", prefix)
		}
	}
}

// TestInventoryTemplateBulkBarToggleA11y: the sheet toggle must be a
// real button with the ARIA state and control wiring, so keyboard and
// screen-reader users can expand the sheet without a pointer, and the
// script must keep aria-expanded in sync with the sheet.
func TestInventoryTemplateBulkBarToggleA11y(t *testing.T) {
	html := mustRead(t, templates.FS, "inventory.html")
	re := regexp.MustCompile(`<button[^>]*id="bulkbar-toggle"[^>]*aria-expanded="false"[^>]*aria-controls="bulkbar-body"`)
	if !re.MatchString(html) {
		t.Error(`inventory.html: the bulk bar toggle must be a real <button> with aria-expanded and aria-controls="bulkbar-body" to stay keyboard and screen-reader friendly`)
	}
	if !strings.Contains(html, `id="bulkbar-body"`) {
		t.Error("inventory.html: missing the #bulkbar-body group the toggle controls")
	}
	js := stripJSComments(mustRead(t, static.FS, "bulkbar.js"))
	for _, want := range []string{
		`setAttribute('aria-expanded', 'false')`, // a fresh selection starts collapsed
		`setAttribute('aria-expanded', String(expanded))`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("bulkbar.js: missing %q; the script must keep the toggle's aria-expanded in sync with the sheet", want)
		}
	}
}

// TestBulkBarSheetFitsViewport: a sheet taller than the viewport (high
// browser zoom) must stay scrollable so its toggle and confirms at the
// top remain reachable, and the script must clear the area the bar
// covers when its top edge sits above the viewport.
func TestBulkBarSheetFitsViewport(t *testing.T) {
	css := mustRead(t, static.FS, "app.css")
	body := ruleBody(css, ".bulkbar")
	if !strings.Contains(body, "max-height") || !strings.Contains(body, "overflow-y") {
		t.Error("app.css: the fixed .bulkbar needs max-height and overflow-y so a sheet taller than the viewport keeps its toggle and confirms reachable")
	}
	js := mustRead(t, static.FS, "bulkbar.js")
	if !strings.Contains(js, "Math.min(r.bottom, innerHeight)") {
		t.Error("bulkbar.js: when the bar's top is above the viewport (r.top <= 0) the clearance must cover the visible part of the bar (r.bottom), not 0")
	}
}

// TestBulkBarSheetLeavesRoomForFocus: below about 280px of viewport
// height (e.g. a 1280x1024 screen at 400% zoom with the sheet
// expanded) the 80vh cap alone leaves 20vh for content, and the
// 3.5rem sticky topbar plus the --space-3 scroll padding use all of
// it, so a focused row has no unobscured place to land. The sheet's
// max-height must therefore also carry a calc(100vh - Nrem) cap with
// N >= 11rem (3.5rem topbar + 1.5rem scroll padding + 2rem bar bottom
// offset + 4rem for a focused row).
func TestBulkBarSheetLeavesRoomForFocus(t *testing.T) {
	css := mustRead(t, static.FS, "app.css")
	mh := decl(ruleBody(css, ".bulkbar"), "max-height")
	m := regexp.MustCompile(`calc\(\s*100vh\s*-\s*(\d+(?:\.\d+)?)rem\s*\)`).FindStringSubmatch(mh)
	if m == nil {
		t.Error(`app.css: .bulkbar max-height must include a calc(100vh - Nrem) cap so a focused row keeps an unobscured place on short viewports (e.g. 400% zoom), not only min(80vh, 24rem)`)
		return
	}
	if n, _ := strconv.ParseFloat(m[1], 64); n < 11 {
		t.Errorf("app.css: the sheet cap calc(100vh - %srem) leaves less than 4rem for a focused row below the topbar, scroll padding and bar offset (needs at least 11rem)", m[1])
	}
}

// TestRuleBodyMatchesWholeSelectorsOnly: the selector must match as a
// whole entry, so a compound rule such as ".foo .main" placed first
// cannot satisfy a .main check (the doc comment's promise).
func TestRuleBodyMatchesWholeSelectorsOnly(t *testing.T) {
	if b := ruleBody(".foo .main {\n  padding-bottom: 1rem;\n}\n", ".main"); b != "" {
		t.Errorf("ruleBody matched the compound selector .foo .main for .main, got body %q", b)
	}
	if b := ruleBody(".main {\n  padding-bottom: 1rem;\n}\n", ".main"); !strings.Contains(b, "padding-bottom") {
		t.Errorf("ruleBody did not match the plain .main rule, got %q", b)
	}
	if b := ruleBody("}\nhtml {\n  scroll-padding-bottom: 1px;\n}\n", "html"); !strings.Contains(b, "scroll-padding-bottom") {
		t.Errorf("ruleBody did not match the html rule after a closing brace, got %q", b)
	}
}
