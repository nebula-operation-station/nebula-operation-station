// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// These tests read docs/admin/guide.md (read only) and check the
// server.json documentation against the strict loader in config.go. They
// do not repeat the key list: the keys come from the json tags of Config,
// read with reflect. A key that the guide leaves out, or an example with a
// misspelled key, fails here instead of at the admin's server start.

// guideAdminPath is the admin guide, relative to this package directory
// (go test runs there), as internal/docsembed/guide_test.go resolves it.
const guideAdminPath = "../../docs/admin/guide.md"

// guideSection61 is the heading of the table of server.json keys.
const guideSection61 = "### 6.1 "

// guideConfigKeysUndocumented lists top-level server.json keys that the
// guide deliberately does not list in the 6.1 table, with the reason and
// the source. An entry must name a real Config key, and it fails when the
// key is documented after all.
var guideConfigKeysUndocumented = map[string]string{
	"token": "Befund ue09, Korrektur in guide.md offen: config.go Z. 123-127 " +
		"documents the top-level token as the server's secret (\"Token is the " +
		"server's secret token\"), and config_test.go TestRegisterFlagsHasNoTokenFlag " +
		"says it comes from the config file only. The 6.1 table does not list it, " +
		"and no reader of Config.Token exists outside serverconfig (checked with grep " +
		"over cmd/ and internal/). Whether admins may set it is a decision still open; " +
		"the guide must either document it or say that it is internal.",
}

// guideTableKeysNotInConfig lists table keys that are not Config keys. It is
// empty: a row without a loader key is always a drift.
var guideTableKeysNotInConfig = map[string]string{}

// guideBlockExclusions names JSON examples in the guide that are not
// server.json. Each marker is a substring of the example; a block that
// contains it is skipped. The test fails if a marker matches no block, so
// a stale exclusion cannot hide anything.
var guideBlockExclusions = map[string]string{
	`"token_file"`: "the nebula-vuln-agent skeleton in section 10.5 (/etc/nebula-vuln-agent/config.json); its top-level data_dir only coincides with a server key",
}

// guideElisions marks examples written with "..." to shorten them. They are
// not complete JSON, so they are skipped. The test fails if one of them stops
// matching.
var guideElisions = map[string]string{
	`"api": {"enabled": true, ...}`:               "section 10.2 prose elision; the api example is covered by the token entries in section 10.2 and 10.4",
	`"api": {"enabled": true, "tokens": [ ... ]}`: "section 10.2 prose elision of the token list",
}

// guidePlaceholders is the fixed table that replaces the placeholders of the
// guide's JSON examples before they are parsed. Each value is a valid value
// for its key, so the example is judged by its keys and not by the
// placeholder text. A placeholder without an entry fails the test.
var guidePlaceholders = map[string]string{
	"<rp-id>":                              "nebula.example.org",
	"<at least 32 random characters>":      "0123456789abcdef0123456789abcdef",
	"<random topic>":                       "nebula-alerts",
	"<optional>":                           "example-ntfy-token",
	"<123456:ABC...>":                      "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"<chat id or @channel>":                "-1001234567890",
	"<printed hash>":                       strings.Repeat("a", 64),
	"<address or prefix of the Hermes VM>": "192.0.2.10",
	"<address of nos-vuln>":                "192.0.2.11",
}

// guideNPlaceholder is the value that replaces a bare N in a value position,
// as in `"traffic": {"retention_days": N}` (1-21 days allowed).
const guideNPlaceholder = "7"

// guideMinimalFields are the required fields of a minimal server.json. A
// block is validated with these added when the block does not give them.
var guideMinimalFields = map[string]any{
	"public_origin":   "https://nebula.example.org",
	"data_dir":        "/var/lib/nebula/server",
	"executor_socket": "/run/nebula/executor.sock",
	"executor_user":   "nebula-executor",
}

var (
	guidePlaceholderRe = regexp.MustCompile(`<[^<>\n]*>`)
	guideNValueRe      = regexp.MustCompile(`(:\s*)N(\s*[,}\]])`)
	guideInlineSpanRe  = regexp.MustCompile("`([^`\n]+)`")
)

// guideLines returns the lines of the admin guide.
func guideLines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(guideAdminPath)
	if err != nil {
		t.Fatalf("read %s: %v", guideAdminPath, err)
	}
	return strings.Split(string(data), "\n")
}

// headingLevel returns the number of leading # of a Markdown heading, or 0.
func headingLevel(line string) int {
	n := len(line) - len(strings.TrimLeft(line, "#"))
	if n == 0 || n > 6 || len(line) <= n || line[n] != ' ' {
		return 0
	}
	return n
}

// guideSection returns the lines of the section whose heading starts with
// prefix, up to the next heading of the same or a higher level. Headings in
// code fences are not headings. It fails with the heading's name when the
// heading is missing.
func guideSection(t *testing.T, lines []string, prefix string) []string {
	t.Helper()
	start, level := -1, 0
	inFence := false
	for i, line := range lines {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if start < 0 {
			if strings.HasPrefix(line, prefix) && headingLevel(line) > 0 {
				start, level = i, headingLevel(line)
			}
			continue
		}
		if l := headingLevel(line); l > 0 && l <= level {
			return lines[start+1 : i]
		}
	}
	if start < 0 {
		t.Fatalf("heading %q not found in %s", strings.TrimSpace(prefix), guideAdminPath)
	}
	return lines[start+1:]
}

// guideRow is one row of a Markdown table: the first cell is the key, the
// default cell is set only when it is a plain backticked value.
type guideRow struct {
	key    string
	def    string
	hasDef bool
	line   string
}

// guideTableRows returns the rows whose first cell is a backticked key.
func guideTableRows(section []string) []guideRow {
	var rows []guideRow
	for _, line := range section {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.TrimSpace(line), "|")
		if len(cells) < 3 {
			continue
		}
		cells = cells[1 : len(cells)-1]
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		r := guideRow{key: strings.Trim(cells[0], "`"), line: line}
		if len(cells) >= 2 && strings.HasPrefix(cells[1], "`") && strings.HasSuffix(cells[1], "`") && len(cells[1]) >= 2 {
			r.def = strings.Trim(cells[1], "`")
			r.hasDef = true
		}
		rows = append(rows, r)
	}
	return rows
}

// configTopLevelKeys returns the json names of the top-level Config fields,
// read with reflect.
func configTopLevelKeys(t *testing.T) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			t.Fatalf("Config.%s has no json name; the guide test needs one", f.Name)
		}
		keys[name] = true
	}
	return keys
}

// TestGuide61TableListsEveryConfigKey checks the first column of the table
// in guide section 6.1 against the json tags of Config: every loader key has
// a row, every row is a loader key, and the exceptions are still needed.
func TestGuide61TableListsEveryConfigKey(t *testing.T) {
	rows := guideTableRows(guideSection(t, guideLines(t), guideSection61))
	if len(rows) == 0 {
		t.Fatalf("no key rows found in the table of section %q", strings.TrimSpace(guideSection61))
	}
	table := map[string]bool{}
	for _, r := range rows {
		if table[r.key] {
			t.Errorf("guide 6.1 lists key %q twice", r.key)
		}
		table[r.key] = true
	}
	cfg := configTopLevelKeys(t)

	var missing []string
	for k := range cfg {
		if table[k] {
			continue
		}
		if _, ok := guideConfigKeysUndocumented[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		t.Errorf("Config key %q has no row in the guide 6.1 table (add the row, or list it in guideConfigKeysUndocumented with a reason)", k)
	}

	var extra []string
	for k := range table {
		if !cfg[k] {
			if _, ok := guideTableKeysNotInConfig[k]; !ok {
				extra = append(extra, k)
			}
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		t.Errorf("guide 6.1 table row %q is not a json key of Config (typo, or the key was removed)", k)
	}

	for k, reason := range guideConfigKeysUndocumented {
		if !cfg[k] {
			t.Errorf("guideConfigKeysUndocumented names %q, which is not a Config key; remove the entry", k)
		}
		if table[k] {
			t.Errorf("guideConfigKeysUndocumented names %q, but the guide 6.1 table now lists it; remove the entry (reason was: %s)", k, reason)
		}
	}
	for k := range guideTableKeysNotInConfig {
		if !table[k] || cfg[k] {
			t.Errorf("guideTableKeysNotInConfig names %q, which is not a table row without a Config key; remove the entry", k)
		}
	}
}

// guideCodeBlock is a JSON-looking block of the guide: fenced, or indented
// by four spaces after a blank line. Line is the 1-based start line.
type guideCodeBlock struct {
	line   int
	fenced bool
	info   string
	body   string
}

// guideCodeBlocks returns the fenced and indented code blocks of the guide.
func guideCodeBlocks(lines []string) []guideCodeBlock {
	var blocks []guideCodeBlock
	inFence := false
	var cur *guideCodeBlock
	var curLines []string
	flush := func() {
		if cur != nil {
			cur.body = strings.Join(curLines, "\n")
			blocks = append(blocks, *cur)
			cur = nil
			curLines = nil
		}
	}
	for i, line := range lines {
		if strings.HasPrefix(line, "```") {
			if inFence {
				flush()
				inFence = false
			} else {
				flush()
				inFence = true
				cur = &guideCodeBlock{line: i + 1, fenced: true, info: strings.TrimSpace(strings.TrimPrefix(line, "```"))}
			}
			continue
		}
		if inFence {
			curLines = append(curLines, line)
			continue
		}
		indented := strings.HasPrefix(line, "    ") && strings.TrimSpace(line) != ""
		prevBlank := i == 0 || strings.TrimSpace(lines[i-1]) == ""
		if indented && (cur == nil || !cur.fenced) {
			if cur == nil {
				if !prevBlank {
					continue
				}
				cur = &guideCodeBlock{line: i + 1}
			}
			curLines = append(curLines, strings.TrimPrefix(line, "    "))
			continue
		}
		if cur != nil && !cur.fenced {
			flush()
		}
	}
	flush()
	return blocks
}

// jsonMembers parses text as a JSON object, or as the member list of an
// object ("key": value, ...) that the guide shows without its braces. It
// fails for anything else, including null.
func jsonMembers(text string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &m); err == nil && m != nil {
		return m, nil
	}
	if err := json.Unmarshal([]byte("{"+text+"}"), &m); err == nil && m != nil {
		return m, nil
	}
	return nil, fmt.Errorf("not a JSON object or member list")
}

// guideFillPlaceholders applies guidePlaceholders and the bare N rule. A
// placeholder that the table does not cover stays in the text; the caller
// reports it.
func guideFillPlaceholders(text string) string {
	for p, v := range guidePlaceholders {
		text = strings.ReplaceAll(text, p, v)
	}
	return guideNValueRe.ReplaceAllString(text, "${1}"+guideNPlaceholder+"${2}")
}

// hasServerKey reports whether the object has a top-level server.json key.
func hasServerKey(m map[string]json.RawMessage, cfg map[string]bool) bool {
	for k := range m {
		if cfg[k] {
			return true
		}
	}
	return false
}

// buildServerConfig returns the document the server would read for an
// example: the minimal required fields, plus the example's members. An
// example that is a token entry (it has "sha256") is placed into
// api.tokens, because the guide shows token entries on their own.
func buildServerConfig(t *testing.T, m map[string]json.RawMessage) []byte {
	t.Helper()
	doc := map[string]any{}
	for k, v := range guideMinimalFields {
		doc[k] = v
	}
	if _, ok := m["sha256"]; ok {
		entry, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal token entry: %v", err)
		}
		doc["api"] = map[string]any{"enabled": true, "tokens": []json.RawMessage{entry}}
	} else {
		for k, v := range m {
			doc[k] = v
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal server.json example: %v", err)
	}
	return out
}

// TestGuideServerJSONExamplesParseStrictly sends every JSON example of the
// admin guide that is a server.json example through Parse, the strict loader
// that the server uses at start (unknown keys and trailing data are errors).
// Examples are fenced or indented blocks and inline code spans of the form
// "key": value. A block or span counts when it has at least one top-level
// server key, or it is a token entry of api.tokens. The examples are
// completed with the minimal required fields and the placeholders replaced
// from guidePlaceholders first.
func TestGuideServerJSONExamplesParseStrictly(t *testing.T) {
	lines := guideLines(t)
	cfg := configTopLevelKeys(t)
	validated := 0
	seenExclusion := map[string]bool{}
	seenElision := map[string]bool{}

	check := func(where, text string, mustParse bool) {
		t.Helper()
		for marker := range guideBlockExclusions {
			if strings.Contains(text, marker) {
				seenExclusion[marker] = true
				return
			}
		}
		for marker := range guideElisions {
			if strings.Contains(text, marker) {
				seenElision[marker] = true
				return
			}
		}
		// Placeholders are filled first: "retention_days": N is only
		// JSON after the N rule has run.
		filled := guideFillPlaceholders(text)
		m, err := jsonMembers(filled)
		if err != nil {
			if mustParse {
				t.Errorf("%s: JSON block does not parse: %v", where, err)
			}
			return
		}
		if _, isEntry := m["sha256"]; !isEntry && !hasServerKey(m, cfg) {
			return
		}
		if left := guidePlaceholderRe.FindString(filled); left != "" {
			t.Errorf("%s: placeholder %s has no entry in guidePlaceholders", where, left)
			return
		}
		if _, err := Parse(buildServerConfig(t, m)); err != nil {
			t.Errorf("%s: example does not pass the strict loader: %v", where, err)
			return
		}
		validated++
	}

	for _, b := range guideCodeBlocks(lines) {
		where := fmt.Sprintf("%s:%d (code block)", guideAdminPath, b.line)
		check(where, b.body, b.fenced && b.info == "json")
	}

	inFence := false
	for i, line := range lines {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, sp := range guideInlineSpanRe.FindAllStringSubmatch(line, -1) {
			if !strings.HasPrefix(sp[1], `"`) {
				continue
			}
			check(fmt.Sprintf("%s:%d (inline example %s)", guideAdminPath, i+1, sp[1]), sp[1], false)
		}
	}

	for marker := range guideBlockExclusions {
		if !seenExclusion[marker] {
			t.Errorf("guideBlockExclusions marker %q matches no example; remove the entry", marker)
		}
	}
	for marker := range guideElisions {
		if !seenElision[marker] {
			t.Errorf("guideElisions marker %q matches no example; remove the entry", marker)
		}
	}
	// The guide has at least the notification, the token entries and the
	// traffic and audit examples. Fewer means the scan lost them.
	const minValidated = 5
	t.Logf("validated %d server.json examples of %s", validated, guideAdminPath)
	if validated < minValidated {
		t.Errorf("validated %d server.json examples, want at least %d; the scan of the guide is broken", validated, minValidated)
	}
}

// TestGuide61DefaultsMatchLoader compares the Default column of section 6.1
// with the value that the loader gives for a minimal configuration, for every
// row whose default is a plain value. The five keys that have a default are
// required, so a changed table cannot drop them silently.
func TestGuide61DefaultsMatchLoader(t *testing.T) {
	rows := guideTableRows(guideSection(t, guideLines(t), guideSection61))
	minimal, err := Parse(buildServerConfig(t, map[string]json.RawMessage{}))
	if err != nil {
		t.Fatalf("minimal configuration does not load: %v", err)
	}
	v := reflect.ValueOf(minimal)
	typ := v.Type()
	loaderValue := map[string]string{}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		loaderValue[name] = fmt.Sprint(v.Field(i).Interface())
	}

	want := map[string]bool{
		"listen":              true,
		"allow_remote_listen": true,
		"discovery_dir":       true,
		"pve_spool_dir":       true,
		"audit_hash_chain":    true,
	}
	checked := map[string]bool{}
	for _, r := range rows {
		if !r.hasDef {
			continue
		}
		got, ok := loaderValue[r.key]
		if !ok {
			continue // not a loader key; TestGuide61TableListsEveryConfigKey reports it
		}
		checked[r.key] = true
		if r.def != got {
			t.Errorf("guide 6.1 default for %q is %q, the loader gives %q for a minimal configuration (guide line: %s)", r.key, r.def, got, r.line)
		}
	}
	for k := range want {
		if !checked[k] {
			t.Errorf("guide 6.1 has no plain default for %q; the table changed or the key lost its default", k)
		}
	}
}
