// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// These tests read docs/admin/guide.md (read only) and check the
// server.json documentation against the strict loader in config.go. They
// do not repeat the key list: the keys come from the json tags of Config,
// read with reflect, and the required and defaulted keys come from the
// loader itself (Parse). A key that the guide leaves out, a default that the
// loader does not give, or an example with a misspelled key fails here
// instead of at the admin's server start.

// guideAdminPath is the admin guide, relative to this package directory
// (go test runs there), as internal/docsembed/guide_test.go resolves it.
const guideAdminPath = "../../docs/admin/guide.md"

// guideSection61 is the heading of the table of server.json keys.
const guideSection61 = "### 6.1 "

// guideRequired is the Default cell of a key the loader requires.
const guideRequired = "(required)"

// guideServerSections are the heading prefixes of the guide sections whose
// JSON and inline examples are server.json examples. Every top-level key in
// them must be a loader key, so a misspelled key fails even when no other
// server key appears in the example.
var guideServerSections = []string{
	"### 6.1 ",  // configuration reference
	"### 9.9 ",  // traffic map: "traffic": {"retention_days": N}
	"### 10.1 ", // notifications
	"### 10.2 ", // read-only API
}

// guideNearMissDistance is the edit distance at which a top-level key of an
// example counts as a misspelled server key, wherever the example is.
const guideNearMissDistance = 2

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

// guideNestedSpans maps inline spans that are members of a nested server.json
// object to the dotted path of that object. They have no top-level key, so
// they are validated inside that path. The test fails if one of them no
// longer occurs in the guide.
var guideNestedSpans = map[string]string{
	`"enabled": true`:    "notifications.daily_digest",
	`"skip_empty": true`: "notifications.daily_digest",
}

// guideProviderFill is the provider that a nested notifications example gets
// in the test document, because an enabled daily digest needs a provider.
const guideProviderFill = `{"url": "https://ntfy.sh", "topic": "nebula-alerts"}`

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
// TestGuide61DefaultsMatchLoader checks that this is exactly the set of keys
// that the loader requires.
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
	guideRangeRe       = regexp.MustCompile(`\((\d+)-(\d+)\)`)
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

// guideHeadingAt returns the nearest heading above the 1-based line, outside
// code fences, or "" when there is none.
func guideHeadingAt(lines []string, line int) string {
	heading := ""
	inFence := false
	for i := 0; i < line-1 && i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "```") {
			inFence = !inFence
			continue
		}
		if !inFence && headingLevel(lines[i]) > 0 {
			heading = lines[i]
		}
	}
	return heading
}

// guideInServerSection reports whether an example under heading is a
// server.json example (see guideServerSections).
func guideInServerSection(heading string) bool {
	for _, p := range guideServerSections {
		if strings.HasPrefix(heading, p) {
			return true
		}
	}
	return false
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

// guideRow is one row of a Markdown table. cells holds every cell, trimmed;
// cells[0] is the key, cells[1] the default and cells[2] the meaning.
type guideRow struct {
	key   string
	cells []string
	line  string
}

// def returns the Default cell, or "" when the row has none.
func (r guideRow) def() string {
	if len(r.cells) < 2 {
		return ""
	}
	return r.cells[1]
}

// meaning returns the Meaning cell, or "" when the row has none.
func (r guideRow) meaning() string {
	if len(r.cells) < 3 {
		return ""
	}
	return r.cells[2]
}

// plainDefault returns the Default cell without its backticks, and false when
// the cell is not a backticked value.
func (r guideRow) plainDefault() (string, bool) {
	d := r.def()
	if len(d) >= 2 && strings.HasPrefix(d, "`") && strings.HasSuffix(d, "`") {
		return d[1 : len(d)-1], true
	}
	return "", false
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
		rows = append(rows, guideRow{key: strings.Trim(cells[0], "`"), cells: cells, line: line})
	}
	return rows
}

// guideRowsByKey indexes table rows by key. A duplicate key keeps its first
// row; TestGuide61TableListsEveryConfigKey reports the duplicate.
func guideRowsByKey(rows []guideRow) map[string]guideRow {
	byKey := map[string]guideRow{}
	for _, r := range rows {
		if _, ok := byKey[r.key]; !ok {
			byKey[r.key] = r
		}
	}
	return byKey
}

// configField is one top-level key of Config: its json name, its Go kind and
// its index in the struct.
type configField struct {
	name  string
	kind  reflect.Kind
	index int
}

// configFields returns the top-level fields of Config, read with reflect.
func configFields(t *testing.T) []configField {
	t.Helper()
	var fields []configField
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			t.Fatalf("Config.%s has no json name; the guide test needs one", f.Name)
		}
		fields = append(fields, configField{name: name, kind: f.Type.Kind(), index: i})
	}
	return fields
}

// configTopLevelKeys returns the json names of the top-level Config fields.
func configTopLevelKeys(t *testing.T) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	for _, f := range configFields(t) {
		keys[f.name] = true
	}
	return keys
}

// sortedKeys returns the keys of m in order, for stable test output.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
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

// guideJSONLooking reports whether an example is written as JSON: an object,
// or a member list such as "key": value. Such an example must parse.
func guideJSONLooking(text string) bool {
	s := strings.TrimSpace(text)
	return strings.HasPrefix(s, "{") || (strings.HasPrefix(s, `"`) && strings.Contains(s, `":`))
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

// editDistance returns the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// isServerExample reports whether an example is a server.json example outside
// the server sections: it has a server key, a key one edit away from a server
// key (a misspelling), or it is a token entry of api.tokens.
func isServerExample(m map[string]json.RawMessage, cfg map[string]bool) bool {
	if _, ok := m["sha256"]; ok {
		return true
	}
	for k := range m {
		if cfg[k] {
			return true
		}
		for c := range cfg {
			if editDistance(k, c) <= guideNearMissDistance {
				return true
			}
		}
	}
	return false
}

// buildServerConfigAt returns the document the server would read for an
// example: the minimal required fields, plus the example's members. With a
// nested path the members sit at that path (and a notifications path gets a
// provider). An example that is a token entry (it has "sha256") is placed
// into api.tokens, because the guide shows token entries on their own.
func buildServerConfigAt(t *testing.T, path []string, m map[string]json.RawMessage) []byte {
	t.Helper()
	doc := map[string]any{}
	for k, v := range guideMinimalFields {
		doc[k] = v
	}
	switch {
	case len(path) > 0:
		var inner any = m
		for i := len(path) - 1; i >= 0; i-- {
			inner = map[string]any{path[i]: inner}
		}
		for k, v := range inner.(map[string]any) {
			doc[k] = v
		}
		if path[0] == "notifications" {
			doc["notifications"].(map[string]any)["ntfy"] = json.RawMessage(guideProviderFill)
		}
	case hasKey(m, "sha256"):
		entry, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal token entry: %v", err)
		}
		doc["api"] = map[string]any{"enabled": true, "tokens": []json.RawMessage{entry}}
	default:
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

// buildServerConfig is buildServerConfigAt for a top-level example.
func buildServerConfig(t *testing.T, m map[string]json.RawMessage) []byte {
	t.Helper()
	return buildServerConfigAt(t, nil, m)
}

// hasKey reports whether m has the key.
func hasKey(m map[string]json.RawMessage, key string) bool {
	_, ok := m[key]
	return ok
}

// guideMinimalDoc returns the minimal server.json without the key omit (pass
// "" to keep all of them).
func guideMinimalDoc(t *testing.T, omit string) []byte {
	t.Helper()
	doc := map[string]any{}
	for k, v := range guideMinimalFields {
		if k != omit {
			doc[k] = v
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal minimal server.json: %v", err)
	}
	return out
}

// TestGuideServerJSONExamplesParseStrictly sends every JSON example of the
// admin guide that is a server.json example through Parse, the strict loader
// that the server uses at start (unknown keys and trailing data are errors).
// An example is a server.json example when it is in a server section
// (guideServerSections), has a server key, has a key one edit away from one,
// or is a token entry of api.tokens. Examples are fenced or indented blocks
// and inline code spans. JSON-looking examples must parse. The examples are
// completed with the minimal required fields and the placeholders replaced
// from guidePlaceholders first.
func TestGuideServerJSONExamplesParseStrictly(t *testing.T) {
	lines := guideLines(t)
	cfg := configTopLevelKeys(t)
	validated := 0
	seenExclusion := map[string]bool{}
	seenElision := map[string]bool{}
	seenNested := map[string]bool{}

	check := func(where, text string, mustParse, inScope bool, nestPath []string) {
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
			if mustParse || guideJSONLooking(text) {
				t.Errorf("%s: JSON example does not parse: %v", where, err)
			}
			return
		}
		if nestPath != nil {
			if _, err := Parse(buildServerConfigAt(t, nestPath, m)); err != nil {
				t.Errorf("%s: example under %s does not pass the strict loader: %v", where, strings.Join(nestPath, "."), err)
				return
			}
			validated++
			return
		}
		if !inScope && !isServerExample(m, cfg) {
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
		inScope := guideInServerSection(guideHeadingAt(lines, b.line))
		check(where, b.body, b.fenced && b.info == "json", inScope, nil)
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
		inScope := guideInServerSection(guideHeadingAt(lines, i+1))
		for _, sp := range guideInlineSpanRe.FindAllStringSubmatch(line, -1) {
			text := sp[1]
			if !strings.HasPrefix(text, `"`) {
				continue
			}
			var nestPath []string
			if p, ok := guideNestedSpans[text]; ok {
				seenNested[text] = true
				nestPath = strings.Split(p, ".")
			}
			check(fmt.Sprintf("%s:%d (inline example %s)", guideAdminPath, i+1, text), text, false, inScope, nestPath)
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
	for span := range guideNestedSpans {
		if !seenNested[span] {
			t.Errorf("guideNestedSpans names %q, which is no inline example of the guide; remove the entry", span)
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

// guideProseDefaults checks the Default cell of a struct-valued key, which is
// prose and not a plain value. Every struct-valued Config key needs an entry;
// the test fails for a key without one.
var guideProseDefaults = map[string]func(t *testing.T, loaded Config, row guideRow){
	"traffic": guideCheckTrafficDefault,
	"notifications": func(t *testing.T, loaded Config, row guideRow) {
		t.Helper()
		if row.def() != "none" {
			t.Errorf("guide 6.1 default for notifications is %q, want \"none\" (guide line: %s)", row.def(), row.line)
		}
		if loaded.Notifications.providerCount() != 0 || loaded.Notifications.DailyDigest.Enabled {
			t.Errorf("guide 6.1 says notifications default to none, but the minimal configuration enables a provider or the daily digest")
		}
	},
	"api": func(t *testing.T, loaded Config, row guideRow) {
		t.Helper()
		if row.def() != "disabled" {
			t.Errorf("guide 6.1 default for api is %q, want \"disabled\" (guide line: %s)", row.def(), row.line)
		}
		if loaded.API.Enabled {
			t.Errorf("guide 6.1 says the api default is disabled, but the minimal configuration enables it")
		}
	},
	"trusted_proxies": func(t *testing.T, loaded Config, row guideRow) {
		t.Helper()
		guideCheckEmptyListDefault(t, "trusted_proxies", loaded.TrustedProxies, row)
	},
	"trusted_proxy_networks": func(t *testing.T, loaded Config, row guideRow) {
		t.Helper()
		guideCheckEmptyListDefault(t, "trusted_proxy_networks", loaded.TrustedProxyNetworks, row)
	},
}

// guideCheckEmptyListDefault checks a list key whose guide default is the
// empty list `[]`, against the loaded minimal configuration.
func guideCheckEmptyListDefault(t *testing.T, key string, loaded []string, row guideRow) {
	t.Helper()
	if got, plain := row.plainDefault(); !plain || got != "[]" {
		t.Errorf("guide 6.1 default for %s is %q, want `[]` (guide line: %s)", key, row.def(), row.line)
	}
	if len(loaded) != 0 {
		t.Errorf("guide 6.1 says %s defaults to [], but the minimal configuration loads %v", key, loaded)
	}
}

// guideCheckTrafficDefault compares the traffic row with the loader: the
// default must be the loader's effective retention in days, and the allowed
// range (lo-hi) in the Meaning cell must match the loader's boundaries.
func guideCheckTrafficDefault(t *testing.T, loaded Config, row guideRow) {
	t.Helper()
	want := fmt.Sprintf("%d days", loaded.Traffic.EffectiveRetentionDays())
	if row.def() != want {
		t.Errorf("guide 6.1 default for traffic is %q, the loader gives %q (guide line: %s)", row.def(), want, row.line)
	}
	m := guideRangeRe.FindStringSubmatch(row.meaning())
	if m == nil {
		t.Errorf("guide 6.1 traffic row does not give the allowed range as (lo-hi) (guide line: %s)", row.line)
		return
	}
	lo, errLo := strconv.Atoi(m[1])
	hi, errHi := strconv.Atoi(m[2])
	if errLo != nil || errHi != nil {
		t.Errorf("guide 6.1 traffic range %q is not two integers (guide line: %s)", m[0], row.line)
		return
	}
	if hi != DefaultTrafficRetentionDays {
		t.Errorf("guide 6.1 traffic range upper bound is %d, the loader's is %d", hi, DefaultTrafficRetentionDays)
	}
	for _, tc := range []struct {
		days int
		ok   bool
	}{{lo - 1, false}, {lo, true}, {hi, true}, {hi + 1, false}} {
		raw := json.RawMessage(fmt.Sprintf(`{"retention_days": %d}`, tc.days))
		_, err := Parse(buildServerConfig(t, map[string]json.RawMessage{"traffic": raw}))
		if (err == nil) != tc.ok {
			t.Errorf("guide 6.1 range is %d-%d; the loader gives an error for retention_days %d = %v, want error = %v", lo, hi, tc.days, err != nil, !tc.ok)
		}
	}
}

// TestGuide61DefaultsMatchLoader derives the required and the defaulted keys
// from the loader, and compares the Default column of section 6.1 with them:
// a key the loader requires must say "(required)" and be in
// guideMinimalFields; a scalar key with a default must have a backticked
// value equal to the loader's value for a minimal configuration; a
// struct-valued key must pass its check in guideProseDefaults. No key is
// listed by hand here, so a new key is covered as soon as it is in Config.
func TestGuide61DefaultsMatchLoader(t *testing.T) {
	rows := guideRowsByKey(guideTableRows(guideSection(t, guideLines(t), guideSection61)))
	fields := configFields(t)
	loaded, err := Parse(guideMinimalDoc(t, ""))
	if err != nil {
		t.Fatalf("minimal configuration does not load: %v", err)
	}
	loadedValues := reflect.ValueOf(loaded)

	// A key is required when the loader rejects the minimal configuration
	// without it. A key that is not in guideMinimalFields leaves the minimal
	// configuration unchanged, so it is never reported as required here.
	required := map[string]bool{}
	for _, f := range fields {
		if _, err := Parse(guideMinimalDoc(t, f.name)); err != nil {
			required[f.name] = true
		}
	}
	for _, k := range sortedKeys(required) {
		if _, ok := guideMinimalFields[k]; !ok {
			t.Errorf("the loader requires %q, but guideMinimalFields does not give it; add it", k)
		}
	}
	for _, k := range sortedKeys(guideMinimalFields) {
		if !required[k] {
			t.Errorf("guideMinimalFields gives %q, which the loader does not require; remove it", k)
		}
	}

	known := map[string]bool{}
	for _, f := range fields {
		known[f.name] = true
	}
	for k := range guideProseDefaults {
		if !known[k] {
			t.Errorf("guideProseDefaults names %q, which is not a Config key; remove the entry", k)
		}
	}

	for _, f := range fields {
		if _, ok := guideConfigKeysUndocumented[f.name]; ok {
			continue
		}
		row, ok := rows[f.name]
		if !ok {
			continue // TestGuide61TableListsEveryConfigKey reports the missing row
		}
		if required[f.name] {
			if row.def() != guideRequired {
				t.Errorf("guide 6.1 default for %q is %q, but the loader requires the key; the cell must be %s (guide line: %s)", f.name, row.def(), guideRequired, row.line)
			}
			continue
		}
		if row.def() == guideRequired {
			t.Errorf("guide 6.1 says %q is %s, but the loader gives it a default (guide line: %s)", f.name, guideRequired, row.line)
			continue
		}
		switch f.kind {
		case reflect.String, reflect.Bool:
			want := fmt.Sprint(loadedValues.Field(f.index).Interface())
			got, plain := row.plainDefault()
			switch {
			case !plain:
				t.Errorf("guide 6.1 default for %q must be a backticked value, the loader gives %q (guide line: %s)", f.name, want, row.line)
			case got != want:
				t.Errorf("guide 6.1 default for %q is %q, the loader gives %q for a minimal configuration (guide line: %s)", f.name, got, want, row.line)
			}
		default:
			check, ok := guideProseDefaults[f.name]
			if !ok {
				t.Errorf("guide 6.1 default for %q is not a plain value, and guideProseDefaults has no check for it", f.name)
				continue
			}
			check(t, loaded, row)
		}
	}
}
