// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"encoding/hex"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
)

// recordSender captures the events it is asked to send.
type recordSender struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordSender) Name() string { return "record" }

func (r *recordSender) Send(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func opsChange() OpsAgentSettingsChange {
	old := opsconfig.Settings{Enabled: true, BaseURL: "http://10.0.0.20:11434/v1", Model: "qwen3.5-9b",
		DataClass: opsconfig.DataClassLab, Language: opsconfig.LanguageDE, Instructions: "secret-free but private text"}
	next := old
	next.DataClass = opsconfig.DataClassExternal
	return OpsAgentSettingsChange{Old: old, New: next, OldVersion: 4, NewVersion: 5}
}

func TestOpsAgentEventCarriesDataClassChangeAndVersions(t *testing.T) {
	at := time.Unix(1791960000, 0)
	e := OpsAgentSettingsEvent(opsChange(), at)
	if KindOpsAgentSettingsChanged != "opsagent.settings_changed" {
		t.Fatalf("kind constant = %q", KindOpsAgentSettingsChanged)
	}
	if e.Kind != KindOpsAgentSettingsChanged {
		t.Fatalf("kind = %q", e.Kind)
	}
	for _, want := range []string{
		"The ops agent settings were changed.",
		"Version 4 -> 5.",
		"data_class: lab -> external",
	} {
		if !strings.Contains(e.Reason, want) {
			t.Errorf("reason %q lacks %q", e.Reason, want)
		}
	}
	if strings.Contains(e.Reason, "enabled:") || strings.Contains(e.Reason, "model:") {
		t.Errorf("reason lists unchanged fields: %q", e.Reason)
	}
	if !e.Time.Equal(at) {
		t.Errorf("time = %v, want %v", e.Time, at)
	}
}

func TestOpsAgentEventShowsFullURLAndModelOnChange(t *testing.T) {
	c := opsChange()
	c.New.BaseURL = "http://10.0.0.21:11434/v1"
	c.New.Model = "llama3.1-8b"
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	for _, want := range []string{"base_url: http://10.0.0.20:11434/v1 -> http://10.0.0.21:11434/v1", "model: qwen3.5-9b -> llama3.1-8b"} {
		if !strings.Contains(e.Reason, want) {
			t.Errorf("reason %q lacks %q", e.Reason, want)
		}
	}
}

func TestOpsAgentEventNeverCarriesInstructionText(t *testing.T) {
	c := opsChange()
	c.New.Instructions = "Prefer Debian trackers; token=abc123"
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	if strings.Contains(e.Reason, "token=abc123") || strings.Contains(e.Text(), "Prefer Debian") {
		t.Fatalf("operator instruction text leaked into the event: %q", e.Reason)
	}
	if !strings.Contains(e.Reason, "operator_instructions: changed (") {
		t.Errorf("reason %q does not report the instruction change by size", e.Reason)
	}
}

func TestNotifyOpsAgentSettingsChangedSendsOnce(t *testing.T) {
	var rec recordSender
	n := NewWithSenders(quiet(), nil, &rec)
	if got := n.NotifyOpsAgentSettingsChanged(context.Background(), opsChange(), time.Unix(1, 0)); got != 1 {
		t.Fatalf("delivered to %d providers, want 1", got)
	}
	if len(rec.events) != 1 || rec.events[0].Kind != KindOpsAgentSettingsChanged {
		t.Fatalf("events = %+v", rec.events)
	}
}

// Every settings field of the event has its own change line: enabled,
// allow_plain_http and language were not covered before.
func TestOpsAgentEventShowsEnabledPlainHTTPAndLanguageChanges(t *testing.T) {
	c := opsChange()
	c.New.Enabled = false
	c.New.AllowPlainHTTP = true
	c.New.Language = opsconfig.LanguageEN
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	for _, want := range []string{"enabled: true -> false", "allow_plain_http: false -> true", "language: de -> en"} {
		if !strings.Contains(e.Reason, want) {
			t.Errorf("reason %q lacks %q", e.Reason, want)
		}
	}
}

// An unchanged field gets no line.
func TestOpsAgentEventOmitsUnchangedFieldLines(t *testing.T) {
	c := opsChange()
	c.New.Enabled = false
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	for _, bad := range []string{"allow_plain_http:", "language:", "base_url:", "model:"} {
		if strings.Contains(e.Reason, bad) {
			t.Errorf("reason lists unchanged field %q: %q", bad, e.Reason)
		}
	}
}

// longURL returns a URL of the maximum settings length (512 bytes) that
// differs from every other longURL only in its last byte.
func longURL(last byte) string {
	const prefix = "https://ollama.lab.example/"
	return prefix + strings.Repeat("p", opsconfig.MaxBaseURL-len(prefix)-1) + string(last)
}

// longModel returns a model name of the maximum settings length (128 bytes)
// that differs from every other longModel only in its last byte.
func longModel(last byte) string {
	const prefix = "llama-"
	return prefix + strings.Repeat("m", opsconfig.MaxModel-len(prefix)-1) + string(last)
}

// worstChange is the largest allowed change of every field: maximum-length
// model and base URLs, and the largest int64 versions. Its fields are the
// ones opsAgentFieldMask flips.
func worstChange() OpsAgentSettingsChange {
	c := opsChange()
	c.OldVersion, c.NewVersion = math.MaxInt64-1, math.MaxInt64
	c.Old.Model, c.New.Model = longModel('1'), longModel('2')
	c.Old.BaseURL, c.New.BaseURL = longURL('1'), longURL('2')
	c.Old.Instructions, c.New.Instructions = "a", "a"
	return c
}

// changeWithMask returns worstChange with the fields selected by mask
// changed: bit 0 data_class, 1 model, 2 base_url, 3 enabled,
// 4 allow_plain_http, 5 language, 6 operator_instructions.
func changeWithMask(mask int) OpsAgentSettingsChange {
	c := worstChange()
	if mask&1 != 0 {
		c.New.DataClass = opsconfig.DataClassExternal
	}
	if mask&2 != 0 {
		c.New.Model = longModel('2')
	}
	if mask&4 != 0 {
		c.New.BaseURL = longURL('2')
	}
	if mask&8 != 0 {
		c.New.Enabled = false
	}
	if mask&16 != 0 {
		c.New.AllowPlainHTTP = true
	}
	if mask&32 != 0 {
		c.New.Language = opsconfig.LanguageEN
	}
	if mask&64 != 0 {
		c.New.Instructions = strings.Repeat("x", opsconfig.MaxInstructions)
	}
	return c
}

// Two 512-byte base URLs, a data class change and a model change must all
// fit into the reason: the notifier cuts the reason at maxField runes, and
// ADR 0016 D12 uses this event for out-of-NOS detection.
func TestOpsAgentEventKeepsSecurityFieldsWithLongURLs(t *testing.T) {
	c := opsChange()
	c.Old.BaseURL = longURL('1')
	c.New.BaseURL = longURL('2')
	c.New.Model = "llama3.1-8b"
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	if n := utf8.RuneCountInString(e.Reason); n > maxField {
		t.Fatalf("reason has %d runes, more than the cap of %d: %q", n, maxField, e.Reason)
	}
	if got := clean(e.Reason, maxField); got != e.Reason {
		t.Fatalf("reason is cut by the notifier's cap:\n got %q\nwant %q", got, e.Reason)
	}
	oldShort, newShort := opsAgentURLShort(c.Old.BaseURL, opsAgentURLLimit), opsAgentURLShort(c.New.BaseURL, opsAgentURLLimit)
	if oldShort == newShort {
		t.Fatalf("short forms of two different URLs are equal: %q", oldShort)
	}
	for _, want := range []string{
		"Version 4 -> 5.",
		"Changed: data_class, model, base_url.",
		"data_class: lab -> external",
		"model: qwen3.5-9b -> llama3.1-8b",
		"base_url: " + oldShort + " -> " + newShort,
	} {
		if !strings.Contains(e.Reason, want) {
			t.Errorf("reason %q lacks %q", e.Reason, want)
		}
	}
}

// Every combination of changed fields, with maximum-length values, must keep
// the security values (data_class, model, base_url) in the part of the reason
// the notifier keeps. The Changed list may be cut; the values may not.
func TestOpsAgentEventEveryFieldCombinationKeepsSecurityValues(t *testing.T) {
	for mask := 0; mask < 1<<7; mask++ {
		c := changeWithMask(mask)
		e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
		kept := clean(e.Reason, maxField)
		var want []string
		if mask&1 != 0 {
			want = append(want, "data_class: lab -> external")
		}
		if mask&2 != 0 {
			want = append(want, "model: "+opsAgentShortValue(c.Old.Model, opsAgentModelLimit)+" -> "+opsAgentShortValue(c.New.Model, opsAgentModelLimit))
		}
		if mask&4 != 0 {
			want = append(want, "base_url: "+opsAgentURLShort(c.Old.BaseURL, opsAgentURLLimit)+" -> "+opsAgentURLShort(c.New.BaseURL, opsAgentURLLimit))
		}
		for _, w := range want {
			if !strings.Contains(kept, w) {
				t.Errorf("mask %07b: kept reason %q lacks %q", mask, kept, w)
			}
		}
	}
}

// The worst case of the security fields: a 128-byte model and a 512-byte base
// URL, both changed, with the largest int64 versions, and data_class changed
// too (mask 7). The security values must fit in the part the notifier keeps,
// and must tell the old and new value apart. The Changed list at the end may
// be cut by the cap; it is not part of this check.
func TestOpsAgentEventWorstCaseFitsCap(t *testing.T) {
	c := changeWithMask(7)
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	head, _, _ := strings.Cut(e.Reason, " Changed: ")
	if n := utf8.RuneCountInString(head); n > maxField {
		t.Fatalf("worst-case security part has %d runes, more than the cap of %d: %q", n, maxField, head)
	}
	kept := clean(e.Reason, maxField)
	oldModel, newModel := opsAgentShortValue(c.Old.Model, opsAgentModelLimit), opsAgentShortValue(c.New.Model, opsAgentModelLimit)
	oldURL, newURL := opsAgentURLShort(c.Old.BaseURL, opsAgentURLLimit), opsAgentURLShort(c.New.BaseURL, opsAgentURLLimit)
	if oldModel == newModel || oldURL == newURL {
		t.Fatalf("short forms of different values are equal: model %q, url %q", oldModel, oldURL)
	}
	for _, want := range []string{
		"Version 9223372036854775806 -> 9223372036854775807.",
		"data_class: lab -> external",
		"model: " + oldModel + " -> " + newModel,
		"base_url: " + oldURL + " -> " + newURL,
	} {
		if !strings.Contains(kept, want) {
			t.Errorf("worst-case reason kept by the cap %q lacks %q", kept, want)
		}
	}
}

// Every settings field changed at once: the security values come first and
// must survive the notifier's cap in full; the tail (the Changed list and the
// non-security lines) may be cut.
func TestOpsAgentEventAllFieldsChangedKeepsSecurityFirst(t *testing.T) {
	c := changeWithMask(127)
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	if !strings.Contains(e.Reason, "Changed: data_class, model, base_url, enabled, allow_plain_http, language, operator_instructions.") {
		t.Errorf("reason %q lacks the full changed list", e.Reason)
	}
	kept := clean(e.Reason, maxField)
	oldModel, newModel := opsAgentShortValue(c.Old.Model, opsAgentModelLimit), opsAgentShortValue(c.New.Model, opsAgentModelLimit)
	oldURL, newURL := opsAgentURLShort(c.Old.BaseURL, opsAgentURLLimit), opsAgentURLShort(c.New.BaseURL, opsAgentURLLimit)
	for _, want := range []string{
		"data_class: lab -> external",
		"model: " + oldModel + " -> " + newModel,
		"base_url: " + oldURL + " -> " + newURL,
	} {
		if !strings.Contains(kept, want) {
			t.Errorf("reason kept by the cap %q lacks %q", kept, want)
		}
	}
	// The new destination's host must be visible in the kept part.
	if !strings.Contains(kept, "ollama.lab.example") {
		t.Errorf("reason kept by the cap %q hides the new destination's host", kept)
	}
}

// A destination whose host is longer than the budget must not be shown as
// a lookalike prefix: the registrable domain at the end of the host stays
// visible, and the digest covers the whole value.
func TestOpsAgentURLShortShowsHostEndNotLookalikePrefix(t *testing.T) {
	const legit = "https://llm.internal.example.org/v1/chat/completions/with/a/long/path"
	const hostile = "https://llm.internal.example.org.attacker.net/v1/chat/completions/with/a/long/path"
	got := opsAgentURLShort(hostile, opsAgentURLLimit)
	if !strings.Contains(got, "attacker.net") {
		t.Fatalf("hostile destination hides its registrable domain: %q", got)
	}
	if strings.HasPrefix(got, "https://llm.internal.example.org") {
		t.Fatalf("hostile destination looks like the legit one: %q", got)
	}
	if opsAgentURLShort(legit, opsAgentURLLimit) == got {
		t.Fatalf("legit and hostile destinations have the same short form: %q", got)
	}
}

// A host that fits the budget is shown whole with scheme, followed by the
// cut mark and the digest of the whole value.
func TestOpsAgentURLShortKeepsSchemeAndWholeHost(t *testing.T) {
	const url = "https://ollama.lab.example/" + "p/p/p/p/p/p/p/p/p/p/p/p/p/p/p/p/p/p/p"
	got := opsAgentURLShort(url, opsAgentURLLimit)
	if !strings.HasPrefix(got, "https://ollama.lab.example…#") {
		t.Fatalf("short form %q does not keep scheme and whole host", got)
	}
	cutDigest(t, got)
}

// cutDigest returns the digest after the last cut mark of a short value and
// checks it is a 64-bit (16 hex digit) digest.
func cutDigest(t *testing.T, short string) string {
	t.Helper()
	i := strings.LastIndex(short, opsAgentCutMark)
	if i < 0 {
		t.Fatalf("short value %q has no cut mark", short)
	}
	d := short[i+len(opsAgentCutMark):]
	if len(d) != 16 {
		t.Fatalf("digest %q has %d hex digits, want 16", d, len(d))
	}
	if _, err := hex.DecodeString(d); err != nil {
		t.Fatalf("digest %q is not hex: %v", d, err)
	}
	return d
}

// The shortener keeps a value whole when it fits the limit and otherwise
// keeps a prefix plus digest of exactly the limit (in runes), never invalid UTF-8.
func TestOpsAgentShortValueFitsLimit(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		limit int
		want  string // "" means: check prefix and digest form only
	}{
		{name: "model at limit whole", in: strings.Repeat("a", opsAgentModelLimit), limit: opsAgentModelLimit, want: strings.Repeat("a", opsAgentModelLimit)},
		{name: "data class whole", in: opsconfig.DataClassExternal, limit: opsAgentDataClassLimit, want: opsconfig.DataClassExternal},
		{name: "long model cut", in: longModel('x'), limit: opsAgentModelLimit},
		{name: "multibyte cut on rune boundary", in: strings.Repeat("ä", 100), limit: opsAgentModelLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := opsAgentShortValue(tt.in, tt.limit)
			if n := utf8.RuneCountInString(got); n > tt.limit {
				t.Fatalf("short value has %d runes, limit %d: %q", n, tt.limit, got)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("short value is not valid UTF-8: %q", got)
			}
			if tt.want != "" {
				if got != tt.want {
					t.Fatalf("got %q, want %q", got, tt.want)
				}
				return
			}
			cutDigest(t, got)
			if !strings.HasPrefix(tt.in, got[:strings.LastIndex(got, opsAgentCutMark)]) {
				t.Fatalf("cut value is not a prefix plus digest: %q", got)
			}
		})
	}
}

// URL short forms never exceed their budget, are valid UTF-8, and end in a
// 64-bit digest when cut.
func TestOpsAgentURLShortFitsLimit(t *testing.T) {
	for _, in := range []string{
		"http://10.0.0.20:11434/v1",
		longURL('x'),
		"https://ä.example/" + strings.Repeat("ö", 400),
		"not a url at all " + strings.Repeat("z", 400),
		"https://[::1",
	} {
		got := opsAgentURLShort(in, opsAgentURLLimit)
		if n := utf8.RuneCountInString(got); n > opsAgentURLLimit {
			t.Errorf("short URL %q has %d runes, limit %d", got, n, opsAgentURLLimit)
		}
		if !utf8.ValidString(got) {
			t.Errorf("short URL %q is not valid UTF-8", got)
		}
		if in != got {
			cutDigest(t, got)
		}
	}
}

// The digest is a function of the whole value: two long URLs that differ
// only in the last byte get different short forms.
func TestOpsAgentURLShortDigestTellsValuesApart(t *testing.T) {
	if a, b := opsAgentURLShort(longURL('1'), opsAgentURLLimit), opsAgentURLShort(longURL('2'), opsAgentURLLimit); a == b {
		t.Fatalf("short forms of different URLs are equal: %q", a)
	}
}

// TestOpsAgentBudgetsFitTheCap derives the budget from a built reason, not
// from constants: with every field changed and maximum-length values, the
// reason up to the first non-security line must fit the cap, so the security
// values are never cut. The check fails if the format or the field order
// changes.
func TestOpsAgentBudgetsFitTheCap(t *testing.T) {
	e := OpsAgentSettingsEvent(changeWithMask(127), time.Unix(1, 0))
	head, _, found := strings.Cut(e.Reason, "; enabled:")
	if !found {
		t.Fatalf("reason %q has no line after the security values", e.Reason)
	}
	if n := utf8.RuneCountInString(head); n > maxField {
		t.Fatalf("security part of the reason has %d runes, more than the cap of %d: %q", n, maxField, head)
	}
	for _, want := range []string{"data_class: lab -> external", "model: ", " -> ", "base_url: "} {
		if !strings.Contains(head, want) {
			t.Errorf("security part %q lacks %q", head, want)
		}
	}
}
