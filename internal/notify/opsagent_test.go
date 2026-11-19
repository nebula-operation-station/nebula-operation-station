// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
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
	oldShort, newShort := opsAgentShortValue(c.Old.BaseURL, opsAgentURLLimit), opsAgentShortValue(c.New.BaseURL, opsAgentURLLimit)
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

// The worst case of the allowed inputs: a 128-byte model and a 512-byte base
// URL, both changed, with the largest int64 versions. The reason must stay
// within the cap, so the notifier never cuts it, and every security field
// must be present with a value that tells the old and new value apart.
func TestOpsAgentEventWorstCaseFitsCap(t *testing.T) {
	c := opsChange()
	c.OldVersion, c.NewVersion = math.MaxInt64-1, math.MaxInt64
	c.Old.Model, c.New.Model = longModel('1'), longModel('2')
	c.Old.BaseURL, c.New.BaseURL = longURL('1'), longURL('2')
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	if n := utf8.RuneCountInString(e.Reason); n > maxField {
		t.Fatalf("worst-case reason has %d runes, more than the cap of %d: %q", n, maxField, e.Reason)
	}
	if got := clean(e.Reason, maxField); got != e.Reason {
		t.Fatalf("worst-case reason is cut by the notifier's cap:\n got %q\nwant %q", got, e.Reason)
	}
	oldModel, newModel := opsAgentShortValue(c.Old.Model, opsAgentModelLimit), opsAgentShortValue(c.New.Model, opsAgentModelLimit)
	oldURL, newURL := opsAgentShortValue(c.Old.BaseURL, opsAgentURLLimit), opsAgentShortValue(c.New.BaseURL, opsAgentURLLimit)
	if oldModel == newModel || oldURL == newURL {
		t.Fatalf("short forms of different values are equal: model %q, url %q", oldModel, oldURL)
	}
	for _, want := range []string{
		"Version 9223372036854775806 -> 9223372036854775807.",
		"Changed: data_class, model, base_url.",
		"data_class: lab -> external",
		"model: " + oldModel + " -> " + newModel,
		"base_url: " + oldURL + " -> " + newURL,
	} {
		if !strings.Contains(e.Reason, want) {
			t.Errorf("worst-case reason %q lacks %q", e.Reason, want)
		}
	}
}

// Every settings field changed at once: the security fields come first and
// must survive; the tail (non-security fields) may be cut by the cap.
func TestOpsAgentEventAllFieldsChangedKeepsSecurityFirst(t *testing.T) {
	c := opsChange()
	c.OldVersion, c.NewVersion = math.MaxInt64-1, math.MaxInt64
	c.Old.Model, c.New.Model = longModel('1'), longModel('2')
	c.Old.BaseURL, c.New.BaseURL = longURL('1'), longURL('2')
	c.New.Enabled = false
	c.New.AllowPlainHTTP = true
	c.New.Language = opsconfig.LanguageEN
	c.New.Instructions = strings.Repeat("x", opsconfig.MaxInstructions)
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	if !strings.Contains(e.Reason, "Changed: data_class, model, base_url, enabled, allow_plain_http, language, operator_instructions.") {
		t.Errorf("reason %q lacks the full changed list", e.Reason)
	}
	// Notify cleans the reason to maxField runes; the security fields must be in that part.
	kept := clean(e.Reason, maxField)
	for _, want := range []string{"data_class: lab -> external", "model: ", "base_url: "} {
		if !strings.Contains(kept, want) {
			t.Errorf("reason kept by the cap %q lacks security field %q", kept, want)
		}
	}
}

// A destination whose scheme and host fit the URL budget keeps them whole:
// a URL whose host is a prefix of another host must not look like it.
func TestOpsAgentEventKeepsDestinationHostPrefix(t *testing.T) {
	const legit = "https://llm.internal.example.org/v1"
	const hostile = "https://llm.internal.example.org.attacker.net/v1"
	if got := opsAgentShortValue(legit, opsAgentURLLimit); got != legit {
		t.Fatalf("short destination changed: %q", got)
	}
	got := opsAgentShortValue(hostile, opsAgentURLLimit)
	if !strings.HasPrefix(got, "https://llm.internal.example.org") {
		t.Fatalf("hostile destination lost its scheme and host prefix: %q", got)
	}
	if got == legit {
		t.Fatalf("hostile destination shows as the legit one: %q", got)
	}
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
		{name: "short URL whole", in: "http://10.0.0.20:11434/v1", limit: opsAgentURLLimit, want: "http://10.0.0.20:11434/v1"},
		{name: "model at limit whole", in: strings.Repeat("a", opsAgentModelLimit), limit: opsAgentModelLimit, want: strings.Repeat("a", opsAgentModelLimit)},
		{name: "long model cut", in: longModel('x'), limit: opsAgentModelLimit},
		{name: "long URL cut", in: longURL('x'), limit: opsAgentURLLimit},
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
			if !strings.Contains(got, "…#") || !strings.HasPrefix(tt.in, got[:strings.Index(got, "…#")]) {
				t.Fatalf("cut value is not a prefix plus digest: %q", got)
			}
		})
	}
}

// Every short value of a changed field must fit its budget, so the sum of
// the budgets plus the fixed text stays within maxField (see opsagent.go).
func TestOpsAgentBudgetsFitTheCap(t *testing.T) {
	const fixedWorst = 184 // fixed text, max-length versions and field lines, see opsagent.go
	if total := fixedWorst + 2*opsAgentModelLimit + 2*opsAgentURLLimit; total > maxField {
		t.Fatalf("budgets need %d runes, more than the cap of %d", total, maxField)
	}
}
