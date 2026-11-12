// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var integrityBase = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

// intRecorder keeps every event it is handed; ok selects whether it accepts.
type intRecorder struct {
	mu     sync.Mutex
	ok     bool
	events []Event
}

func (r *intRecorder) Name() string { return "intRecorder" }

func (r *intRecorder) Send(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ok {
		return errors.New("refused")
	}
	r.events = append(r.events, e)
	return nil
}

func (r *intRecorder) list() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// clock is an injected time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func validEvent(kind IntegrityKind) IntegrityEvent {
	return IntegrityEvent{Kind: kind, Host: "pve-01", Class: "binary", Severity: SeverityCritical, Count: 1,
		Link: "https://nos.example.net/integrity/findings/1"}
}

func newTestGate(t *testing.T, s ...Sender) (*IntegrityGate, *clock) {
	t.Helper()
	clk := &clock{t: integrityBase}
	n := NewWithSenders(quiet(), nil, s...)
	return NewIntegrityGate(n, clk.now), clk
}

var allIntegrityKinds = []IntegrityKind{IntegrityNOSMismatch, IntegrityHostChange, IntegrityScanIncomplete,
	IntegrityBaselineTamper, IntegrityReferenceConflict}

func TestIntegrityEventHasOnlyStructuredFields(t *testing.T) {
	// The type must not be able to carry a host-supplied path or content.
	want := []string{"Kind", "Host", "Class", "Severity", "Count", "Link"}
	var got []string
	typ := reflect.TypeOf(IntegrityEvent{})
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fields %v, want exactly %v", got, want)
	}
}

func TestIntegrityKindsSendInEveryChannel(t *testing.T) {
	var wc, nc, tc captured
	wsrv := wc.server(t, 204)
	nsrv := nc.server(t, 200)
	tsrv := tc.server(t, 200)
	n := NewWithSenders(quiet(), nil,
		&webhook{url: wsrv.URL, secret: []byte(secret), client: http.DefaultClient},
		&ntfy{url: nsrv.URL + "/nebula", client: http.DefaultClient},
		&telegram{base: tsrv.URL, token: botToken, chatID: "-100123", client: http.DefaultClient})
	clk := &clock{t: integrityBase}
	g := NewIntegrityGate(n, clk.now)
	for i, k := range allIntegrityKinds {
		d, err := g.Submit(context.Background(), validEvent(k), NewIntegrityKey("host-"+string(rune('a'+i)), "binary", "/usr/bin/nebula"))
		if err != nil || d != DecisionSent {
			t.Fatalf("%s: decision %v, err %v", k, d, err)
		}
	}
	if len(wc.body) != 5 || len(nc.body) != 5 || len(tc.body) != 5 {
		t.Fatalf("channels received %d/%d/%d, want 5 each", len(wc.body), len(nc.body), len(tc.body))
	}
	for i, k := range allIntegrityKinds {
		var p WebhookPayload
		if err := json.Unmarshal(wc.body[i], &p); err != nil {
			t.Fatal(err)
		}
		if p.Kind != string(k) || p.State != string(SeverityCritical) || p.Link != "https://nos.example.net/integrity/findings/1" {
			t.Fatalf("webhook %d: %+v", i, p)
		}
		if !strings.HasPrefix(string(nc.body[i]), "Nebula: integrity: ") || !strings.Contains(string(nc.body[i]), "State: critical") {
			t.Fatalf("ntfy %d: %q", i, nc.body[i])
		}
		if !strings.Contains(string(nc.body[i]), "https://nos.example.net/integrity/findings/1") {
			t.Fatalf("ntfy %d lacks the NOS link: %q", i, nc.body[i])
		}
		var msg map[string]any
		if err := json.Unmarshal(tc.body[i], &msg); err != nil {
			t.Fatal(err)
		}
		text, _ := msg["text"].(string)
		if !strings.Contains(text, "pve-01") || !strings.Contains(text, "Class: binary") || msg["parse_mode"] != nil {
			t.Fatalf("telegram %d: %q", i, text)
		}
	}
	if !strings.Contains(string(tc.body[0]), "NOS mismatch") || !strings.Contains(string(tc.body[4]), "reference conflict") {
		t.Fatalf("titles not per kind: %q / %q", tc.body[0], tc.body[4])
	}
}

func TestHostileHostLabelsAreNeutralized(t *testing.T) {
	cases := map[string]string{
		"markdown link": "[click here](https://evil.example/x)",
		"bare url":      "https://evil.example/login",
		"ansi escape":   "docker\x1b[2Jflux",
		"bidi override": "pve" + string(rune(0x202e)) + "01",
		"newline":       "pve-01\n\nState: OK",
		"mention":       "@everyone",
		"long":          strings.Repeat("h", 500),
	}
	for name, label := range cases {
		t.Run(name, func(t *testing.T) {
			var r intRecorder
			r.ok = true
			g, _ := newTestGate(t, &r)
			ev := validEvent(IntegrityHostChange)
			ev.Host = label
			if d, err := g.Submit(context.Background(), ev, NewIntegrityKey("s", "binary", "/p")); err != nil || d != DecisionSent {
				t.Fatalf("decision %v, err %v", d, err)
			}
			got := r.list()
			if len(got) != 1 {
				t.Fatalf("sent %d", len(got))
			}
			text := got[0].Text()
			if !strings.Contains(text, "Details: https://nos.example.net/integrity/findings/1") {
				t.Fatalf("NOS link lost: %q", text)
			}
			// The NOS link is ours and legitimately contains "://"; check the rest.
			rest := strings.Replace(text, "https://nos.example.net/integrity/findings/1", "", 1)
			for _, bad := range []string{"[", "](", "://", "\x1b", string(rune(0x202e)), "\n\n", "@everyone"} {
				if strings.Contains(rest, bad) {
					t.Fatalf("message contains %q: %q", bad, text)
				}
			}
			if len([]rune(got[0].Title())) > 120 || len(text) > 1000 {
				t.Fatalf("unbounded message: %d bytes", len(text))
			}
		})
	}
}

func TestRateLimitTenPerHourThenDigest(t *testing.T) {
	var r intRecorder
	r.ok = true
	g, clk := newTestGate(t, &r)
	ctx := context.Background()
	for i := 0; i < MaxIntegrityPerHour; i++ {
		d, err := g.Submit(ctx, validEvent(IntegrityNOSMismatch), NewIntegrityKey("s", "binary", string(rune('a'+i))))
		if err != nil || d != DecisionSent {
			t.Fatalf("message %d: %v %v", i, d, err)
		}
	}
	for i := 0; i < 2; i++ {
		ev := validEvent(IntegrityHostChange)
		d, err := g.Submit(ctx, ev, NewIntegrityKey("s", "binary", string(rune('x'+i))))
		if err != nil || d != DecisionHeld {
			t.Fatalf("11th/12th: %v %v", d, err)
		}
	}
	if n := len(r.list()); n != MaxIntegrityPerHour {
		t.Fatalf("%d sent inside the hour, want %d", n, MaxIntegrityPerHour)
	}
	// Still inside the hour: no digest yet.
	clk.t = integrityBase.Add(59 * time.Minute)
	if g.Flush(ctx) {
		t.Fatal("digest before the hour ended")
	}
	clk.t = integrityBase.Add(time.Hour)
	if !g.Flush(ctx) {
		t.Fatal("digest not sent after the hour")
	}
	got := r.list()
	last := got[len(got)-1]
	if last.Kind != KindIntegrityDigest || !strings.Contains(last.Reason, "2 integrity notifications") ||
		!strings.Contains(last.Reason, "integrity.host_change: 2") || strings.Contains(last.Text(), "/p") {
		t.Fatalf("digest %+v", last)
	}
	if g.Flush(ctx) {
		t.Fatal("second digest for the same counts")
	}
	// A new hour starts with a fresh limit.
	d, err := g.Submit(ctx, validEvent(IntegrityScanIncomplete), NewIntegrityKey("s", "binary", "/new"))
	if err != nil || d != DecisionSent {
		t.Fatalf("new hour: %v %v", d, err)
	}
}

func TestDigestIsSentBeforeTheNextMessageAfterTheHour(t *testing.T) {
	var r intRecorder
	r.ok = true
	g, clk := newTestGate(t, &r)
	ctx := context.Background()
	for i := 0; i <= MaxIntegrityPerHour; i++ {
		_, _ = g.Submit(ctx, validEvent(IntegrityNOSMismatch), NewIntegrityKey("s", "binary", string(rune('a'+i))))
	}
	clk.t = integrityBase.Add(time.Hour)
	if d, _ := g.Submit(ctx, validEvent(IntegrityNOSMismatch), NewIntegrityKey("s", "binary", "late")); d != DecisionSent {
		t.Fatalf("decision %v", d)
	}
	got := r.list()
	if len(got) != MaxIntegrityPerHour+2 || got[MaxIntegrityPerHour].Kind != KindIntegrityDigest {
		t.Fatalf("order wrong: %d events", len(got))
	}
}

func TestDedupePerSubjectClassPathAndKind(t *testing.T) {
	var r intRecorder
	r.ok = true
	g, _ := newTestGate(t, &r)
	ctx := context.Background()
	key := NewIntegrityKey("host-1", "binary", "/usr/bin/nebula-server")
	if d, _ := g.Submit(ctx, validEvent(IntegrityHostChange), key); d != DecisionSent {
		t.Fatalf("first: %v", d)
	}
	if d, _ := g.Submit(ctx, validEvent(IntegrityHostChange), key); d != DecisionDuplicate {
		t.Fatalf("repeat of same key and kind: %v", d)
	}
	// Same path, another event type: a separate episode.
	if d, _ := g.Submit(ctx, validEvent(IntegrityBaselineTamper), key); d != DecisionSent {
		t.Fatalf("other kind: %v", d)
	}
	// Other subject, other path, other class: all separate.
	for _, k := range []IntegrityKey{
		NewIntegrityKey("host-2", "binary", "/usr/bin/nebula-server"),
		NewIntegrityKey("host-1", "binary", "/usr/bin/nebula-server2"),
		NewIntegrityKey("host-1", "unit", "/usr/bin/nebula-server"),
	} {
		if d, _ := g.Submit(ctx, validEvent(IntegrityHostChange), k); d != DecisionSent {
			t.Fatalf("separate key: %v", d)
		}
	}
	if n := len(r.list()); n != 5 {
		t.Fatalf("sent %d, want 5", n)
	}
}

func TestDuplicatesDoNotUseTheHourlyLimit(t *testing.T) {
	var r intRecorder
	r.ok = true
	g, _ := newTestGate(t, &r)
	ctx := context.Background()
	key := NewIntegrityKey("s", "binary", "/p")
	for i := 0; i < 50; i++ {
		_, _ = g.Submit(ctx, validEvent(IntegrityHostChange), key)
	}
	if d, _ := g.Submit(ctx, validEvent(IntegrityHostChange), NewIntegrityKey("s", "binary", "/q")); d != DecisionSent {
		t.Fatalf("limit used by duplicates: %v", d)
	}
}

func TestUndeliveredReleasesSlotAndIsRetried(t *testing.T) {
	var r intRecorder
	g, _ := newTestGate(t, &r)
	ctx := context.Background()
	key := NewIntegrityKey("s", "binary", "/p")
	for i := 0; i < MaxIntegrityPerHour+3; i++ {
		d, err := g.Submit(ctx, validEvent(IntegrityNOSMismatch), NewIntegrityKey("s", "binary", string(rune('a'+i))))
		if err != nil || d != DecisionUndelivered {
			t.Fatalf("refused sink: %v %v", d, err)
		}
	}
	r.ok = true
	if d, _ := g.Submit(ctx, validEvent(IntegrityHostChange), key); d != DecisionSent {
		t.Fatalf("refused messages still hold the limit: %v", d)
	}
	// The undelivered key was not marked, so it may still be sent.
	if d, _ := g.Submit(ctx, validEvent(IntegrityNOSMismatch), NewIntegrityKey("s", "binary", "a")); d != DecisionSent {
		t.Fatalf("undelivered key treated as sent: %v", d)
	}
}

func TestFailedDigestKeepsItsCounts(t *testing.T) {
	r := intRecorder{ok: true}
	g, clk := newTestGate(t, &r)
	ctx := context.Background()
	for i := 0; i < MaxIntegrityPerHour+1; i++ {
		_, _ = g.Submit(ctx, validEvent(IntegrityNOSMismatch), NewIntegrityKey("s", "binary", string(rune('a'+i))))
	}
	clk.t = integrityBase.Add(time.Hour)
	r.ok = false
	if g.Flush(ctx) {
		t.Fatal("digest reported sent while the sink refuses")
	}
	r.ok = true
	if !g.Flush(ctx) {
		t.Fatal("digest not retried")
	}
	last := r.list()[MaxIntegrityPerHour]
	if last.Kind != KindIntegrityDigest || !strings.Contains(last.Reason, "1 integrity notification") {
		t.Fatalf("counts lost: %+v", last)
	}
}

func TestKeyHashesSubjectClassAndPath(t *testing.T) {
	a := NewIntegrityKey("ab", "c", "")
	if a == NewIntegrityKey("a", "bc", "") || a == NewIntegrityKey("ab", "", "c") {
		t.Fatal("field boundaries not part of the key")
	}
	if a != NewIntegrityKey("ab", "c", "") {
		t.Fatal("key not deterministic")
	}
	path := "/home/victim/.ssh/authorized_keys"
	k := NewIntegrityKey("host-1", "ssh", path)
	if strings.Contains(string(k[:]), path) {
		t.Fatal("key holds the path in clear")
	}
}

func TestInvalidEventsAreRejectedAndNotSent(t *testing.T) {
	cases := map[string]func(*IntegrityEvent){
		"unknown kind":     func(e *IntegrityEvent) { e.Kind = "integrity.something" },
		"vuln kind":        func(e *IntegrityEvent) { e.Kind = "vuln.kev_new" },
		"empty class":      func(e *IntegrityEvent) { e.Class = "" },
		"class with path":  func(e *IntegrityEvent) { e.Class = "/etc/passwd" },
		"class uppercase":  func(e *IntegrityEvent) { e.Class = "Binary" },
		"long class":       func(e *IntegrityEvent) { e.Class = strings.Repeat("a", 33) },
		"unknown severity": func(e *IntegrityEvent) { e.Severity = "urgent" },
		"negative count":   func(e *IntegrityEvent) { e.Count = -1 },
		"javascript link":  func(e *IntegrityEvent) { e.Link = "javascript:alert(1)" },
		"link with space":  func(e *IntegrityEvent) { e.Link = "https://nos.example.net/a b" },
		"link no host":     func(e *IntegrityEvent) { e.Link = "https:///x" },
		"long link":        func(e *IntegrityEvent) { e.Link = "https://nos.example.net/" + strings.Repeat("a", 600) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			var r intRecorder
			r.ok = true
			g, _ := newTestGate(t, &r)
			ev := validEvent(IntegrityNOSMismatch)
			mut(&ev)
			d, err := g.Submit(context.Background(), ev, NewIntegrityKey("s", "binary", "/p"))
			if !errors.Is(err, ErrInvalidIntegrityEvent) || d != DecisionNone {
				t.Fatalf("decision %v, err %v", d, err)
			}
			if len(r.list()) != 0 {
				t.Fatal("invalid event sent")
			}
		})
	}
}

func TestIntegrityTitlesPerKind(t *testing.T) {
	want := map[IntegrityKind]string{
		IntegrityNOSMismatch:       "Nebula: integrity: NOS mismatch on pve-01",
		IntegrityHostChange:        "Nebula: integrity: host change on pve-01",
		IntegrityScanIncomplete:    "Nebula: integrity: scan incomplete on pve-01",
		IntegrityBaselineTamper:    "Nebula: integrity: baseline tamper on pve-01",
		IntegrityReferenceConflict: "Nebula: integrity: reference conflict on pve-01",
	}
	for _, k := range allIntegrityKinds {
		if got := validEvent(k).message(integrityBase).Title(); got != want[k] {
			t.Fatalf("%s: title %q, want %q", k, got, want[k])
		}
	}
}
