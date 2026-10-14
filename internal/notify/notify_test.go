// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
)

const (
	secret   = "0123456789abcdef0123456789abcdef"
	botToken = "123456:ABCdefGHIjklMNOpqrSTUvwxYZ012345"
)

type captured struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (c *captured) server(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs = append(c.reqs, r)
		c.body = append(c.body, b)
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

var mismatch = Event{Kind: KindHostKeyMismatch, Host: "docker\x1b[2Jflux", State: "BLOCKED",
	Reason: "10.8.0.5:22 presented SHA256:new\ninjected line", Time: time.Unix(1791960000, 0)}

func TestWebhookIsSignedAndClean(t *testing.T) {
	var c captured
	srv := c.server(t, 204)
	n := New(serverconfig.Notifications{Webhook: &serverconfig.WebhookConfig{URL: srv.URL + "/hook", Secret: secret}}, nil, quiet())
	if n.Notify(context.Background(), mismatch) != 1 {
		t.Fatal("not sent")
	}
	r, body := c.reqs[0], c.body[0]
	if got, want := r.Header.Get("X-Nebula-Signature"), Sign([]byte(secret), r.Header.Get("X-Nebula-Timestamp"), body); got != want {
		t.Fatalf("signature %q, want %q", got, want)
	}
	if Sign([]byte(secret), "1", body) == Sign([]byte(secret), "2", body) {
		t.Fatal("timestamp not covered by the signature")
	}
	var p WebhookPayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Kind != KindHostKeyMismatch || strings.ContainsAny(p.Host+p.Reason, "\x1b\n") || !strings.HasSuffix(p.Time, "Z") {
		t.Fatalf("payload %+v", p)
	}
}

func TestNtfyAndTelegram(t *testing.T) {
	var nc, tc captured
	nsrv := nc.server(t, 200)
	tsrv := tc.server(t, 200)
	n := New(serverconfig.Notifications{Ntfy: &serverconfig.NtfyConfig{URL: nsrv.URL + "/", Topic: "nebula-ops", Token: "tk_abc"}}, nil, quiet())
	n.senders = append(n.senders, &telegram{base: tsrv.URL, token: botToken, chatID: "-100123", client: http.DefaultClient})
	if n.Notify(context.Background(), mismatch) != 2 {
		t.Fatal("not sent to both")
	}
	r := nc.reqs[0]
	if r.URL.Path != "/nebula-ops" || r.Header.Get("Priority") != "urgent" || r.Header.Get("Authorization") != "Bearer tk_abc" ||
		strings.ContainsAny(r.Header.Get("Title"), "\x1b") || !strings.Contains(string(nc.body[0]), "SHA256:new") {
		t.Fatalf("ntfy %s %v %q", r.URL.Path, r.Header, nc.body[0])
	}
	r = tc.reqs[0]
	var msg map[string]any
	_ = json.Unmarshal(tc.body[0], &msg)
	if r.URL.Path != "/bot"+botToken+"/sendMessage" || msg["chat_id"] != "-100123" || msg["parse_mode"] != nil ||
		!strings.Contains(msg["text"].(string), "host key mismatch") {
		t.Fatalf("telegram %s %v", r.URL.Path, msg)
	}
}

func TestErrorsNeverContainTheToken(t *testing.T) {
	var logged strings.Builder
	log := slog.New(slog.NewTextHandler(&logged, nil))
	var c captured
	srv := c.server(t, 401)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	for _, base := range []string{srv.URL, closed.URL} {
		n := NewWithSenders(log, nil, &telegram{base: base, token: botToken, chatID: "1", client: http.DefaultClient})
		if n.Notify(context.Background(), mismatch) != 0 {
			t.Fatal("failure counted as sent")
		}
	}
	if strings.Contains(logged.String(), botToken) || strings.Contains(logged.String(), "ABCdef") {
		t.Fatalf("token in log: %s", logged.String())
	}
	if !strings.Contains(logged.String(), "HTTP 401") {
		t.Fatalf("status missing: %s", logged.String())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var target captured
	tsrv := target.server(t, 200)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, tsrv.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	n := New(serverconfig.Notifications{Webhook: &serverconfig.WebhookConfig{URL: redir.URL, Secret: secret}}, nil, quiet())
	n.retryDelays = nil
	if n.Notify(context.Background(), mismatch) != 0 || len(target.reqs) != 0 {
		t.Fatal("redirect followed")
	}
}

type flaky struct {
	fails int
	calls int
}

func (f *flaky) Name() string { return "flaky" }
func (f *flaky) Send(context.Context, Event) error {
	f.calls++
	if f.calls <= f.fails {
		return errors.New("temporary")
	}
	return nil
}

func TestRetries(t *testing.T) {
	f := &flaky{fails: 2}
	n := NewWithSenders(quiet(), []time.Duration{time.Millisecond, time.Millisecond}, f)
	if n.Notify(context.Background(), mismatch) != 1 || f.calls != 3 {
		t.Fatalf("calls %d", f.calls)
	}
	f = &flaky{fails: 5}
	n = NewWithSenders(quiet(), []time.Duration{time.Millisecond, time.Millisecond}, f)
	if n.Notify(context.Background(), mismatch) != 0 || f.calls != 3 {
		t.Fatalf("calls %d", f.calls)
	}
}

func TestCleanBoundsAndStripsControls(t *testing.T) {
	got := clean("a\u202eb\x00c\nd"+strings.Repeat("x", 400), 50)
	if strings.ContainsAny(got, "\u202e\x00\n") || len([]rune(got)) != 51 {
		t.Fatalf("%q", got)
	}
}
