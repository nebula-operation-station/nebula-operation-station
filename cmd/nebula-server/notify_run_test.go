// SPDX-License-Identifier: AGPL-3.0-or-later

// End-to-end notification tests: server.json is loaded by runServer, the
// notifier built from it sends through the real webhook and ntfy providers,
// and the receivers are protocol-level loopback servers (httptest). Nothing
// here uses NewWithSenders or a test sink.
//
// The webhook receiver verifies the signature by itself. It uses only what
// docs/admin/guide.md section 10.1 describes (HMAC-SHA256 with the secret,
// over the body) and the header names of the implementation, which the
// guide does not name. Those parts are named exceptions in
// TestNotifyWebhookSignatureFormat.

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnnotify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

const (
	// nrWebhookSecret is at least 32 characters (serverconfig minSecretLen).
	nrWebhookSecret = "nr-webhook-secret-0123456789abcdefgh"
	nrNtfyToken     = "nr-ntfy-token-0123456789"
	nrNtfyTopic     = "nebula_notify-run"
	// nrRetries is the number of retries after a failed send (the notifier
	// retries twice, so a rejecting provider is asked three times).
	nrRetries = 3
)

// nrRequest is one request a receiver got.
type nrRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// nrReceiver is a loopback HTTP receiver that answers with a fixed status.
type nrReceiver struct {
	srv      *httptest.Server
	status   int
	location string
	mu       sync.Mutex
	reqs     []nrRequest
}

func newNRReceiver(t *testing.T, status int) *nrReceiver {
	t.Helper()
	r := &nrReceiver{status: status}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, nrRequest{Method: req.Method, Path: req.URL.Path, Header: req.Header.Clone(), Body: body})
		loc := r.location
		r.mu.Unlock()
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(r.status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *nrReceiver) requests() []nrRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]nrRequest(nil), r.reqs...)
}

// nrNotifications is the notifications section of server.json, in the form
// of docs/admin/guide.md section 10.1 (without telegram).
func nrNotifications(webhookURL, ntfyURL string) map[string]any {
	n := map[string]any{}
	if webhookURL != "" {
		n["webhook"] = map[string]any{"url": webhookURL, "secret": nrWebhookSecret}
	}
	if ntfyURL != "" {
		n["ntfy"] = map[string]any{"url": ntfyURL, "topic": nrNtfyTopic, "token": nrNtfyToken}
	}
	return map[string]any{"notifications": n}
}

// nrConfig is a server.json in dir with the notifications section and no
// executor (the socket is never created).
func nrConfig(t *testing.T, dir string, notifications map[string]any, apiCfg any) map[string]any {
	t.Helper()
	cfg := vrConfig(t, dir, filepath.Join(dir, "no-executor.sock"), apiCfg)
	for k, v := range notifications {
		cfg[k] = v
	}
	return cfg
}

// nrNotifyTest runs `-config <path> -notify-test` through runServer and
// returns its error and stderr.
func nrNotifyTest(t *testing.T, cfg map[string]any) (error, string) {
	t.Helper()
	path := writeConfig(t, t.TempDir(), cfg)
	var stderr bytes.Buffer
	err := runServer(context.Background(), []string{"-config", path, "-notify-test"}, &stderr, vulnHooks{})
	return err, stderr.String()
}

// nrCheckSecretsAbsent fails if a secret appears in text (logs or errors).
func nrCheckSecretsAbsent(t *testing.T, what, text string) {
	t.Helper()
	for _, secret := range []string{nrWebhookSecret, nrNtfyToken} {
		if strings.Contains(text, secret) {
			t.Errorf("%s contains a secret", what)
		}
	}
}

// nrVerifyWebhook checks a webhook request as the handbook describes it:
// the body is JSON signed with HMAC-SHA256 using the secret. The signed
// bytes, the header names and the "sha256=" prefix are not in the guide
// (see TestNotifyWebhookSignatureFormat); they are checked here as the
// implementation sends them.
func nrVerifyWebhook(t *testing.T, r nrRequest) map[string]any {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Fatalf("webhook method = %s, want POST", r.Method)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("webhook Content-Type = %q", ct)
	}
	var payload map[string]any
	if err := json.Unmarshal(r.Body, &payload); err != nil {
		t.Fatalf("webhook body is not JSON: %v", err)
	}
	ts := r.Header.Get("X-Nebula-Timestamp")
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		t.Fatalf("X-Nebula-Timestamp %q is not a unix time: %v", ts, err)
	}
	sig, ok := strings.CutPrefix(r.Header.Get("X-Nebula-Signature"), "sha256=")
	if !ok {
		t.Fatalf("X-Nebula-Signature has no sha256= prefix")
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		t.Fatalf("X-Nebula-Signature is not hex: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(nrWebhookSecret))
	mac.Write([]byte(ts + "." + string(r.Body)))
	if !hmac.Equal(got, mac.Sum(nil)) {
		t.Fatalf("webhook signature does not verify with the configured secret")
	}
	return payload
}

// TestNotifyTestSendsToWebhookAndNtfy starts `-notify-test` with the
// notifications of guide section 10.1 and checks that each receiver got
// exactly one correctly formed request and that the command returned nil.
func TestNotifyTestSendsToWebhookAndNtfy(t *testing.T) {
	t.Parallel()
	webhook := newNRReceiver(t, http.StatusOK)
	ntfy := newNRReceiver(t, http.StatusOK)
	cfg := nrConfig(t, t.TempDir(), nrNotifications(webhook.srv.URL, ntfy.srv.URL), nil)

	err, stderr := nrNotifyTest(t, cfg)
	if err != nil {
		t.Fatalf("-notify-test: %v", err)
	}
	if !strings.Contains(stderr, "test notification sent") {
		t.Errorf("stderr does not report the test notification: %s", stderr)
	}
	nrCheckSecretsAbsent(t, "stderr", stderr)

	wr := webhook.requests()
	if len(wr) != 1 {
		t.Fatalf("webhook got %d requests, want 1", len(wr))
	}
	payload := nrVerifyWebhook(t, wr[0])
	if payload["kind"] != "test" {
		t.Errorf("webhook kind = %v, want test", payload["kind"])
	}

	nr := ntfy.requests()
	if len(nr) != 1 {
		t.Fatalf("ntfy got %d requests, want 1", len(nr))
	}
	if nr[0].Method != http.MethodPost || nr[0].Path != "/"+nrNtfyTopic {
		t.Errorf("ntfy request = %s %s, want POST /%s", nr[0].Method, nr[0].Path, nrNtfyTopic)
	}
	if auth := nr[0].Header.Get("Authorization"); auth != "Bearer "+nrNtfyToken {
		t.Errorf("ntfy Authorization = %q, want the configured bearer token", auth)
	}
	if nr[0].Header.Get("Title") == "" || len(nr[0].Body) == 0 {
		t.Errorf("ntfy request has no Title or no text")
	}
}

// TestNotifyWebhookSignatureFormat pins the signature as sent and records the
// gap with docs/admin/guide.md section 10.1 (guide.md is protected and was
// not changed; see the PR text).
//
// Named exceptions, all because the guide does not state them:
//   - the header names X-Nebula-Signature and X-Nebula-Timestamp;
//   - the "sha256=" prefix of the signature value;
//   - the signed bytes "<timestamp>.<body>" (the guide says only "HMAC-SHA256
//     using the secret" over the body).
//
// A receiver that reads the guide literally (HMAC over the body alone) does
// not verify the request. That is asserted below, so a change to either side
// fails this test.
func TestNotifyWebhookSignatureFormat(t *testing.T) {
	t.Parallel()
	webhook := newNRReceiver(t, http.StatusOK)
	cfg := nrConfig(t, t.TempDir(), nrNotifications(webhook.srv.URL, ""), nil)
	if err, _ := nrNotifyTest(t, cfg); err != nil {
		t.Fatalf("-notify-test: %v", err)
	}
	wr := webhook.requests()
	if len(wr) != 1 {
		t.Fatalf("webhook got %d requests, want 1", len(wr))
	}
	nrVerifyWebhook(t, wr[0])

	// Guide-literal reading: the body alone. It must not match, which is
	// the documented gap.
	sig, _ := strings.CutPrefix(wr[0].Header.Get("X-Nebula-Signature"), "sha256=")
	plain := hmac.New(sha256.New, []byte(nrWebhookSecret))
	plain.Write(wr[0].Body)
	if hex.EncodeToString(plain.Sum(nil)) == sig {
		t.Fatal("signature over the body alone verifies: guide 10.1 and the code agree now; remove the exception")
	}
}

// TestNotifyTestWithoutProviderFails: with no provider, -notify-test ends with
// the error of main.go, and sends nothing.
func TestNotifyTestWithoutProviderFails(t *testing.T) {
	t.Parallel()
	err, stderr := nrNotifyTest(t, nrConfig(t, t.TempDir(), map[string]any{}, nil))
	if err == nil || err.Error() != "no notification provider configured" {
		t.Fatalf("err = %v, want no notification provider configured", err)
	}
	if strings.Contains(stderr, "test notification sent") {
		t.Errorf("reported a sent test notification without a provider")
	}
}

// TestNotifyTestFailsWhenBothProvidersReject: both receivers answer 500 for
// every attempt. The command returns the error (the notifier retries twice,
// about 12 s per provider).
func TestNotifyTestFailsWhenBothProvidersReject(t *testing.T) {
	t.Parallel()
	webhook := newNRReceiver(t, http.StatusInternalServerError)
	ntfy := newNRReceiver(t, http.StatusInternalServerError)
	cfg := nrConfig(t, t.TempDir(), nrNotifications(webhook.srv.URL, ntfy.srv.URL), nil)

	err, stderr := nrNotifyTest(t, cfg)
	if err == nil || err.Error() != "no provider accepted the test notification (see the log)" {
		t.Fatalf("err = %v, want no provider accepted", err)
	}
	if got := len(webhook.requests()); got != nrRetries {
		t.Errorf("webhook got %d requests, want %d", got, nrRetries)
	}
	if got := len(ntfy.requests()); got != nrRetries {
		t.Errorf("ntfy got %d requests, want %d", got, nrRetries)
	}
	if !strings.Contains(stderr, `"msg":"notification failed"`) {
		t.Errorf("stderr has no failure line: %s", stderr)
	}
	nrCheckSecretsAbsent(t, "stderr", stderr)
	nrCheckSecretsAbsent(t, "error", err.Error())
}

// TestNotifyTestOneAcceptingProviderIsEnough: the webhook answers 500, ntfy
// accepts. The command ends with nil; the failure of the webhook is in the
// log.
func TestNotifyTestOneAcceptingProviderIsEnough(t *testing.T) {
	t.Parallel()
	webhook := newNRReceiver(t, http.StatusInternalServerError)
	ntfy := newNRReceiver(t, http.StatusOK)
	cfg := nrConfig(t, t.TempDir(), nrNotifications(webhook.srv.URL, ntfy.srv.URL), nil)

	err, stderr := nrNotifyTest(t, cfg)
	if err != nil {
		t.Fatalf("-notify-test with one accepting provider: %v", err)
	}
	if !strings.Contains(stderr, "test notification sent") {
		t.Errorf("stderr does not report the test notification: %s", stderr)
	}
	if !strings.Contains(stderr, `"msg":"notification failed"`) || !strings.Contains(stderr, `"provider":"webhook"`) {
		t.Errorf("stderr does not record the webhook failure: %s", stderr)
	}
	if got := len(ntfy.requests()); got != 1 {
		t.Errorf("ntfy got %d requests, want 1", got)
	}
	nrCheckSecretsAbsent(t, "stderr", stderr)
}

// TestNotifyTestDoesNotFollowRedirect: the webhook answers with a redirect to
// a second receiver. The redirect is not followed, so the target gets nothing
// and the webhook counts as rejecting.
func TestNotifyTestDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	target := newNRReceiver(t, http.StatusOK)
	webhook := newNRReceiver(t, http.StatusFound)
	webhook.location = target.srv.URL + "/moved"
	ntfy := newNRReceiver(t, http.StatusOK)
	cfg := nrConfig(t, t.TempDir(), nrNotifications(webhook.srv.URL, ntfy.srv.URL), nil)

	err, stderr := nrNotifyTest(t, cfg)
	if err != nil {
		t.Fatalf("-notify-test: %v", err)
	}
	if got := len(target.requests()); got != 0 {
		t.Errorf("redirect target got %d requests, want 0 (redirects must not be followed)", got)
	}
	if got := len(webhook.requests()); got != nrRetries {
		t.Errorf("webhook got %d requests, want %d", got, nrRetries)
	}
	if !strings.Contains(stderr, `"provider":"webhook"`) {
		t.Errorf("stderr does not record the webhook as failed: %s", stderr)
	}
}

// nrStart runs the server with cfg (written to dir/server.json) through
// runServer, without a notification sink and with short vulnerability loop
// intervals, and waits until it serves /login. The returned stop cancels
// the server and waits for it; it is safe to call twice.
func nrStart(t *testing.T, dir string, cfg map[string]any) *vrServer {
	t.Helper()
	listen := freeListenAddr(t)
	cfg["listen"] = listen
	path := writeConfig(t, dir, cfg)
	s := &vrServer{base: "http://" + listen, stderr: &bytes.Buffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runServer(ctx, []string{"-config", path}, s.stderr, vulnHooks{sweepInterval: vrFast, notifyInterval: vrFast})
	}()
	var once sync.Once
	s.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("runServer: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("runServer did not return after cancel")
			}
		})
	}
	t.Cleanup(s.stop)
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(s.base + "/login")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestRealVulnEventWithoutExecutorReachesWebhookAndLog starts the server with
// a notification config, a vulnerability token and an executor socket that
// nobody listens on. The vulnerability loop finds the kev feed stale (the
// same event as TestRunWiresVulnManagement, without the fake executor). It
// must arrive at the webhook receiver, and the notification log in server.db
// must have it as sent.
//
// Source of the event: the vulnerability notification loop (internal/vulnnotify),
// which does not need the executor. The executor-state events of
// internal/notify/executor.go do not fire here: an unreachable executor is
// recorded as "unreachable" and sends nothing.
func TestRealVulnEventWithoutExecutorReachesWebhookAndLog(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	webhook := newNRReceiver(t, http.StatusOK)
	ntfy := newNRReceiver(t, http.StatusOK)
	apiCfg := map[string]any{"enabled": true, "tokens": []any{map[string]any{
		"name": serverconfig.DefaultVulnTokenName, "sha256": api.HashToken(vrToken),
		"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		"source_addresses": []string{"127.0.0.1"}}}}
	cfg := nrConfig(t, dir, nrNotifications(webhook.srv.URL, ntfy.srv.URL), apiCfg)
	s := nrStart(t, dir, cfg)

	code, body := s.do(t, http.MethodGet, "/api/v1/vuln/inventory", "", vrToken, nil)
	if code != http.StatusOK {
		t.Fatalf("inventory = %d %s", code, body)
	}
	var inv struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.Unmarshal(body, &inv); err != nil || inv.SnapshotID == "" {
		t.Fatalf("inventory body %s: %v", body, err)
	}
	// kev with data 100 h old (its maximum age is 72 h), osv fresh.
	now := time.Now().UTC()
	src := func(id string, at time.Time) map[string]any {
		return map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none", "date_kind": "data",
			"content_date": at.Format(time.RFC3339)}
	}
	code, body = s.do(t, http.MethodPost, "/api/v1/vuln/runs", "", vrToken, map[string]any{
		"inventory_snapshot_id": inv.SnapshotID, "matcher_version": "1.4.0",
		"sources": []any{src("kev", now.Add(-100*time.Hour)), src("osv", now.Add(-time.Hour))}})
	if code != http.StatusCreated {
		t.Fatalf("run start = %d %s", code, body)
	}

	// Wait for the feed_stale event at the webhook receiver.
	var got map[string]any
	waitFor(t, "vuln.feed_stale at the webhook", func() bool {
		for _, r := range webhook.requests() {
			if p := nrPayloadOf(r); p["kind"] == vulnnotify.KindFeedStale {
				got = nrVerifyWebhook(t, r)
				return true
			}
		}
		return false
	})
	if reason, _ := got["reason"].(string); !strings.Contains(reason, "feed kev stale since") {
		t.Errorf("feed_stale reason = %q, want kev", reason)
	}
	nrCheckSecretsAbsent(t, "webhook body", string(mustJSON(t, got)))

	// Stop the server (flushes the notification log), then read server.db.
	s.stop()
	nrCheckSecretsAbsent(t, "server stderr", s.stderr.String())
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := notifylog.New(db, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := store.List(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	sent := 0
	for _, e := range entries {
		if e.Kind == notifylog.KindVulnFeedStale && e.Outcome == notifylog.OutcomeSent {
			sent++
		}
	}
	if sent == 0 {
		t.Fatalf("notification log has no sent %s entry (%d entries)", notifylog.KindVulnFeedStale, len(entries))
	}
}

// nrPayloadOf decodes a webhook body without checking the signature (used to
// find the request; nrVerifyWebhook checks it).
func nrPayloadOf(r nrRequest) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(r.Body, &p)
	return p
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
