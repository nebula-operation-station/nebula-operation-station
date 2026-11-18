// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notify sends notifications (spec 13): generic webhook (JSON,
// HMAC-SHA256 signed), ntfy and Telegram. Notifications are a read-only
// path: nothing here can trigger an execution.
//
// Messages carry host, state, reason and (later) an execution ID, never
// log content. Host-provided text is untrusted (spec 09): it is reduced to
// printable characters and bounded before it is sent. Provider tokens never
// appear in errors or logs: request errors are reported without the URL
// (the Telegram token is part of it).
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
)

// Event kinds.
const (
	KindHostKeyMismatch = "host_key_mismatch"
	KindTest            = "test"
	KindOpsState        = "ops_state"
	// KindExecution is an execution that finished with WARNING (some
	// hosts failed) or FAILED (all hosts failed, or it could not run).
	KindExecution = "execution"
	// KindExecutorLocked is the executor found locked after a restart (or
	// when the server starts): runs wait until `nebula unlock`.
	KindExecutorLocked = "executor_locked"
)

// Event is one notification.
type Event struct {
	Kind        string
	Host        string
	State       string
	Reason      string
	ExecutionID string
	// link is a NOS UI link for integrity events. Only IntegrityGate sets
	// it, after validating it; it is empty for every other kind.
	link string
	// logLink is the NOS path of the same link (for example
	// "/integrity/findings/7"), which the notification log stores. Only
	// IntegrityGate sets it, from the validated link.
	logLink string
	Time    time.Time
}

// Vulnerability and digest kinds. internal/vulnnotify sends them and imports
// this package, so the strings are repeated here; the values must match
// vulnnotify's constants.
const (
	kindVulnKEVNew        = "vuln.kev_new"
	kindVulnCriticalNew   = "vuln.critical_new"
	kindVulnHermesStale   = "vuln.hermes_stale"
	kindVulnFeedStale     = "vuln.feed_stale"
	kindVulnFeedRegressed = "vuln.feed_regressed"
	kindVulnFeedMarkReset = "vuln.feed_mark_reset"
	kindVulnDigest        = "vuln.digest"
)

const (
	maxField     = 300
	sendTimeout  = 10 * time.Second
	maxBodyDrain = 4 << 10
)

// clean reduces untrusted text to printable characters on one line.
func clean(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= limit {
			b.WriteString("…")
			break
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case !unicode.IsPrint(r) || unicode.Is(unicode.Bidi_Control, r):
			b.WriteRune('�')
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

func (e Event) cleaned() Event {
	return Event{Kind: clean(e.Kind, 64), Host: clean(e.Host, 64), State: clean(e.State, 64), Reason: clean(e.Reason, maxField),
		ExecutionID: clean(e.ExecutionID, 128), link: clean(e.link, maxIntegrityLink), logLink: e.logLink,
		Time: e.Time.UTC().Truncate(time.Second)}
}

// Title is a short summary line.
func (e Event) Title() string {
	if t, ok := integrityTitle(e); ok {
		return t
	}
	switch e.Kind {
	case KindHostKeyMismatch:
		return "Nebula: host key mismatch on " + e.Host
	case KindTest:
		return "Nebula: test notification"
	case KindOpsState:
		return "Nebula: " + e.Host + " is " + e.State
	case KindExecution:
		return "Nebula: operation finished with " + e.State
	case KindExecutorLocked:
		return "Nebula: executor is locked"
	}
	return "Nebula: " + e.Kind + " " + e.Host
}

// Text is the plain-text message.
func (e Event) Text() string {
	var b strings.Builder
	b.WriteString(e.Title())
	if e.State != "" {
		b.WriteString("\nState: " + e.State)
	}
	if e.Reason != "" {
		b.WriteString("\n" + e.Reason)
	}
	if e.ExecutionID != "" {
		b.WriteString("\nExecution: " + e.ExecutionID)
	}
	if e.link != "" {
		b.WriteString("\nDetails: " + e.link)
	}
	b.WriteString("\n" + e.Time.Format(time.RFC3339))
	return b.String()
}

// Sender is one provider.
type Sender interface {
	Name() string
	Send(ctx context.Context, e Event) error
}

// Notifier fans events out to all configured senders.
type Notifier struct {
	senders []Sender
	log     *slog.Logger
	// retryDelays between attempts; tests shorten them.
	retryDelays []time.Duration
	// rec stores each decision in the notification log (ADR 0016 D10). nil
	// means no log; the notifier then behaves as before.
	rec Recorder
	// recSlots bounds the log writes in flight: one slot per write. It is
	// made by SetRecorder.
	recSlots chan struct{}
	// recDropped counts records dropped because every slot was taken.
	recDropped atomic.Int64
}

// Recorder stores one notification decision in the notification log (ADR
// 0016 D10). *notifylog.Store implements it. A Recorder error is logged and
// never changes the delivery result.
type Recorder interface {
	Append(ctx context.Context, r notifylog.Record) (int64, error)
}

// recordTimeout bounds one log write, so a stuck database cannot hold a write
// slot for long.
const recordTimeout = 5 * time.Second

// maxPendingRecords bounds the log writes in flight. When all are taken, a new
// record is dropped and counted (RecordsDropped), so a slow database never
// makes memory or goroutines grow without limit.
const maxPendingRecords = 64

// SetRecorder sets the notification log. Call it before the notifier is used
// concurrently; nil removes the log.
func (n *Notifier) SetRecorder(r Recorder) {
	n.rec = r
	if r != nil && n.recSlots == nil {
		n.recSlots = make(chan struct{}, maxPendingRecords)
	}
}

// RecordsDropped returns how many records were dropped because the log could
// not keep up. Dropped records are not in the log.
func (n *Notifier) RecordsDropped() int64 { return n.recDropped.Load() }

// FlushRecords waits until the log writes in flight have ended, or until ctx
// ends. It holds every write slot while it waits, so a record that arrives
// meanwhile is dropped; call it when sending has stopped (shutdown, tests).
func (n *Notifier) FlushRecords(ctx context.Context) error {
	if n.recSlots == nil {
		return nil
	}
	taken := 0
	defer func() {
		for ; taken > 0; taken-- {
			<-n.recSlots
		}
	}()
	for taken < cap(n.recSlots) {
		select {
		case n.recSlots <- struct{}{}:
			taken++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// record stores r in the notification log. The write runs in its own
// goroutine, so a slow or locked database never delays a send or the next
// notification; the caller does not wait for it. The write uses a context that
// a cancelled send does not cancel (the decision must still be logged) and is
// bounded by recordTimeout. When no write slot is free, r is dropped and
// counted. A failed write is logged without the message text. record never
// returns an error.
func (n *Notifier) record(ctx context.Context, r notifylog.Record) {
	if n.rec == nil {
		return
	}
	select {
	case n.recSlots <- struct{}{}:
	default:
		dropped := n.recDropped.Add(1)
		n.log.Warn("notification log is behind, record dropped", "kind", string(r.Kind), "dropped_total", dropped)
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	go func() {
		defer func() {
			cancel()
			<-n.recSlots
		}()
		if _, err := n.rec.Append(rctx, r); err != nil {
			n.log.Warn("notification log write failed", "kind", string(r.Kind), "outcome", string(r.Outcome), "error", err.Error())
		}
	}()
}

// logHost returns the host the notification log stores for a host label: the
// label itself when it is an inventory host ID (lowercase, at most 63 bytes),
// otherwise "". A display label such as "Web01" is not an ID, and Append
// refuses a record with a host that is not an ID, so a label that is not one
// is stored empty and the event is still logged. The message text is
// unchanged.
func logHost(s string) string {
	if notifylog.ValidHost(s) {
		return s
	}
	return ""
}

// logExecutionID returns the execution ID the log stores: the value when it is
// a lowercase UUIDv4, otherwise "" (see logHost).
func logExecutionID(s string) string {
	if notifylog.ValidExecutionID(s) {
		return s
	}
	return ""
}

// statusError is a provider answer with a non-2xx status. Its text is the same
// as before; the type lets the log tell a rejection from a network failure.
type statusError struct {
	name string
	code int
}

func (e *statusError) Error() string { return fmt.Sprintf("%s: answered HTTP %d", e.name, e.code) }

// reasonOf maps a delivery error to the log's closed reason code.
func reasonOf(err error) notifylog.ReasonCode {
	var se *statusError
	if errors.As(err, &se) {
		return notifylog.ReasonProviderRejected
	}
	return notifylog.ReasonForError(err)
}

// New builds a notifier from the configuration. client may be nil.
func New(cfg serverconfig.Notifications, client *http.Client, log *slog.Logger) *Notifier {
	if client == nil {
		client = &http.Client{Timeout: sendTimeout}
	}
	// Never follow redirects: a redirect could carry a token-bearing URL
	// or a signed body somewhere else.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if log == nil {
		log = slog.Default()
	}
	n := &Notifier{log: log, retryDelays: []time.Duration{2 * time.Second, 10 * time.Second}}
	if w := cfg.Webhook; w != nil {
		n.senders = append(n.senders, &webhook{url: w.URL, secret: []byte(string(w.Secret)), client: &c})
	}
	if t := cfg.Ntfy; t != nil {
		n.senders = append(n.senders, &ntfy{url: strings.TrimRight(t.URL, "/") + "/" + t.Topic, token: string(t.Token), client: &c})
	}
	if t := cfg.Telegram; t != nil {
		n.senders = append(n.senders, &telegram{base: "https://api.telegram.org", token: string(t.BotToken), chatID: t.ChatID, client: &c})
	}
	return n
}

// NewWithSenders is for tests.
func NewWithSenders(log *slog.Logger, retryDelays []time.Duration, s ...Sender) *Notifier {
	return &Notifier{senders: s, log: log, retryDelays: retryDelays}
}

// Enabled reports whether any provider is configured.
func (n *Notifier) Enabled() bool { return len(n.senders) > 0 }

// Notify sends e to every provider, retrying each a few times. It reports
// how many providers accepted it; failures are logged without secrets.
func (n *Notifier) Notify(ctx context.Context, e Event) int {
	return len(n.NotifyProviders(ctx, e, nil))
}

// Providers returns the names of the configured providers.
func (n *Notifier) Providers() []string {
	names := make([]string, 0, len(n.senders))
	for _, s := range n.senders {
		names = append(names, s.Name())
	}
	return names
}

// NotifyProviders sends e to every provider skip does not exclude (nil
// skips none) and returns the names of those that accepted it.
//
// Integrity kinds and the integrity digest are refused here and send
// nothing: they must go through IntegrityGate, which applies the link
// allow-list and the host-label rules. Refusing them keeps those rules from
// being skipped.
func (n *Notifier) NotifyProviders(ctx context.Context, e Event, skip func(provider string) bool) []string {
	if isIntegrityKind(e.Kind) {
		n.log.Warn("integrity notification refused outside IntegrityGate", "kind", e.Kind)
		return nil
	}
	return n.send(ctx, e, skip)
}

// isIntegrityKind reports whether kind belongs to the integrity events or
// their digest.
func isIntegrityKind(kind string) bool {
	switch IntegrityKind(kind) {
	case IntegrityNOSMismatch, IntegrityHostChange, IntegrityScanIncomplete, IntegrityBaselineTamper, IntegrityReferenceConflict:
		return true
	}
	return kind == KindIntegrityDigest
}

// send is the delivery loop shared by NotifyProviders and IntegrityGate.
func (n *Notifier) send(ctx context.Context, e Event, skip func(provider string) bool) []string {
	e = e.cleaned()
	var ok []string
	addressed := 0
	var lastErr error
	for _, s := range n.senders {
		if skip != nil && skip(s.Name()) {
			continue
		}
		addressed++
		var err error
		for attempt := 0; ; attempt++ {
			sctx, cancel := context.WithTimeout(ctx, sendTimeout)
			err = s.Send(sctx, e)
			cancel()
			if err == nil || attempt >= len(n.retryDelays) || ctx.Err() != nil {
				break
			}
			select {
			case <-time.After(n.retryDelays[attempt]):
			case <-ctx.Done():
			}
		}
		if err != nil {
			n.log.Warn("notification failed", "provider", s.Name(), "kind", e.Kind, "host", e.Host, "error", err.Error())
			lastErr = err
			continue
		}
		ok = append(ok, s.Name())
		n.log.Info("notification sent", "provider", s.Name(), "kind", e.Kind, "host", e.Host)
	}
	// Nothing was addressed (all skipped, or no provider): nothing to log.
	if addressed > 0 {
		if r, known := newRecord(e); known {
			r.Providers = addressed
			if len(ok) > 0 {
				r.Outcome = notifylog.OutcomeSent
			} else {
				r.Outcome = notifylog.OutcomeFailed
				r.Reason = reasonOf(lastErr)
			}
			n.record(ctx, r)
		} else {
			n.log.Debug("event kind has no notification log code", "kind", e.Kind)
		}
	}
	return ok
}

// post sends a request and checks the status; the error never contains
// the URL.
func post(ctx context.Context, c *http.Client, name, u string, body []byte, header http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: bad request", name)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s: request failed: %w", name, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyDrain))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &statusError{name: name, code: resp.StatusCode}
	}
	return nil
}

type webhook struct {
	url    string
	secret []byte
	client *http.Client
}

func (w *webhook) Name() string { return "webhook" }

// WebhookPayload is the JSON body of a webhook notification.
type WebhookPayload struct {
	Kind        string `json:"kind"`
	Host        string `json:"host,omitempty"`
	State       string `json:"state,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ExecutionID string `json:"execution_id,omitempty"`
	Link        string `json:"link,omitempty"`
	Time        string `json:"time"`
}

// Sign returns the signature header value for a webhook body: HMAC-SHA256
// over "<timestamp>.<body>", so a captured request cannot be replayed with
// another timestamp.
func Sign(secret []byte, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(timestamp))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (w *webhook) Send(ctx context.Context, e Event) error {
	body, err := json.Marshal(WebhookPayload{Kind: e.Kind, Host: e.Host, State: e.State, Reason: e.Reason,
		ExecutionID: e.ExecutionID, Link: e.link, Time: e.Time.Format(time.RFC3339)})
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Nebula-Timestamp", ts)
	h.Set("X-Nebula-Signature", Sign(w.secret, ts, body))
	return post(ctx, w.client, w.Name(), w.url, body, h)
}

type ntfy struct {
	url    string
	token  string
	client *http.Client
}

func (n *ntfy) Name() string { return "ntfy" }

// headerSafe keeps printable ASCII only (ntfy reads the title from a
// header).
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

func (n *ntfy) Send(ctx context.Context, e Event) error {
	h := http.Header{}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Title", headerSafe(e.Title()))
	if e.Kind == KindHostKeyMismatch {
		h.Set("Priority", "urgent")
		h.Set("Tags", "warning,lock")
	}
	if n.token != "" {
		h.Set("Authorization", "Bearer "+n.token)
	}
	return post(ctx, n.client, n.Name(), n.url, []byte(e.Text()), h)
}

type telegram struct {
	base   string
	token  string
	chatID string
	client *http.Client
}

func (t *telegram) Name() string { return "telegram" }

func (t *telegram) Send(ctx context.Context, e Event) error {
	// Plain text (no parse_mode): host text cannot inject markup.
	body, err := json.Marshal(map[string]any{"chat_id": t.chatID, "text": e.Text(), "disable_web_page_preview": true})
	if err != nil {
		return err
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return post(ctx, t.client, t.Name(), t.base+"/bot"+t.token+"/sendMessage", body, h)
}
