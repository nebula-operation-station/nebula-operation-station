// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// IntegrityKind is one of the integrity notification events (spec 13,
// ADR 0015 D9).
type IntegrityKind string

// Integrity event kinds.
const (
	// IntegrityNOSMismatch: an I1 finding on the NOS machine.
	IntegrityNOSMismatch IntegrityKind = "integrity.nos_mismatch"
	// IntegrityHostChange: an I2 finding on a managed host.
	IntegrityHostChange IntegrityKind = "integrity.host_change"
	// IntegrityScanIncomplete: an I1 check or I2 run that could not complete.
	IntegrityScanIncomplete IntegrityKind = "integrity.scan_incomplete"
	// IntegrityBaselineTamper: the I2 baseline list does not match the
	// executor-stored digest.
	IntegrityBaselineTamper IntegrityKind = "integrity.baseline_tamper"
	// IntegrityReferenceConflict: the executor rejected a package reference
	// that differs from the one admitted for the same package, version and arch.
	IntegrityReferenceConflict IntegrityKind = "integrity.reference_conflict"
)

// KindIntegrityDigest summarises the integrity messages the hourly limit
// held back. ADR 0015 D9 requires the hourly digest; spec 13 names only the
// five events above.
const KindIntegrityDigest = "integrity.digest"

// Severity is the fixed severity scale of integrity findings.
type Severity string

// Severities.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Limits (ADR 0015 D9, ADR 0011 D9).
const (
	// MaxIntegrityPerHour is the number of integrity messages that may leave
	// in any hour; the rest are counted into the digest.
	MaxIntegrityPerHour = 10
	// IntegrityWindow is the period MaxIntegrityPerHour applies to.
	IntegrityWindow = time.Hour
	// MaxTrackedIntegrityKeys bounds the de-duplication state; the oldest
	// entries are dropped first.
	MaxTrackedIntegrityKeys = 100_000
	// maxIntegrityClass bounds the class code.
	maxIntegrityClass = 32
	// maxIntegrityLink bounds the NOS link.
	maxIntegrityLink = 512
	// maxIntegrityLinkID bounds the decimal finding ID at the end of the link.
	maxIntegrityLinkID = 20
	// integrityLinkRoute is the fixed NOS UI route of an integrity finding,
	// relative to the configured NOS base URL. The link carries no other path,
	// query or fragment.
	integrityLinkRoute = "/integrity/findings/"
	// maxIntegrityLabel bounds the host label (the plain-text rule of clean).
	maxIntegrityLabel = 64
	// unnamedHost stands in for an empty host label.
	unnamedHost = "unnamed host"
)

// ErrInvalidIntegrityEvent is returned for an event with an unknown kind,
// class, severity or link, or a negative count. Such an event is never sent.
var ErrInvalidIntegrityEvent = errors.New("invalid integrity event")

// ErrInvalidNOSBase is returned by NewIntegrityGate for a NOS base URL that
// is not an absolute http or https URL with a host and without user info,
// query or fragment.
var ErrInvalidNOSBase = errors.New("invalid NOS base URL")

// IntegrityEvent is one integrity notification. It has fixed fields only:
// there is no field for a path or for file content, so no host-supplied
// path or content can reach a message through it. The path that identifies
// a finding enters only as a hash, through NewIntegrityKey.
type IntegrityEvent struct {
	// Kind selects the event and its fixed wording.
	Kind IntegrityKind
	// Host is the host label as the admin set it; it is reduced to letters,
	// digits, spaces, '-' and '_' before it is sent. Every other character,
	// including '.', becomes '?', so no domain-like text is left for a chat
	// client to link.
	Host string
	// Class is the fixed class code of the finding (lowercase letters,
	// digits and '_', starting with a letter).
	Class string
	// Severity is the fixed severity scale.
	Severity Severity
	// Count is the number of findings the event covers.
	Count int
	// Link is the NOS UI link for the finding. It must be the configured NOS
	// base URL followed by the fixed integrity route and a decimal finding
	// ID, and nothing else. Empty is allowed.
	Link string
}

// IntegrityKey identifies a finding for de-duplication (spec 13
// v26-13-01: per (subject, class, path), not per kind). It holds a SHA-256
// hash of the three parts, so the path is never kept in clear, and the
// class in clear, so Submit can check that the key belongs to the event's
// class. Build it with NewIntegrityKey; the zero value matches no finding and
// is rejected by Submit.
type IntegrityKey struct {
	digest [sha256.Size]byte
	class  string
}

// NewIntegrityKey returns the de-duplication key of a finding. Each part is
// length-prefixed, so different splits of the same text give different keys.
func NewIntegrityKey(subject, class, path string) IntegrityKey {
	h := sha256.New()
	for _, part := range []string{subject, class, path} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	var k IntegrityKey
	copy(k.digest[:], h.Sum(nil))
	k.class = class
	return k
}

// Decision is the outcome of IntegrityGate.Submit.
type Decision int

// Decisions.
const (
	// DecisionNone: the event was rejected, nothing was sent or recorded.
	DecisionNone Decision = iota
	// DecisionSent: a provider accepted the message.
	DecisionSent
	// DecisionDuplicate: the same key was already notified or held.
	DecisionDuplicate
	// DecisionHeld: the hourly limit held the message; the digest counts it.
	DecisionHeld
	// DecisionUndelivered: no provider accepted the message. Its key is not
	// recorded, so a later event with the same key may send it.
	DecisionUndelivered
)

// IntegrityGate applies de-duplication and the hourly limit to integrity
// events, then sends them through a Notifier. It is the only sender of
// integrity kinds: Notifier.Notify refuses them. It is safe for concurrent
// use; messages are sent outside its lock.
//
// A submission for a key that is still being sent waits for that send to
// finish, then reports DecisionDuplicate if it was delivered or sends the
// event itself if it was not. So concurrent submissions of one finding send
// it at most once.
//
// De-duplication state is held in memory: after a restart a finding that is
// still open notifies once more inside the limit. Forget clears the state of
// a finding when it closes or its baseline is approved.
type IntegrityGate struct {
	n         *Notifier
	now       func() time.Time
	linkStart string // NOS base URL plus the integrity route

	mu        sync.Mutex
	sent      []time.Time // delivery times (and reserved slots) inside the window
	notified  map[IntegrityKey]bool
	inflight  map[IntegrityKey]chan struct{} // closed when the send ends
	order     []IntegrityKey                 // insertion order for eviction
	held      map[IntegrityKind]int
	heldSince time.Time
}

// NewIntegrityGate returns a gate that sends through n. nosBase is the
// configured NOS base URL that finding links must start with, for example
// "https://nos.example.net". now defaults to time.Now. The error never
// contains nosBase: it may carry credentials.
func NewIntegrityGate(n *Notifier, nosBase string, now func() time.Time) (*IntegrityGate, error) {
	if now == nil {
		now = time.Now
	}
	u, err := url.Parse(nosBase)
	var reason string
	switch {
	case err != nil:
		reason = "not a URL"
	case u.Scheme != "http" && u.Scheme != "https":
		reason = "scheme must be http or https"
	case u.Host == "":
		reason = "missing host"
	case u.User != nil:
		reason = "user info is not allowed"
	case u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		reason = "query, fragment or opaque form is not allowed"
	}
	if reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrInvalidNOSBase, reason)
	}
	return &IntegrityGate{
		n:         n,
		now:       now,
		linkStart: strings.TrimSuffix(nosBase, "/") + integrityLinkRoute,
		notified:  map[IntegrityKey]bool{},
		inflight:  map[IntegrityKey]chan struct{}{},
		held:      map[IntegrityKind]int{},
	}, nil
}

// Submit validates ev and, unless it is a duplicate, sends it inside the
// hourly limit or holds it for the digest. A due digest is sent first. key
// must be built by NewIntegrityKey with the same class as ev.Class.
func (g *IntegrityGate) Submit(ctx context.Context, ev IntegrityEvent, key IntegrityKey) (Decision, error) {
	if err := ev.validate(g.linkStart); err != nil {
		return DecisionNone, err
	}
	if key.class != ev.Class {
		return DecisionNone, fmt.Errorf("%w: key class does not match event class", ErrInvalidIntegrityEvent)
	}
	dk := key // the dedupe key; spec 13 dedupes per (subject, class, path)
	for {
		g.mu.Lock()
		now := g.now()
		due := g.digestLocked(now)
		if g.notified[dk] {
			g.mu.Unlock()
			g.deliverDigest(ctx, due)
			return DecisionDuplicate, nil
		}
		if busy, ok := g.inflight[dk]; ok {
			// Another submission is sending this finding. Wait for its outcome.
			g.mu.Unlock()
			g.deliverDigest(ctx, due)
			select {
			case <-busy:
				continue
			case <-ctx.Done():
				return DecisionNone, ctx.Err()
			}
		}
		g.prune(now)
		if len(g.sent) >= MaxIntegrityPerHour {
			// Held messages count as notified: the digest reports them.
			g.holdLocked(ev.Kind, now)
			g.markLocked(dk)
			g.mu.Unlock()
			g.deliverDigest(ctx, due)
			return DecisionHeld, nil
		}
		g.sent = append(g.sent, now)
		done := make(chan struct{})
		g.inflight[dk] = done
		g.mu.Unlock()

		g.deliverDigest(ctx, due)
		ok := len(g.n.send(ctx, ev.message(now), nil)) > 0

		g.mu.Lock()
		delete(g.inflight, dk)
		close(done)
		if !ok {
			g.releaseLocked(now)
			g.mu.Unlock()
			return DecisionUndelivered, nil
		}
		g.markLocked(dk)
		g.mu.Unlock()
		return DecisionSent, nil
	}
}

// Forget drops the de-duplication state of key, so a later event for the
// same finding notifies again. Call it when the finding
// closes or its baseline is approved. A send already in flight for key is not
// cancelled; it records its key when it ends.
func (g *IntegrityGate) Forget(key IntegrityKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	kept := g.order[:0]
	for _, dk := range g.order {
		if dk == key {
			delete(g.notified, dk)
			continue
		}
		kept = append(kept, dk)
	}
	g.order = kept
}

// Flush sends the digest if its hour has ended and reports whether a digest
// was sent. Call it periodically so a quiet hour still gets its summary.
func (g *IntegrityGate) Flush(ctx context.Context) bool {
	g.mu.Lock()
	due := g.digestLocked(g.now())
	g.mu.Unlock()
	return g.deliverDigest(ctx, due)
}

// message renders ev as a notification with fixed wording.
func (ev IntegrityEvent) message(now time.Time) Event {
	return Event{Kind: string(ev.Kind), Host: integrityLabel(ev.Host), State: string(ev.Severity),
		Reason: fmt.Sprintf("Class: %s, count: %d", ev.Class, ev.Count), link: ev.Link, Time: now}
}

func (ev IntegrityEvent) validate(linkStart string) error {
	switch ev.Kind {
	case IntegrityNOSMismatch, IntegrityHostChange, IntegrityScanIncomplete, IntegrityBaselineTamper, IntegrityReferenceConflict:
	default:
		return fmt.Errorf("%w: unknown kind", ErrInvalidIntegrityEvent)
	}
	if !validClass(ev.Class) {
		return fmt.Errorf("%w: class", ErrInvalidIntegrityEvent)
	}
	switch ev.Severity {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return fmt.Errorf("%w: severity", ErrInvalidIntegrityEvent)
	}
	if ev.Count < 0 {
		return fmt.Errorf("%w: negative count", ErrInvalidIntegrityEvent)
	}
	if ev.Link != "" && !validLink(ev.Link, linkStart) {
		return fmt.Errorf("%w: link", ErrInvalidIntegrityEvent)
	}
	return nil
}

// validClass accepts 1 to maxIntegrityClass bytes of a-z, 0-9 and '_',
// starting with a letter.
func validClass(s string) bool {
	if s == "" || len(s) > maxIntegrityClass || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// validLink accepts only linkStart (the configured NOS base URL and the fixed
// integrity route) followed by a decimal finding ID of 1 to maxIntegrityLinkID
// digits. Nothing else can follow: no path segment, query, fragment or
// host-supplied text.
func validLink(s, linkStart string) bool {
	if len(s) > maxIntegrityLink || !strings.HasPrefix(s, linkStart) {
		return false
	}
	id := s[len(linkStart):]
	if id == "" || len(id) > maxIntegrityLinkID {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}

// integrityLabel reduces a host label to plain text: the shared clean rules
// (control and bidi characters, one line, length bound), then only letters,
// digits, spaces and '-', '_'. Everything else, including '.', Markdown
// link syntax, URLs and mentions, becomes '?'. Dropping '.' keeps a label
// from forming a domain that a chat client would link.
func integrityLabel(s string) string {
	s = clean(s, maxIntegrityLabel)
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('?')
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return unnamedHost
	}
	return out
}

// integrityTitle returns the title of an integrity event; ok is false for
// other kinds.
func integrityTitle(e Event) (string, bool) {
	var what string
	switch IntegrityKind(e.Kind) {
	case IntegrityNOSMismatch:
		what = "NOS mismatch on "
	case IntegrityHostChange:
		what = "host change on "
	case IntegrityScanIncomplete:
		what = "scan incomplete on "
	case IntegrityBaselineTamper:
		what = "baseline tamper on "
	case IntegrityReferenceConflict:
		what = "reference conflict on "
	default:
		if e.Kind == KindIntegrityDigest {
			return "Nebula: integrity: summary of the last hour", true
		}
		return "", false
	}
	return "Nebula: integrity: " + what + e.Host, true
}

// digestLocked takes the held counts when their hour has ended. Caller
// holds g.mu.
func (g *IntegrityGate) digestLocked(now time.Time) *integrityDigest {
	if len(g.held) == 0 || now.Sub(g.heldSince) < IntegrityWindow {
		return nil
	}
	d := &integrityDigest{counts: g.held, since: g.heldSince}
	g.held = map[IntegrityKind]int{}
	g.heldSince = time.Time{}
	return d
}

type integrityDigest struct {
	counts map[IntegrityKind]int
	since  time.Time
}

// deliverDigest sends d. A digest no provider accepts gives its counts back,
// so the next attempt reports them.
func (g *IntegrityGate) deliverDigest(ctx context.Context, d *integrityDigest) bool {
	if d == nil {
		return false
	}
	kinds := make([]string, 0, len(d.counts))
	total := 0
	for k, c := range d.counts {
		kinds = append(kinds, string(k))
		total += c
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s: %d", k, d.counts[IntegrityKind(k)]))
	}
	noun := "notifications"
	if total == 1 {
		noun = "notification"
	}
	ev := Event{Kind: KindIntegrityDigest, State: "digest",
		Reason: fmt.Sprintf("%d integrity %s held by the hourly limit (%s)", total, noun, strings.Join(parts, ", ")),
		Time:   g.now()}
	if len(g.n.send(ctx, ev, nil)) > 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, c := range d.counts {
		g.held[k] += c
	}
	if g.heldSince.IsZero() || d.since.Before(g.heldSince) {
		g.heldSince = d.since
	}
	return false
}

// prune drops delivery times that left the window. Caller holds g.mu.
func (g *IntegrityGate) prune(now time.Time) {
	cut := 0
	for cut < len(g.sent) && now.Sub(g.sent[cut]) >= IntegrityWindow {
		cut++
	}
	g.sent = g.sent[cut:]
}

// releaseLocked removes one reserved slot taken at t. Caller holds g.mu.
func (g *IntegrityGate) releaseLocked(t time.Time) {
	for i := len(g.sent) - 1; i >= 0; i-- {
		if g.sent[i].Equal(t) {
			g.sent = append(g.sent[:i], g.sent[i+1:]...)
			return
		}
	}
}

// holdLocked counts one held message of kind. Caller holds g.mu.
func (g *IntegrityGate) holdLocked(kind IntegrityKind, now time.Time) {
	if len(g.held) == 0 {
		g.heldSince = now
	}
	g.held[kind]++
}

// markLocked records that key was notified or held. Caller holds g.mu.
func (g *IntegrityGate) markLocked(dk IntegrityKey) {
	if g.notified[dk] {
		return
	}
	g.notified[dk] = true
	g.order = append(g.order, dk)
	if len(g.order) > MaxTrackedIntegrityKeys {
		delete(g.notified, g.order[0])
		g.order = g.order[1:]
	}
}
